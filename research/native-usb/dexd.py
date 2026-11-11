"""dexd: the DeX pipeline in the backend machine (dexd.service, User=dex; 77-DEXD_PIPELINE.md, revised).

One backend run serves one viewer (user 2026-11-03):
1. on backend start, find
   the single phone (vvvv:pppp), check the source pins, and run
   reconnect_relisten.sh once with the backend machine start as its epoch, inside
   DeX's indication window. That only reopens the phone's one-shot listener;
   DeX is not connected yet;
2. wait until a viewer holds RUN/viewer.lock (dex_desktop.py --attach);
   Before waiting, the black-screen app is started if absent: the phone screen is
   black whenever the phone is in the backend machine (user 2026-11-03), DeX or not;
3. run ONE session (kms_daemon_probe) for it;
4. when the session ends (viewer gone, KMS closed or an error), write a request
   in REQUEST_DIR to replug
   the phone, so the next viewer gets a fresh start.
   Replug always (user 2026-11-06): after restart-only cycles the phone refused
   the next connect (status 4, error 111) 7 of 30 times that day, after replug
   cycles 0 of 7; a replug cycle is ready ~8 s later (19-21 s against 11-12 s).
SIGTERM (systemd at backend stop) goes to the running child as ONE SIGTERM:
the session ends its window, sends TEARDOWN and runs every cleanup. Standing
approval (user 2026-11-03) covers these phone actions; nothing else is sent.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
RESEARCH=ROOT/"research/native-usb"
LOGDIR=Path(os.environ.get("DEXD_LOG_DIR",RESEARCH/"dexd"))
RUN=Path(os.environ.get("RUNTIME_DIRECTORY","/run/dex-run"))
# Where dexd leaves its replug request.
REQUEST_DIR=Path(os.environ.get("DEXD_REQUEST_DIR","<request-dir>"))
# Direct TLS gateway settings (token and certificate paths); absent = no gateway.
GATEWAY_CONFIG=Path.home()/".config/dex-gateway/server.json"
# Per-site settings (user 2026-11-07):
# {"timezone": "Area/City", "phone_serial": "..."}; both optional.
SITE_CONFIG=Path.home()/".config/dex-gateway/site.json"
RELISTEN=RESEARCH/"reconnect_relisten.sh"
BLACKSCREEN=RESEARCH/"blackscreen/blackscreen.sh"
PROBE=RESEARCH/"kms_daemon_probe.py"
PYTHONPATH=":".join(str(ROOT/p) for p in ("tools/crypto-root/usr/lib/python3/dist-packages",
                                          "tools/usb-root/usr/lib/python3/dist-packages"))
VENDOR,PRODUCT=0x0000,0x0000
PHONE_WAIT_SECONDS=30
# reconnect_relisten.sh refuses a marker older than 45 s.
RELISTEN_WINDOW_SECONDS=45
RELISTEN_SECONDS=120
UI_DEADLINE_SECONDS=75
# The child gets this long after SIGTERM (TEARDOWN 2 s, cleanup a few s); dexd.service allows 50 s.
STOP_SECONDS=40
POLL_SECONDS=.5
ADB_SECONDS=30
KEEP_SESSIONS=20
EXPECTED={'duplex_link.py': 'e9cc017b3d0b2106ddaacd7daa6d27cc3a4cbcfe57ae613203a1da9b237c46d0', 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4', 'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0', 'rtsp_hello.py': 'f3d487c194cb51d5041942ce3599928148d8b10cb6db88ea9cd71ea54a00db3b', 'rtsp_capabilities.py': '0ea945fea841680ce14d58f435e5adcaa90e7100505e3ea4650b42e4a088a7d4', 'rtsp_setup.py': '9d2acc07e2ea07a039a2c1020ac3995227f3f77cb74f0f553d54c38bc4ebe238', 'rtsp_udp_setup.py': 'e926b95bdfde5cb7fde209fa44d3db5986c6d0a67863b57e8b609cf786af83f1', 'ui_confirm.py': 'dcc55d9ab5866842370f6dd39f84f803a0ba0e3c1ae050be7d6edf48058c0394', 'wfd_startup.py': '150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df', 'idc_handshake.py': '1826c43df350a83531547887444a88fc6aa91e9c36200c62e5758b3616514d6e', 'idc.py': 'b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6', 'usb_tunnel.py': 'e4835e708921672a012be58e19a1fb276301c15a7a26c1e6715d76c108238133', 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1', 'udp_tunnel.py': 'fa9a7ce9f0657279b05662335b0860f53a2125849b8bbf5a174a9d8833628d04', 'idc_capture.py': '0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647', 'loopback_transfer.py': 'a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6', 'loopback_capture.py': 'ec5ffe6c70eca6e6c937e5b51cc17f27c4154b8072e9f4c0b92342a04fa0a267', 'auth_probe.py': '3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6', 'capabilities_probe.py': '368005a3113d4fcbf9eccaf3ffe176c8959072b93d61d57bfd2767d2ddaceba2', 'pss_probe.py': '48874690a939687a193e78e81d56c7370c6fd15bec034e80d58c1896bd53c41b', 'tunnel_probe.py': '824add622548ccae8f0fbc3633bd5dec5abad986c36b7f1323cb2eeb0ded1f14', 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1', 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a', 'version_query.py': 'bf3b459d624655f6b37074c23876bab20f72275967a36752edf600e5a130a758', 'rtsp_udp_play.py': '18ab29b2a6780dc803702268fa2b36557269f39a5758ef8d69a1d3db84ffa2a1', 'conn_transfer.py': 'cc681c6ca5b7a0117d8f017e6538d511bc3f27bc6ad9049e4b52467f18f6d6cf', 'rtsp_udp_live.py': 'a66248078833f8429042715e1980a9dc6f10f67e3cab47cc818e2840960d157f', 'live_sink.py': 'ad6054c773fcfe1c63473757469bdf1ccc74eb1c965805d77e9f4617139b0a73', 'rtsp_udp_long.py': 'efe5132db7bc8c82bafc1c81cbfd8eb1f5c4d51c512acc8b671ff73560c23dc3', 'kms_mouse_live.py': '5576f8d1261f388f941b6d7b5221728fc4626b96c5e30214322c1f18dc571cf9', 'kms_handshake.py': '47a530360a186008f313eaa68ff89ad151ad5ab8fd844d7dd1027d0340924ac2', 'sidesync_packets.py': 'a382472f8d5e6ff8c8901371efe946937137017bae27d2fe7058a5af24738ce9', 'kms_hover_live.py': '5096acb84dd28d7691d9a8fdc5eb1e5505160fd97ba2e0526d46feb4360bea09', 'kms_input_live.py': '9d560161d09a9094d4849f44fb0d436abb0abbc8ff407f50d6efdfb7acf553b1', 'kms_session_live.py': 'c529a8dabe0c31539d248fcafaed759e79a089f6d1f44cf0f57d0ed082a927de', 'kms_daemon_live.py': 'e15b67b7034f71fc0d0d270cf1c1547043aae2e2568e264fbaabe63027fda08c', 'kms_daemon_probe.py': '33c6304cee24136010395db5aeb0acd544d9330ba77fbb6a5161a4e87e07665b', 'reconnect_relisten.sh': '75c12a98b7d68bb675529604a5bd98f11ebf7fcb98dc1ce826402bd0c4aecb85', 'blackscreen/blackscreen.sh': '42f6568251273ac57f671b4bf3b13242a42a8ad5a50d94447bbc9305591df808', 'threaded_input.py': '258c5694ff5bf78b02da259255f6d4b8c9870818e1d097d9fb905ab08ac8e46f', 'site_env.py': '4787c7ff8a4b2a0afaf5e2fc68834530f5beb08d5d1a006de01de0b902294fd9', 'clipboard_bridge.py': '4471c768f0210c092244430aeb412a834d85b9b80e2bdc086b6adb8e870e3225', 'file_bridge.py': '1afc3615e7aedeb34689743183a2d73e9797dad07f247d29760206c4c880cba2', 'phone_files.py': 'a731251a363f62ba430d08d41ec331f7492ea07591d85d94d477045396241124', 'direct_gateway.py': 'f0d6874b8ee45a1bba8cd8333eabb26671262afd09b86b2fbe692e14741bb7ee'}


def site_settings(path=None):
    """The site settings; {} when absent or unreadable (UTC logs, any single phone)."""
    try:
        data=json.loads(Path(path or SITE_CONFIG).read_text())
    except (OSError,ValueError):
        return {}
    return {k:v for k,v in data.items()
            if k in ("timezone","phone_serial","sink_name","video_mode") and isinstance(v,str) and v}


def session_environment(settings):
    """Sink name and video mode for the session (site_env reads and validates them)."""
    return {name:settings[key] for key,name in (("sink_name","DEX_SINK_NAME"),("video_mode","DEX_VIDEO_MODE"))
            if key in settings}


def apply_timezone(settings):
    if settings.get("timezone"):
        os.environ["TZ"]=settings["timezone"]
        time.tzset()


def log(message):
    line="%s dexd %s"%(time.strftime("%Y-%m-%dT%H:%M:%S%z"),message)
    print(line,flush=True)
    try:
        with open(LOGDIR/"dexd.log","a") as out:
            out.write(line+"\n")
    except OSError:
        pass


def container_started_epoch():
    """/proc/uptime here counts from the backend start: now minus uptime is that start."""
    with open("/proc/uptime") as f:
        return int(time.time()-float(f.read().split()[0]))


def find_phone():
    """(bus, address) of the single phone, or None."""
    import usb.core
    phones=list(usb.core.find(find_all=True,idVendor=VENDOR,idProduct=PRODUCT))
    return (phones[0].bus,phones[0].address) if len(phones)==1 else None


def check_pins():
    if not EXPECTED:
        raise RuntimeError("empty approved source manifest")
    for name,digest in EXPECTED.items():
        if hashlib.sha256((RESEARCH/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError("approved source mismatch: "+name)


def rotate(keep=KEEP_SESSIONS):
    sessions=sorted(p for p in LOGDIR.glob("session-*") if p.is_dir())
    for old in sessions[:-keep] if keep else sessions:
        shutil.rmtree(old,ignore_errors=True)
        Path(str(old)+".stderr.log").unlink(missing_ok=True)


def viewer_waiting():
    """True while a viewer holds viewer.lock (its flock -n succeeded)."""
    with open(RUN/"viewer.lock","a") as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EAGAIN,errno.EACCES):
                return True
            raise
        fcntl.flock(lock,fcntl.LOCK_UN)
        return False


def request_replug(reason,mode):
    """One request file; written then renamed, so its reader never sees half of it.

    mode=replug: the phone gets a fresh USB connect (dexd's only mode since 2026-11-06).
    mode=restart (backend restart only, proven 2026-11-03 12:44) is still understood."""
    try:
        tmp=REQUEST_DIR/".replug.tmp"
        tmp.write_text("%s mode=%s %s\n"%(time.strftime("%Y-%m-%dT%H:%M:%S%z"),mode,reason))
        tmp.rename(REQUEST_DIR/"replug")
        log("%s requested: %s"%(mode,reason))
    except OSError as error:
        log("replug request failed (%s); replug the phone by hand"%error)


def fresh_run_dir():
    """New FIFOs for this backend run (one session); stale markers removed."""
    for name in ("ts.fifo","input.fifo","cursor.fifo","stop","streaming"):
        (RUN/name).unlink(missing_ok=True)
    # cursor.fifo: the session's pointer-shape lines for the gateway (cosmetic).
    for name in ("ts.fifo","input.fifo","cursor.fifo"):
        os.mkfifo(RUN/name,0o600)


def signal_group(child,signum):
    try:
        os.killpg(child.pid,signum)
    except ProcessLookupError:
        pass


class Dexd:
    def __init__(self):
        self.stopping=threading.Event()
        self.gateway=None

    def terminate(self,signum=None,frame=None):
        # Only a flag: the wait loop forwards ONE SIGTERM. A second one would raise
        # inside the probe's cleanup if it arrived before the media window.
        self.stopping.set()

    def spawn(self,argv,**kwargs):
        if self.stopping.is_set():
            return None
        return subprocess.Popen(argv,start_new_session=True,stdin=subprocess.DEVNULL,**kwargs)

    def finish(self,child,seconds):
        """Wait for the child; once stopping, it gets one SIGTERM and STOP_SECONDS, then SIGKILL."""
        deadline=time.monotonic()+seconds
        stop_deadline=None
        while True:
            try:
                return child.wait(POLL_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            now=time.monotonic()
            if self.stopping.is_set() and stop_deadline is None:
                signal_group(child,signal.SIGTERM)
                stop_deadline=now+STOP_SECONDS
            if now>=deadline or (stop_deadline is not None and now>=stop_deadline):
                log("child %d did not exit; killing it"%child.pid)
                signal_group(child,signal.SIGKILL)
                return child.wait()

    def relisten(self,phone,epoch):
        age=int(time.time())-epoch
        if age>RELISTEN_WINDOW_SECONDS:
            log("relisten skipped: backend started %d s ago (window %d s)"%(age,RELISTEN_WINDOW_SECONDS))
            return False
        child=self.spawn(["bash",str(RELISTEN),"%03d"%phone[0],"%03d"%phone[1],str(epoch)],
                         cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        if child is None:
            return False
        lines=[]
        reader=threading.Thread(target=lambda:lines.extend(child.stdout),daemon=True)
        reader.start()
        rc=self.finish(child,RELISTEN_SECONDS)
        reader.join(5)
        child.stdout.close()
        finished=next((l.strip() for l in reversed(lines) if l.startswith("RECONNECT_FINISHED")),None)
        stopped=next((l.strip() for l in lines if l.startswith("STOP:")),None)
        ok=False
        output=finished and dict(f.split("=",1) for f in finished.split()[1:] if "=" in f).get("output")
        if output:
            try:
                result=json.loads((ROOT/output/"result.json").read_text())
                ok=rc==0 and result.get("bootstrap_observed") is True and result.get("errors")==[]
                log("relisten exit=%d bootstrap_observed=%s errors=%s output=%s"%(
                    rc,result.get("bootstrap_observed"),result.get("errors"),output))
            except (OSError,ValueError) as error:
                log("relisten exit=%d output=%s unreadable result: %s"%(rc,output,error))
        else:
            log("relisten exit=%d %s"%(rc,stopped or "no result"))
        return ok

    def ensure_blackscreen(self):
        """One read; start the app only if it is not running."""
        def adb(command):
            serial=site_settings().get("phone_serial","")
            return subprocess.run(["bash",str(BLACKSCREEN),command],cwd=ROOT,stdin=subprocess.DEVNULL,
                                  env=dict(os.environ,DEX_PHONE_SERIAL=serial),
                                  capture_output=True,text=True,timeout=2*ADB_SECONDS)
        try:
            if adb("running").returncode==0:
                log("black screen running")
                return
            done=adb("start")
            log("black screen started exit=%d"%done.returncode if done.returncode==0 else
                "black screen start failed exit=%d: %s"%(done.returncode,(done.stderr or done.stdout).strip()[-300:]))
        except (OSError,subprocess.TimeoutExpired) as error:
            log("black screen check failed: %s"%error)

    def session(self,phone):
        """The viewer's session; exit status 0 after viewer_left, SIGTERM or the stop file."""
        try:
            check_pins()
        except (OSError,RuntimeError) as error:
            log("session refused: %s"%error)
            return 1
        rotate(KEEP_SESSIONS-1)
        stamp=time.strftime("%Y%m%dT%H%M%S%z")
        output=LOGDIR/("session-"+stamp)
        # TZ comes from site settings (apply_timezone at start), inherited via os.environ.
        env=dict(os.environ,PYTHONPATH=PYTHONPATH,
                 DEX_AUTO_UI_DEADLINE=str(time.monotonic()+UI_DEADLINE_SECONDS),
                 **session_environment(site_settings()))
        with open(str(output)+".stderr.log","x") as stderr:
            child=self.spawn([sys.executable,str(PROBE),"--approved-phone-kms-daemon",
                "--accept-persistent-state","--bus",str(phone[0]),"--address",str(phone[1]),
                "--output",str(output),"--ts-fifo",str(RUN/"ts.fifo"),"--stop-file",str(RUN/"stop"),
                "--input-fifo",str(RUN/"input.fifo"),"--event-log",str(LOGDIR/"dexd.log"),
                "--streaming-file",str(RUN/"streaming")],
                cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=stderr)
        if child is None:
            return 1
        log("session started pid=%d bus=%03d address=%03d output=%s"%(child.pid,phone[0],phone[1],output))
        while True:
            try:
                rc=child.wait(POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass
            if self.stopping.is_set():
                rc=self.finish(child,STOP_SECONDS)
                break
        try:
            result=json.loads((output/"result.json").read_text())
            live=result.get("live",{})
            log("session exit=%d stop_reason=%s error=%s: %s teardown=%s sink=%s"%(
                rc,live.get("stop_reason"),result.get("error_type"),result.get("error"),
                result.get("rtsp_teardown_status"),live.get("sink")))
        except (OSError,ValueError):
            log("session exit=%d without result.json; see %s.stderr.log"%(rc,output))
        return rc

    def start_adb(self):
        """Local only: the black screen and ui_confirm's ADB calls need the backend machine's server."""
        try:
            subprocess.run(["adb","start-server"],stdin=subprocess.DEVNULL,capture_output=True,
                           timeout=15,check=True)
        except (OSError,subprocess.SubprocessError) as error:
            log("adb server did not start: %s"%error)

    def run(self):
        apply_timezone(site_settings())
        LOGDIR.mkdir(parents=True,exist_ok=True)
        signal.signal(signal.SIGTERM,self.terminate)
        epoch=container_started_epoch()
        log("start pid=%d container_started=%d"%(os.getpid(),epoch))
        try:
            self.serve(epoch)
            while not self.stopping.is_set():
                time.sleep(1)
        finally:
            if self.gateway is not None:
                self.gateway.close()
                self.gateway=None
        log("stop")
        return 0

    def serve(self,epoch):
        phone=None
        deadline=time.monotonic()+PHONE_WAIT_SECONDS
        while not self.stopping.is_set():
            phone=find_phone()
            if phone or time.monotonic()>=deadline:
                break
            time.sleep(1)
        if phone is None:
            log("no single phone %04x:%04x; idle until stopped"%(VENDOR,PRODUCT))
            return
        try:
            # Before the relisten too: it is a phone action.
            check_pins()
        except (OSError,RuntimeError) as error:
            log("refused: %s; idle until stopped"%error)
            return
        relistened=self.relisten(phone,epoch)
        # Before waiting: the viewer opens ts.fifo while its lock is held. The session must
        # keep these FIFOs: a viewer blocked in open() on a replaced one would never see data.
        fresh_run_dir()
        config=GATEWAY_CONFIG
        if config.exists():
            from direct_gateway import configured
            self.gateway=configured(config,RUN,lambda event:log("gateway "+json.dumps(event))).start()
            log("direct TLS gateway ready port=7443")
        self.start_adb()
        # In a thread: a slow ADB call must not delay a stop.
        threading.Thread(target=self.ensure_blackscreen,name="dexd-blackscreen",daemon=True).start()
        log("waiting for a viewer")
        while not self.stopping.is_set():
            if viewer_waiting():
                break
            time.sleep(POLL_SECONDS)
        if self.stopping.is_set():
            return
        log("viewer connected")
        self.start_adb()
        rc=self.session(phone)
        if self.gateway is not None:
            self.gateway.close()
            self.gateway=None
        if not self.stopping.is_set():
            # The listener accepted once: the next viewer needs a fresh USB connection.
            # Restart-only cycles let the phone refuse the next connect (docstring step 4).
            request_replug("session ended exit=%d relisten=%s"%(rc,relistened),"replug")

if __name__=="__main__":
    raise SystemExit(Dexd().run())
