"""Focused dexd checks with fake relisten/probe scripts: epoch window, viewer wait, replug request, single SIGTERM
forwarding, kill after the stop limit, FIFOs, rotation, pins; no phone, USB or ADB."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import dexd

# Counts SIGTERMs; writes result.json with stop_reason=sigterm on the first and exits after
# DELAY seconds (env), so a second SIGTERM in that time would be counted too.
FAKE_PROBE='''import json,os,signal,sys,time
args=sys.argv[1:]
out=args[args.index("--output")+1]
os.mkdir(out)
open(args[args.index("--streaming-file")+1],"w").close()
terms=[]
signal.signal(signal.SIGTERM,lambda *a:terms.append(1))
deadline=None
while True:
    time.sleep(.05)
    if terms and deadline is None:
        deadline=time.monotonic()+float(os.environ.get("FAKE_DELAY","0.5"))
    if deadline is not None and time.monotonic()>=deadline:
        break
json.dump(dict(terms=len(terms),live=dict(stop_reason="sigterm"),rtsp_teardown_status=200),open(out+"/result.json","w"))
sys.exit(0)
'''


def hold(path):
    """A viewer stand-in that holds the lock itself, so killing it releases the lock."""
    return subprocess.Popen([sys.executable,"-c","import fcntl,sys,time\nf=open(sys.argv[1],'a')\n"
                             "fcntl.flock(f,fcntl.LOCK_EX)\ntime.sleep(10)",str(path)])


class Env:
    def __init__(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.logdir,self.run=root/"log",root/"run"
        self.logdir.mkdir()
        self.run.mkdir(mode=0o700)
        self.probe=root/"probe.py"
        self.probe.write_text(FAKE_PROBE)
        self.patches=[patch.object(dexd,"LOGDIR",self.logdir),patch.object(dexd,"RUN",self.run),
                      patch.object(dexd,"PROBE",self.probe),
                      # Never the real gateway: on backend its port belongs to the running dexd.
                      patch.object(dexd,"GATEWAY_CONFIG",root/"no-gateway.json"),
                      patch.object(dexd,"check_pins",lambda:None)]  # last: a test stops it
        for p in self.patches:
            p.start()

    def close(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def log(self):
        return (self.logdir/"dexd.log").read_text()


class Tests(unittest.TestCase):
    def setUp(self):
        self.env=Env()
        self.addCleanup(self.env.close)
        self.out=contextlib.redirect_stdout(io.StringIO())
        self.out.__enter__()
        self.addCleanup(self.out.__exit__,None,None,None)

    def test_container_epoch_is_now_minus_container_uptime(self):
        with patch("builtins.open",lambda *a,**k:io.StringIO("12.75 3.0\n")),patch.object(time,"time",lambda:1000.0):
            self.assertEqual(dexd.container_started_epoch(),987)

    def test_relisten_only_inside_the_window_and_judged_by_its_result(self):
        d=dexd.Dexd()
        with patch.object(d,"spawn") as spawn:
            self.assertFalse(d.relisten((3,9),int(time.time())-dexd.RELISTEN_WINDOW_SECONDS-1))
            spawn.assert_not_called()
        self.assertIn("relisten skipped",self.env.log())
        script=Path(self.env.tmp.name)/"relisten.sh"
        for errors,expected in (([],True),(["helper"],False)):
            outdir=Path(self.env.tmp.name)/("relisten-%d"%len(errors))
            outdir.mkdir()
            (outdir/"result.json").write_text(json.dumps(dict(bootstrap_observed=True,errors=errors)))
            script.write_text('[ "$1 $2" = "003 009" ] || exit 9\necho noise\n'
                              'echo "RECONNECT_FINISHED exit=0 output=%s transcript=t"\n'%outdir)
            with patch.object(dexd,"RELISTEN",script):
                self.assertIs(d.relisten((3,9),int(time.time())),expected)
        self.assertIn("relisten exit=0 bootstrap_observed=True errors=['helper']",self.env.log())

    def test_refused_relisten_is_logged_with_its_stop_line(self):
        script=Path(self.env.tmp.name)/"relisten.sh"
        script.write_text("echo 'STOP: this reconnect marker has already been consumed.' >&2\nexit 1\n")
        with patch.object(dexd,"RELISTEN",script):
            self.assertFalse(dexd.Dexd().relisten((3,9),int(time.time())))
        self.assertIn("relisten exit=1 STOP: this reconnect marker",self.env.log())

    def test_session_stop_sends_one_sigterm_and_never_touches_the_black_screen(self):
        d=dexd.Dexd()
        checks=[]
        d.ensure_blackscreen=lambda:checks.append(1)
        rc=[]
        dexd.fresh_run_dir()
        before=os.lstat(self.env.run/"ts.fifo").st_ino
        worker=threading.Thread(target=lambda:rc.append(d.session((3,9))))
        worker.start()
        wait=time.monotonic()+5
        while not (self.env.run/"streaming").exists() and time.monotonic()<wait:
            time.sleep(.05)
        time.sleep(.6)
        self.assertEqual(checks,[])
        for name in ("ts.fifo","input.fifo"):
            self.assertTrue(stat.S_ISFIFO(os.lstat(self.env.run/name).st_mode))
        # The session keeps the FIFO a waiting viewer has open.
        self.assertEqual(os.lstat(self.env.run/"ts.fifo").st_ino,before)
        d.terminate()
        d.terminate()
        worker.join(10)
        self.assertEqual(rc,[0])
        result=json.loads(next(self.env.logdir.glob("session-*/result.json")).read_text())
        self.assertEqual(result["terms"],1)
        self.assertIn("stop_reason=sigterm",self.env.log())

    def test_child_that_ignores_sigterm_is_killed_after_the_stop_limit(self):
        d=dexd.Dexd()
        child=d.spawn([sys.executable,"-c","import signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(30)"])
        time.sleep(.3)
        d.terminate()
        started=time.monotonic()
        with patch.object(dexd,"STOP_SECONDS",1):
            self.assertEqual(d.finish(child,60),-9)
        self.assertLess(time.monotonic()-started,5)
        self.assertIsNone(d.spawn(["true"]))

    def run_dexd(self,d,**patches):
        dexd.LOGDIR.mkdir(exist_ok=True)
        # Never a real ADB call from a test.
        vars(d).setdefault("ensure_blackscreen",lambda:None)
        worker=threading.Thread(target=d.serve,args=(int(time.time()),))
        with patch.object(dexd.subprocess,"run"):
            ctx=[patch.object(d,k,v) if hasattr(d,k) and k in ("relisten","session") else patch.object(dexd,k,v)
                 for k,v in patches.items()]
            for c in ctx:
                c.start()
            try:
                worker.start()
                yield worker
            finally:
                d.terminate()
                worker.join(10)
                for c in ctx:
                    c.stop()

    def test_one_session_only_after_a_viewer_holds_the_lock_then_replug_request(self):
        d=dexd.Dexd()
        calls=[]
        order=[]
        requests=Path(self.env.tmp.name)/"host"
        requests.mkdir()
        d.ensure_blackscreen=lambda:order.append("blackscreen")
        flow=self.run_dexd(d,find_phone=lambda:(3,9),relisten=lambda p,e:order.append("relisten") or True,
                           session=lambda phone:calls.append(phone) or 0,REQUEST_DIR=requests,
                           check_pins=lambda:order.append("pins"))
        next(flow)
        time.sleep(1.2)
        # The black screen comes with the phone, before any viewer.
        self.assertEqual((calls,order),([],["pins","relisten","blackscreen"]))
        # While waiting, the FIFOs are there for the viewer to open.
        for name in ("ts.fifo","input.fifo","cursor.fifo"):
            self.assertTrue(stat.S_ISFIFO(os.lstat(self.env.run/name).st_mode))
        holder=hold(self.env.run/"viewer.lock")
        try:
            wait=time.monotonic()+5
            while not (requests/"replug").exists() and time.monotonic()<wait:
                time.sleep(.05)
        finally:
            holder.kill();holder.wait()
        self.assertEqual(calls,[(3,9)])
        # Replug even after a clean session: restart-only cycles let the phone refuse the next connect.
        self.assertIn("mode=replug session ended exit=0 relisten=True",(requests/"replug").read_text())
        self.assertFalse((requests/".replug.tmp").exists())
        time.sleep(1)
        self.assertEqual(calls,[(3,9)])
        with contextlib.suppress(StopIteration):
            next(flow)
        log=self.env.log()
        self.assertLess(log.index("waiting for a viewer"),log.index("viewer connected"))

    def test_failed_relisten_asks_for_a_replug_not_a_restart(self):
        d=dexd.Dexd()
        requests=Path(self.env.tmp.name)/"host"
        requests.mkdir()
        flow=self.run_dexd(d,find_phone=lambda:(3,9),relisten=lambda p,e:False,
                           session=lambda phone:1,REQUEST_DIR=requests)
        next(flow)
        holder=hold(self.env.run/"viewer.lock")
        try:
            wait=time.monotonic()+5
            while not (requests/"replug").exists() and time.monotonic()<wait:
                time.sleep(.05)
        finally:
            holder.kill();holder.wait()
        with contextlib.suppress(StopIteration):
            next(flow)
        self.assertIn("mode=replug session ended exit=1 relisten=False",(requests/"replug").read_text())

    def test_failed_session_after_a_passed_relisten_asks_for_a_replug(self):
        d=dexd.Dexd()
        requests=Path(self.env.tmp.name)/"host"
        requests.mkdir()
        flow=self.run_dexd(d,find_phone=lambda:(3,9),relisten=lambda p,e:True,
                           session=lambda phone:1,REQUEST_DIR=requests)
        next(flow)
        holder=hold(self.env.run/"viewer.lock")
        try:
            wait=time.monotonic()+5
            while not (requests/"replug").exists() and time.monotonic()<wait:
                time.sleep(.05)
        finally:
            holder.kill();holder.wait()
        with contextlib.suppress(StopIteration):
            next(flow)
        self.assertIn("mode=replug session ended exit=1 relisten=True",(requests/"replug").read_text())

    def test_stop_while_waiting_means_no_session_and_no_request(self):
        d=dexd.Dexd()
        requests=Path(self.env.tmp.name)/"host"
        requests.mkdir()
        flow=self.run_dexd(d,find_phone=lambda:(3,9),relisten=lambda p,e:True,
                           session=lambda phone:self.fail("no viewer"),REQUEST_DIR=requests)
        next(flow)
        time.sleep(.5)
        with contextlib.suppress(StopIteration):
            next(flow)
        self.assertEqual(list(requests.iterdir()),[])
        self.assertNotIn("viewer connected",self.env.log())

    def test_pin_mismatch_refuses_before_the_relisten(self):
        d=dexd.Dexd()
        def bad():
            raise RuntimeError("approved source mismatch: dexd.py")
        flow=self.run_dexd(d,find_phone=lambda:(3,9),relisten=lambda p,e:self.fail("relisten"),
                           session=lambda phone:self.fail("session"),check_pins=bad)
        next(flow)
        time.sleep(.5)
        with contextlib.suppress(StopIteration):
            next(flow)
        self.assertIn("refused: approved source mismatch",self.env.log())

    def test_viewer_waiting_follows_a_real_flock_holder(self):
        self.assertFalse(dexd.viewer_waiting())
        holder=hold(self.env.run/"viewer.lock")
        try:
            wait=time.monotonic()+3
            while not dexd.viewer_waiting() and time.monotonic()<wait:
                time.sleep(.05)
            self.assertTrue(dexd.viewer_waiting())
        finally:
            holder.kill();holder.wait()
        self.assertFalse(dexd.viewer_waiting())

    def test_missing_host_folder_is_logged(self):
        with patch.object(dexd,"REQUEST_DIR",Path(self.env.tmp.name)/"absent"):
            dexd.request_replug("x","restart")
        self.assertIn("replug request failed",self.env.log())

    def test_no_phone_means_no_relisten_or_session(self):
        d=dexd.Dexd()
        threading.Timer(.3,d.terminate).start()
        with patch.object(dexd,"find_phone",lambda:None),patch.object(dexd,"PHONE_WAIT_SECONDS",0), \
                patch.object(d,"relisten") as relisten,patch.object(d,"session") as session:
            d.run()
        relisten.assert_not_called()
        session.assert_not_called()
        self.assertIn("no single phone",self.env.log())

    def test_fresh_run_dir_replaces_fifos_and_old_markers(self):
        (self.env.run/"ts.fifo").write_text("stale regular file")
        (self.env.run/"stop").touch()
        (self.env.run/"streaming").touch()
        dexd.fresh_run_dir()
        self.assertEqual(sorted(p.name for p in self.env.run.iterdir()),["cursor.fifo","input.fifo","ts.fifo"])
        self.assertTrue(stat.S_ISFIFO(os.lstat(self.env.run/"cursor.fifo").st_mode))
        self.assertTrue(stat.S_ISFIFO(os.lstat(self.env.run/"ts.fifo").st_mode))

    def test_rotation_keeps_the_newest_sessions_and_their_logs(self):
        for i in range(5):
            (self.env.logdir/("session-2026110%d"%i)).mkdir()
            (self.env.logdir/("session-2026110%d.stderr.log"%i)).touch()
        dexd.rotate(2)
        self.assertEqual(sorted(p.name for p in self.env.logdir.iterdir()),
                         ["session-20261103","session-20261103.stderr.log",
                          "session-20261104","session-20261104.stderr.log"])

    def test_pin_mismatch_refuses_the_session(self):
        self.env.patches[-1].stop()
        self.env.patches.pop()
        name=Path(self.env.tmp.name)/"pinned.py"
        name.write_text("x=1\n")
        with patch.object(dexd,"RESEARCH",name.parent),patch.object(dexd,"EXPECTED",{"pinned.py":"0"*64}):
            self.assertEqual(dexd.Dexd().session((3,9)),1)
        self.assertIn("approved source mismatch: pinned.py",self.env.log())
        with patch.object(dexd,"EXPECTED",{}):
            self.assertRaisesRegex(RuntimeError,"empty",dexd.check_pins)

    def test_black_screen_is_only_ever_checked_or_started(self):
        # User 2026-11-03: once on, only the user turns it off, physically. dexd never stops it.
        for running,expected in ((0,["running"]),(1,["running","start"])):
            calls=[]
            def run(argv,**kw):
                calls.append(argv[-1])
                return subprocess.CompletedProcess(argv,running if argv[-1]=="running" else 0,"","")
            with patch.object(dexd.subprocess,"run",run):
                dexd.Dexd().ensure_blackscreen()
            self.assertEqual(calls,expected)
        source=Path(dexd.__file__).read_text()
        for command in ("stop","uninstall","force-stop"):
            self.assertNotIn('adb("%s")'%command,source)
            self.assertNotIn(command+'"]',source.replace("killpg",""))

    def test_shipped_unit_runs_dexd_as_dex_with_a_private_run_dir(self):
        unit=(Path(dexd.__file__).parent/"dexd.service").read_text()
        for line in ("User=dex","RuntimeDirectory=dex-run","RuntimeDirectoryMode=0700","KillMode=mixed",
                     "TimeoutStopSec=50","Restart=no","ExecStart=/usr/bin/python3 -u /home/dex/dex-experiment/research/native-usb/dexd.py"):
            self.assertIn(line+"\n",unit)
        self.assertNotIn("PrivateTmp",unit)
        self.assertLess(dexd.STOP_SECONDS,50)


if __name__=="__main__":
    unittest.main()
