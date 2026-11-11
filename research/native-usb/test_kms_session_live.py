"""Focused keyboard, extra-button, release, pin and session-script checks; no phone or real ADB server."""
from collections import Counter
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kms_input_live as base
import kms_session_live as ks
import kms_session_live_probe as probe
import kms_session_live_launch as launch
import rtsp_udp_long as long
import sidesync_packets
from usb_tunnel import TunnelError

HERE=Path(__file__).parent


def session():
    s=ks.SessionInput.__new__(ks.SessionInput)
    s.input=SimpleNamespace(events=lambda:[],counts=Counter(),close=lambda:None)
    s.kms_connection=SimpleNamespace(closed_by_phone=False)
    s.window_open=True
    s.cleanup=False
    s.pending=[]
    s.held={}
    s.keys_held=set()
    s.last_position=None
    s.input_sends=0
    s.input_error=None
    s.sent=Counter()
    s.dropped=Counter()
    s.releases_sent=s.keys_released=0
    s.heartbeats_sent=0
    s.last_heartbeat=None
    s.now=0
    s.clock=lambda:s.now
    s.log=lambda *a,**k:None
    s.wires=[]
    s.send=lambda connection,payload,**kw:s.wires.append(payload)
    return s


def feed(s,events):
    s.input=SimpleNamespace(events=lambda:list(events),counts=Counter(),close=lambda:None)


class Tests(unittest.TestCase):
    def test_key_packet_is_little_endian_scan_code_in_kind_0x15(self):
        self.assertEqual(ks.key_packet(ks.KEY_DOWN,30),bytes.fromhex("03 15 00 0b 00 00 00 1e 00 00 00"))
        self.assertEqual(ks.key_packet(ks.KEY_UP,0x2ff),bytes.fromhex("03 15 00 0b 00 01 00 ff 02 00 00"))

    def test_parse_accepts_keys_and_every_mapped_mouse_event(self):
        # 9, 10 and 13 are the file drag move/drop/start (file_bridge).
        for event in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17):
            self.assertEqual(ks.InputReader.parse(b"M %d 1 2"%event),(event,1,2))
        self.assertEqual(ks.InputReader.parse(b"K d 30"),("K",0,30))
        self.assertEqual(ks.InputReader.parse(b"K u 767"),("K",1,767))
        for line in (b"M 18 1 1",b"K d 0",b"K d 768",
                     b"K x 30",b"K d 30 ",b"K d -1",b"M 0 1920 0"):
            self.assertIsNone(ks.InputReader.parse(line),line)

    def test_mixed_batch_tracks_keys_and_buttons_in_order(self):
        s=session()
        feed(s,[("K",0,29),(6,5,5),("K",0,46),("K",1,46),(5,5,5),(15,7,7)])
        s._pump_input()
        self.assertEqual(s.wires,[ks.key_packet(0,29)+sidesync_packets.mouse_event(6,5,5)
                                  +ks.key_packet(0,46)+ks.key_packet(1,46)
                                  +sidesync_packets.mouse_event(5,5,5)+sidesync_packets.mouse_event(15,7,7)])
        self.assertEqual((s.keys_held,s.held,s.last_position),({29},{15:True},(7,7)))
        self.assertEqual(dict(s.sent),{"key_down":2,"key_up":1,"6":1,"5":1,"15":1})

    def test_window_end_releases_keys_then_buttons_once(self):
        s=session()
        s.keys_held={56,29}
        s.held={2:True,17:True}
        s.last_position=(3,4)
        s._release_held()
        s._release_held()
        self.assertEqual(s.wires,[ks.key_packet(1,29)+ks.key_packet(1,56)
                                  +sidesync_packets.mouse_event(1,3,4)+sidesync_packets.mouse_event(16,3,4)])
        self.assertEqual((s.keys_released,s.releases_sent,s.keys_held,s.held),(2,2,set(),{}))

    def test_failed_send_holds_pressed_keys_for_the_final_release(self):
        s=session()
        calls=[]
        def fail(connection,payload,**kw):
            calls.append(payload)
            raise TunnelError("gone")
        s.send=fail
        feed(s,[("K",0,42)])
        with self.assertRaisesRegex(TunnelError,"gone"):
            s._pump_input()
        self.assertEqual(s.keys_held,{42})
        s._release_held()
        self.assertEqual(calls[-1],ks.key_packet(1,42))
        self.assertIn("release",s.input_error)

    def test_release_failure_of_any_kind_never_raises(self):
        s=session()
        s.keys_held={30}
        s.send=lambda *a,**k:(_ for _ in ()).throw(RuntimeError("request budget"))
        s._release_held()
        self.assertIn("budget",s.input_error)

    def test_release_skipped_when_kms_closed(self):
        s=session()
        s.keys_held={30}
        s.kms_connection.closed_by_phone=True
        s._release_held()
        self.assertEqual((s.wires,s.dropped["release_skipped"]),([],1))

    def test_window_uses_keyboard_reader_and_releases_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.fifo"
            os.mkfifo(path,0o600)
            writer=None
            s=session()
            s.input=None
            s.input_fifo=path
            s.window_armed=True
            def window(self,seconds,until):
                self.window_armed=False
                self.keys_held={30}
                raise TunnelError("phone closed")
            try:
                with patch.object(long.LongSession,"wait",window):
                    with self.assertRaisesRegex(TunnelError,"phone closed"):
                        s.wait(5)
            finally:
                if writer is not None:
                    os.close(writer)
            self.assertIsInstance(s.input,ks.InputReader)
            self.assertIsNone(s.input.fd)
            self.assertEqual(s.wires,[ks.key_packet(1,30)])
            self.assertIs(base.InputReader.parse(b"K d 30"),None)

    def test_overflow_drops_oldest_presses_and_moves_but_keeps_releases(self):
        counts=Counter()
        events=[("K",0,30),(2,1,1)]+[(0,i,i) for i in range(5)]+[("K",1,30),(1,1,1)]
        kept=ks.trim(events,4,counts)
        self.assertEqual(kept,[(0,3,3),(0,4,4),("K",1,30),(1,1,1)])
        self.assertEqual(counts["pending_overflow"],5)
        self.assertEqual(ks.trim(events,20,counts),events)
        # A release among the oldest events survives too.
        early=[(1,1,1),("K",1,29)]+[(0,i,i) for i in range(6)]
        self.assertEqual(ks.trim(early,4,Counter()),[(1,1,1),("K",1,29),(0,4,4),(0,5,5)])

    def test_session_slice_is_10_ms_and_guarded(self):
        for start in (.2,.05,.01):
            with patch.object(base.live,"KEEPALIVE_SLICE_SECONDS",start):
                ks.configure()
                self.assertEqual(base.live.KEEPALIVE_SLICE_SECONDS,.01)
        with patch.object(base.live,"KEEPALIVE_SLICE_SECONDS",.3):
            with self.assertRaises(RuntimeError):
                ks.configure()

    def test_session_send_budget_applies(self):
        s=session()
        s.input_sends=ks.MAX_INPUT_SENDS
        feed(s,[(0,1,1)])
        s._pump_input()
        self.assertEqual((s.wires,s.dropped["send_budget"]),([],1))
        s=session()
        s.input_sends=base.MAX_INPUT_SENDS
        feed(s,[(0,1,1)])
        s._pump_input()
        self.assertEqual(len(s.wires),1)

    def test_summary_counts_only(self):
        s=session()
        with patch.object(base.InputSession,"summary",lambda self:dict(kms_input=dict(sends=1))):
            self.assertEqual(s.summary()["kms_input"],dict(sends=1,keys_released=0,keys_held_at_end=0))

    def test_budget_sink_window_and_pins(self):
        self.assertEqual(probe.MAX_REQUESTS,
                         48+long.LONG_KEEPALIVES+7+ks.MAX_INPUT_SENDS+base.MAX_HEARTBEATS+1)
        self.assertEqual(probe.SINK_OPEN_SECONDS,30)
        for name,digest in launch.EXPECTED.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest,name)
        for name in ("kms_session_live.py","kms_input_live.py","kms_hover_live.py","kms_mouse_live.py"):
            self.assertIn(name,launch.EXPECTED)

    def test_plan_only_never_selects_usb_or_checks_adb(self):
        with patch.object(launch,'require_adb_server',side_effect=AssertionError('ADB')),\
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(launch.main([]),0)


class DefaultRunner(unittest.TestCase):
    def test_default_runner_is_the_shipped_once_script(self):
        text=(HERE/"dex_session.sh").read_text()
        default=text.split("once=${DEX_SESSION_ONCE:-$research/",1)[1].split("}",1)[0]
        self.assertTrue((HERE/default).is_file(),default)
        self.assertIn(default,launch.EXPECTED)


class SessionScript(unittest.TestCase):
    """dex_session.sh against a temporary project root and a fake one-shot runner."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.research=root/"research/native-usb"
        self.research.mkdir(parents=True)
        self.fifos=root/"fifos"
        self.fifos.mkdir()
        self.calls=root/"calls.txt"
        fake=root/"fake_once.sh"
        # Arguments: flags, --output OUT --ts-fifo TS --stop-file STOP --input-fifo INPUT.
        fake.write_text('#!/bin/bash\necho "$@" >> %s\ntest -p "$6" && test -p "${10}"\n'
                        'while [ ! -e "$8" ]; do sleep .05; done\n' % self.calls)
        # Like the shipped once scripts, the runner is not executable: it must be run with bash.
        fake.chmod(0o644)
        self.env=dict(os.environ,DEX_ROOT=str(root),DEX_FIFO_BASE=str(self.fifos),
                      DEX_SESSION_ONCE=str(fake))

    def tearDown(self):
        self.tmp.cleanup()

    def relisten(self,name="relisten-20261103T100000Z-$",ok=True,age=0):
        d=self.research/name
        d.mkdir()
        f=d/"result.json"
        f.write_text(json.dumps(dict(bootstrap_observed=ok,errors=[] if ok else ["x"])))
        if age:
            os.utime(f,(time.time()-age,)*2)
        return d

    def run_script(self,*args):
        return subprocess.run(["bash",str(HERE/"dex_session.sh"),*args],env=self.env,
                              capture_output=True,text=True,timeout=20)

    def fields(self,out):
        return dict(line.split("=",1) for line in out.splitlines() if "=" in line)

    def test_start_runs_once_then_refuses_reuse_and_stop_ends_it(self):
        self.relisten()
        first=self.run_script("start")
        self.assertEqual(first.returncode,0,first.stderr)
        f=self.fields(first.stdout)
        fifo=Path(f["FIFO_DIR"])
        self.assertTrue((fifo/"ts.fifo").is_fifo() and (fifo/"input.fifo").is_fifo())
        self.assertEqual(oct(fifo.stat().st_mode&0o777),"0o700")
        busy=self.run_script("start")
        self.assertNotEqual(busy.returncode,0)
        self.assertIn("already running",busy.stderr)
        self.assertEqual(self.run_script("stop",str(fifo)).returncode,0)
        for _ in range(100):
            if not fifo.exists():
                break
            time.sleep(.1)
        self.assertFalse(fifo.exists())
        # The runner keeps the lock until its final FIFO hold ends.
        for _ in range(100):
            if "SESSION_EXIT" in Path(f["OUTPUT"]+".run.log").read_text():
                break
            time.sleep(.1)
        args=self.calls.read_text().split()
        self.assertEqual(args[:2],["--approved-phone-kms-session-live","--accept-persistent-state"])
        self.assertEqual(args[3],f["OUTPUT"])
        again=self.run_script("start")
        self.assertNotEqual(again.returncode,0)
        self.assertIn("already used",again.stderr)

    def test_early_runner_failure_releases_blocked_viewer_readers(self):
        failing=Path(self.tmp.name)/"failing_once.sh"
        failing.write_text("#!/bin/bash\nexit 3\n")
        failing.chmod(0o644)
        self.env["DEX_SESSION_ONCE"]=str(failing)
        self.relisten()
        started=self.run_script("start")
        self.assertEqual(started.returncode,0,started.stderr)
        fields=self.fields(started.stdout)
        fifo=fields["FIFO_DIR"]
        # A viewer cat that opened the FIFOs just after start must not hang.
        reader=subprocess.Popen(["cat",fifo+"/ts.fifo"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        writer=subprocess.Popen(["bash","-c","cat > "+fifo+"/input.fifo"],stdin=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        reader.wait(10)
        writer.stdin.close()
        writer.wait(10)
        for _ in range(50):
            if not Path(fifo).exists():
                break
            time.sleep(.1)
        self.assertFalse(Path(fifo).exists())
        for _ in range(50):
            log=Path(fields["OUTPUT"]+".run.log").read_text()
            if "SESSION_EXIT" in log:
                break
            time.sleep(.1)
        self.assertIn("SESSION_EXIT=3",log)

    def test_start_refuses_missing_failed_or_stale_relisten(self):
        self.assertIn("no relisten result",self.run_script("start").stderr)
        self.relisten("relisten-20261103T100001Z-$",ok=False)
        self.assertIn("not successful",self.run_script("start").stderr)
        self.relisten("relisten-20261103T100002Z-$",age=900)
        self.assertIn("older than",self.run_script("start").stderr)
        self.assertFalse(self.calls.exists())

    def test_stop_refuses_paths_outside_the_fifo_base(self):
        elsewhere=Path(self.tmp.name)/"elsewhere/dex-live-20261103T000000+0000"
        elsewhere.mkdir(parents=True)
        odd=self.fifos/"other"
        odd.mkdir()
        for path in (str(elsewhere),str(self.fifos)+"/x/../dex-live-20261103T000000+0000",str(odd)):
            self.assertNotEqual(self.run_script("stop",path).returncode,0,path)
        self.assertFalse((elsewhere/"stop").exists() or (odd/"stop").exists())


if __name__=='__main__':
    unittest.main()
