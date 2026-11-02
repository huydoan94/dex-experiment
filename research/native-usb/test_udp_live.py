"""Live PLAY keep-alive, TS forwarding, FIFO-only sink and wiring; synthetic phone, no USB/ADB."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

import conn_transfer
import idc_handshake
import live_sink
import rtsp_capabilities as caps
import rtsp_hello
import rtsp_udp_live as live
import rtsp_udp_play as play
import udp_live_launch as launch
import udp_live_probe as probe
import wfd_startup as wfd
from test_idc_handshake import KEY
from test_loopback_transfer import Device
from test_udp_play import PlayPhone,PLAY_OK,TEARDOWN_OK
from test_usb_tunnel import UID
from tunnel_probe import Link

MARK=b"SCREEN_TS_NEVER_SAVE"
TS=(b"\x47"+MARK+bytes(187-len(MARK)))*7
M16=b"GET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 9\r\nSession: 42\r\n\r\n"


class FakeSink:
    def __init__(self):self.data=[]
    def put(self,data):self.data.append(bytes(data))
    def summary(self):return dict(chunks=len(self.data))


class LivePhone(PlayPhone):
    """Serves PLAY 200 (optionally followed by an RTSP request) and answers TEARDOWN whenever it is sent."""
    def __init__(self,after_play=b"",**kwargs):
        super().__init__(play_reply=PLAY_OK+after_play,teardown_reply=b"",payload=TS,**kwargs)
        self.sent_seen=0
    def _handle(self,frame):
        super()._handle(frame)
        if len(self.rtsp_sent)!=self.sent_seen:
            self.sent_seen=len(self.rtsp_sent)
            if self.rtsp_sent[-1].startswith(b"TEARDOWN "):
                self.push_data(1204,50004,TEARDOWN_OK)


def run(phone,sink):
    result,events={},[]
    link=Link(Device(phone),TimeoutError,max_requests=56,
              record=lambda *args:(_ for _ in ()).throw(AssertionError("raw recorder not replaced")))
    session=live.LiveSession(link,1,65536,65536,sink=sink,clock=phone.clock,
                             log=lambda event,**kw:events.append(dict(event=event,**kw)))
    session.get_version();session.exchange(0,tcp_send_buffer_bytes=0)
    session.open_config(256,UID,15000)
    main=session.connect(40000)
    callback=lambda *args:wfd.startup(*args,confirm=lambda *a:phone.tap(),
        after_rtsp=lambda *a:rtsp_hello.exchange(*a,after_query=lambda *b:
            caps.exchange(*b,profile=caps.UDP_PROFILE,after_selection=live.exchange)))
    try:
        idc_handshake.handshake(session,main,KEY,result,after_handshake=callback)
    except Exception as error:
        result["error"]=str(error)
    return result,events


class Tests(unittest.TestCase):
    def setUp(self):
        patcher=patch.multiple(play,**live.BASE)
        patcher.start()
        self.addCleanup(patcher.stop)
        profile=patch.object(probe.cap,"PROFILE",dict(probe.cap.PROFILE))
        profile.start()
        self.addCleanup(profile.stop)

    def test_plain_profile_lowers_only_pc_version_and_refuses_other_base(self):
        before=dict(probe.cap.PROFILE)
        live.plain_profile(probe.cap);live.plain_profile(probe.cap)
        self.assertEqual(probe.cap.PROFILE,dict(before,PcVer="2.0.0.23"))
        self.assertEqual(probe.cap.terminal_info()["PARAM"]["PcVer"],"2.0.0.23")
        probe.cap.PROFILE=dict(before,PcVer="9.9.9.9")
        with self.assertRaisesRegex(RuntimeError,"pinned base"):live.plain_profile(probe.cap)

    def test_apply_sets_live_limits_and_refuses_changed_base(self):
        live.apply();live.apply()
        self.assertEqual({name:getattr(play,name) for name in live.LIVE},live.LIVE)
        play.PLAY_ACKS=1
        with self.assertRaisesRegex(RuntimeError,"pinned base"):live.apply()

    def test_ts_payload_skips_csrc_and_extension_and_rejects_bad_rtp(self):
        self.assertEqual(live.ts_payload(bytes([0x80,33])+bytes(10)+b"TS"),b"TS")
        packet=bytes([0x91,33])+bytes(10)+b"CSRC"+b"\x00\x00\x00\x01"+b"EXT!"+b"TS"
        self.assertEqual(live.ts_payload(packet),b"TS")
        self.assertIsNone(live.ts_payload(bytes([0x40,33])+bytes(10)))
        self.assertIsNone(live.ts_payload(bytes([0x90,33])+bytes(10)+b"\x00\x00\x00\x09"))
        # Padding bit: the last byte counts padding bytes (itself included); they never reach ffplay.
        self.assertEqual(live.ts_payload(bytes([0xa0,33])+bytes(10)+b"TS"+b"\x00\x00\x03"),b"TS")
        self.assertIsNone(live.ts_payload(bytes([0xa0,33])+bytes(10)+b"\x00"))
        self.assertIsNone(live.ts_payload(bytes([0xa0,33])+bytes(10)+b"\x10"))

    def bare_session(self,now=100.0):
        clock=[now]
        session=live.LiveSession(Link(Device(LivePhone()),TimeoutError),1,65536,65536,
                                 sink=FakeSink(),clock=lambda:clock[0])
        session.rtsp_connection=SimpleNamespace(received=bytearray(b"OLD"))
        return session,clock

    def test_window_is_cut_to_end_before_the_stage_deadline(self):
        live.apply()
        for latest,expected in ((200.0,60),(120.0,15.0),(103.0,1)):
            session,clock=self.bare_session()
            session.stage_latest=latest
            session.collect_media=True
            self.assertEqual((session.window_seconds,play.MEDIA_SECONDS),(expected,expected))
            self.assertEqual(session.keepalive_offset,3)
            self.assertEqual(session.summary()["window_seconds"],expected)

    def test_live_wait_checks_caller_condition_once_per_slice(self):
        live.apply()
        session,clock=self.bare_session()
        session.stage_latest=200.0
        session.collect_media=True
        calls=[]
        def fake_wait(self,seconds,until=lambda:False):
            # Real frame handling evaluates until() per frame; model one frame per slice.
            until()
            clock[0]+=seconds
            return False
        with patch.object(play.PlaySession,"wait",fake_wait):
            self.assertFalse(session.wait(1.0,until=lambda:calls.append(1) or False))
            self.assertTrue(session.wait(1.0,until=lambda:True))
        # One check per 0.2 s slice plus the final one (float rounding may add a slice).
        self.assertIn(len(calls),(6,7))

    def test_forwards_every_accepted_ts_payload_and_saves_none_of_it(self):
        live.apply();play.MEDIA_DATAGRAMS=100
        sink=FakeSink()
        result,events=run(LivePhone(count=100),sink)
        self.assertNotIn("error",result)
        self.assertTrue(result["rtp_media_verified"])
        self.assertEqual(result["rtsp_teardown_status"],200)
        self.assertEqual(b"".join(sink.data),TS*100)
        self.assertEqual(result["live"]["ts"],dict(packets=700,sync_ok=700,sync_bad=0,unaligned=0,invalid_rtp=0))
        self.assertEqual(result["live"]["rtp_sequence_gaps"],0)
        saved=json.dumps(dict(result=result,events=events))
        self.assertNotIn(MARK.decode(),saved)
        self.assertNotIn(MARK.hex(),saved)

    def test_keepalive_during_media_is_answered_once(self):
        live.apply();play.MEDIA_DATAGRAMS=100
        phone=LivePhone(count=100,after_play=M16)
        result,events=run(phone,FakeSink())
        self.assertNotIn("error",result)
        self.assertEqual(result["live"]["keepalives_answered"],1)
        self.assertIn(b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n",phone.rtsp_sent)
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"TEARDOWN "))
        self.assertIn({"event":"rtsp_keepalive_reply","cseq":9},events)

    def test_unexpected_rtsp_request_stops_media_but_still_tears_down(self):
        live.apply();play.MEDIA_DATAGRAMS=100
        other=b"SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n"
        phone=LivePhone(count=100,after_play=other)
        result,events=run(phone,FakeSink())
        self.assertIn("unexpected RTSP request",result["play_first_error"])
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"TEARDOWN "))
        self.assertEqual(result["live"]["keepalives_answered"],0)

    def test_sink_refuses_regular_file_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"not-a-fifo"
            path.write_bytes(b"")
            sink=live_sink.TsSink(path,open_seconds=.2).start()
            sink.put(TS)
            sink.thread.join(1)
            sink.close()
            self.assertEqual(path.read_bytes(),b"")
            summary=sink.summary()
            self.assertEqual((summary["opened"],summary["error_type"],summary["forwarded_bytes"]),
                             (False,"RuntimeError",0))

    def test_sink_forwards_through_fifo_and_close_never_hangs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"ts.fifo"
            os.mkfifo(path,0o600)
            received=bytearray()
            def reader():
                with open(path,"rb") as fifo:received.extend(fifo.read())
            thread=threading.Thread(target=reader);thread.start()
            sink=live_sink.TsSink(path,queue_bytes=4*len(TS)).start()
            for _ in range(3):sink.put(TS)
            sink.close();thread.join(2)
            self.assertEqual(bytes(received),TS*3)
            self.assertEqual(sink.summary()["dropped_bytes"],0)
            # A reader that never reads: writes block, put() still returns and close() is bounded.
            blocked=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
            try:
                sink=live_sink.TsSink(path,queue_bytes=1<<20).start()
                started=time.monotonic()
                for _ in range(200):sink.put(TS)
                sink.close()
                self.assertLess(time.monotonic()-started,live_sink.STOP_SECONDS+1)
                self.assertFalse(sink.summary()["stopped"])
                sink.put(TS)
                self.assertEqual(sink.summary()["dropped_bytes"],len(TS))
            finally:os.close(blocked)
            sink.thread.join(2)
            self.assertEqual(sink.summary()["error_type"],"BrokenPipeError")

    def test_probe_plan_and_wiring_use_live_owner_and_fifo(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        seen={}
        def fake_probe(device,owner,timeout,out,result,**kwargs):
            sessions=kwargs["session_class"].__self__
            seen.update(owner=owner,sessions=sessions,max_requests=kwargs["max_requests"])
            result.update(ui_tap_command_succeeded=True,wfd_startup_verified=True,rtp_media_verified=True)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),patch.dict("sys.modules",
                {"usb":usb,"usb.core":core,"usb.util":util}),patch.object(probe.auth_probe,
                "probe",side_effect=fake_probe),patch.object(probe.live_sink,"TsSink") as sink_class,\
                contextlib.redirect_stdout(io.StringIO()):
            sink_class.return_value.start.return_value=sink_class.return_value
            sink_class.return_value.summary.return_value={"opened":True,"forwarded_bytes":1316}
            self.assertEqual(probe.main(["--approved-phone-udp-live","--accept-persistent-state",
                "--bus","3","--address","13","--output",tmp+"/new","--ts-fifo",tmp+"/ts.fifo"]),0)
            plan=json.loads(Path(tmp+"/new/plan.json").read_text())
            saved=json.loads(Path(tmp+"/new/result.json").read_text())
        sink_class.assert_called_once_with(Path(tmp+"/ts.fifo"))
        sink_class.return_value.close.assert_called_once()
        self.assertIsInstance(seen["owner"],live.LiveOwner)
        self.assertIsInstance(seen["sessions"],conn_transfer.TransferSessions)
        self.assertIs(seen["sessions"].owner,seen["owner"])
        self.assertEqual(seen["max_requests"],56)
        self.assertEqual((plan["media_seconds"],plan["max_acks"],plan["max_reads"],plan["media_saved"]),
                         (60,42000,126000,"headers_only"))
        self.assertTrue(plan["live_view"] and plan["transfer_pad_decoder"])
        self.assertEqual(plan["client_profile"]["PcVer"],"2.0.0.23")
        self.assertEqual(saved["live"]["sink"],{"opened":True,"forwarded_bytes":1316})
        self.assertTrue(saved["video_tested"])

    def test_launch_requires_fifo_hashes_and_execs_live_probe(self):
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[SimpleNamespace(bus=3,address=13)]
        usb.core=core
        # execv and ADB are patched for every call, so no mutant can ever reach the real probe.
        with tempfile.TemporaryDirectory() as tmp,patch.dict("sys.modules",{"usb":usb,"usb.core":core}),\
                patch.object(launch,"require_adb_server"),patch.object(launch.os,"execv") as execute,\
                contextlib.redirect_stdout(io.StringIO()):
            regular=Path(tmp)/"regular";regular.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError,"not an existing FIFO"):
                launch.main(["--approved-phone-udp-live","--accept-persistent-state",
                             "--output",tmp+"/new","--ts-fifo",str(regular)])
            execute.assert_not_called()
            fifo=Path(tmp)/"ts.fifo";os.mkfifo(fifo,0o600)
            launch.main(["--approved-phone-udp-live","--accept-persistent-state",
                         "--output",tmp+"/new","--ts-fifo",str(fifo)])
            args=execute.call_args.args[1]
        self.assertIn("research/native-usb/udp_live_probe.py",args)
        self.assertEqual(args[-2:],["--ts-fifo",str(fifo)])
        for name in ("rtsp_udp_live.py","live_sink.py","conn_transfer.py","duplex_link.py"):
            self.assertIn(name,launch.EXPECTED)
        self.assertNotIn("rtsp_udp_stream.py",launch.EXPECTED)

if __name__=="__main__":unittest.main()
