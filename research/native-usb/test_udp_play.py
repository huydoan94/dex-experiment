"""Bounded media-header sampling and fail-closed recording; all phone data synthetic."""
import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame,encode
import idc_handshake
import rtsp_capabilities as caps
import rtsp_hello
import rtsp_udp_play as play
import udp_play_probe as probe
import udp_play_launch as launch
import ui_confirm as ui
import wfd_startup as wfd
from tunnel_probe import Link
from test_udp_setup import UdpSetupPhone
from test_idc_handshake import KEY
from test_usb_tunnel import UID
from test_loopback_transfer import Device
from test_ui_confirm import FakeRunner

SECRET=b"SCREEN_CONTENT_NEVER_SAVE_THIS"
PLAY_OK=b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 42\r\n\r\n"
TEARDOWN_OK=b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 42\r\n\r\n"


def datagram(config,port,source,sequence,payload=SECRET):
    packet=bytes([0x80,0xa1])+sequence.to_bytes(2,"big")+(sequence*3000).to_bytes(4,"big")+b"SSRC"+payload
    body=struct.pack("<9I",17,config,2,port,source,port,port,56,len(packet))+packet
    return Frame(5,1,100000+sequence+(10000 if config==1206 else 0),body)


class PlayPhone(UdpSetupPhone):
    def __init__(self,count=100,rtcp=0,play_reply=PLAY_OK,teardown_reply=TEARDOWN_OK,payload=SECRET):
        super().__init__()
        self.reply=self.reply.replace(b"client_port=46002;server_port=33000",
            b"client_port=46002-46003;server_port=19000-19001")
        self.count,self.rtcp=count,rtcp
        self.play_reply,self.teardown_reply=play_reply,teardown_reply
        self.payload=payload
        self.media_acks=[]
    def _handle(self,frame):
        if frame.command==5 and frame.kind==2 and frame.transaction>=100000:
            self.media_acks.append(frame.transaction)
        super()._handle(frame)
        if frame.kind!=1 or frame.command!=5 or self.host_data[-1][0]!=1204:
            return
        if len(self.rtsp_sent)==7:
            if self.play_reply:
                self.push_data(1204,50004,self.play_reply)
            for n in range(self.count):
                self.inbound+=encode(datagram(1205,46002,19000,n,self.payload))
            for n in range(self.rtcp):
                self.inbound+=encode(datagram(1206,46003,19001,n,self.payload))
        elif len(self.rtsp_sent)==8 and self.teardown_reply:
            self.push_data(1204,50004,self.teardown_reply)


def opened(phone,events):
    link=Link(Device(phone),TimeoutError,max_requests=48,
              record=lambda *args: (_ for _ in ()).throw(AssertionError("raw recorder not replaced")))
    session=play.PlaySession(link,1,65536,65536,clock=phone.clock,
                             log=lambda event,**kw:events.append(dict(event=event,**kw)))
    session.get_version();session.exchange(0,tcp_send_buffer_bytes=0)
    session.open_config(256,UID,15000)
    return session,session.connect(40000)


def run(phone):
    result,events={},[]
    session,main=opened(phone,events)
    callback=lambda *args:wfd.startup(*args,confirm=lambda *a:phone.tap(),
        after_rtsp=lambda *a:rtsp_hello.exchange(*a,after_query=lambda *b:
            caps.exchange(*b,profile=caps.UDP_PROFILE,after_selection=play.exchange)))
    try:
        idc_handshake.handshake(session,main,KEY,result,after_handshake=callback)
    except Exception as error:
        result["error"]=str(error)
    return result,session,events


class Tests(unittest.TestCase):
    def test_more_than64_packets_exactly64_rtp_acks_and_no_payload(self):
        phone=PlayPhone(count=100)
        result,session,events=run(phone)
        self.assertNotIn("error",result)
        self.assertTrue(result["rtsp_play_verified"])
        self.assertTrue(result["rtp_media_verified"])
        self.assertEqual(len(phone.media_acks),64)
        self.assertEqual(result["media_unacked_datagrams"],36)
        self.assertEqual(len(phone.rtsp_sent),8)
        self.assertTrue(phone.rtsp_sent[6].startswith(b"PLAY "))
        self.assertTrue(phone.rtsp_sent[7].startswith(b"TEARDOWN "))
        self.assertEqual(phone.closed[:2],[1206,1205])
        self.assertEqual(set(session.configs),{256})
        self.assertEqual(session.datagrams,[])
        self.assertEqual(session.dropped_datagrams,[])
        saved=json.dumps(dict(result=result,events=events))
        self.assertNotIn(SECRET.decode(),saved)
        self.assertNotIn(SECRET.hex(),saved)
        self.assertTrue(any(e["event"]=="usb_frame_in_data" for e in events))

    def test_teardown_timeout_is_recorded_without_losing_media_success(self):
        result,session,events=run(PlayPhone(teardown_reply=b""))
        self.assertNotIn("error",result)
        self.assertTrue(result["rtp_media_verified"])
        self.assertIn("rtsp_teardown_error",result)
        self.assertEqual(result["media_close_statuses"],{"1206":0,"1205":0})

    def test_missing_rtp_and_rejected_play_fail_cleanly(self):
        for phone in (PlayPhone(count=0),PlayPhone(play_reply=PLAY_OK.replace(b"200 OK",b"403 Forbidden"))):
            result,session,events=run(phone)
            self.assertIn("error",result)
            self.assertFalse(result.get("rtp_media_verified",False))
            self.assertEqual(result["media_close_statuses"],{"1206":0,"1205":0})
            self.assertNotIn(SECRET.hex(),json.dumps(events))

    def test_no_rtp_still_attempts_teardown_after_play200(self):
        phone=PlayPhone(count=0)
        result,session,events=run(phone)
        self.assertIn("no RTP datagram",result["error"])
        self.assertTrue(result["rtsp_play_verified"])
        self.assertTrue(result["rtsp_teardown_attempted"])
        self.assertEqual(result["rtsp_teardown_status"],200)
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"TEARDOWN "))
        self.assertEqual(phone.closed[:2],[1206,1205])

    def test_rtcp_flood_is_bounded_during_cleanup(self):
        result,session,events=run(PlayPhone(count=200,rtcp=100,payload=SECRET*3))
        self.assertNotIn("error",result)
        self.assertEqual(len([x for x in session.media if x["config_id"]==1205]),64)
        self.assertLessEqual(len([x for x in session.media if x["config_id"]==1206]),play.RTCP_DATAGRAMS)
        self.assertEqual(sum(x<110000 for x in session.link.device.phone.media_acks),64)
        self.assertLessEqual(sum(x>=110000 for x in session.link.device.phone.media_acks),play.RTCP_DATAGRAMS)
        self.assertEqual(result["media_cleanup_errors"],[])
        self.assertEqual(result["wfd_cleanup_errors"],[])
        self.assertEqual(result["idc_cleanup_errors"],[])
        self.assertGreater(session.link.reads_left,0)

    def test_recorder_split_frame_normal_frame_and_malformed_bytes(self):
        events=[]
        record=play.RedactingRecorder(lambda event,**kw:events.append(dict(event=event,**kw)),65536)
        media=encode(datagram(1205,46002,19000,1))
        record("in",media[:60]);record("in",media[60:])
        record("in",encode(Frame(2,2,4,bytes(4))))
        record("out",encode(Frame(2,1,5,b"")))
        record("in",b"X"*20+SECRET)
        record("in",SECRET)
        # Even malformed Data with a wrong config/protocol is never raw.
        record2=play.RedactingRecorder(lambda event,**kw:events.append(dict(event=event,**kw)),65536)
        record2("in",encode(Frame(5,1,6,SECRET)))
        text=json.dumps(events)
        self.assertNotIn(SECRET.decode(),text)
        self.assertNotIn(SECRET.hex(),text)
        self.assertIn("usb_in_unparsed",text)
        self.assertIn("usb_frame_in",text)
        self.assertTrue(any(e.get("direction")=="out" for e in events))

    def test_real_link_budgets_installed_before_io(self):
        phone=PlayPhone()
        link=Link(Device(phone),TimeoutError)
        session=play.PlaySession(link,1,65536,65536)
        self.assertEqual((link.acks_left,link.reads_left),(play.PLAY_ACKS,play.PLAY_READS))
        self.assertIsInstance(link.record,play.RedactingRecorder)
        self.assertFalse(phone.inbound)

    def test_plan_only_and_missing_grant_never_import_usb(self):
        original=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=="usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB")
            return original(name,*args,**kwargs)
        with patch("builtins.__import__",guard),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main([]),0)
            self.assertEqual(launch.main([]),0)

    def test_launcher_pins_and_selection(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(launch.EXPECTED,{"rtsp_udp_play.py":"0"*64}):
            with self.assertRaisesRegex(RuntimeError,"approved source mismatch"):
                launch.main(["--approved-phone-udp-play","--accept-persistent-state","--output",tmp+"/new"])
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[SimpleNamespace(bus=3,address=10)]
        usb.core=core
        with tempfile.TemporaryDirectory() as tmp,patch.dict("sys.modules",{"usb":usb,"usb.core":core}),patch.object(
                launch.socket,"create_connection"),patch.object(launch.os,"execv") as execute,contextlib.redirect_stdout(io.StringIO()):
            launch.main(["--approved-phone-udp-play","--accept-persistent-state","--output",tmp+"/new"])
        self.assertTrue(execute.call_args.args[1][1].endswith("udp_play_probe.py"))

    def test_invalid_header_and_preplay_datagrams_do_not_prove_playback(self):
        phone=PlayPhone(count=0)
        phone.datagrams=3  # inherited fake injects these before PLAY from33000
        phone.reply=phone.reply.replace(b"server_port=19000-19001",b"server_port=33000-33001")
        result,session,events=run(phone)
        self.assertIn("before PLAY",result["error"])
        self.assertGreaterEqual(result["media_before_play_datagrams"],1)
        self.assertEqual(result["media_summary"]["rtp_datagrams"],0)
        self.assertFalse(play.media_header(bytes([0x8f,33])+bytes(10))["rtp"])
        self.assertFalse(play.media_header(bytes([0x90,33])+bytes(10))["rtp"])
        summary=play.media_header(bytes([0x80,200])+bytes(6),1206)
        self.assertEqual(summary["packet_type"],200)
        self.assertNotIn("sequence",summary)

    def test_media_byte_failure_can_still_drain_cleanup(self):
        with patch.object(play,"MEDIA_BYTES",128):
            result,session,events=run(PlayPhone(count=100))
        self.assertIn("media byte limit",result["error"])
        self.assertEqual(result["media_cleanup_errors"],[])
        self.assertEqual(result["media_close_statuses"],{"1206":0,"1205":0})
        self.assertEqual(set(session.configs),{256})

    def test_large_backlog_uses_real_read_budget_and_does_not_resume_media(self):
        class FastPhone(PlayPhone):
            def read(self,size,timeout_ms):
                now=self.now
                data=super().read(size,timeout_ms)
                if data:
                    self.now=now+.0001
                return data
        phone=FastPhone(count=450,rtcp=450,payload=SECRET*35)
        result,session,events=run(phone)
        self.assertNotIn("error",result)
        self.assertGreater(session.media_bytes,900000)
        self.assertEqual(len(phone.media_acks),64+play.RTCP_DATAGRAMS)
        self.assertGreater(session.link.reads_left,0)
        self.assertLess(session.link.reads_left,play.PLAY_READS-1000)
        self.assertEqual(result["media_cleanup_errors"],[])

    def test_corrupt_unknown_nondata_frame_is_also_hashed(self):
        events=[]
        record=play.RedactingRecorder(lambda event,**kw:events.append(dict(event=event,**kw)),65536)
        record("in",encode(Frame(99,1,100,SECRET)))
        record("in",encode(Frame(2,2,101,SECRET)))
        self.assertNotIn(SECRET.hex(),json.dumps(events))
        self.assertNotIn(SECRET.decode(),json.dumps(events))

    def test_actual_probe_main_wiring_and_saved_results(self):
        phone=PlayPhone(count=100)
        events=[]
        session,connection=opened(phone,events)
        from test_ui_display0 import DisplayRunner
        runner=DisplayRunner(phone)
        original_confirm=probe.ui_confirm.confirm
        def confirm(s,m,r,log,deadline,output,bus):
            return original_confirm(s,m,r,log,deadline,output,bus,runner=runner)
        def fake_probe(device,util,timeout,output,result,after_auth,**kwargs):
            self.assertIs(kwargs["session_class"],play.PlaySession)
            self.assertEqual(kwargs["max_requests"],48)
            client=SimpleNamespace(codec=lambda:SimpleNamespace(_key=KEY))
            after_auth(session,connection,client,result,session.clock,lambda **kw:None)
            (output/"events.jsonl").write_text("\n".join(json.dumps(e) for e in events)+"\n")
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}):
            with patch.dict("sys.modules",{"usb":usb,"usb.core":core,"usb.util":util}),patch.object(
                    probe.auth_probe,"probe",side_effect=fake_probe),patch.object(
                    probe.cap,"capabilities"),patch.object(probe.pss_probe,"pss_ready"),patch.object(
                    probe.ui_confirm,"confirm",side_effect=confirm),contextlib.redirect_stdout(io.StringIO()):
                code=probe.main(["--approved-phone-udp-play","--accept-persistent-state",
                                 "--bus","3","--address","10","--output",tmp+"/run"])
            output=Path(tmp)/"run"
            result=json.loads((output/"result.json").read_text())
            plan=json.loads((output/"plan.json").read_text())
            self.assertEqual(code,0)
            self.assertTrue(result["rtp_media_verified"])
            self.assertTrue(result["auto_confirmation_verified"])
            self.assertEqual(plan["rtsp_sends"],8)
            self.assertEqual(len(runner.commands),4)
            for name in ["events.jsonl","result.json"]:
                data=(output/name).read_text()
                self.assertNotIn(SECRET.hex(),data)
                self.assertNotIn(SECRET.decode(),data)

    def test_empty_pins_and_invalid_deadline_fail_before_usb(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(launch.EXPECTED,{},clear=True):
            with self.assertRaisesRegex(RuntimeError,"empty approved source"):
                launch.main(["--approved-phone-udp-play","--accept-persistent-state","--output",tmp+"/new"])
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":"nan"}),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                probe.main(["--approved-phone-udp-play","--accept-persistent-state",
                            "--bus","3","--address","10","--output",tmp+"/new"])
            self.assertFalse((Path(tmp)/"new").exists())

    def test_cleanup_media_burst_never_restarts_rtp_acknowledgements(self):
        class CleanupBurstPhone(PlayPhone):
            def __init__(self):
                super().__init__()
                self.burst=False
            def _handle(self,frame):
                if frame.kind==1 and frame.command==21 and not self.burst:
                    self.burst=True
                    for n in range(200,220):
                        self.inbound+=encode(datagram(1205,46002,19000,n))
                super()._handle(frame)
        phone=CleanupBurstPhone()
        result,session,events=run(phone)
        self.assertNotIn("error",result)
        self.assertEqual(len(phone.media_acks),64)
        self.assertEqual(result["media_after_cleanup_datagrams"],20)
        self.assertEqual(result["media_close_statuses"],{"1206":0,"1205":0})

    def test_response_rejects_wrong_session_status_sequence_or_body(self):
        import rtsp
        for response in (PLAY_OK.replace(b"Session: 42",b"Session: other"),
                         PLAY_OK.replace(b"CSeq: 3",b"CSeq: 4"),
                         PLAY_OK.replace(b"200 OK",b"403 Forbidden"),
                         PLAY_OK.replace(b"Session: 42\r\n",b"Content-Length: 1\r\n")+b"x"):
            with self.subTest(response=response),self.assertRaises(ValueError):
                play.play_response(rtsp.parse(response)[0],3,"42")


    def test_wrong_rtp_source_port_and_unbound_client_range_stop_play(self):
        original=datagram
        def wrong(*args,**kwargs):
            frame=original(*args,**kwargs)
            body=bytearray(frame.body)
            struct.pack_into("<I",body,16,19999)
            return Frame(frame.command,frame.kind,frame.transaction,bytes(body))
        with patch(__name__+".datagram",side_effect=wrong):
            result,session,events=run(PlayPhone())
        self.assertIn("source port",result["error"])
        self.assertEqual(result["media_cleanup_errors"],[])
        self.assertFalse(result.get("rtp_media_verified",False))
        phone=PlayPhone()
        phone.reply=phone.reply.replace(b"client_port=46002-46003",b"client_port=46002-46009")
        result,session,events=run(phone)
        self.assertIn("bound media sockets",result["error"])
        self.assertEqual(len(phone.rtsp_sent),6)
