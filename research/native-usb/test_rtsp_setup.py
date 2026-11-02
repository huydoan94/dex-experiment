"""Complete synthetic SETUP path; exact sends and no PLAY/media receiver."""
import builtins
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import idc_handshake as handshake
import rtsp
import rtsp_hello
import rtsp_capabilities as caps
import rtsp_setup as setup
import wfd_startup as wfd
from test_rtsp_capabilities import CapsPhone
from test_idc_handshake import opened,KEY

TRIGGER_BODY=b"wfd_trigger_method: SETUP\r\n"
TRIGGER=(b"SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 4\r\n"
         b"Content-Type: text/parameters\r\nContent-Length: "+
         str(len(TRIGGER_BODY)).encode()+b"\r\n\r\n"+TRIGGER_BODY)
REPLY=(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 42;timeout=30\r\n"
       b"Transport: RTP/AVP/TCP;interleaved=0-1;\r\n\r\n")


class SetupPhone(CapsPhone):
    def __init__(self,trigger=TRIGGER,reply=REPLY,fragment=False):
        super().__init__()
        self.trigger,self.reply,self.fragment=trigger,reply,fragment

    def _handle(self,frame):
        super()._handle(frame)
        if frame.kind!=1 or frame.command!=5 or self.host_data[-1][0]!=1204:
            return
        count=len(self.rtsp_sent)
        if count==4:
            self.push_data(1204,50004,self.trigger)
        elif count==6:
            if self.fragment:
                self.push_data(1204,50004,self.reply[:40])
                self.push_data(1204,50004,self.reply[40:])
            elif self.reply:
                self.push_data(1204,50004,self.reply)


def startup(*args):
    return wfd.startup(*args,after_rtsp=lambda *a:
        rtsp_hello.exchange(*a,after_query=lambda *b:
            caps.exchange(*b,after_selection=setup.exchange)))


def run(phone,result):
    session,main=opened(phone)
    handshake.handshake(session,main,KEY,result,after_handshake=startup)
    return session


class Tests(unittest.TestCase):
    def test_exact_request_and_response(self):
        uri=setup.presentation_uri({"wfd_presentation_url":
                                   "rtsp://127.0.0.1/wfd1.0/streamid=0 none"})
        self.assertEqual(setup.setup_request(uri),
            b"SETUP rtsp://127.0.0.1/wfd1.0/streamid=0 RTSP/1.0\r\nCSeq: 2\r\n"
            b"Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n")
        self.assertEqual(setup.response(3),b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n")
        self.assertEqual(setup.setup_response(rtsp.parse(REPLY)[0]),
                         dict(session_id="42",timeout_seconds=30,
                              transport="RTP/AVP/TCP;interleaved=0-1;"))

    def test_url_cannot_change_destination_or_inject_headers(self):
        for url in ("rtsp://evil/wfd1.0/streamid=0 none",
                    "rtsp://user@127.0.0.1/wfd1.0/streamid=0 none",
                    "rtsp://127.0.0.1:80/wfd1.0/streamid=0 none",
                    "rtsp://127.0.0.1/wfd1.0/streamid=0?q=x none",
                    "rtsp://127.0.0.1/wfd1.0/streamid=0#x none",
                    "rtsp://127.0.0.1/elsewhere none",
                    "rtsp://127.0.0.1/wfd1.0/streamid=0\x00 none",
                    "rtsp://127.0.0.1/wfd1.0/streamid=0 other",
                    "rtsp://127.0.0.1/wfd1.0/streamid=0 none extra"):
            with self.subTest(url=url),self.assertRaises(ValueError):
                setup.presentation_uri({"wfd_presentation_url":url})

    def test_bad_setup_response_session_transport_cseq(self):
        for wire in (REPLY.replace(b"200 OK",b"403 Forbidden"),
                     REPLY.replace(b"CSeq: 2",b"CSeq: 1"),
                     REPLY.replace(b"Session: 42;timeout=30\r\n",b""),
                     REPLY.replace(b"timeout=30",b"timeout=0"),
                     REPLY.replace(b"timeout=30",b"timeout=abc"),
                     REPLY.replace(b"timeout=30",b"timeout=30;timeout=30"),
                     REPLY.replace(b"interleaved=0-1",b"interleaved=2-3"),
                     REPLY.replace(b"interleaved=0-1",b"interleaved=0-1;interleaved=0-1"),
                     REPLY.replace(b"RTP/AVP/TCP",b"RTP/AVP/UDP")):
            with self.subTest(wire=wire),self.assertRaises(ValueError):
                setup.setup_response(rtsp.parse(wire)[0])

    def test_full_path_six_messages_and_no_play(self):
        for fragment in (False,True):
            phone,result=SetupPhone(fragment=fragment),{}
            session=run(phone,result)
            self.assertTrue(result["rtsp_setup_verified"])
            self.assertTrue(result["rtsp_m5_trigger_verified"])
            self.assertEqual(result["rtsp_setup"]["session_id"],"42")
            self.assertEqual(len(phone.rtsp_sent),6)
            self.assertEqual(phone.rtsp_sent[3],setup.response(3))
            self.assertEqual(phone.rtsp_sent[4],setup.response(4))
            self.assertEqual(rtsp.parse(phone.rtsp_sent[5])[0]["method"],"SETUP")
            self.assertFalse(any(data.startswith(b"PLAY ") for data in phone.rtsp_sent))
            self.assertEqual(len(phone.host_data),8)
            self.assertEqual(set(session.configs),{256})
            self.assertEqual(result["wfd_cleanup_errors"],[])
            self.assertEqual(result["idc_cleanup_errors"],[])
            self.assertNotIn(KEY.hex(),str(result))

    def test_trigger_must_be_exact_and_new_cseq(self):
        for trigger in (TRIGGER.replace(b"SETUP",b"PLAY "),
                        TRIGGER.replace(b"CSeq: 4",b"CSeq: 3"),
                        TRIGGER.replace(b"SET_PARAMETER",b"GET_PARAMETER"),
                        TRIGGER.replace(b"text/parameters",b"other/parameters")):
            phone,result=SetupPhone(trigger=trigger),{}
            with self.subTest(trigger=trigger[:100]),self.assertRaises(ValueError):
                run(phone,result)
            self.assertEqual(len(phone.rtsp_sent),4)
            self.assertNotIn("rtsp_setup_attempted",result)
            self.assertEqual(result["idc_cleanup_errors"],[])

    def test_response_failure_and_early_media_abort_without_play(self):
        for reply in (REPLY.replace(b"200 OK",b"403 Forbidden"),
                      REPLY+b"$\x00\x00\x01x", b"$\x00\x00\x01x"):
            phone,result=SetupPhone(reply=reply),{}
            with self.subTest(reply=reply[:60]),self.assertRaises(ValueError):
                run(phone,result)
            self.assertNotIn("rtsp_setup_verified",result)
            self.assertEqual(len(phone.rtsp_sent),6)
            self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_silent_setup_deadline_and_cleanup(self):
        phone,result=SetupPhone(reply=b""),{}
        with self.assertRaisesRegex(Exception,"SETUP acceptance deadline"):
            run(phone,result)
        self.assertEqual(len(phone.rtsp_sent),6)
        self.assertEqual(result["idc_cleanup_errors"],[])

    def test_late_send_and_main_close_block_followup(self):
        for close in (False,True):
            phone,result=SetupPhone(),{}
            session,main=opened(phone)
            original=session.send
            def send(connection,payload,**kwargs):
                answer=original(connection,payload,**kwargs)
                if connection.config_id==1204 and len(phone.rtsp_sent)==4:
                    if close:
                        main.closed_by_phone=True
                    else:
                        phone.now+=9
                return answer
            session.send=send
            with self.subTest(close=close),self.assertRaises(Exception):
                handshake.handshake(session,main,KEY,result,after_handshake=startup)
            self.assertEqual(len(phone.rtsp_sent),4)
            self.assertNotIn("rtsp_setup_verified",result)
            self.assertEqual(result["idc_cleanup_errors"],[])

    def test_late_final_send_cannot_accept_setup_response(self):
        phone,result=SetupPhone(),{}
        session,main=opened(phone)
        original=session.send
        def send(connection,payload,**kwargs):
            answer=original(connection,payload,**kwargs)
            if connection.config_id==1204 and len(phone.rtsp_sent)==6:
                phone.now+=9
            return answer
        session.send=send
        with self.assertRaisesRegex(Exception,"SETUP acceptance deadline"):
            handshake.handshake(session,main,KEY,result,after_handshake=startup)
        self.assertEqual(len(phone.rtsp_sent),6)
        self.assertNotIn("rtsp_setup_verified",result)
        self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_actual_m4_fixture_and_safe_scramble_flag(self):
        p=Path(__file__).with_name("fixtures")/"rtsp-selected-20261102.json"
        wire=bytes.fromhex(json.loads(p.read_text())["rtsp_message_hex"])
        values,names=caps.selected_parameters(rtsp.parse(wire)[0])
        self.assertTrue(caps.selection_compatible(values))
        self.assertEqual(values["wfd_sec_scramble"],"enable")
        self.assertEqual(setup.presentation_uri(values),
                         "rtsp://127.0.0.1/wfd1.0/streamid=0")

    def test_missing_grant_never_imports_usb(self):
        original=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=="usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name,*args,**kwargs)
        with patch("builtins.__import__",guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.main([]),0)
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                setup.main(["--approved-phone-rtsp-setup"])
