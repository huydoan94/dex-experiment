"""Pure capability wire and complete fake WFD/RTSP negotiation; no phone IO."""
import builtins
import contextlib
import io
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import idc_handshake as handshake
import rtsp
import rtsp_hello
import rtsp_capabilities as caps
import wfd_startup as wfd
from test_rtsp import HelloPhone, RESPONSE
from test_idc_handshake import opened, KEY

NAMES = ["wfd_video_formats","wfd_audio_codecs","wfd_uibc_capability",
         "wfd_client_rtp_ports","wfd_content_protection","wfd_sec_screensharing",
         "wfd_sec_portrait_display","wfd_sec_rotation","wfd_sec_hw_rotation",
         "wfd_sec_framerate"]
QUERY_BODY = ("\r\n".join(NAMES)+"\r\n").encode()
QUERY = (b"GET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 2\r\n"
         b"Content-Type: text/parameters\r\nContent-Length: "+
         str(len(QUERY_BODY)).encode()+b"\r\n\r\n"+QUERY_BODY)
SELECTED = (
 b"wfd_video_formats: 00 00 02 04 00000080 00000000 00000000 00 0000 0000 00 none none\r\n"
 b"wfd_presentation_URL: rtsp://127.0.0.1/wfd1.0/streamid=0 none\r\n"
 b"wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play\r\n")


def m4(body=SELECTED,cseq=3):
    return (b"SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: "+
            str(cseq).encode()+b"\r\nContent-Type: text/parameters\r\nContent-Length: "+
            str(len(body)).encode()+b"\r\n\r\n"+body)


class CapsPhone(HelloPhone):
    def __init__(self,next_message=None,fragment=False):
        super().__init__(answer=RESPONSE+QUERY)
        self.next_message=m4() if next_message is None else next_message
        self.fragment_m4=fragment

    def _handle(self,frame):
        super()._handle(frame)
        if (frame.kind==1 and frame.command==5 and self.host_data[-1][0]==1204
                and len(self.rtsp_sent)==3):
            parts=([self.next_message[:50],self.next_message[50:]]
                   if self.fragment_m4 else [self.next_message])
            for part in parts:
                if part:
                    self.push_data(1204,50004,part)


def startup(*args):
    return wfd.startup(*args,after_rtsp=lambda *a:
                      rtsp_hello.exchange(*a,after_query=caps.exchange))


def run(phone,result):
    session,main=opened(phone)
    handshake.handshake(session,main,KEY,result,after_handshake=startup)
    return session


class Tests(unittest.TestCase):
    def test_capability_reply_exact_profile_and_omission(self):
        data=caps.capability_reply(2,NAMES)
        message,size=rtsp.parse(data)
        self.assertEqual(size,len(data))
        self.assertEqual(message["status"],200)
        self.assertEqual(message["cseq"],2)
        self.assertEqual(message["body"],
            b"wfd_video_formats: 38 00 02 04 00000081 00000000 00000000 00 0000 0000 00 none none\r\n"
            b"wfd_audio_codecs: none\r\n"
            b"wfd_uibc_capability: none\r\n"
            b"wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play\r\n"
            b"wfd_content_protection: none\r\n")
        self.assertNotIn(b"wfd_sec_",data)
        self.assertEqual(len(QUERY_BODY),211)  # actual captured query schema

    def test_unknown_or_missing_query_schema_refused(self):
        for names in (NAMES+["unknown"],["wfd_video_formats"],[]):
            with self.subTest(names=names),self.assertRaises(ValueError):
                caps.capability_reply(2,names)

    def test_selected_parameters_casefold_and_redacted_values(self):
        msg,_=rtsp.parse(m4(SELECTED+b"wfd_sec_private: opaque-do-not-export\r\n"))
        values,names=caps.selected_parameters(msg)
        self.assertIn("wfd_presentation_url",values)
        self.assertIn("wfd_sec_private",names)
        self.assertNotIn("opaque-do-not-export",str(values))
        self.assertTrue(caps.selection_compatible(values))

    def test_bad_selected_body_and_activation_trigger(self):
        bodies=[b"",SELECTED+b"wfd_trigger_method: SETUP\r\n",
                SELECTED+b"wfd_video_formats: none\r\n",
                SELECTED+b"bad-name-without-value\r\n",
                SELECTED+b"wfd_thing: tab\tvalue\r\n"]
        for body in bodies:
            with self.subTest(body=body[-70:]),self.assertRaises(ValueError):
                caps.selected_parameters(rtsp.parse(m4(body))[0])

    def test_success_sends_three_rtsp_messages_and_never_acks_m4(self):
        for fragment in (False,True):
            phone,result=CapsPhone(fragment=fragment),{}
            session=run(phone,result)
            self.assertTrue(result["rtsp_capabilities_verified"])
            self.assertTrue(result["rtsp_selection_compatible"])
            self.assertEqual(len(phone.rtsp_sent),3)
            self.assertEqual(phone.rtsp_sent[-1],caps.capability_reply(2,NAMES))
            self.assertEqual(len(phone.host_data),5)  # IDC+CONTROL+3 RTSP
            self.assertEqual(result["wfd_cleanup_errors"],[])
            self.assertEqual(result["idc_cleanup_errors"],[])
            self.assertEqual(set(session.configs),{256})
            self.assertNotIn(KEY.hex(),str(result))

    def test_bad_m4_never_gets_response_or_activation(self):
        for message in (m4(cseq=2),m4()+b"x",
                        m4().replace(b"SET_PARAMETER",b"GET_PARAMETER"),
                        m4(SELECTED+b"wfd_trigger_method: SETUP\r\n"),
                        m4(SELECTED.replace(b"00000080",b"00000100")),
                        m4(SELECTED.replace(b"TCP;interleaved",b"UDP;unicast 19000 0"))):
            phone,result=CapsPhone(message),{}
            with self.subTest(message=message[:70]),self.assertRaises(ValueError):
                run(phone,result)
            self.assertNotIn("rtsp_capabilities_verified",result)
            self.assertEqual(len(phone.rtsp_sent),3)
            self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_silent_source_deadline_and_cleanup(self):
        phone,result=CapsPhone(b""),{}
        with self.assertRaisesRegex(Exception,"capability acceptance deadline"):
            run(phone,result)
        self.assertEqual(len(phone.rtsp_sent),3)
        self.assertEqual(result["idc_cleanup_errors"],[])

    def test_late_reply_or_main_close_cannot_be_success(self):
        for close in (False,True):
            phone,result=CapsPhone(),{}
            session,main=opened(phone)
            original=session.send
            def send(connection,payload,**kwargs):
                answer=original(connection,payload,**kwargs)
                if connection.config_id==1204 and len(phone.rtsp_sent)==3:
                    if close:
                        main.closed_by_phone=True
                    else:
                        phone.now+=6
                return answer
            session.send=send
            with self.subTest(close=close),self.assertRaises(Exception):
                handshake.handshake(session,main,KEY,result,after_handshake=startup)
            self.assertNotIn("rtsp_capabilities_verified",result)
            self.assertEqual(len(phone.rtsp_sent),3)
            self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_selection_outside_declared_profile(self):
        values,_=caps.selected_parameters(rtsp.parse(m4())[0])
        for value in ("none",values["wfd_video_formats"].replace("02 04","01 01"),
                      values["wfd_video_formats"].replace("00000080","00000100")):
            self.assertFalse(caps.selection_compatible(dict(values,wfd_video_formats=value)))

    def test_missing_presentation_and_extra_format_features_refused(self):
        values,_=caps.selected_parameters(rtsp.parse(m4())[0])
        absent=dict(values); absent.pop("wfd_presentation_url")
        self.assertFalse(caps.selection_compatible(absent))
        for uri in ("https://127.0.0.1/ none", "rtsp://127.0.0.1/ other", ""):
            self.assertFalse(caps.selection_compatible(dict(values,wfd_presentation_url=uri)))
        tokens=values["wfd_video_formats"].split()
        for index in (1,7,8,9,10):
            changed=tokens.copy()
            changed[index]="1".zfill(len(tokens[index]))
            self.assertFalse(caps.selection_compatible(dict(values,wfd_video_formats=" ".join(changed))))

    def test_grant_guards_before_usb_import(self):
        original=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=="usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name,*args,**kwargs)
        with patch("builtins.__import__",guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(caps.main([]),0)
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                caps.main(["--approved-phone-rtsp-capabilities"])
