"""UDP capability selection with automatic confirmation; no M4 ACK/SETUP/UDP packets."""
import builtins
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

import auto_confirm_probe as probe
import auto_confirm_launch as launch
import rtsp
import rtsp_capabilities as caps
import ui_confirm as ui
from conn_frames import Decoder
from test_rtsp_capabilities import CapsPhone,SELECTED,NAMES,m4
from test_idc_handshake import opened,KEY
from test_ui_confirm import FakeRunner

UDP_SELECTED=SELECTED.replace(b"RTP/AVP/TCP;interleaved mode=play",
                             b"RTP/AVP/UDP;unicast 46002 0 mode=play")


class UdpPhone(CapsPhone):
    def __init__(self,selected=UDP_SELECTED):
        super().__init__(next_message=m4(selected))
        self.held_accept=b""
    def _handle(self,frame):
        super()._handle(frame)
        if frame.kind==1 and frame.command==5 and self.host_data[-1][0]==1203:
            self.held_accept=bytes(self.inbound[-44:])
            self.inbound[-44:]=b""
            assert Decoder(65536).feed(self.held_accept)[0].command==3
    def tap(self):
        assert self.held_accept
        self.inbound+=self.held_accept
        self.held_accept=b""


class Tests(unittest.TestCase):
    def run_main(self,phone):
        session,connection=opened(phone)
        runner=FakeRunner(phone)
        original_confirm=ui.confirm
        def confirm(s,m,r,log,deadline,output,bus):
            return original_confirm(s,m,r,log,deadline,output,bus,runner=runner)
        def fake_probe(device,util,timeout,output,result,after_auth,**kwargs):
            self.assertEqual(kwargs["max_requests"],40)
            client=SimpleNamespace(codec=lambda:SimpleNamespace(_key=KEY))
            after_auth(session,connection,client,result,session.clock,lambda **kw:None)
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kwargs:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        with tempfile.TemporaryDirectory() as tmp,patch.dict(
                os.environ,{"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}):
            with patch.dict("sys.modules",{"usb":usb,"usb.core":core,"usb.util":util}),patch.object(
                    probe.auth_probe,"probe",side_effect=fake_probe),patch.object(
                    probe.cap,"capabilities"),patch.object(probe.pss_probe,"pss_ready"),patch.object(
                    probe.ui_confirm,"confirm",side_effect=confirm),contextlib.redirect_stdout(io.StringIO()):
                code=probe.main(["--approved-phone-auto-start-now","--approved-udp-capabilities",
                                 "--accept-persistent-state","--bus","3","--address","10",
                                 "--output",tmp+"/run"])
            result=json.loads((Path(tmp)/"run"/"result.json").read_text())
            plan=json.loads((Path(tmp)/"run"/"plan.json").read_text())
        return code,result,plan,runner,session

    def test_udp_profile_reply_and_selection_are_explicit(self):
        message,size=rtsp.parse(caps.capability_reply(2,NAMES,caps.UDP_PROFILE))
        self.assertIn(b"wfd_client_rtp_ports: RTP/AVP/UDP;unicast 46002 0 mode=play\r\n",
                      message["body"])
        self.assertNotIn(b"TCP",message["body"])
        values,names=caps.selected_parameters(rtsp.parse(m4(UDP_SELECTED))[0])
        self.assertTrue(caps.selection_compatible(values,caps.UDP_PROFILE))
        self.assertFalse(caps.selection_compatible(values))
        tcp,names=caps.selected_parameters(rtsp.parse(m4())[0])
        self.assertFalse(caps.selection_compatible(tcp,caps.UDP_PROFILE))

    def test_full_auto_main_sends_three_messages_and_stops_before_m4_ack(self):
        phone=UdpPhone()
        code,result,plan,runner,session=self.run_main(phone)
        self.assertEqual(code,0)
        self.assertTrue(result["auto_confirmation_verified"])
        self.assertTrue(result["rtsp_capabilities_verified"])
        self.assertEqual(len(runner.commands),4)
        self.assertEqual(len(phone.rtsp_sent),3)
        self.assertEqual(phone.rtsp_sent[-1],caps.capability_reply(2,NAMES,caps.UDP_PROFILE))
        self.assertFalse(any(data.startswith(b"SETUP ") for data in phone.rtsp_sent))
        self.assertEqual(len(phone.host_data),5)
        self.assertEqual(set(session.configs),{256})
        self.assertEqual(plan["rtsp_sends"],3)
        self.assertEqual(plan["max_requests"],40)
        self.assertFalse(plan["setup"])
        self.assertEqual(plan["diagnostic_wfd_profile"],caps.UDP_PROFILE)

    def test_source_cannot_select_old_crashing_transport(self):
        phone=UdpPhone(SELECTED)
        code,result,plan,runner,session=self.run_main(phone)
        self.assertEqual(code,1)
        self.assertIn("outside declared profile",result["error"])
        self.assertTrue(result["auto_confirmation_verified"])
        self.assertEqual(len(phone.rtsp_sent),3)
        self.assertNotIn("rtsp_m4_reply_attempted",result)
        self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_stage_flag_without_primary_grant_never_imports_usb(self):
        original=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=="usb" or name.startswith("usb."):
                raise AssertionError("USB not authorized")
            return original(name,*args,**kwargs)
        for main in (probe.main,launch.main):
            with patch("builtins.__import__",guard),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--approved-udp-capabilities"]),0)

    def test_launcher_forwards_explicit_udp_stage(self):
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kwargs:[SimpleNamespace(bus=3,address=10)]
        usb.core=core
        with tempfile.TemporaryDirectory() as tmp,patch.dict(
                "sys.modules",{"usb":usb,"usb.core":core}),patch.object(
                launch.socket,"create_connection"),patch.object(launch.os,"execv") as execute:
            with contextlib.redirect_stdout(io.StringIO()):
                launch.main(["--approved-phone-auto-start-now","--approved-udp-capabilities",
                             "--accept-persistent-state","--output",tmp+"/new"])
            self.assertIn("--approved-udp-capabilities",execute.call_args.args[1])
            self.assertNotIn("--ready-for-start-now",execute.call_args.args[1])
