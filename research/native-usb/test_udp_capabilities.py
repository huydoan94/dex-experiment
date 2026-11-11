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




