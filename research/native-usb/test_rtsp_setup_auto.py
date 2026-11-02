"""Automatic UI confirmation composed with the six-send SETUP diagnostic, offline only."""
import builtins
import contextlib
import io
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace,ModuleType
import unittest
from unittest.mock import patch

import rtsp_setup as setup
import rtsp_setup_launch as launch
import ui_confirm as ui
from conn_frames import Decoder
from test_rtsp_setup import SetupPhone
from test_ui_confirm import FakeRunner
from test_idc_handshake import opened,KEY


class AutoSetupPhone(SetupPhone):
    def __init__(self):
        super().__init__()
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
    def run_chain(self,runner_factory):
        phone,result=AutoSetupPhone(),{}
        session,main=opened(phone)
        runner=runner_factory(phone)
        self.last_chain=(phone,result,runner,session)
        with tempfile.TemporaryDirectory() as tmp:
            def confirm(s,m,r,log,deadline):
                ui.confirm(s,m,r,log,deadline,tmp,3,runner=runner)
            client=SimpleNamespace(codec=lambda:SimpleNamespace(_key=KEY))
            with patch.object(setup.cap,"capabilities"),patch.object(setup.pss_probe,"pss_ready"):
                setup.after_auth(session,main,client,result,session.clock,lambda **kw:None,
                                 confirm=confirm)
        return phone,result,runner,session

    def test_automatic_tap_then_exact_six_rtsp_sends_without_play(self):
        phone,result,runner,session=self.run_chain(FakeRunner)
        self.assertTrue(result["ui_tap_command_succeeded"])
        self.assertTrue(result["wfd_startup_verified"])
        self.assertTrue(result["rtsp_setup_verified"])
        self.assertEqual(len(runner.commands),4)
        self.assertEqual(len(phone.rtsp_sent),6)
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"SETUP "))
        self.assertFalse(any(x.startswith(b"PLAY ") for x in phone.rtsp_sent))
        self.assertEqual(set(session.configs),{256})
        self.assertEqual(result["wfd_cleanup_errors"],[])
        self.assertEqual(result["idc_cleanup_errors"],[])

    def test_wrong_focus_prevents_tap_and_all_rtsp_sends(self):
        def runner(phone):
            return FakeRunner(phone,focus=b"mCurrentFocus=null\n")
        with self.assertRaisesRegex(ValueError,"current focus"):
            self.run_chain(runner)
        phone,result,runner,session=self.last_chain
        self.assertFalse(any("input" in argv for argv in runner.commands))
        self.assertEqual(phone.rtsp_sent,[])
        self.assertNotIn("ui_tap_attempted",result)
        self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_disabled_direct_cli_refused_before_usb_and_output(self):
        original=builtins.__import__
        def guard(name,*args,**kwargs):
            if name=="usb" or name.startswith("usb."):
                raise AssertionError("must validate before USB")
            return original(name,*args,**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            for deadline in ("nan","inf","0",str(time.monotonic()+1000)):
                with patch.dict(os.environ,{"DEX_AUTO_UI_DEADLINE":deadline}),patch(
                        "builtins.__import__",guard),contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        setup.main(["--approved-phone-rtsp-setup","--approved-auto-start-now",
                                    "--accept-persistent-state","--bus","3","--address","10",
                                    "--output",tmp+"/new"])
                self.assertFalse((Path(tmp)/"new").exists())

    def test_auto_and_manual_modes_cannot_be_combined(self):
        for main in (setup.main,launch.main):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main(["--approved-phone-rtsp-setup","--approved-auto-start-now",
                      "--ready-for-start-now","--accept-persistent-state","--output","unused"])

    def test_disabled_automatic_launcher_never_preflights_or_execs(self):
        import auto_confirm_launch
        with tempfile.TemporaryDirectory() as tmp,patch.object(
                auto_confirm_launch,"require_adb_server") as preflight,patch.object(
                launch.os,"execv") as execute:
            with self.assertRaisesRegex(RuntimeError,"confirmed Samsung RTPSender abort"):
                launch.main(["--approved-phone-rtsp-setup","--approved-auto-start-now",
                             "--accept-persistent-state","--output",tmp+"/new"])
            preflight.assert_not_called()
            execute.assert_not_called()
            self.assertFalse((Path(tmp)/"new").exists())

    def test_direct_main_refuses_crashing_transport_before_probe_or_output(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(
                os.environ,{"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}):
            with patch("auth_probe.probe") as probe,contextlib.redirect_stderr(
                    io.StringIO()),self.assertRaises(SystemExit):
                setup.main(["--approved-phone-rtsp-setup","--approved-auto-start-now",
                            "--accept-persistent-state","--bus","3","--address","10",
                            "--output",tmp+"/new"])
            probe.assert_not_called()
            self.assertFalse((Path(tmp)/"new").exists())
