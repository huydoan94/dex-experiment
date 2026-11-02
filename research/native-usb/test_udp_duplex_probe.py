"""Only new duplex probe/launcher wiring and grant guards, no actual USB/ADB."""
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

import duplex_link
import udp_duplex_probe as probe
import udp_duplex_launch as launch

class Tests(unittest.TestCase):
    def test_plan_and_invalid_deadline_stop_before_usb(self):
        with contextlib.redirect_stdout(io.StringIO()) as log:
            self.assertEqual(probe.main([]),0)
            self.assertEqual(launch.main([]),0)
        self.assertIn("PLAN_ONLY",log.getvalue())
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{"DEX_AUTO_UI_DEADLINE":"nan"}):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                probe.main(["--approved-phone-udp-duplex","--accept-persistent-state",
                            "--bus","3","--address","13","--output",tmp+"/new"])
            self.assertFalse(Path(tmp+"/new").exists())

    def test_probe_passes_owning_util_and_session_factory(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        def fake_probe(device,owner,timeout,out,result,**kwargs):
            self.assertIsInstance(owner,duplex_link.UsbOwner)
            self.assertIs(owner.util,util)
            self.assertIs(kwargs["session_class"].__self__,owner)
            self.assertEqual(kwargs["max_requests"],48)
            self.assertTrue(callable(kwargs["after_auth"]))
            result.update(ui_tap_command_succeeded=True,wfd_startup_verified=True,rtp_media_verified=True)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),patch.dict("sys.modules",
                {"usb":usb,"usb.core":core,"usb.util":util}),patch.object(probe.auth_probe,
                "probe",side_effect=fake_probe),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(["--approved-phone-udp-duplex","--accept-persistent-state",
                "--bus","3","--address","13","--output",tmp+"/new"]),0)
            plan=json.loads(Path(tmp+"/new/plan.json").read_text())
            self.assertTrue(plan["duplex_in"])
            self.assertEqual(plan["duplex_queue_bytes"],2097152)
            self.assertEqual(plan["duplex_read_timeout_ms"],200)
            self.assertEqual(plan["max_reads"],6000)

    def test_live_reader_skips_interpreter_teardown_after_result(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        def stuck_probe(device,owner,timeout,out,result,**kwargs):
            owner.reader=SimpleNamespace(alive=lambda:True)
            raise RuntimeError("duplex reader still owns USB handle")
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),patch.dict("sys.modules",
                {"usb":usb,"usb.core":core,"usb.util":util}),patch.object(probe.auth_probe,
                "probe",side_effect=stuck_probe),patch.object(probe.os,"_exit",
                side_effect=SystemExit) as hard_exit,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                probe.main(["--approved-phone-udp-duplex","--accept-persistent-state",
                    "--bus","3","--address","13","--output",tmp+"/new"])
            hard_exit.assert_called_once_with(1)
            self.assertFalse(json.loads(Path(tmp+"/new/result.json").read_text())["transport_completed"])

    def test_launch_hashes_and_execs_only_duplex_probe(self):
        import types
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[types.SimpleNamespace(bus=3,address=13)]
        usb.core=core
        with tempfile.TemporaryDirectory() as tmp,patch.dict("sys.modules",{"usb":usb,"usb.core":core}):
            with patch.object(launch,"require_adb_server"),patch.object(launch.os,"execv") as execute,contextlib.redirect_stdout(io.StringIO()):
                launch.main(["--approved-phone-udp-duplex","--accept-persistent-state","--output",tmp+"/new"])
            args=execute.call_args.args[1]
            self.assertIn("research/native-usb/udp_duplex_probe.py",args)
            self.assertIn("--approved-phone-udp-duplex",args)
            self.assertNotIn("--approved-phone-udp-play",args)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(launch.EXPECTED,{"duplex_link.py":"0"*64},clear=True),self.assertRaisesRegex(RuntimeError,"source mismatch"):
            launch.main(["--approved-phone-udp-duplex","--accept-persistent-state","--output",tmp+"/new"])

if __name__=="__main__":unittest.main()
