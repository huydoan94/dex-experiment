"""Launcher guards/hash binding/exec selection with fake USB only."""
import builtins
import contextlib
import io
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import rtsp_capabilities_launch as launch


class Tests(unittest.TestCase):
    def test_no_usb_import_before_complete_grant(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(launch.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                launch.main(["--approved-phone-rtsp-capabilities"])

    def test_existing_output_refused_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError):
                launch.main(["--approved-phone-rtsp-capabilities", "--accept-persistent-state",
                             "--ready-for-start-now", "--output", directory])

    def test_hash_mismatch_refused_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(launch.EXPECTED, {"wfd_startup.py": "0"*64}):
                with self.assertRaisesRegex(RuntimeError, "approved source mismatch"):
                    launch.main(["--approved-phone-rtsp-capabilities", "--accept-persistent-state",
                                 "--ready-for-start-now", "--output", directory+"/new"])

    def test_fake_selection_execs_exact_runner_and_flags(self):
        usb, core = ModuleType("usb"), ModuleType("usb.core")
        core.find = lambda **kwargs: [SimpleNamespace(bus=3, address=9)]
        usb.core = core
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("sys.modules", {"usb": usb, "usb.core": core}):
                with patch.object(launch.os, "execv") as execute:
                    with contextlib.redirect_stdout(io.StringIO()):
                        launch.main(["--approved-phone-rtsp-capabilities", "--accept-persistent-state",
                                     "--ready-for-start-now", "--output", directory+"/new"])
        args = execute.call_args.args[1]
        self.assertEqual(args[1], "research/native-usb/rtsp_capabilities.py")
        self.assertIn("--ready-for-start-now", args)
        self.assertEqual(args[args.index("--bus")+1], "3")
        self.assertEqual(args[args.index("--address")+1], "9")
        self.assertEqual(execute.call_count, 1)
