"""Launcher guards/hash binding/exec selection with fake USB only."""
import builtins
import contextlib
import io
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import rtsp_setup_launch as launch


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
                launch.main(["--approved-phone-rtsp-setup"])

    def test_existing_output_refused_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError):
                launch.main(["--approved-phone-rtsp-setup", "--accept-persistent-state",
                             "--ready-for-start-now", "--output", directory])

    def test_hash_mismatch_refused_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(launch.EXPECTED, {"wfd_startup.py": "0"*64}):
                with self.assertRaisesRegex(RuntimeError, "approved source mismatch"):
                    launch.main(["--approved-phone-rtsp-setup", "--accept-persistent-state",
                                 "--ready-for-start-now", "--output", directory+"/new"])

    def test_known_crashing_transport_refused_before_usb_or_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(launch.os,"execv") as execute:
                with self.assertRaisesRegex(RuntimeError,"confirmed Samsung RTPSender abort"):
                    launch.main(["--approved-phone-rtsp-setup","--accept-persistent-state",
                                 "--ready-for-start-now","--output",directory+"/new"])
                execute.assert_not_called()
            self.assertFalse((Path(directory)/"new").exists())
