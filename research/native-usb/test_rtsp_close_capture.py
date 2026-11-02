"""Receive-only recovery diagnostic: exact transaction, quiet, no bulk OUT."""
import builtins
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import queued_close_probe as queued
import rtsp_close_capture as capture
from test_queued_close_probe import ReadDevice
from test_tunnel_probe import Util, FakeTimeout


class Tests(unittest.TestCase):
    def run_capture(self, chunks):
        self.device = ReadDevice(chunks)
        self.result = {}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            queued.capture(self.device, Util(), FakeTimeout, Path(tmp), self.result,
                           clock=lambda: self.device.now,
                           expected_close_transaction=801837119, allow_old_data=False)

    def test_exact_new_close_and_quiet_without_bulk_out(self):
        self.run_capture([encode(Frame(21, 2, 801837119, struct.pack("<I",0)))])
        self.assertTrue(self.result["old_close_confirmed"])
        self.assertTrue(self.result["quiet_observed"])
        self.assertEqual(self.device.calls[-2:], ["release","dispose"])

    def test_wrong_transaction_status_and_unexpected_accept_fail(self):
        frames = [Frame(21,2,801837118,struct.pack("<I",0)),
                  Frame(21,2,801837119,struct.pack("<I",1)),
                  Frame(3,1,71,struct.pack("<I16sI",1201,bytes(16),1032))]
        for frame in frames:
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                self.run_capture([encode(frame)])
            self.assertEqual(self.device.calls[-2:], ["release","dispose"])

    def test_old_data_not_allowed_in_new_close_capture(self):
        from test_queued_close_probe import old_data
        with self.assertRaisesRegex(ValueError, "unexpected queued"):
            self.run_capture([old_data()])

    def test_guards_before_usb_import(self):
        original = builtins.__import__
        def guard(name,*args,**kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name,*args,**kwargs)
        with patch("builtins.__import__",guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(capture.main([]),0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                capture.main(["--approved-phone-rtsp-close-capture"])
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FileExistsError):
                    capture.main(["--approved-phone-rtsp-close-capture","--output",tmp])
                with patch.dict(capture.EXPECTED,{"queued_close_probe.py":"0"*64}):
                    with self.assertRaisesRegex(RuntimeError,"source mismatch"):
                        capture.main(["--approved-phone-rtsp-close-capture","--output",tmp+"/new"])
