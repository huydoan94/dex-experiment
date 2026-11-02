"""Offline only. Placeholder accept frame tests recording, not real wire layout."""
import builtins
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import loopback_capture as c
from test_multi_config import MultiPhone


class LoopPhone(MultiPhone):
    def get_active_configuration(self):
        return object()

    def is_kernel_driver_active(self, interface):
        assert interface == 3
        return False

    def write(self, endpoint, data=None, timeout=None):
        if data is None:  # MultiPhone API not used by real Link
            raise AssertionError("expected USB endpoint wrapper")
        assert endpoint == 3
        return super().write(data, timeout)

    def read(self, endpoint, size, timeout=None):
        assert endpoint == 133
        if not self.inbound:
            self.now += timeout / 1000
        return super().read(size, timeout)

    def _handle(self, frame):
        super()._handle(frame)
        if frame.kind == 1 and frame.command == 3:
            # Synthetic fixture; does NOT assert actual inbound layout.
            body = struct.pack("<I16sI", c.LISTENER_CONFIG,
                               b"127.0.0.1".ljust(16, b"\0"), 1234)
            self.inbound += encode(Frame(3, 1, 90000, body))


class Util:
    def __init__(self):
        self.actions = []

    def claim_interface(self, device, interface):
        self.actions.append(("claim", interface))

    def release_interface(self, device, interface):
        self.actions.append(("release", interface))

    def dispose_resources(self, device):
        self.actions.append(("dispose",))


class Tests(unittest.TestCase):
    def test_full_probe_records_without_auth_or_data_and_cleans_up(self):
        phone, util, result = LoopPhone(), Util(), {}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(c, "validate_config"), contextlib.redirect_stdout(io.StringIO()):
                c.probe(phone, util, TimeoutError, output, result, clock=phone.clock)
            events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
        self.assertEqual(result["unknown_frames"], 1)
        self.assertFalse(result["inbound_layout_verified"])
        self.assertTrue(result["capture_window_completed"])
        self.assertEqual(result["listener_port"], 46001)
        self.assertEqual(phone.cfgs[c.CONNECT_CONFIG], (46001, 2))
        self.assertEqual(result["close_statuses"], {"602": 0, "601": 0})
        self.assertEqual(result["cleanup_errors"], [])
        self.assertEqual(phone.host_data, [])
        writes = [e for e in events if e["event"] == "usb_write"]
        self.assertEqual(len(writes), 8)
        self.assertNotIn(5, [e["command"] for e in writes])
        self.assertEqual(util.actions, [("claim", 3), ("release", 3), ("dispose",)])
        self.assertTrue(result["usb_released"])
        self.assertTrue(result["usb_disposed"])

    def test_failure_closes_both_configs_and_releases_usb(self):
        phone, util, result = LoopPhone(), Util(), {}
        original = phone._handle
        def fail(frame):
            if frame.kind == 1 and frame.command == 3:
                raise RuntimeError("synthetic Connect failure")
            original(frame)
        phone._handle = fail
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(c, "validate_config"), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "synthetic Connect failure"):
                    c.probe(phone, util, TimeoutError, Path(directory), result, clock=phone.clock)
        self.assertEqual(set(phone.closed), {601, 602})
        self.assertEqual(util.actions[-2:], [("release", 3), ("dispose",)])
        self.assertTrue(result["cleanup_errors"])

    def test_invalid_listener_port_stops_before_connect(self):
        phone, util, result = LoopPhone(), Util(), {}
        original = phone._reply
        def reply(command, transaction, body):
            if command == 0x14 and struct.unpack_from("<I", body, 4)[0] == 601:
                body = struct.pack("<4I", 0, 601, 0, 0)
            original(command, transaction, body)
        phone._reply = reply
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(c, "validate_config"), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "valid bound port"):
                    c.probe(phone, util, TimeoutError, Path(directory), result, clock=phone.clock)
        self.assertNotIn(602, phone.cfgs)
        self.assertEqual(phone.closed, [601])

    def test_default_and_missing_arguments_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB import without grant")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(c.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                c.main(["--approved-phone-loopback-capture"])
