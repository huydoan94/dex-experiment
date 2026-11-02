"""Fake-device validation of the bounded loopback transfer; no phone access."""
import builtins
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import loopback_capture as base
import loopback_transfer as transfer
from test_inbound_session import TransferPhone
from test_loopback_capture import Util
from usb_tunnel import TunnelError


class Device:
    def __init__(self, phone):
        self.phone = phone

    def get_active_configuration(self):
        return object()

    def is_kernel_driver_active(self, interface):
        assert interface == 3
        return False

    def write(self, endpoint, data, timeout):
        assert endpoint == 3
        return self.phone.write(data, timeout)

    def read(self, endpoint, size, timeout):
        assert endpoint == 133
        if not self.phone.inbound:
            self.phone.now += timeout / 1000
        return self.phone.read(size, timeout)


def run(phone, result, util, output):
    with patch.object(base, "validate_config"), contextlib.redirect_stdout(io.StringIO()):
        base.probe(Device(phone), util, TimeoutError, output, result,
                   clock=phone.clock, session_class=transfer.TransferSession,
                   exchange_fn=transfer.transfer, max_requests=11)


class Tests(unittest.TestCase):
    def test_full_transfer_budgets_and_both_key_cleanup(self):
        phone, util, result = TransferPhone(), Util(), {}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            run(phone, result, util, output)
            events = [json.loads(line) for line in (output/"events.jsonl").read_text().splitlines()]
        self.assertTrue(result["bidirectional_verified"])
        self.assertTrue(result["forward_verified"])
        self.assertTrue(result["reverse_verified"])
        self.assertEqual(phone.host_data, [(602, 50002, transfer.FORWARD),
                                          (601, 65535, transfer.REVERSE)])
        self.assertEqual(phone.disconnect_ports, [(601, phone.accepted_key), (602, 1000)])
        self.assertEqual(result["close_statuses"], {"602": 0, "601": 0})
        self.assertEqual(result["cleanup_errors"], [])
        self.assertEqual(util.actions, [("claim", 3), ("release", 3), ("dispose",)])
        writes = [e for e in events if e["event"] == "usb_write"]
        self.assertEqual(sum(e["kind"] == 1 for e in writes), 11)
        self.assertEqual(sum(e["kind"] == 2 for e in writes), 3)

    def test_corrupt_forward_payload_stops_without_reverse_or_retry(self):
        phone, util, result = TransferPhone(), Util(), {}
        original = phone.push_data
        def corrupt(config, host, payload):
            original(config, host, b"X" * len(payload))
        phone.push_data = corrupt
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(TunnelError, "forward payload not confirmed"):
                run(phone, result, util, Path(directory))
        self.assertFalse(result["bidirectional_verified"])
        self.assertEqual(len(phone.host_data), 1)
        self.assertEqual(set(phone.closed), {601, 602})
        self.assertEqual(len(phone.disconnect_ports), 2)
        self.assertTrue(result["usb_released"])

    def test_default_and_missing_arguments_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(transfer.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                transfer.main(["--approved-phone-loopback-transfer"])
