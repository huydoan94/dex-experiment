"""Offline queued native replies; device rejects every bulk OUT attempt."""
import builtins
from collections import deque
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
from test_tunnel_probe import Device, Util, FakeTimeout, Phone
import queued_close_probe as p


def close(transaction=2655014204):
    return encode(Frame(21, 2, transaction, struct.pack("<I", 0)))


def old_data(config=193, transaction=99):
    payload = b"synthetic encrypted bytes"
    body = struct.pack("<9I", 6, config, 2, 1002, 48989, 15000, 0, 56, len(payload)) + payload
    return encode(Frame(5, 1, transaction, body))


class ReadDevice(Device):
    def __init__(self, chunks):
        super().__init__(Phone())
        self.chunks = deque(chunks)
        self.now = 0.
        self.read_count = 0
        self.last_packet_at = None
    def write(self, *args, **kwargs):
        raise AssertionError("forbidden bulk OUT")
    def read(self, endpoint, size, timeout):
        assert endpoint == 133 and size == 512
        self.read_count += 1
        self.calls.append("read")
        if not self.chunks:
            self.now += timeout / 1000
            raise FakeTimeout()
        item = self.chunks.popleft()
        if isinstance(item, tuple):
            delay, data = item
            self.now += delay
            if data is None:
                raise FakeTimeout()
        else:
            self.now += .001
            data = item
        self.last_packet_at = self.now
        return data


class Tests(unittest.TestCase):
    def run_capture(self, chunks):
        self.device = ReadDevice(chunks)
        self.result = {}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            p.capture(self.device, Util(), FakeTimeout, Path(tmp), self.result,
                      clock=lambda: self.device.now)

    def test_expected_close_and_quiet_no_bulk_out(self):
        self.run_capture([close()])
        self.assertTrue(self.result["old_close_confirmed"])
        self.assertTrue(self.result["quiet_observed"])
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_old_data_then_fragmented_close_captured_without_ack(self):
        self.run_capture([old_data(), close()[:10], close()[10:]])
        self.assertEqual(self.result["old_data_frames"], 1)
        self.assertTrue(self.result["old_close_confirmed"])

    def test_unknown_duplicate_and_excess_data_rejected(self):
        for chunks in ([close(123)], [old_data(194)], [close(), close()],
                       [old_data(transaction=i + 1) for i in range(5)]):
            with self.subTest(chunks=chunks[:1]), self.assertRaises(ValueError):
                self.run_capture(chunks)
            self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_timeout_and_partial_trailing_data_are_not_clean(self):
        for chunks in ([], [close() + b"x"]):
            with self.subTest(chunks=chunks), self.assertRaises((ValueError, TimeoutError)):
                self.run_capture(chunks)
            self.assertLessEqual(self.device.read_count, 16)
            self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_successful_empty_usb_packet_does_not_mean_quiet(self):
        self.run_capture([close(), b""])
        self.assertTrue(self.result["quiet_observed"])
        self.assertEqual(self.device.read_count, 3)
        self.assertGreaterEqual(self.device.now - self.device.last_packet_at, .2 - 1e-9)

    def test_quiet_restarts_after_old_data_and_early_timeout(self):
        self.run_capture([close(), (.19, old_data()), (.01, None)])
        self.assertTrue(self.result["quiet_observed"])
        self.assertGreaterEqual(self.device.read_count, 4)
        self.assertGreaterEqual(self.device.now - self.device.last_packet_at, .2 - 1e-9)

    def test_close_near_overall_deadline_cannot_shorten_quiet(self):
        with self.assertRaises(TimeoutError):
            self.run_capture([(1.9, close())])
        self.assertTrue(self.result["old_close_confirmed"])
        self.assertFalse(self.result.get("quiet_observed", False))

    def test_duplicate_old_data_transaction_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate old data"):
            self.run_capture([close(), old_data(), old_data()])

    def test_read_budget_limits_fragmented_header(self):
        with self.assertRaises(TimeoutError):
            self.run_capture([bytes([value]) for value in close()[:16]])
        self.assertEqual(self.device.read_count, 16)

    def test_default_and_existing_output_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB imported")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.main([]), 0)
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FileExistsError):
                    p.main(["--approved-phone-old-close-capture", "--bus", "3",
                            "--address", "4", "--output", tmp])


if __name__ == "__main__":
    unittest.main()

