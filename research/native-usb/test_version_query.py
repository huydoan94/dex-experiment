import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS

spec = importlib.util.spec_from_file_location("version_query", Path(__file__).with_name("version_query.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def response(transaction=42):
    return struct.pack("<4s7I64s", b"CONN", 2, 96, 2, transaction, 0, 2, 0, b"reference")


class Interface(list):
    bInterfaceNumber = 3
    bAlternateSetting = 0
    bInterfaceClass = 255
    bInterfaceSubClass = 64
    bInterfaceProtocol = 2


class Config(list):
    bConfigurationValue = 1


class Device:
    def __init__(self, chunks=None, busy=False, partial=False):
        self.config = Config([Interface([
            NS(bEndpointAddress=3, bmAttributes=2, wMaxPacketSize=512),
            NS(bEndpointAddress=133, bmAttributes=2, wMaxPacketSize=512)])])
        self.calls = []
        self.chunks = list(chunks if chunks is not None else [response()])
        self.busy, self.partial = busy, partial

    def get_active_configuration(self):
        self.calls.append("config")
        return self.config

    def is_kernel_driver_active(self, interface):
        assert interface == 3
        self.calls.append("kernel")
        return self.busy

    def write(self, endpoint, data, timeout):
        assert endpoint == 3 and timeout == 1000 and data == q.request(42)
        self.calls.append("write")
        return 5 if self.partial else len(data)

    def read(self, endpoint, size, timeout):
        assert endpoint == 133 and size == 512 and 0 < timeout <= 1000
        self.calls.append("read")
        item = self.chunks.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class Util:
    def __init__(self, device, release_error=False):
        self.device, self.release_error = device, release_error

    def claim_interface(self, device, interface):
        assert device is self.device and interface == 3
        device.calls.append("claim")

    def release_interface(self, device, interface):
        assert interface == 3
        device.calls.append("release")
        if self.release_error:
            raise OSError("release failure")

    def dispose_resources(self, device):
        device.calls.append("dispose")


class Tests(unittest.TestCase):
    def run_query(self, device, util=None, clock=lambda: 0):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            return q.query(device, util or Util(device), Path(directory), 42, clock=clock)

    def test_plan_has_no_usb_import(self):
        # Import trap proves the default guard holds, rather than mocking discovery alone.
        import builtins
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("default mode imported USB")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guarded), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(q.main([]), 0)

    def test_exact_request(self):
        self.assertEqual(q.request(42).hex(), "434f4e4e0200000014000000010000002a000000")
        for transaction in (0, -1, 0x100000000):
            with self.assertRaises(ValueError):
                q.request(transaction)

    def test_fragmented_response(self):
        payload = response()
        for cut in range(96):
            self.assertIsNone(q.version_response(payload[:cut], 42))
        self.assertEqual(self.run_query(Device([payload[:10], payload[10:40], payload[40:]]))["major"], 2)

    def test_rejects_wrong_headers_status_and_trailing_data(self):
        for offset in (0, 4, 8, 12, 16, 20):
            data = bytearray(response())
            data[offset] ^= 1
            with self.assertRaises(ValueError):
                q.version_response(data, 42)
        for data in (response()+b"x", b"x"*4097):
            with self.assertRaises(ValueError):
                q.version_response(data, 42)

    def test_success_releases_only_interface3(self):
        d = Device()
        self.run_query(d)
        self.assertEqual(d.calls, ["config", "kernel", "claim", "write", "read", "release", "dispose"])

    def test_busy_does_not_claim_or_write(self):
        d = Device(busy=True)
        with self.assertRaises(RuntimeError):
            self.run_query(d)
        self.assertEqual(d.calls, ["config", "kernel", "dispose"])

    def test_bad_descriptor_stops_before_claim(self):
        d = Device()
        d.config[0][1].bEndpointAddress = 134
        with self.assertRaises(ValueError):
            self.run_query(d)
        self.assertEqual(d.calls, ["config", "dispose"])

    def test_partial_write_never_retries(self):
        d = Device(partial=True)
        with self.assertRaises(RuntimeError):
            self.run_query(d)
        self.assertEqual(d.calls, ["config", "kernel", "claim", "write", "release", "dispose"])

    def test_timeout_still_releases(self):
        d = Device([TimeoutError("USB timeout")])
        with self.assertRaises(TimeoutError):
            self.run_query(d)
        self.assertEqual(d.calls[-2:], ["release", "dispose"])

    def test_release_failure_still_closes(self):
        d = Device()
        with self.assertRaises(OSError):
            self.run_query(d, Util(d, release_error=True))
        self.assertEqual(d.calls[-2:], ["release", "dispose"])

    def test_cleanup_logging_failure_still_releases_and_disposes(self):
        d = Device()
        def broken_log(event, **fields):
            if event in ("usb_release", "usb_dispose"):
                raise BrokenPipeError("output closed")
        with patch.object(q, "emit", broken_log), self.assertRaises(BrokenPipeError):
            self.run_query(d)
        self.assertEqual(d.calls[-2:], ["release", "dispose"])

    def test_deadline_stops_before_read(self):
        d = Device()
        ticks = iter([0, 9])
        with self.assertRaises(TimeoutError):
            self.run_query(d, clock=lambda: next(ticks))
        self.assertNotIn("read", d.calls)
        self.assertEqual(d.calls[-2:], ["release", "dispose"])

    def test_read_count_bounded(self):
        d = Device([b""] * 8)
        with self.assertRaises(TimeoutError):
            self.run_query(d)
        self.assertEqual(d.calls.count("read"), 8)
        self.assertEqual(d.calls.count("write"), 1)


if __name__ == "__main__":
    unittest.main()
