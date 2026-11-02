"""Offline full-packet/ZLP and late-ACK cleanup regressions. No hardware."""
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
import auth_probe as auth
import capabilities_probe as cap
from conn_frames import Frame
from tunnel_probe import Link
from usb_tunnel import Session, TunnelError
from test_capabilities_probe import CapabilityPhone
from test_tunnel_probe import Device, Util, FakeTimeout
from test_usb_tunnel import FakePhone, _data_reply

UID = b"test-host".ljust(64, b"\0")


class PacketDevice(Device):
    """Device-side bulk request completes only on a short packet or ZLP."""
    def __init__(self, phone, ignore_zlp=False, fail_zlp=False):
        super().__init__(phone)
        self.pending = bytearray()
        self.sizes = []
        self.ignore_zlp = ignore_zlp
        self.fail_zlp = fail_zlp

    def write(self, endpoint, data, timeout):
        assert endpoint == 3 and 0 < timeout <= 1000
        data = bytes(data)
        self.calls.append("write")
        self.sizes.append(len(data))
        self.pending.extend(data)
        if not data and self.fail_zlp:
            raise OSError("synthetic ZLP transfer failure")
        if (data and len(data) % 512) or (not data and not self.ignore_zlp):
            wire = bytes(self.pending)
            self.pending.clear()
            self.phone.write(wire, timeout)
        return len(data)


class BoundaryTests(unittest.TestCase):
    def run_packet_probe(self, ignore_zlp=False, fail_zlp=False):
        self.phone = CapabilityPhone()
        self.device = PacketDevice(self.phone, ignore_zlp=ignore_zlp, fail_zlp=fail_zlp)
        self.result = {}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(ec, "generate_private_key",
                              return_value=ec.derive_private_key(1, ec.SECP521R1())):
                auth.probe(self.device, Util(), FakeTimeout, Path(tmp), self.result,
                           clock=self.phone.clock, after_auth=cap.capabilities, max_requests=10)

    def test_full_packet_capability_completes_with_zlp(self):
        self.run_packet_probe()
        self.assertTrue(self.result["capabilities_verified"])
        self.assertEqual(self.device.sizes.count(0), 1)
        i = self.device.sizes.index(0)
        self.assertEqual(self.device.sizes[i - 1], 512)
        self.assertFalse(self.device.pending)
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)

    def test_without_packet_termination_timeout_remains_failure_but_cleanup_succeeds(self):
        with self.assertRaisesRegex(TunnelError, "USB deadline expired"):
            self.run_packet_probe(ignore_zlp=True)
        self.assertTrue(self.result["authentication_verified"])
        self.assertFalse(self.result["terminal_info_accepted"])
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.phone.cap_count, 1)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_zlp_error_keeps_known_late_ack_cleanup_safe(self):
        with self.assertRaisesRegex(OSError, "synthetic ZLP transfer failure"):
            self.run_packet_probe(fail_zlp=True)
        self.assertTrue(self.result["authentication_verified"])
        self.assertFalse(self.result["terminal_info_accepted"])
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_zlp_only_after_complete_full_packet_write(self):
        class Out:
            def __init__(self, returned=None):
                self.sizes = []
                self.returned = returned
            def write(self, endpoint, data, timeout):
                self.sizes.append(len(data))
                return len(data) if self.returned is None else self.returned
        for length, returned, expected in ((511, None, [511]),
                                            (512, None, [512, 0]),
                                            (1024, None, [1024, 0]),
                                            (512, 511, [512])):
            frame = bytearray(length)
            struct.pack_into("<I", frame, 12, 1)
            out = Out(returned)
            link = Link(out, FakeTimeout)
            link.write(bytes(frame), 1000)
            self.assertEqual(out.sizes, expected)
            self.assertEqual(link.requests_left, 7)

    def test_zlp_failure_is_not_retried(self):
        class Out:
            def __init__(self, error=False):
                self.sizes = []
                self.error = error
            def write(self, endpoint, data, timeout):
                self.sizes.append(len(data))
                if not data:
                    if self.error:
                        raise OSError("synthetic ZLP error")
                    return 1
                return len(data)
        frame = bytearray(512)
        struct.pack_into("<I", frame, 12, 1)
        for error in (False, True):
            out = Out(error)
            with self.assertRaises((TunnelError, OSError)):
                Link(out, FakeTimeout).write(bytes(frame), 1000)
            self.assertEqual(out.sizes, [512, 0])


class LateAckPhone(FakePhone):
    def __init__(self, late="valid"):
        super().__init__()
        self.late = late
        self.saved = None

    def _handle(self, frame):
        if frame.kind == 1 and frame.command == 5:
            self.saved = frame
            return
        super()._handle(frame)
        if frame.kind == 1 and frame.command == 4:
            transaction = self.saved.transaction
            size = 20 + len(self.saved.body)
            if self.late == "unknown":
                transaction += 100
            if self.late == "malformed":
                size += 1
            reply = Frame(5, 2, transaction, _data_reply(size))
            self.push_raw(reply)
            if self.late == "duplicate":
                self.push_raw(reply)


class LateAckTests(unittest.TestCase):
    def prepare(self, kind="valid"):
        phone = LateAckPhone(kind)
        events = []
        session = Session(phone, 7, 1 << 18, 65536, clock=phone.clock,
                          log=lambda event, **fields: events.append(event))
        session.get_version()
        session.exchange(0, 0)
        session.open_config(123, UID, 15000)
        conn = session.connect(41000)
        with self.assertRaisesRegex(TunnelError, "USB deadline expired"):
            session.send(conn, b"test", timeout_s=.1)
        return phone, session, conn, events

    def test_known_late_ack_after_disconnect_does_not_block_config_close(self):
        phone, session, conn, events = self.prepare()
        self.assertEqual(len(session.late_data), 1)
        session.begin_cleanup()
        self.assertEqual(session.disconnect(conn), 0)
        self.assertEqual(session.close_config(UID), 0)
        self.assertEqual(events.count("late_data_reply"), 1)
        self.assertFalse(session.late_data)

    def test_unknown_malformed_and_duplicate_late_ack_are_not_ignored(self):
        for kind in ("unknown", "malformed", "duplicate"):
            with self.subTest(kind=kind):
                phone, session, conn, events = self.prepare(kind)
                session.begin_cleanup()
                self.assertEqual(session.disconnect(conn), 0)
                with self.assertRaises(TunnelError):
                    session.close_config(UID)

    def test_late_ack_not_ignored_outside_cleanup(self):
        phone, session, conn, events = self.prepare()
        self.assertEqual(session.disconnect(conn), 0)
        with self.assertRaisesRegex(TunnelError, "unsolicited response"):
            session.close_config(UID)
        self.assertNotIn("late_data_reply", events)

    def test_cleanup_refuses_new_setup_requests(self):
        phone, session, conn, events = self.prepare()
        session.begin_cleanup()
        with self.assertRaisesRegex(TunnelError, "only disconnect/close"):
            session.get_version()


if __name__ == "__main__":
    unittest.main()

