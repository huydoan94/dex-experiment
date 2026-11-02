"""Offline AUTH over the existing fake USB daemon; never accesses hardware."""
import base64
import builtins
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
import auth_probe as p
from conn_frames import Frame
from test_tunnel_probe import Phone, Device, Util, FakeTimeout
from test_usb_tunnel import _status

V = json.loads(Path(__file__).with_name("main-channel-vectors.json").read_text())


class AuthPhone(Phone):
    def __init__(self, fault=None, fragments=False):
        super().__init__(usb_buffer_bytes=4095)
        self.fault = fault
        self.fragments = fragments
        self.seq = []

    def _handle(self, frame):
        if frame.kind == 1 and frame.command == 3:
            # Passive Phone helper bypasses FakePhone's port tracking on Connect.
            self.host_ports.add(struct.unpack_from("<I", frame.body, 20)[0])
        if frame.kind == 1 and frame.command == 4 and self.fault == "disconnect":
            self.commands.append(4)
            self.disconnect_ports.append(struct.unpack_from("<I", frame.body, 20)[0])
            self._reply(4, frame.transaction, _status(1))
            return
        super()._handle(frame)
        if frame.kind != 1 or frame.command != 5:
            return
        wire = self.host_data[-1]
        length, sid = struct.unpack(">II", wire[:8])
        assert length == len(wire) - 8 and sid == len(self.seq) + 1
        request = json.loads(wire[8:].decode())
        assert request["TYPE"] == "AUTH"
        seq = request["MSG"]
        self.seq.append(seq)
        if self.fault == "silent":
            return
        if self.fault == "phone-close":
            self.push_disconnect(12345, self.host_port)
            return
        if seq == "SEQ1":
            assert request["PARAM"] == {"MAC": V["mac"]}
            param = dict(HPubKey=V["commitment"], UID=V["uid"])
        elif seq == "SEQ2":
            assert request["PARAM"] == {"PubKey": V["client_public"]}
            param = dict(PubKey=V["phone_public"], HMAC=V["phone_hmac"])
            if self.fault == "HMAC":
                param["HMAC"] = base64.b64encode(bytes(32)).decode()
        elif seq == "SEQ3":
            assert request["PARAM"] == {"HMAC": V["client_hmac"]}
            param = dict(Verified=True)
        else:
            raise AssertionError("unexpected AUTH send")
        payload = json.dumps(dict(TYPE="AUTH", MSG=seq, PARAM=param)).encode()
        response = struct.pack(">II", len(payload), 910 + len(self.seq)) + payload
        if self.fault == "double":
            response += response
        if self.fault == "truncated":
            response = response[:-1]
        if self.fault == "trailing-after-verified" and seq == "SEQ3":
            response += b"\x00"
        chunks = ([response[:2], response[2:7], response[7:17], response[17:]]
                  if self.fragments else [response])
        for i, chunk in enumerate(chunks):
            self.push_data(20000 + len(self.seq) * 10 + i, self.host_port, chunk)


class Tests(unittest.TestCase):
    def run_probe(self, phone, busy=False, util=None):
        device = Device(phone, busy=busy)
        self.device, self.result = device, {}
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(ec, "generate_private_key",
                              return_value=ec.derive_private_key(1, ec.SECP521R1())):
                try:
                    p.probe(device, util or Util(), FakeTimeout, Path(directory),
                            self.result, clock=phone.clock)
                finally:
                    self.events = (Path(directory) / "events.jsonl").read_text()
        return device

    def test_three_sends_and_key_disconnect(self):
        phone = AuthPhone()
        self.run_probe(phone)
        self.assertEqual(phone.seq, ["SEQ1", "SEQ2", "SEQ3"])
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 5, 5, 5, 4, 0x15])
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])
        self.assertNotIn(V["session_key"], self.events)
        self.assertNotIn(V["secret"], self.events)

    def test_verified_evidence_survives_trailing_partial_frame(self):
        phone = AuthPhone(fault="trailing-after-verified")
        with self.assertRaisesRegex(p.ProtocolError, "truncated frame"):
            self.run_probe(phone)
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_verified_evidence_survives_final_event_log_failure(self):
        original = p.emit
        def broken(event, **fields):
            if event == "auth_verified":
                raise OSError("synthetic final event logging failure")
            return original(event, **fields)
        phone = AuthPhone()
        with patch.object(p, "emit", broken):
            with self.assertRaisesRegex(OSError, "synthetic final event logging failure"):
                self.run_probe(phone)
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_fragmented_native_data(self):
        phone = AuthPhone(fragments=True)
        self.run_probe(phone)
        self.assertEqual(phone.seq, ["SEQ1", "SEQ2", "SEQ3"])
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(len(phone.acked_sizes), 12)

    def test_failures_cleanup_without_resend(self):
        expected = {"HMAC": ("AUTH exchange failed", 2),
                    "silent": ("AUTH reply deadline expired", 1),
                    "phone-close": ("phone closed AUTH connection", 1),
                    "double": ("unexpected additional AUTH frame", 1),
                    "truncated": ("AUTH reply deadline expired", 1)}
        for fault, (message, sends) in expected.items():
            with self.subTest(fault=fault):
                phone = AuthPhone(fault=fault)
                with self.assertRaisesRegex(p.ProtocolError, message):
                    self.run_probe(phone)
                self.assertFalse(self.result["authentication_verified"])
                self.assertEqual(phone.commands.count(0x15), 1)
                self.assertEqual(self.device.calls[-2:], ["release", "dispose"])
                self.assertEqual(len(phone.seq), sends)
                self.assertEqual(len(phone.seq), len(set(phone.seq)))

    def test_disconnect_status_failure_is_not_success(self):
        phone = AuthPhone(fault="disconnect")
        with self.assertRaisesRegex(Exception, "cleanup was not confirmed"):
            self.run_probe(phone)
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(self.result["disconnect_status"], 1)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_connect_refused_does_not_send_auth(self):
        phone = AuthPhone()
        phone.connect_status = 1
        with self.assertRaises(Exception):
            self.run_probe(phone)
        self.assertEqual(phone.seq, [])
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 0x15])
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_busy_interface_disposed_without_claim(self):
        phone = AuthPhone()
        with self.assertRaisesRegex(Exception, "kernel driver"):
            self.run_probe(phone, busy=True)
        self.assertEqual(self.device.calls, ["config", "kernel", "dispose"])
        self.assertEqual(phone.commands, [])

    def test_release_error_still_disposes(self):
        class BrokenUtil(Util):
            def release_interface(self, device, interface):
                super().release_interface(device, interface)
                raise OSError("synthetic release failure")
        with self.assertRaisesRegex(OSError, "synthetic release failure"):
            self.run_probe(AuthPhone(), util=BrokenUtil())
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_default_and_existing_output_never_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB imported")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.main([]), 0)
            with tempfile.TemporaryDirectory() as existing:
                with self.assertRaises(FileExistsError):
                    p.main(["--approved-phone-auth-test", "--bus", "3", "--address", "4",
                            "--output", existing])

    def test_missing_or_invalid_target_refused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in (["--approved-phone-auth-test"],
                         ["--approved-phone-auth-test", "--output", "unused",
                          "--bus", "0", "--address", "4"]):
                with self.assertRaises(SystemExit):
                    p.main(args)


if __name__ == "__main__":
    unittest.main()

