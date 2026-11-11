"""Capability caller tests use only fake USB and fixed OpenSSL ciphertext."""
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
import auth_probe as auth
import capabilities_probe as p
from test_auth_probe import AuthPhone
from test_tunnel_probe import Phone, Device, FakeTimeout, Util

V = json.loads(Path(__file__).with_name("capabilities-vectors.json").read_text())


class CapabilityPhone(AuthPhone):
    def __init__(self, fault=None, fragments=False):
        super().__init__()
        self.cap_fault = fault
        self.cap_fragments = fragments
        self.cap_count = 0

    def _handle(self, frame):
        if frame.kind != 1 or frame.command != 5 or len(self.seq) != 3:
            return super()._handle(frame)
        # The independent native fake verifies ports and builds the native ACK.
        Phone._handle(self, frame)
        self.cap_count += 1
        wire = self.host_data[-1]
        length, sid = struct.unpack(">II", wire[:8])
        assert sid == 4 and length == len(wire) - 8
        assert wire[8:].hex() == V["request_cipher"]
        if self.cap_fault == "silent":
            return
        if self.cap_fault == "phone-close":
            self.push_disconnect(23456, self.host_port)
            return
        ciphertext = bytes.fromhex(V.get(self.cap_fault, V["normal"]))
        if self.cap_fault == "plaintext":
            ciphertext = json.dumps(V["response"]).encode()
        response = struct.pack(">II", len(ciphertext), 42) + ciphertext
        if self.cap_fault == "trailing":
            response += b"\0"
        if self.cap_fault == "double":
            response += response
        chunks = ([response[:1], response[1:6], response[6:20], response[20:]]
                  if self.cap_fragments else [response])
        for i, chunk in enumerate(chunks):
            self.push_data(31000 + i, self.host_port, chunk)


class Tests(unittest.TestCase):
    def run_probe(self, phone):
        self.result = {}
        self.device = Device(phone)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(ec, "generate_private_key",
                              return_value=ec.derive_private_key(1, ec.SECP521R1())):
                try:
                    auth.probe(self.device, Util(), FakeTimeout, Path(tmp), self.result,
                               clock=phone.clock, after_auth=p.capabilities,
                               max_requests=10)
                finally:
                    self.events = (Path(tmp) / "events.jsonl").read_text()

    def assert_cleanup(self, phone):
        self.assertTrue(self.result["authentication_verified"])
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_encrypted_exchange_and_cleanup(self):
        phone = CapabilityPhone()
        self.run_probe(phone)
        self.assertEqual(phone.seq, ["SEQ1", "SEQ2", "SEQ3"])
        self.assertEqual(phone.cap_count, 1)
        self.assertEqual(phone.commands, [2, 22, 20, 3, 5, 5, 5, 5, 4, 21])
        self.assertTrue(self.result["terminal_info_attempted"])
        self.assertTrue(self.result["terminal_info_accepted"])
        self.assertTrue(self.result["capabilities_verified"])
        self.assert_cleanup(phone)
        param = self.result["capabilities"]["PARAM"]
        self.assertEqual(param["SerialNumber"], "[device-id]")
        self.assertEqual(param["Wifi_MACAddress"], "[device-id]")
        self.assertNotIn("synthetic-serial-digest", json.dumps(self.result))
        self.assertNotIn("synthetic-wifi-digest", json.dumps(self.result))

    def test_fragmented_capability_reply(self):
        phone = CapabilityPhone(fragments=True)
        self.run_probe(phone)
        self.assertTrue(self.result["capabilities_verified"])
        self.assertEqual(len(phone.acked_sizes), 7)
        self.assert_cleanup(phone)

    def test_rejection_and_malformed_reply_fail_once(self):
        for fault in ("silent", "phone-close", "plaintext", "invalid-json",
                      "wrong-message", "rejected", "truthy-result", "double"):
            with self.subTest(fault=fault):
                phone = CapabilityPhone(fault=fault)
                with self.assertRaises(p.ProtocolError):
                    self.run_probe(phone)
                self.assertTrue(self.result["authentication_verified"])
                self.assertFalse(self.result["capabilities_verified"])
                self.assertFalse(self.result["terminal_info_accepted"])
                self.assertEqual(phone.cap_count, 1)
                self.assertEqual(self.result["close_status"], 0)
                self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_accepted_reply_with_bad_capabilities_preserved(self):
        for fault in ("wrong-model", "wrong-sdk", "wrong-encrypt-version",
                      "wfd-false", "bad-resolution"):
            with self.subTest(fault=fault):
                phone = CapabilityPhone(fault=fault)
                with self.assertRaises(p.ProtocolError):
                    self.run_probe(phone)
                self.assertTrue(self.result["terminal_info_accepted"])
                self.assertFalse(self.result["capabilities_verified"])
                self.assertEqual(phone.cap_count, 1)
                self.assert_cleanup(phone)

    def test_trailing_frame_preserves_verified_reply(self):
        phone = CapabilityPhone(fault="trailing")
        with self.assertRaisesRegex(p.ProtocolError, "truncated frame"):
            self.run_probe(phone)
        self.assertTrue(self.result["terminal_info_accepted"])
        self.assertTrue(self.result["capabilities_verified"])
        self.assert_cleanup(phone)

    def test_final_logging_failure_preserves_verified_reply(self):
        original = auth.emit
        def broken(event, **fields):
            if event == "capabilities_verified":
                raise OSError("synthetic capability event failure")
            return original(event, **fields)
        phone = CapabilityPhone()
        with patch.object(auth, "emit", broken):
            with self.assertRaisesRegex(OSError, "synthetic capability event failure"):
                self.run_probe(phone)
        self.assertTrue(self.result["terminal_info_accepted"])
        self.assertTrue(self.result["capabilities_verified"])
        self.assert_cleanup(phone)

    def test_profile_is_independent_and_disables_optional_features(self):
        self.assertEqual(p.terminal_info(), V["request"])
        params = p.terminal_info()["PARAM"]
        self.assertIs(params["SinkAutoStartStatus"], False)
        self.assertIs(params["SinkIDCConnectBeforehand"], False)
        params["SinkName"] = "altered"
        self.assertEqual(p.terminal_info()["PARAM"]["SinkName"], "DeX-PC")

    def test_default_and_persistence_guard_make_no_usb_import(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB imported")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    p.main(["--approved-phone-capabilities-test", "--bus", "3",
                            "--address", "4", "--output", "not-created"])
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FileExistsError):
                    p.main(["--approved-phone-capabilities-test", "--accept-persistent-preferences",
                            "--bus", "3", "--address", "4", "--output", tmp])


if __name__ == "__main__":
    unittest.main()

