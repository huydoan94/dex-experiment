"""ChangePSSState caller tests use only fake USB and fixed OpenSSL ciphertext."""
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
import pss_probe as p
from test_capabilities_probe import CapabilityPhone
from test_tunnel_probe import Phone, Device, FakeTimeout, Util

V = json.loads(Path(__file__).with_name("pss-vectors.json").read_text())


class PssPhone(CapabilityPhone):
    def __init__(self, fault=None, fragments=False, cap_fault=None):
        super().__init__(fault=cap_fault)
        self.pss_fault = fault
        self.pss_fragments = fragments
        self.pss_count = 0

    def _handle(self, frame):
        if frame.kind != 1 or frame.command != 5 or self.cap_count != 1:
            return super()._handle(frame)
        Phone._handle(self, frame)
        self.pss_count += 1
        wire = self.host_data[-1]
        length, sid = struct.unpack(">II", wire[:8])
        assert sid == 5 and length == len(wire) - 8
        assert wire[8:].hex() == V["request_cipher"]
        if self.pss_fault == "silent":
            return
        if self.pss_fault == "phone-close":
            self.push_disconnect(34567, self.host_port)
            return
        response = bytes.fromhex(V.get(self.pss_fault, V["normal"]))
        if self.pss_fault == "plaintext":
            response = json.dumps(V["response"]).encode()
        response = struct.pack(">II", len(response), 43) + response
        if self.pss_fault == "double":
            response += response
        chunks = ([response[:3], response[3:9], response[9:]]
                  if self.pss_fragments else [response])
        for i, chunk in enumerate(chunks):
            self.push_data(32000 + i, self.host_port, chunk)


class Tests(unittest.TestCase):
    def run_probe(self, phone):
        self.result = {}
        self.device = Device(phone)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(ec, "generate_private_key",
                              return_value=ec.derive_private_key(1, ec.SECP521R1())):
                try:
                    auth.probe(self.device, Util(), FakeTimeout, Path(tmp), self.result,
                               clock=phone.clock, after_auth=p.after_auth,
                               max_requests=p.MAX_REQUESTS)
                finally:
                    self.events = (Path(tmp) / "events.jsonl").read_text()

    def assert_cleanup(self, phone):
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertEqual(self.result["disconnect_status"], 0)
        self.assertEqual(self.result["close_status"], 0)
        self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_ready_confirmed_then_cleanup(self):
        phone = PssPhone()
        self.run_probe(phone)
        self.assertTrue(self.result["capabilities_verified"])
        self.assertEqual(phone.pss_count, 1)
        self.assertEqual(phone.commands, [2, 22, 20, 3, 5, 5, 5, 5, 5, 4, 21])
        self.assertTrue(self.result["pss_attempted"])
        self.assertTrue(self.result["pss_ready_confirmed"])
        self.assertEqual(self.result["pss_reply"], V["response"])
        self.assert_cleanup(phone)

    def test_fragmented_reply(self):
        phone = PssPhone(fragments=True)
        self.run_probe(phone)
        self.assertTrue(self.result["pss_ready_confirmed"])
        self.assert_cleanup(phone)

    def test_rejected_or_malformed_reply_fails_once(self):
        for fault in ("silent", "phone-close", "plaintext", "rejected", "truthy-result",
                      "wrong-message", "request-type", "double"):
            with self.subTest(fault=fault):
                phone = PssPhone(fault=fault)
                with self.assertRaises(p.ProtocolError):
                    self.run_probe(phone)
                self.assertTrue(self.result["capabilities_verified"])
                self.assertTrue(self.result["pss_attempted"])
                self.assertFalse(self.result["pss_ready_confirmed"])
                self.assertEqual(phone.pss_count, 1)
                self.assertEqual(self.result["close_status"], 0)
                self.assertEqual(self.device.calls[-2:], ["release", "dispose"])

    def test_failed_capabilities_never_send_pss(self):
        phone = PssPhone(cap_fault="rejected")
        with self.assertRaises(p.ProtocolError):
            self.run_probe(phone)
        self.assertEqual(phone.pss_count, 0)
        self.assertNotIn("pss_attempted", self.result)
        self.assertEqual(phone.commands, [2, 22, 20, 3, 5, 5, 5, 5, 4, 21])
        self.assert_cleanup(phone)

    def test_request_is_the_only_wimp_start_value(self):
        self.assertEqual(p.change_pss(), V["request"])
        p.change_pss()["PARAM"]["PSS_STATE"] = 0
        self.assertEqual(p.change_pss()["PARAM"], {"PSS_STATE": 1, "PSS_MODE": 0})

    def test_default_and_guards_make_no_usb_import(self):
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
                    p.main(["--approved-phone-pss-ready-test", "--bus", "3",
                            "--address", "4", "--output", "not-created"])
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FileExistsError):
                    p.main(["--approved-phone-pss-ready-test", "--accept-persistent-preferences",
                            "--bus", "3", "--address", "4", "--output", tmp])


if __name__ == "__main__":
    unittest.main()
