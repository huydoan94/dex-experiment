"""Offline IDC framing tests: round-trip, writeUTF layout, field rules."""
import base64
import struct
import unittest

import idc
from main_channel import IV
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))


class Tests(unittest.TestCase):
    def test_connect_info_field0_is_listener_port(self):
        info = idc.connect_info(46001)
        parts = info.split("/&%")
        self.assertEqual(parts[0], "46001")
        self.assertGreaterEqual(len(parts), 8)
        self.assertNotIn(" ", info)

    def test_connect_info_rejects_bad_port(self):
        for bad in (0, 65536, "x", 1.0):
            with self.assertRaises(ValueError):
                idc.connect_info(bad)

    def test_command_text_shape(self):
        info = idc.connect_info(7000)
        text = idc.command_text("CONNECT", "SIDESYNC_CONN", "REQUEST", info, seq=1)
        tok = text.split(" ")
        self.assertEqual((tok[0], tok[1], tok[2], tok[3], tok[4]),
                         (str(len(info)), "1", "CONNECT", "SIDESYNC_CONN", "REQUEST"))
        self.assertEqual(text.split(" ", 5)[5], info)

    def test_encode_is_len_prefixed_base64_of_aes(self):
        frame = idc.sidesync_conn_request(KEY, 46001, seq=3)
        length = struct.unpack_from(">H", frame, 0)[0]
        blob = frame[2:]
        self.assertEqual(len(blob), length)
        # ASCII Base64 only (writeUTF of ASCII == bytes).
        blob.decode("ascii")
        cipher = base64.b64decode(blob, validate=True)
        self.assertEqual(len(cipher) % 16, 0)
        # Decrypts with the same key/IV/PKCS7 as the (live-proven) main channel.
        dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
        padded = dec.update(cipher) + dec.finalize()
        unp = padding.PKCS7(128).unpadder()
        text = (unp.update(padded) + unp.finalize()).decode("utf-8")
        self.assertTrue(text.endswith(idc.connect_info(46001)))
        self.assertIn(" CONNECT SIDESYNC_CONN REQUEST ", text)

    def test_round_trip_decode(self):
        frame = idc.sidesync_conn_request(KEY, 7777, seq=5)
        text = idc.decode(KEY, frame)
        self.assertTrue(text.startswith("%d 5 CONNECT SIDESYNC_CONN REQUEST "
                                        % len(idc.connect_info(7777))))

    def test_decode_rejects_truncated_and_bad_key(self):
        frame = idc.sidesync_conn_request(KEY, 7777)
        with self.assertRaises(ValueError):
            idc.decode(KEY, frame[:-1])              # truncated body
        with self.assertRaises(ValueError):
            idc.decode(bytes(32), frame)             # wrong key -> bad padding

    def test_strict_response_acceptance_and_redaction(self):
        info = "54321/&%MAC-secret/&%ID-secret/&%false/&%version/&%device/&%USB/&%name"
        wire = idc.encode(KEY, idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", info))
        self.assertEqual(idc.sidesync_conn_response(KEY, wire),
                         dict(accepted=True, control_port=54321, sequence=1))

    def test_strict_response_rejections(self):
        for reason in ("BUSY", "INVALID"):
            wire = idc.encode(KEY, idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", reason))
            self.assertEqual(idc.sidesync_conn_response(KEY, wire),
                             dict(accepted=False, reason=reason, sequence=1))

    def test_strict_response_rejects_bad_envelopes_and_framing(self):
        info = idc.connect_info(1234)
        valid = idc.encode(KEY, idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", info))
        bad_texts = [
            idc.command_text("CONNECT", "SIDESYNC_CONN", "REQUEST", info),
            "999 1 CONNECT SIDESYNC_CONN RESPONSE " + info,
            "1 -1 CONNECT SIDESYNC_CONN RESPONSE x",
            idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", "0/&%a/&%b/&%c/&%d/&%e/&%f/&%g"),
            idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", "garbage"),
        ]
        for wire in [valid[:-1], valid + b"x", valid + valid, b"", b"\x00\x01!"]:
            with self.subTest(wire_length=len(wire)), self.assertRaises(ValueError):
                idc.sidesync_conn_response(KEY, wire)
        for text in bad_texts:
            with self.subTest(text=text), self.assertRaises(ValueError):
                idc.sidesync_conn_response(KEY, idc.encode(KEY, text))
        text = idc.command_text("CONNECT", "SIDESYNC_CONN", "RESPONSE", info)
        with self.assertRaises(ValueError):
            idc.sidesync_conn_response(KEY, struct.pack(">H", len(text)) + text.encode())
        with self.assertRaises(ValueError):
            idc.sidesync_conn_response(bytes(32), valid)

    def test_response_length_uses_java_utf16_units(self):
        info = idc.connect_info(1234, name="test😀")
        text = "%d 1 CONNECT SIDESYNC_CONN RESPONSE %s" % (
            len(info.encode("utf-16-be")) // 2, info)
        self.assertTrue(idc.sidesync_conn_response(KEY, idc.encode(KEY, text))["accepted"])

    def test_decode_passes_through_plaintext(self):
        text = "10 1 CONNECT SIDESYNC_CONN RESPONSE x"
        data = struct.pack(">H", len(text)) + text.encode()
        self.assertEqual(idc.decode(KEY, data), text)


if __name__ == "__main__":
    unittest.main()
