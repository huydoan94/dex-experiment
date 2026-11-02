"""Literal fixtures from native stores; no USB, sockets, ADB or suite imports."""
import unittest

import sidesync_packets as packets


class Tests(unittest.TestCase):
    def test_mouse_native_fixture(self):
        self.assertEqual(packets.mouse_event(1, 0x01020304, -2),
                         bytes.fromhex("03 14 00 0e 00 01 01 02 03 04 ff ff ff fe"))

    def test_mouse_signed_boundaries(self):
        self.assertEqual(packets.mouse_event(0, -(1 << 31), (1 << 31) - 1),
                         bytes.fromhex("03 14 00 0e 00 00 80 00 00 00 7f ff ff ff"))
        for args in ((-1, 0, 0), (256, 0, 0), (0, 1 << 31, 0),
                     (0, 0, -(1 << 31) - 1), (0, True, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                packets.mouse_event(*args)

    def test_keyboard_preserves_raw_bytes(self):
        self.assertEqual(packets.keyboard_event(1, 0x7f, bytes.fromhex("1e 00 ab cd")),
                         bytes.fromhex("03 15 00 0b 00 01 7f 1e 00 ab cd"))

    def test_keyboard_rejects_bad_arguments(self):
        for args in ((-1, 0, b"1234"), (0, 256, b"1234"), (0, 0, b"123"),
                     (0, 0, bytearray(b"1234"))):
            with self.subTest(args=args), self.assertRaises(ValueError):
                packets.keyboard_event(*args)

    def test_control_fixtures_exclude_allocation_terminator(self):
        self.assertEqual(packets.connect_confirmed(), bytes.fromhex("03 04 00 05 00"))
        self.assertEqual(packets.heartbeat_request(), bytes.fromhex("03 01 00 05 00"))
        self.assertEqual(packets.heartbeat_response(), bytes.fromhex("03 05 00 05 00"))

    def test_parse_security_body_is_opaque(self):
        packet = packets.parse(bytes.fromhex("03 5a 00 07 00 ab cd"))
        self.assertEqual(packet.kind, 0x5a)
        self.assertEqual(packet.body, bytes.fromhex("00 ab cd"))
        self.assertEqual(packets.encode(packet.kind, packet.body),
                         bytes.fromhex("03 5a 00 07 00 ab cd"))

    def test_parse_rejects_truncation_trailing_data_and_wrong_version(self):
        for wire in ("", "03 14 00", "03 04 00 03", "03 04 00 06 00",
                     "03 04 00 04 00", "02 04 00 05 00",
                     "03 04 00 05 00 03 04 00 05 00"):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                packets.parse(bytes.fromhex(wire))

    def test_maximum_length(self):
        body = b"x" * 65531
        frame = packets.encode(0x5b, body)
        self.assertEqual(frame[:4], bytes.fromhex("03 5b ff ff"))
        self.assertEqual(packets.parse(frame).body, body)
        with self.assertRaises(ValueError):
            packets.encode(0x5b, body + b"x")

    def test_empty_body_and_invalid_encode_arguments(self):
        self.assertEqual(packets.parse(bytes.fromhex("03 7f 00 04")),
                         packets.Packet(0x7f, b""))
        for kind, body in ((-1, b""), (256, b""), (True, b""), (1, "text")):
            with self.subTest(kind=kind, body=body), self.assertRaises(ValueError):
                packets.encode(kind, body)


if __name__ == "__main__":
    unittest.main()
