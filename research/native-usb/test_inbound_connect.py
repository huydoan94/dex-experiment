"""Offline replay of the captured S20+ frame, not a live phone test."""
import struct
import unittest
from conn_frames import Decoder, Frame
import tcp_control as tcp

# Exact frame from loopback-capture-20261102T114115+0000/result.json.
RAW = bytes.fromhex(
    "434f4e4e030000002c000000010000001800000059020000"
    "00000000000000000000000000000000f1030000")


class Tests(unittest.TestCase):
    def test_exact_live_capture_and_fragmented_stream(self):
        decoder = Decoder(65536)
        frames = []
        for byte in RAW:
            frames.extend(decoder.feed(bytes([byte])))
        self.assertEqual(len(frames), 1)
        message = tcp.inbound_connect_message(frames[0], {601})
        self.assertEqual((message.transaction, message.config_id, message.connection_key),
                         (24, 601, 1009))

    def test_wrong_identity_or_body_is_rejected(self):
        body = RAW[20:]
        for frame in (Frame(3, 2, 24, body), Frame(4, 1, 24, body),
                      Frame(3, 1, 0, body), Frame(3, 1, 24, body[:-1]),
                      Frame(3, 1, 24, body + b"x")):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                tcp.inbound_connect_message(frame, {601})

    def test_unknown_listener_metadata_and_invalid_key_are_rejected(self):
        for config, metadata, key in (
            (602, bytes(16), 1009),
            (601, b"127.0.0.1".ljust(16, b"\0"), 1009),
            (601, bytes(16), 0),
            (601, bytes(16), 65530),
            (601, bytes(16), 65536)):
            frame = Frame(3, 1, 24, struct.pack("<I16sI", config, metadata, key))
            with self.subTest(config=config, key=key), self.assertRaises(ValueError):
                tcp.inbound_connect_message(frame, {601})
