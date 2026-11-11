import hashlib
from pathlib import Path
import struct
import unittest
from conn_frames import Decoder, Frame, encode

SAVED = (Path(__file__).resolve().parent / "query-20261101T171251Z").is_dir()

ROOT = Path(__file__).resolve().parent


class FramingTests(unittest.TestCase):
    @unittest.skipUnless(SAVED, "saved capture is kept outside the repository")
    def test_saved_actual_phone_response_all_split_positions(self):
        raw = (ROOT / 'query-20261101T171251Z/response.bin').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'e36f580a5b9d3513545ffd15db80d7876c892d5af5614df052ebf47fdda6bc89')
        for split in range(len(raw) + 1):
            decoder = Decoder(4096)
            frames = decoder.feed(raw[:split]) + decoder.feed(raw[split:])
            decoder.finish()
            self.assertEqual(len(frames), 1)
            self.assertEqual((frames[0].command, frames[0].kind), (2, 2))
            self.assertEqual(struct.unpack_from('<I', frames[0].body)[0], 0)
            self.assertEqual(encode(frames[0]), raw)

    @unittest.skipUnless(SAVED, "saved capture is kept outside the repository")
    def test_saved_request_and_notification(self):
        for path in ('query-20261101T171251Z/request.bin',
                     'bootstrap-20261101T201318Z/notification.bin'):
            raw = (ROOT / path).read_bytes()
            decoder = Decoder(4096)
            frames = decoder.feed(raw)
            decoder.finish()
            self.assertEqual(len(frames), 1)
            self.assertEqual(encode(frames[0]), raw)
        self.assertEqual(frames[0].transaction, None)
        self.assertEqual(frames[0].body, b'dop pc app start' + bytes(240))

    def test_coalescing_and_single_byte_fragmentation(self):
        expected = [Frame(2, 1, 19, b''), Frame(12, 3, None, b'x'),
                    Frame(20, 2, 20, bytes(16))]
        raw = b''.join(map(encode, expected))
        for chunks in ([raw], [raw[i:i + 1] for i in range(len(raw))]):
            decoder = Decoder(100)
            actual = []
            for chunk in chunks:
                actual.extend(decoder.feed(chunk))
                self.assertLessEqual(decoder.pending_bytes, 100)
            decoder.finish()
            self.assertEqual(actual, expected)

    def test_empty_notification_and_large_coalesced_input(self):
        frame = Frame(12, 3, None, b'')
        decoder = Decoder(20)
        self.assertEqual(decoder.feed(encode(frame) * 1000), [frame] * 1000)
        decoder.finish()

    def test_untrusted_headers_fail_closed(self):
        for magic, size, kind in ((b'FAIL', 20, 1), (b'CONN', 20, 0),
                                  (b'CONN', 20, 4), (b'CONN', 19, 1),
                                  (b'CONN', 15, 3), (b'CONN', 101, 2),
                                  (b'CONN', 0xffffffff, 3)):
            decoder = Decoder(100)
            with self.assertRaises(ValueError):
                decoder.feed(struct.pack('<4sIII', magic, 2, size, kind) + bytes(200))
            self.assertEqual(decoder.pending_bytes, 0)
            with self.assertRaises(ValueError):
                decoder.feed(encode(Frame(2, 1, 1, b'')))

    def test_truncation_all_positions(self):
        raw = encode(Frame(20, 2, 1, bytes(16)))
        for end in range(1, len(raw)):
            decoder = Decoder(100)
            self.assertEqual(decoder.feed(raw[:end]), [])
            with self.assertRaises(ValueError):
                decoder.finish()

    def test_saved_padded_phone_frame_all_split_positions(self):
        # Real capture: a 128-byte Data frame (128 % 64 == 0) + one 0x5a pad.
        raw = bytes.fromhex(
            '434f4e4e0500000080000000010000000f000000060000007800000002000000'
            'ed030000c4aa0000983a000000000000380000004800000000000040000000'
            '054ee9197e1613c16341f9dfa0f6b2167cacf8ecb3fab6403470d52611fc82b3'
            '04aa676e55b573e224c5bf81f653a4af274e04de56fd02b829ce5069d242d0d3'
            '635a')
        self.assertEqual((len(raw), raw[-1]), (129, 0x5a))
        frame_bytes = raw[:128]
        for split in range(len(raw) + 1):
            decoder = Decoder(4096)
            frames = decoder.feed(raw[:split]) + decoder.feed(raw[split:])
            decoder.finish()
            self.assertEqual(len(frames), 1)
            self.assertEqual((frames[0].command, frames[0].kind, frames[0].transaction),
                             (5, 1, 15))
            self.assertEqual(encode(frames[0]), frame_bytes)

    def test_pad_stripped_only_after_boundary_multiple(self):
        f1 = encode(Frame(5, 2, 7, bytes(44)))   # 64 bytes, a boundary multiple
        self.assertEqual(len(f1), 64)
        f2 = encode(Frame(2, 1, 8, b''))
        stream = f1 + b'\x5a' + f2
        for chunks in ([stream], [stream[i:i + 1] for i in range(len(stream))]):
            decoder = Decoder(100)
            out = []
            for chunk in chunks:
                out.extend(decoder.feed(chunk))
            decoder.finish()
            self.assertEqual([(f.command, f.transaction) for f in out], [(5, 7), (2, 8)])

    def test_boundary_multiple_without_pad_is_tolerated(self):
        # No pad present: the next frame's 'C' header must not be eaten as a pad.
        f1 = encode(Frame(5, 2, 7, bytes(44)))
        f2 = encode(Frame(2, 1, 8, b''))
        decoder = Decoder(100)
        out = decoder.feed(f1 + f2)
        decoder.finish()
        self.assertEqual([(f.command, f.transaction) for f in out], [(5, 7), (2, 8)])

    def test_stray_pad_after_unaligned_frame_fails_closed(self):
        f1 = encode(Frame(2, 1, 1, b''))         # 20 bytes, not a boundary multiple
        decoder = Decoder(100)
        self.assertEqual(decoder.feed(f1), [Frame(2, 1, 1, b'')])
        with self.assertRaises(ValueError):
            decoder.feed(b'\x5a' + encode(Frame(2, 1, 2, b'')))

    def test_length_limit_and_encoder_contract(self):
        for cap in (-1, 19, 0x100000000):
            with self.assertRaises(ValueError):
                Decoder(cap)
        for frame in (Frame(2, 0, None, b''), Frame(2, 1, None, b''),
                      Frame(12, 3, 1, b'')):
            with self.assertRaises(ValueError):
                encode(frame)
        frame = Frame(2, 2, 0xffffffff, bytes(80))
        self.assertEqual(Decoder(100).feed(encode(frame)), [frame])


if __name__ == '__main__':
    unittest.main()
