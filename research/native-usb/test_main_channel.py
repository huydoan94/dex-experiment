"""Offline vectors and malformed-input tests; never uses USB, ADB or sockets."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
import main_channel as m

V = json.loads(Path(__file__).with_name("main-channel-vectors.json").read_text())
MAC = V["mac"]
UID = V["uid"]


def b64(raw):
    return base64.b64encode(raw).decode()


def reply(seq, param, sid=987, **extra):
    return m.Frame(sid, json.dumps(
        {"TYPE": "AUTH", "MSG": seq, "PARAM": param, **extra}).encode())


class FramingTests(unittest.TestCase):
    def test_known_header_and_every_split(self):
        wire = b"\x00\x00\x00\x03\x00\x00\x00\x07abc"
        self.assertEqual(m.encode_frame(m.Frame(7, b"abc")), wire)
        for split in range(len(wire) + 1):
            d = m.FrameDecoder()
            self.assertEqual(d.feed(wire[:split]) + d.feed(wire[split:]), [m.Frame(7, b"abc")])
            d.finish()

    def test_coalesced_and_bytewise(self):
        wire = m.encode_frame(m.Frame(1, b"a")) + m.encode_frame(m.Frame(999, b"bc"))
        for chunks in ([wire], [bytes([b]) for b in wire]):
            d = m.FrameDecoder()
            frames = [f for chunk in chunks for f in d.feed(chunk)]
            self.assertEqual(frames, [m.Frame(1, b"a"), m.Frame(999, b"bc")])
            d.finish()

    def test_invalid_headers_fail_closed(self):
        for length, sid in [(0, 1), (4097, 1), (0xffffffff, 1), (1, 0), (1, 1000)]:
            with self.subTest(length=length, sid=sid):
                d = m.FrameDecoder(4096)
                with self.assertRaises(m.ProtocolError):
                    d.feed(struct.pack(">II", length, sid))
                with self.assertRaises(m.ProtocolError):
                    d.feed(b"x")
                self.assertEqual(len(d._buf), 0)

    def test_truncation_and_finish(self):
        for wire in (b"\0", struct.pack(">II", 3, 1), struct.pack(">II", 3, 1) + b"ab"):
            d = m.FrameDecoder()
            d.feed(wire)
            with self.assertRaises(m.ProtocolError):
                d.finish()
            with self.assertRaises(m.ProtocolError):
                d.feed(b"c")

    def test_feed_bound_and_limits(self):
        for limit in (0, m.MAX_PAYLOAD + 1, True):
            with self.assertRaises(ValueError):
                m.FrameDecoder(limit)
        d = m.FrameDecoder()
        with self.assertRaises(m.ProtocolError):
            d.feed(b"x" * (m.MAX_FEED + 1))
        d = m.FrameDecoder(4096)
        wire = m.encode_frame(m.Frame(1, b"a" * 4096))
        self.assertEqual(len(d.feed(wire)[0].payload), 4096)
        for frame in (m.Frame(True, b"a"), m.Frame(1000, b"a"), m.Frame(1, b"")):
            with self.assertRaises(m.ProtocolError):
                m.encode_frame(frame)

    def test_json_strictness(self):
        for payload in (
            b'{"TYPE":"AUTH","TYPE":"AUTH","MSG":"SEQ1"}',
            b'{"TYPE":"AUTH","MSG":"SEQ1","PARAM":{"x":1,"x":2}}',
            b'{"TYPE":"AUTH","MSG":"SEQ1","x":NaN}',
            b'{"TYPE":"AUTH","MSG":"SEQ1","x":Infinity}',
            b'{"TYPE":"AUTH","MSG":1}', b'[]', b'\xff',
            b'{"TYPE":"AUTH","MSG":"SEQ1"} trailing',
            b'[' * 2000 + b']' * 2000,
        ):
            with self.subTest(payload=payload[:50]), self.assertRaises(m.ProtocolError):
                m.decode_json(payload)
        obj = {"TYPE": "NOTI", "MSG": "example", "PARAM": {"unicode": "é"}}
        self.assertEqual(m.decode_json(m.encode_json(obj)), obj)


class AuthTests(unittest.TestCase):
    def client(self):
        # Scalar one is only a reproducible test key; production always uses RNG.
        with patch.object(m.ec, "generate_private_key",
                          return_value=ec.derive_private_key(1, ec.SECP521R1())):
            return m.AuthClient(MAC)

    def through_seq1(self, client):
        self.assertEqual(m.decode_json(client.start().payload)["PARAM"]["MAC"], MAC)
        return client.receive(reply("SEQ1", {"HPubKey": V["commitment"], "UID": UID}), 2)

    def seq2(self, **changes):
        return reply("SEQ2", {"PubKey": V["phone_public"], "HMAC": V["phone_hmac"], **changes})

    def test_complete_exchange_against_openssl_fixture(self):
        c = self.client()
        frame = self.through_seq1(c)
        self.assertEqual(m.decode_json(frame.payload)["PARAM"]["PubKey"], V["client_public"])
        with self.assertRaises(m.ProtocolError):
            c.codec()
        frame = c.receive(self.seq2(), 3)
        self.assertEqual(m.decode_json(frame.payload)["PARAM"]["HMAC"], V["client_hmac"])
        self.assertEqual(c.state, "WAIT_SEQ3")
        with self.assertRaises(m.ProtocolError):
            c.codec()
        self.assertIsNone(c.receive(reply("SEQ3", {"Verified": True})))
        self.assertEqual(c.state, "AUTHENTICATED")
        self.assertEqual(c.codec().encrypt(V["control"]), bytes.fromhex(V["ciphertext"]))
        self.assertIsNone(c._private)

    def test_key_derivation_and_passkey_vector(self):
        secret = bytes.fromhex(V["secret"])
        self.assertEqual(len(secret), 66)
        self.assertEqual(m._session_key(secret, MAC, UID).hex(), V["session_key"])
        self.assertEqual(m.passkey(secret, MAC, UID), V["passkey"])
        # This vector distinguishes first-six decimal digits from modulo 10**6.
        number = int(hashlib.sha256((b64(secret) + MAC + UID).encode()).hexdigest()[:6], 16)
        self.assertGreater(number, 999999)
        self.assertNotEqual(m.passkey(secret, MAC, UID), f"{number % 1000000:06d}")

    def test_commitment_rejection_precedes_seq3(self):
        c = self.client()
        c.start()
        c.receive(reply("SEQ1", {"HPubKey": b64(bytes(32)), "UID": UID}), 2)
        with self.assertRaises(m.ProtocolError):
            c.receive(self.seq2(), 3)
        self.assertEqual(c.state, "FAILED")
        self.assertIsNone(c._key)
        self.assertIsNone(c._private)

    def test_phone_hmac_rejection(self):
        c = self.client()
        self.through_seq1(c)
        with self.assertRaises(m.ProtocolError):
            c.receive(self.seq2(HMAC=b64(bytes(32))), 3)
        self.assertEqual(c.state, "FAILED")
        self.assertIsNone(c._key)

    def test_invalid_public_points(self):
        for raw in (b"\x04" + bytes(132), b"\x02" + bytes(132), bytes(133)):
            c = self.client()
            c.start()
            c.receive(reply("SEQ1", {"HPubKey": b64(hashlib.sha256(raw).digest()), "UID": UID}), 2)
            with self.assertRaises(m.ProtocolError):
                c.receive(self.seq2(PubKey=b64(raw)), 3)
            self.assertEqual(c.state, "FAILED")

    def test_invalid_verified_values(self):
        for verified in (False, 1, "true", None):
            c = self.client()
            self.through_seq1(c)
            c.receive(self.seq2(), 3)
            with self.assertRaises(m.ProtocolError):
                c.receive(reply("SEQ3", {"Verified": verified}))
            self.assertIsNone(c._key)

    def test_order_errors_are_terminal(self):
        for response in (
            reply("SEQ2", {}), reply("SEQ1", {}, REASON={"Code": 400}),
            reply("SEQ1", {}, RESULT=False), reply("SEQ1", []),
            m.Frame(1, b'{"TYPE":"RESP","MSG":"SEQ1","RESULT":false}'),
            reply("SEQ1", {"UID": UID, "HPubKey": V["commitment"]}, sid=0),
        ):
            c = self.client()
            c.start()
            with self.assertRaises(m.ProtocolError):
                c.receive(response, 2)
            self.assertEqual(c.state, "FAILED")
            with self.assertRaises(m.ProtocolError):
                c.start()

    def test_duplicate_start_invalid_next_sid(self):
        c = self.client()
        c.start()
        with self.assertRaises(m.ProtocolError):
            c.start()
        self.assertEqual(c.state, "FAILED")
        for sid in (None, 0, 1000, True):
            c = self.client()
            c.start()
            with self.assertRaises(m.ProtocolError):
                c.receive(reply("SEQ1", {"HPubKey": V["commitment"], "UID": UID}), sid)

    def test_canonical_base64(self):
        for value in (V["commitment"] + "\n", "!" * 44, b64(bytes(31)), 1):
            c = self.client()
            c.start()
            with self.assertRaises(m.ProtocolError):
                c.receive(reply("SEQ1", {"HPubKey": value, "UID": UID}), 2)

    def test_plain_auth_must_fit_limit(self):
        c = self.client()
        c.start()
        with self.assertRaises(m.ProtocolError):
            c.receive(m.Frame(1, b" " * 4097), 2)

    def test_no_secrets_in_repr_or_error(self):
        c = self.client()
        self.through_seq1(c)
        with self.assertRaises(m.ProtocolError) as caught:
            c.receive(self.seq2(HMAC="sensitive received garbage"), 3)
        self.assertNotIn("sensitive", str(caught.exception))
        self.assertNotIn("secret", repr(m.Frame(1, b"secret")))
        self.assertNotIn(V["secret"], repr(c))
        self.assertNotIn(V["session_key"], repr(c))

    def test_wrong_hmac_transcript_order(self):
        c = self.client()
        self.through_seq1(c)
        with self.assertRaises(m.ProtocolError):
            c.receive(self.seq2(HMAC=V["client_hmac"]), 3)


class CipherTests(unittest.TestCase):
    def test_openssl_ciphertext_and_decryption(self):
        codec = m.ControlCodec(bytes.fromhex(V["session_key"]))
        ciphertext = bytes.fromhex(V["ciphertext"])
        self.assertEqual(codec.encrypt(V["control"]), ciphertext)
        self.assertEqual(codec.decrypt(ciphertext), V["control"])

    def test_ciphertext_bounds_and_bad_padding(self):
        codec = m.ControlCodec(bytes.fromhex(V["session_key"]))
        for payload in (b"", b"x", b"x" * (m.MAX_PAYLOAD + 1),
                        bytes.fromhex(V["bad_padding_ciphertext"])):
            with self.assertRaises(m.ProtocolError):
                codec.decrypt(payload)

    def test_checkconnect_request_is_encrypted(self):
        codec = m.ControlCodec(bytes(32))
        obj = {"TYPE": "REQ", "MSG": "CheckConnect"}
        self.assertEqual(codec.decrypt(codec.encrypt(obj)), obj)

    def test_plaintext_messages_explicit_only(self):
        codec = m.ControlCodec(bytes(32))
        for obj in ({"TYPE": "AUTH", "MSG": "SEQ1"},
                    {"TYPE": "RESP", "MSG": "CheckConnect"}):
            with self.assertRaises(m.ProtocolError):
                codec.encrypt(obj)


if __name__ == "__main__":
    unittest.main()

