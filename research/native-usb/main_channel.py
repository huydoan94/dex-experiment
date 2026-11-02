"""Offline DeX TCP15000 framing and AUTH; contains no device/network operations.

Wire rules recovered from the saved S20+ DeXonPC APK and Crypto++ library.
This proves local protocol behavior only, not compatibility with a live phone.
"""
import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAX_PAYLOAD = 1_258_291
MAX_FEED = 65_536
AUTH_LIMIT = 4096
IV = bytes.fromhex("b468769781b3295b8276be53562c4fb7")


class ProtocolError(ValueError):
    """Generic failure; never includes a received payload or key material."""


@dataclass(frozen=True, repr=False)
class Frame:
    sid: int
    payload: bytes

    def __repr__(self):
        return f"Frame(sid={self.sid}, payload_bytes={len(self.payload)})"


def _sid(sid):
    if type(sid) is not int or not 1 <= sid <= 999:
        raise ProtocolError("SID outside 1..999")


def encode_frame(frame, max_payload=MAX_PAYLOAD):
    if type(max_payload) is not int or not 1 <= max_payload <= MAX_PAYLOAD:
        raise ValueError("invalid frame limit")
    _sid(frame.sid)
    if not isinstance(frame.payload, bytes) or not 0 < len(frame.payload) <= max_payload:
        raise ProtocolError("invalid frame payload length")
    return struct.pack(">II", len(frame.payload), frame.sid) + frame.payload


class FrameDecoder:
    """Incremental parser, one bounded partial frame; failed parsers cannot resume."""

    def __init__(self, max_payload=MAX_PAYLOAD):
        if type(max_payload) is not int or not 1 <= max_payload <= MAX_PAYLOAD:
            raise ValueError("invalid frame limit")
        self.limit = max_payload
        self._buf = bytearray()
        self._need = 8
        self._sid = None
        self._failed = False

    def feed(self, chunk):
        if self._failed:
            raise ProtocolError("decoder is closed")
        try:
            if not isinstance(chunk, bytes) or len(chunk) > MAX_FEED:
                raise ProtocolError("invalid feed size or type")
            frames = []
            offset = 0
            while offset < len(chunk):
                count = min(self._need - len(self._buf), len(chunk) - offset)
                self._buf.extend(chunk[offset:offset + count])
                offset += count
                if len(self._buf) != self._need:
                    continue
                if self._sid is None:
                    length, sid = struct.unpack(">II", self._buf)
                    _sid(sid)
                    if not 0 < length <= self.limit:
                        raise ProtocolError("invalid frame payload length")
                    self._sid = sid
                    self._need = length
                    self._buf.clear()
                else:
                    frames.append(Frame(self._sid, bytes(self._buf)))
                    self._sid = None
                    self._need = 8
                    self._buf.clear()
            return frames
        except ProtocolError:
            self._failed = True
            self._buf.clear()
            raise

    def finish(self):
        if self._failed:
            raise ProtocolError("decoder is closed")
        self._failed = True
        if self._buf or self._sid is not None:
            self._buf.clear()
            raise ProtocolError("truncated frame")


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ProtocolError("duplicate JSON field")
        obj[key] = value
    return obj


def _reject_constant(value):
    raise ProtocolError("nonfinite JSON value")


def decode_json(payload, limit=MAX_PAYLOAD):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= limit:
        raise ProtocolError("invalid JSON length")
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("invalid JSON") from None
    if (not isinstance(obj, dict) or obj.get("TYPE") not in ("AUTH", "REQ", "RESP", "NOTI")
            or not isinstance(obj.get("MSG"), str) or not 0 < len(obj["MSG"]) <= 128):
        raise ProtocolError("invalid message envelope")
    return obj


def encode_json(obj, limit=MAX_PAYLOAD):
    try:
        payload = json.dumps(obj, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ProtocolError("invalid JSON") from None
    decode_json(payload, limit)
    return payload


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(value, size):
    if not isinstance(value, str) or len(value) != 4 * ((size + 2) // 3):
        raise ProtocolError("invalid base64 field")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("invalid base64 field") from None
    if len(data) != size or _b64(data) != value:
        raise ProtocolError("invalid base64 encoding")
    return data


def _session_key(secret, mac, uid):
    return hashlib.sha256((secret.hex().upper() + mac + uid).encode("utf-8")).digest()


def passkey(secret, mac, uid):
    """Display value; explicitly requested by caller, never logged internally."""
    value = int(hashlib.sha256((_b64(secret) + mac + uid).encode()).hexdigest()[:6], 16)
    return f"{value:06d}"[:6]


class ControlCodec:
    """Authenticated-session AES-CBC codec. Legacy wire format has no message MAC."""

    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("AES key must be 32 bytes")
        self._key = key

    def encrypt(self, obj):
        if not isinstance(obj, dict):
            raise ProtocolError("invalid message envelope")
        if (obj.get("TYPE") == "AUTH" or
                (obj.get("TYPE") == "RESP" and obj.get("MSG") == "CheckConnect")):
            raise ProtocolError("message requires explicit plaintext handling")
        plain = encode_json(obj, MAX_PAYLOAD - 16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        enc = Cipher(algorithms.AES(self._key), modes.CBC(IV)).encryptor()
        return enc.update(padded) + enc.finalize()

    def decrypt(self, payload):
        if (not isinstance(payload, bytes) or not payload
                or len(payload) > MAX_PAYLOAD or len(payload) % 16):
            raise ProtocolError("invalid ciphertext length")
        try:
            dec = Cipher(algorithms.AES(self._key), modes.CBC(IV)).decryptor()
            padded = dec.update(payload) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise ProtocolError("invalid encrypted message") from None
        return decode_json(plain)


class AuthClient:
    """One AUTH attempt; unexpected/malformed replies fail closed.

    Caller owns transport, deadline, cleanup, SID allocation and authorization.
    Phone reply SIDs are independent counters, not echoed request identifiers.
    No retry, TerminalInfo, capability write or keepalive is performed here.
    """

    def __init__(self, mac):
        if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
            raise ValueError("MAC must have six colon-separated hex octets")
        self._mac = mac
        self._private = ec.generate_private_key(ec.SECP521R1())
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self._public = _b64(raw)
        self._key = None
        self._commitment = None
        self._uid = None
        self.state = "NEW"

    def _outgoing(self, seq, params, sid):
        return Frame(sid, encode_json({"TYPE": "AUTH", "MSG": seq, "PARAM": params}, AUTH_LIMIT))

    def start(self, sid=1):
        try:
            _sid(sid)
            if self.state != "NEW":
                raise ProtocolError("AUTH attempt already started")
            frame = self._outgoing("SEQ1", {"MAC": self._mac}, sid)
            self.state = "WAIT_SEQ1"
            return frame
        except ProtocolError:
            self._fail()
            raise

    def _fail(self):
        self.state = "FAILED"
        self._private = self._key = self._commitment = self._uid = None

    def receive(self, frame, next_sid=None):
        """Returns SEQ2/SEQ3 frame, then None only after Verified=true."""
        try:
            _sid(frame.sid)
            if self.state not in ("WAIT_SEQ1", "WAIT_SEQ2", "WAIT_SEQ3"):
                raise ProtocolError("no AUTH reply expected")
            seq = self.state.removeprefix("WAIT_")
            obj = decode_json(frame.payload, AUTH_LIMIT)
            if (obj["TYPE"] != "AUTH" or obj["MSG"] != seq
                    or obj.get("REASON") is not None
                    or obj.get("RESULT") is False or not isinstance(obj.get("PARAM"), dict)):
                raise ProtocolError("unexpected AUTH reply")
            param = obj["PARAM"]
            if seq == "SEQ1":
                _sid(next_sid)
                self._commitment = _unb64(param.get("HPubKey"), 32)
                self._uid = param.get("UID")
                _unb64(self._uid, 20)
                self.state = "WAIT_SEQ2"
                return self._outgoing("SEQ2", {"PubKey": self._public}, next_sid)
            if seq == "SEQ2":
                _sid(next_sid)
                raw = _unb64(param.get("PubKey"), 133)
                if raw[0] != 4 or not hmac.compare_digest(hashlib.sha256(raw).digest(), self._commitment):
                    raise ProtocolError("phone key commitment failed")
                try:
                    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), raw)
                    secret = self._private.exchange(ec.ECDH(), peer)
                except ValueError:
                    raise ProtocolError("invalid phone public key") from None
                if len(secret) != 66:
                    raise ProtocolError("unexpected ECDH size")
                phone_b64 = param["PubKey"]
                message = (self._public + phone_b64 + self._mac + self._uid).encode()
                expected = hmac.digest(secret, message, "sha256")
                if not hmac.compare_digest(expected, _unb64(param.get("HMAC"), 32)):
                    raise ProtocolError("phone HMAC failed")
                message = (phone_b64 + self._public + self._uid + self._mac).encode()
                client_mac = _b64(hmac.digest(secret, message, "sha256"))
                self._key = _session_key(secret, self._mac, self._uid)
                self._private = None
                self.state = "WAIT_SEQ3"
                return self._outgoing("SEQ3", {"HMAC": client_mac}, next_sid)
            if param.get("Verified") is not True:
                raise ProtocolError("phone did not verify client")
            self.state = "AUTHENTICATED"
            self._uid = self._commitment = None
            return None
        except (ProtocolError, AttributeError):
            self._fail()
            raise ProtocolError("AUTH exchange failed") from None

    def codec(self):
        if self.state != "AUTHENTICATED" or self._key is None:
            raise ProtocolError("AUTH is incomplete")
        return ControlCodec(self._key)

