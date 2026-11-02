"""Offline SideSync event framing recovered from libSideSyncNative.so.

No transport, security handshake, encryption, viewer mapping or phone I/O.
Native source addresses and limits are recorded in SIDESYNC_INPUT_RESEARCH.md.
"""
from dataclasses import dataclass
import struct

EVENT_PORT = 30830
VERSION = 3
MAX_PACKET_BYTES = 65535


@dataclass(frozen=True)
class Packet:
    kind: int
    body: bytes


def encode(kind: int, body: bytes) -> bytes:
    """Frame an opaque body; security envelopes remain opaque."""
    if type(kind) is not int or not 0 <= kind <= 255:
        raise ValueError("packet kind must be a byte")
    if not isinstance(body, bytes):
        raise ValueError("body must be bytes")
    size = len(body) + 4
    if size > MAX_PACKET_BYTES:
        raise ValueError("packet exceeds 16-bit total length")
    return struct.pack(">BBH", VERSION, kind, size) + body


def parse(data: bytes) -> Packet:
    """Parse exactly one complete frame, without interpreting its body."""
    if not isinstance(data, bytes) or not 4 <= len(data) <= MAX_PACKET_BYTES:
        raise ValueError("invalid packet size")
    version, kind, size = struct.unpack_from(">BBH", data)
    if version != VERSION or size != len(data):
        raise ValueError("unsupported version or mismatched total length")
    return Packet(kind, data[4:])


def mouse_event(event: int, x: int, y: int) -> bytes:
    """Preserve native signed 32-bit coordinate arguments, in network order."""
    if type(event) is not int or not 0 <= event <= 255:
        raise ValueError("mouse event must be a byte")
    if any(type(v) is not int or not -(1 << 31) <= v < (1 << 31) for v in (x, y)):
        raise ValueError("mouse coordinates must be signed 32-bit integers")
    return encode(0x14, struct.pack(">BBii", 0, event, x, y))


def keyboard_event(event: int, auxiliary: int, scan_code_bytes: bytes) -> bytes:
    """Keep the native four-byte scan code and unresolved second argument raw."""
    if any(type(v) is not int or not 0 <= v <= 255 for v in (event, auxiliary)):
        raise ValueError("keyboard arguments must be bytes")
    if not isinstance(scan_code_bytes, bytes) or len(scan_code_bytes) != 4:
        raise ValueError("scan code must be exactly four bytes")
    return encode(0x15, bytes((0, event, auxiliary)) + scan_code_bytes)


def connect_confirmed() -> bytes:
    return encode(4, b"\x00")


def heartbeat_request() -> bytes:
    return encode(1, b"\x00")


def heartbeat_response() -> bytes:
    return encode(5, b"\x00")
