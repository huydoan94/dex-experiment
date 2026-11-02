"""Pure CONN framing. No device, subprocess, or socket access.

Layouts: saved daemon framing and builders; only GetVersion is live-verified.
The caller chooses a memory cap, not a claimed protocol maximum.
"""
from dataclasses import dataclass
import struct

_PREFIX = struct.Struct('<4sIII')
_TRANSACTION = struct.Struct('<I')

# The daemon appends exactly one PAD_BYTE after any frame whose total length
# is a multiple of the IN endpoint's max packet (decompiled-usb-dispatch.c: the
# field at +0x2f4, defaulting to 0x40 = 64). A real frame always begins with
# b'CONN', so a PAD_BYTE where a header would start is never a valid frame.
PAD_BYTE = 0x5a
PAD_BOUNDARY = 64


@dataclass(frozen=True)
class Frame:
    command: int
    kind: int
    transaction: int | None
    body: bytes


def encode(frame):
    if frame.kind not in (1, 2, 3):
        raise ValueError('unsupported frame kind')
    if frame.kind == 3:
        if frame.transaction is not None:
            raise ValueError('notifications have no transaction')
        tail = frame.body
    else:
        if frame.transaction is None:
            raise ValueError('request/response requires transaction')
        tail = _TRANSACTION.pack(frame.transaction) + frame.body
    return _PREFIX.pack(b'CONN', frame.command, 16 + len(tail), frame.kind) + tail


class Decoder:
    """Incremental decoder; malformed input poisons the stream until discarded."""

    def __init__(self, max_frame_bytes):
        if not 20 <= max_frame_bytes <= 0xffffffff:
            raise ValueError('frame cap must be between20 and4294967295bytes')
        self.max_frame_bytes = max_frame_bytes
        self._buffer = bytearray()
        self._expected = None
        self._failed = False
        self._pad_pending = False

    @property
    def pending_bytes(self):
        return len(self._buffer)

    def feed(self, data):
        if self._failed:
            raise ValueError('decoder previously failed; discard the stream')
        view = memoryview(data)
        frames = []
        offset = 0
        try:
            while offset < len(view):
                if self._pad_pending:
                    # Drop one trailing pad byte; otherwise it is the next header.
                    self._pad_pending = False
                    if view[offset] == PAD_BYTE:
                        offset += 1
                        continue
                target = 16 if self._expected is None else self._expected
                count = min(target - len(self._buffer), len(view) - offset)
                self._buffer.extend(view[offset:offset + count])
                offset += count
                if self._expected is None and len(self._buffer) == 16:
                    magic, command, size, kind = _PREFIX.unpack(self._buffer)
                    if magic != b'CONN' or kind not in (1, 2, 3):
                        raise ValueError('invalid CONN header')
                    minimum = 16 if kind == 3 else 20
                    if not minimum <= size <= self.max_frame_bytes:
                        raise ValueError('invalid or oversized frame length')
                    self._expected = size
                if self._expected is not None and len(self._buffer) == self._expected:
                    magic, command, size, kind = _PREFIX.unpack_from(self._buffer)
                    transaction = None if kind == 3 else _TRANSACTION.unpack_from(self._buffer, 16)[0]
                    body_offset = 16 if kind == 3 else 20
                    frames.append(Frame(command, kind, transaction, bytes(self._buffer[body_offset:])))
                    self._buffer.clear()
                    self._expected = None
                    self._pad_pending = size % PAD_BOUNDARY == 0
        except Exception:
            self._failed = True
            self._buffer.clear()
            raise
        return frames

    def finish(self):
        if self._failed or self._buffer:
            self._failed = True
            raise ValueError('failed or truncated CONN stream')
