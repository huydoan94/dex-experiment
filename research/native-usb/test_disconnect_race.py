"""Replay the exact approved phone transfer, including concurrent close."""
from collections import deque
import json
from pathlib import Path
import struct
import unittest

from loopback_transfer import transfer, TransferSession
from test_inbound_session import TransferPhone, opened
from usb_tunnel import Connection


class ReplayLink:
    def __init__(self):
        path = Path(__file__).with_name("fixtures")/"loopback-transfer-20261102.json"
        self.raw = deque(json.loads(path.read_text()))
        self.now = 0.0

    def clock(self):
        return self.now

    def begin_cleanup(self):
        pass

    def write(self, data, timeout_ms):
        item = self.raw.popleft()
        assert item["direction"] == "out", item
        assert bytes.fromhex(item["bytes_hex"]) == data, "outbound replay mismatch"
        return len(data)

    def read(self, size, timeout_ms):
        self.now += 0.001
        item = self.raw.popleft()
        assert item["direction"] == "in", item
        data = bytes.fromhex(item["bytes_hex"])
        assert len(data) <= size
        return data


class Tests(unittest.TestCase):
    def test_exact_live_transfer_replays_without_extra_io(self):
        link, result, logs = ReplayLink(), {}, []
        session = TransferSession(link, 1, 65536, 65536, clock=link.clock,
                                  log=lambda event, **fields: logs.append((event, fields)))
        transfer(session, result)
        self.assertTrue(result["bidirectional_verified"])
        self.assertFalse(link.raw)
        self.assertEqual(result["cleanup_errors"], [])
        self.assertEqual(result["disconnect_statuses"], {"65535": 0, "50002": 0})
        self.assertIn(("disconnect_peer_close_race", dict(host_port=50002, native_status=1)), logs)
        self.assertIn(("disconnect_reply", dict(host_port=50002, connection_key=1013,
                       status=1, closed_by_phone=True)), logs)

    def test_status1_without_matching_phone_close_remains_failure(self):
        phone = TransferPhone()
        session = opened(phone)
        outbound = session.connect(50002, config_id=602)
        original = phone._reply
        def reject(command, transaction, body):
            original(command, transaction, struct.pack("<I", 1) if command == 4 else body)
        phone._reply = reject
        # A different connection's close must not normalize this one.
        accepted = [c for c in session.connections.values() if c.inbound][0]
        accepted.closed_by_phone = True
        self.assertEqual(session.disconnect(outbound), 1)

    def test_other_native_error_is_not_normalized(self):
        phone = TransferPhone()
        session = opened(phone)
        outbound = session.connect(50002, config_id=602)
        original = phone._handle
        def reject(frame):
            if frame.kind == 1 and frame.command == 4:
                outbound.closed_by_phone = True
                phone._reply(4, frame.transaction, struct.pack("<I", 9))
                return
            original(frame)
        phone._handle = reject
        self.assertEqual(session.disconnect(outbound), 9)
