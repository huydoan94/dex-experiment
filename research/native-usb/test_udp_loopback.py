"""Offline tests of the UDP datagram codecs, Session routing and UDP loopback.

The fake daemon follows UDP_TRANSPORT_MAP.md (saved A54 reference). Not proof
of S20+ behaviour.
"""
import builtins
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import loopback_capture as base
import tcp_control as tcp
import udp_tunnel as ut
from test_loopback_capture import Util
from test_loopback_transfer import Device
from test_multi_config import MultiPhone
from test_usb_tunnel import UID
from udp_tunnel import UdpSession
from usb_tunnel import TunnelError


class UdpPhone(MultiPhone):
    def __init__(self):
        super().__init__(usb_buffer_bytes=4095)
        self.udp_cfgs = {}
        self.sockets = []
        self.next_ephemeral = 38000
        self.datagram_acks = []
        self.sent = []
        self.corrupt = False
        self.open_status = 0
        self.data_status = 0
        self.wrong_key_for = None   # config whose pushed datagram names a wrong socket

    def _socket(self, config_id, key):
        for s in self.sockets:
            if s["key"] == key and self.udp_cfgs[s["config_id"]] == (1, key):
                return s
        for s in self.sockets:
            if s["config_id"] == config_id and s["key"] == key:
                return s
        s = dict(config_id=config_id, key=key, bound=self.next_ephemeral)
        self.next_ephemeral += 1
        self.sockets.append(s)
        return s

    def _handle(self, frame):
        t, c, body = frame.transaction, frame.command, frame.body
        if frame.kind == 2 and c == 5:
            self.datagram_acks.append(struct.unpack_from("<I", body, 4)[0])
            return
        if frame.kind == 1 and c == 0x14 and struct.unpack_from("<I", body, 80)[0] == 17:
            cfg = struct.unpack_from("<I", body, 0)[0]
            operation, port = struct.unpack_from("<I", body, 72)[0], struct.unpack_from("<I", body, 84)[0]
            self.udp_cfgs[cfg] = (operation, port)
            if operation == 1:
                self.sockets.append(dict(config_id=cfg, key=port, bound=port))
            self._reply(0x14, t, struct.pack("<IIII", self.open_status, cfg,
                                             port if operation == 1 else 0, 0))
            return
        if frame.kind == 1 and c == 5 and struct.unpack_from("<I", body, 0)[0] == 17:
            _, cfg, _, peer, key, _, _, offset, length = struct.unpack_from("<9I", body)
            payload = bytes(body[offset - 20:offset - 20 + length])
            source = self._socket(cfg, key)
            self.sent.append((cfg, key, peer, payload))
            self._reply(5, t, struct.pack("<III", self.data_status, 20 + len(body), 0))
            target = next((s for s in self.sockets if s["bound"] == peer), None)
            if target is not None:
                tcfg = target["config_id"]
                operation, port = self.udp_cfgs[tcfg]
                data = b"X" * len(payload) if self.corrupt else payload
                key = target["key"] + (1 if tcfg == self.wrong_key_for else 0)
                out = struct.pack("<9I", 17, tcfg, 2, key, source["bound"], port,
                                  port if operation == 1 else 0, 56, len(data)) + data
                self.inbound += encode(Frame(5, 1, 80000 + len(self.sent), out))
            return
        super()._handle(frame)


def run(phone, result, util, output):
    with patch.object(base, "validate_config"), contextlib.redirect_stdout(io.StringIO()):
        base.probe(Device(phone), util, TimeoutError, output, result, clock=phone.clock,
                   session_class=UdpSession, exchange_fn=udp.transfer,
                   max_requests=udp.MAX_REQUESTS)


def opened(phone):
    session = UdpSession(phone, 1, 65536, 65536, clock=phone.clock, accept_inbound=True)
    session.get_version()
    session.exchange(0, tcp_send_buffer_bytes=0)
    session.open_udp(611, UID, 46003, operation=1)
    session.open_udp(612, UID, 0)
    return session


class CodecTests(unittest.TestCase):
    def test_udp_open_matches_tcp_layout_except_protocol(self):
        tcp_raw = encode(tcp.configuration_request(7, 611, UID, 46003, operation=1))
        udp_raw = encode(ut.configuration_request(7, 611, UID, 46003, 1))
        self.assertEqual(udp_raw[:100] + udp_raw[104:], tcp_raw[:100] + tcp_raw[104:])
        self.assertEqual(struct.unpack_from("<IIII", udp_raw, 92), (1, 2, 17, 46003))
        ephemeral = encode(ut.configuration_request(8, 612, UID, 0, 2))
        self.assertEqual(struct.unpack_from("<IIII", ephemeral, 92), (2, 2, 17, 0))

    def test_open_port_rules(self):
        for port, operation in ((0, 1), (46003, 2), (0, 3)):
            with self.subTest(port=port, operation=operation), self.assertRaises(ValueError):
                ut.configuration_request(7, 611, UID, port, operation)

    def test_datagram_request_layout(self):
        raw = encode(ut.datagram_request(9, 612, 50003, 46003, b"abc", 4095))
        self.assertEqual(struct.unpack_from("<9I", raw, 20),
                         (17, 612, 2, 46003, 50003, 0, 0, 56, 3))
        self.assertEqual(raw[56:], b"abc")
        with self.assertRaises(ValueError):
            ut.datagram_request(9, 612, 50003, 46003, b"", 4095)
        with self.assertRaises(ValueError):
            ut.datagram_request(9, 612, 50003, 46003, b"x" * 4040, 4095)

    def test_datagram_message_validation(self):
        def frame(protocol=17, cfg=611, offset=56, length=None, payload=b"hi"):
            length = len(payload) if length is None else length
            return Frame(5, 1, 3, struct.pack("<9I", protocol, cfg, 2, 46003, 38000,
                                              46003, 46003, offset, length) + payload)
        message = ut.datagram_message(frame(), {611})
        self.assertEqual((message.socket_port, message.source_port, message.payload),
                         (46003, 38000, b"hi"))
        for bad in (frame(protocol=6), frame(cfg=612), frame(offset=52),
                    frame(length=3), frame(payload=b"")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ut.datagram_message(bad, {611})


class SessionTests(unittest.TestCase):
    def test_datagrams_routed_and_acked_by_exact_size(self):
        phone = UdpPhone()
        session = opened(phone)
        session.send_datagram(612, 50003, 46003, b"one")
        session.wait(1, until=lambda: bool(session.datagrams))
        self.assertEqual(session.datagrams[0].payload, b"one")
        self.assertEqual(phone.datagram_acks, [20 + 36 + 3])

    def test_udp_config_rejects_tcp_connect_and_tcp_accept(self):
        phone = UdpPhone()
        session = opened(phone)
        with self.assertRaisesRegex(TunnelError, "UDP config"):
            session.connect(50002, config_id=611)
        with self.assertRaisesRegex(TunnelError, "TCP accept on a UDP config"):
            session._phone_request(Frame(3, 1, 30, struct.pack("<I16sI", 611, bytes(16), 2000)))

    def test_datagram_on_tcp_config_or_unknown_config_fails(self):
        phone = UdpPhone()
        session = opened(phone)
        session.open_config(613, UID, 46001)
        for config_id in (613, 999):
            with self.subTest(config_id=config_id), \
                    self.assertRaisesRegex(TunnelError, "unknown UDP config"):
                session.send_datagram(config_id, 50003, 46003, b"x")
        bad = Frame(5, 1, 31, struct.pack("<9I", 17, 999, 2, 1, 1, 0, 0, 56, 1) + b"x")
        with self.assertRaises(ValueError):
            session._phone_request(bad)

    def test_late_datagram_after_close_is_acked_and_dropped(self):
        phone = UdpPhone()
        session = opened(phone)
        session.begin_cleanup()
        self.assertEqual(session.close_config(UID, config_id=611), 0)
        late = Frame(5, 1, 32, struct.pack("<9I", 17, 611, 2, 46003, 38000,
                                           46003, 46003, 56, 2) + b"zz")
        session._phone_request(late)
        self.assertEqual(session.datagrams, [])
        self.assertEqual([d.payload for d in session.dropped_datagrams], [b"zz"])
        self.assertEqual(phone.datagram_acks, [20 + 36 + 2])

    def test_late_datagram_for_closed_config_outside_cleanup_is_kept_apart(self):
        phone = UdpPhone()
        session = opened(phone)
        session.close_config(UID, config_id=611)
        late = Frame(5, 1, 33, struct.pack("<9I", 17, 611, 2, 46003, 38000,
                                           46003, 46003, 56, 1) + b"q")
        session._phone_request(late)
        self.assertEqual((session.datagrams, len(session.dropped_datagrams)), ([], 1))
        self.assertEqual(phone.datagram_acks, [20 + 36 + 1])

    def test_nonzero_datagram_status_fails(self):
        phone = UdpPhone()
        session = opened(phone)
        phone.data_status = 1
        with self.assertRaisesRegex(TunnelError, "datagram status 1"):
            session.send_datagram(612, 50003, 46003, b"x")

    def test_receive_limit_enforced(self):
        phone = UdpPhone()
        session = UdpSession(phone, 1, 65536, 4, clock=phone.clock)
        session.get_version()
        session.exchange(0, tcp_send_buffer_bytes=0)
        session.open_udp(611, UID, 46003, operation=1)
        session.open_udp(612, UID, 0)
        session.send_datagram(612, 50003, 46003, b"12345")
        with self.assertRaisesRegex(TunnelError, "receive limit"):
            session.wait(1, until=lambda: False)

    def test_failed_open_is_rolled_back(self):
        phone = UdpPhone()
        session = UdpSession(phone, 1, 65536, 65536, clock=phone.clock)
        session.get_version()
        session.exchange(0, tcp_send_buffer_bytes=0)
        phone.open_status = 7
        with self.assertRaisesRegex(TunnelError, "open status 7"):
            session.open_udp(611, UID, 46003, operation=1)
        self.assertNotIn(611, session.configs)
        self.assertNotIn(611, session.udp_configs)

    def test_socket_key_guards_and_id_reuse(self):
        phone = UdpPhone()
        session = opened(phone)
        with self.assertRaisesRegex(TunnelError, "bound socket port"):
            session.send_datagram(611, 46004, 38000, b"x")
        with self.assertRaisesRegex(TunnelError, "another config socket"):
            session.send_datagram(612, 46003, 38000, b"x")
        with self.assertRaisesRegex(TunnelError, "already bound"):
            session.open_udp(614, UID, 46003, operation=1)
        session.close_config(UID, config_id=612)
        for open_again in (lambda: session.open_udp(612, UID, 0),
                           lambda: session.open_config(612, UID, 46001)):
            with self.assertRaisesRegex(TunnelError, "already used"):
                open_again()
        self.assertEqual(phone.sent, [])





if __name__ == "__main__":
    unittest.main()
