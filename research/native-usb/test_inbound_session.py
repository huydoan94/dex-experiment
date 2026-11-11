"""Offline tests of statically mapped inbound acknowledgment and Data routing."""
import struct
import unittest

from conn_frames import Decoder, Frame, encode
import tcp_control as tcp
import usb_tunnel
from usb_tunnel import Session, TunnelError
from test_multi_config import MultiPhone
from test_usb_tunnel import UID


class TransferPhone(MultiPhone):
    def __init__(self):
        super().__init__(usb_buffer_bytes=4095)
        self.accepted_key = None
        self.accepted_host = None
        self.outbound_host = None
        self.inbound_ack = None
        self.fail_ack = False

    def _handle(self, frame):
        if frame.kind == 2 and frame.command == 3:
            if self.fail_ack:
                raise TimeoutError("synthetic failed Connect ack")
            self.inbound_ack = frame
            status, error, cfg, address, host = struct.unpack("<III16sI", frame.body)
            if status == 1:
                assert host == 0
                return
            assert (status, error, cfg, address) == (0, 0, 601, b"127.0.0.1".ljust(16, b"\0"))
            self.accepted_host = host
            self.keys[(601, host)] = self.accepted_key
            return
        super()._handle(frame)
        if frame.kind != 1:
            return
        if frame.command == 3:
            self.outbound_host = struct.unpack_from("<I", frame.body, 20)[0]
            self.accepted_key = self.next_key
            self.next_key += 1
            # Accept before outbound reply, matching the order in the live read.
            body = struct.pack("<I16sI", 601, bytes(16), self.accepted_key)
            self.inbound[:0] = encode(Frame(3, 1, 24, body))
        elif frame.command == 5:
            cfg, host, data = self.host_data[-1]
            if cfg == 602:
                assert self.accepted_host is not None, "Data before inbound ACK"
                self.push_data(601, self.accepted_host, data)
            elif cfg == 601:
                self.push_data(602, self.outbound_host, data)


def opened(phone, enabled=True):
    session = Session(phone, 1, 65536, 65536, clock=phone.clock, accept_inbound=enabled)
    session.get_version()
    session.exchange(0, tcp_send_buffer_bytes=0)
    session.open_config(601, UID, 46001, operation=1)
    session.open_config(602, UID, 46001)
    return session


class Tests(unittest.TestCase):
    def test_ack_layout_and_bidirectional_routing(self):
        phone = TransferPhone()
        session = opened(phone)
        outbound = session.connect(50002, config_id=602)
        accepted = [c for c in session.connections.values() if c.inbound][0]
        self.assertEqual((accepted.host_port, accepted.key, accepted.config_id),
                         (65535, phone.accepted_key, 601))
        self.assertEqual(phone.inbound_ack.transaction, 24)
        self.assertEqual(len(encode(phone.inbound_ack)), 52)
        session.send(outbound, b"forward")
        session.wait(1, until=lambda: bool(accepted.received))
        self.assertEqual(bytes(accepted.received), b"forward")
        session.send(accepted, b"reverse")
        session.wait(1, until=lambda: bool(outbound.received))
        self.assertEqual(bytes(outbound.received), b"reverse")
        self.assertEqual(session.disconnect(accepted), 0)
        self.assertEqual(session.disconnect(outbound), 0)
        self.assertIn((601, accepted.key), phone.disconnect_ports)
        self.assertIn((602, outbound.key), phone.disconnect_ports)

    def test_ack_failure_keeps_accepted_key_for_cleanup(self):
        phone = TransferPhone()
        phone.fail_ack = True
        session = opened(phone)
        with self.assertRaises(TunnelError):
            session.connect(50002, config_id=602)
        accepted = [c for c in session.connections.values() if c.inbound][0]
        self.assertEqual(accepted.key, phone.accepted_key)
        self.assertEqual(session.inbound_count, 1)

    def test_default_strict_session_does_not_ack_inbound(self):
        phone = TransferPhone()
        session = opened(phone, enabled=False)
        with self.assertRaises(TunnelError):
            session.connect(50002, config_id=602)
        self.assertIsNone(phone.inbound_ack)
        self.assertFalse(any(c.inbound for c in session.connections.values()))

    def test_duplicate_key_wrong_config_and_cleanup_refusal(self):
        phone = TransferPhone()
        session = opened(phone)
        outbound = session.connect(50002, config_id=602)
        accepted = [c for c in session.connections.values() if c.inbound][0]
        for config, key in ((601, accepted.key), (601, outbound.key), (602, 2000)):
            with self.subTest(config=config, key=key), self.assertRaises((TunnelError, ValueError)):
                session._phone_request(Frame(3, 1, 25, struct.pack("<I16sI", config, bytes(16), key)))
        session.begin_cleanup()
        session._phone_request(Frame(3, 1, 26, struct.pack("<I16sI", 601, bytes(16), 2000)))
        self.assertEqual(session.inbound_count, 2)
        self.assertEqual(len([c for c in session.connections.values() if c.inbound]), 1)

    def test_phone_disconnect_uses_host_identifier(self):
        phone = TransferPhone()
        session = opened(phone)
        session.connect(50002, config_id=602)
        accepted = [c for c in session.connections.values() if c.inbound][0]
        frame = Frame(4, 1, 25, struct.pack("<I16sI", 601,
                      b"127.0.0.1".ljust(16, b"\0"), accepted.host_port))
        phone.inbound += encode(frame)
        session.wait(1, until=lambda: accepted.closed_by_phone)
        self.assertTrue(accepted.closed_by_phone)
        self.assertEqual(session.disconnect(accepted), 0)

    def test_host_identifier_avoids_active_and_retired_values(self):
        phone = TransferPhone()
        session = opened(phone)
        session.retired[65535] = 2000
        session.connect(65534, config_id=602)
        accepted = [c for c in session.connections.values() if c.inbound][0]
        self.assertEqual(accepted.host_port, 65533)

    def test_inbound_limit_and_identifier_exhaustion(self):
        phone = TransferPhone()
        session = opened(phone)
        for port in range(40000, 40000 + usb_tunnel.MAX_ACTIVE_INBOUND):
            session.connections[port] = usb_tunnel.Connection(5000 + port, port, config_id=601, inbound=True)
        frame = Frame(3, 1, 24, struct.pack("<I16sI", 601, bytes(16), 2000))
        with self.assertRaisesRegex(TunnelError, "count exceeded"):
            session._phone_request(frame)
        session.connections.clear()
        session.retired.update({port: None for port in range(60000, 65536)})
        with self.assertRaisesRegex(TunnelError, "identifiers exhausted"):
            session._phone_request(frame)
        self.assertFalse(session.connections)
        self.assertIsNone(phone.inbound_ack)

    def test_closed_inbound_connections_do_not_count(self):
        # The phone opens one short-lived connection per IDC event: a long session sees many.
        phone = TransferPhone()
        session = opened(phone)
        for key in range(3000, 3000 + 3 * usb_tunnel.MAX_ACTIVE_INBOUND):
            session._phone_request(Frame(3, 1, 24, struct.pack("<I16sI", 601, bytes(16), key)))
            accepted = next(c for c in session.connections.values() if c.key == key)
            accepted.closed_by_phone = True
        self.assertEqual(session.inbound_count, 3 * usb_tunnel.MAX_ACTIVE_INBOUND)
        self.assertEqual(session._active_inbound(), 0)

    def test_ack_rejects_invalid_identifiers(self):
        for args in ((0, 601, 60000), (24, 0, 60000), (24, 601, 0), (24, 601, 65536)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                tcp.inbound_connect_ack(*args)
