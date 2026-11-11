"""Fake-phone tests for usb_tunnel.Session.

The fake builds replies from the A54 reference reply shapes with independent
struct literals (not the tcp_control reply builders the Session parses with),
so a codec bug cannot hide here. It is a stand-in for the daemon, not proof of
S20+ behaviour. One real captured GetVersion exchange is replayed byte for byte.
"""
from pathlib import Path
import struct
import unittest

from conn_frames import Decoder, Frame, encode
from usb_tunnel import Session, TunnelError

SAVED_CAPTURES = (Path(__file__).resolve().parent / "query-20261101T171251Z").is_dir() and (Path(__file__).resolve().parent / "bootstrap-20261101T201318Z").is_dir()

UID = b'host-service' + bytes(52)
SAVED = Path(__file__).with_name('query-20261101T171251Z')
TICK_S = 0.05


def _version(status=0, major=2, minor=0, text=b'2.17.21.0'):
    return struct.pack('<III', status, major, minor) + text.ljust(64, b'\0')


def _exchange(usb_buffer_bytes, os_type=2, status=0):
    fields = [0] * 13
    fields[1] = usb_buffer_bytes
    return struct.pack('<IH13I', status, os_type, *fields)


def _open(config_id, status=0, port=0, client_port=0):
    return struct.pack('<IIII', status, config_id, port, client_port)


def _connect(config_id, key, status=0, net_error=0, address=b'127.0.0.1'):
    return struct.pack('<III16sI', status, net_error, config_id, address.ljust(16, b'\0'), key)


def _status(value=0):
    return struct.pack('<I', value)


def _data_reply(size, status=0, error=0):
    return struct.pack('<III', status, size, error)


class FakePhone:
    def __init__(self, usb_buffer_bytes=4096, key=1000):
        self.now = 0.0
        self.decoder = Decoder(1 << 20)
        self.inbound = bytearray()
        self.usb_buffer_bytes = usb_buffer_bytes
        self.key = key
        self.config_id = None
        self.host_data = []
        self.acked_sizes = []
        self.disconnect_acked = []
        self.disconnect_ports = []
        self.fail_next_write = False
        self.version_body = _version()
        self.wrong_transaction = False
        self.host_ports = set()
        self.silent = set()         # commands the fake never answers
        # command -> callable run once just before / after queueing that reply,
        # so phone requests can share a read with the reply.
        self.before_reply = {}
        self.after_reply = {}
        self.write_delay_s = 0.0
        self.read_timeouts_ms = []

    def clock(self):
        return self.now

    def write(self, data, timeout_ms):
        self.now += self.write_delay_s
        if self.fail_next_write:
            self.fail_next_write = False
            return len(data) - 1
        for frame in self.decoder.feed(data):
            self._handle(frame)
        return len(data)

    def read(self, size, timeout_ms):
        self.read_timeouts_ms.append(timeout_ms)
        self.now += TICK_S
        chunk = bytes(self.inbound[:size])
        del self.inbound[:size]
        return chunk

    def push_data(self, transaction, host_port, payload, config_id=None):
        body = struct.pack('<9I', 6, self.config_id if config_id is None else config_id,
                           2, self.key, host_port, 15000, 0, 56, len(payload)) + payload
        self.inbound += encode(Frame(5, 1, transaction, body))

    def push_disconnect(self, transaction, host_port, address=b'127.0.0.1'):
        body = struct.pack('<I16sI', self.config_id, address.ljust(16, b'\0'), host_port)
        self.inbound += encode(Frame(4, 1, transaction, body))

    def push_raw(self, frame):
        self.inbound += encode(frame)

    def _reply(self, command, transaction, body):
        hook = self.before_reply.pop(command, None)
        if hook:
            hook()
        self.inbound += encode(Frame(command, 2, transaction, body))
        hook = self.after_reply.pop(command, None)
        if hook:
            hook()

    def _handle(self, frame):
        t = frame.transaction
        if frame.kind == 2:
            if frame.command == 5:
                self.acked_sizes.append(struct.unpack_from('<I', frame.body, 4)[0])
            elif frame.command == 4:
                self.disconnect_acked.append(t)
            return
        c = frame.command
        if c in self.silent:
            return
        if c == 2:
            self._reply(2, t + 1 if self.wrong_transaction else t, self.version_body)
        elif c == 0x16:
            self._reply(0x16, t, _exchange(self.usb_buffer_bytes))
        elif c == 0x14:
            self.config_id = struct.unpack_from('<I', frame.body, 0)[0]
            self._reply(0x14, t, _open(self.config_id))
        elif c == 3:
            cfg, host_port = struct.unpack_from('<I16xI', frame.body, 0)
            self.host_ports.add(host_port)
            self._reply(3, t, _connect(cfg, self.key))
        elif c == 5:
            self._check_host_data(frame)
            self.host_data.append(bytes(frame.body[36:]))
            self._reply(5, t, _data_reply(20 + len(frame.body)))
        elif c == 4:
            # Like ref 0003fc78: the port field must be the connection key.
            self.disconnect_ports.append(struct.unpack_from('<I', frame.body, 20)[0])
            self._reply(4, t, _status(0 if self.disconnect_ports[-1] == self.key else 1))
        elif c == 0x15:
            self._reply(0x15, t, _status(0))
        else:
            raise AssertionError('fake phone got unexpected command %d' % c)

    def _check_host_data(self, frame):
        # The real daemon copies the frame into a UsbBufferSize buffer unchecked
        # and trusts offset/length, so these are hard failures, not replies.
        (protocol, cfg, _, sender, receiver, port, _, offset,
         length) = struct.unpack_from('<9I', frame.body, 0)
        total = 20 + len(frame.body)
        if total > self.usb_buffer_bytes:
            raise AssertionError('host data frame %d > buffer %d' % (total, self.usb_buffer_bytes))
        if (protocol, cfg, offset, length) != (6, self.config_id, 56, len(frame.body) - 36):
            raise AssertionError('host data header inconsistent')
        if sender not in self.host_ports or receiver != self.key or port != 15000:
            raise AssertionError('host data ports wrong: %d -> %d' % (sender, receiver))


class CannedLink:
    def __init__(self, inbound):
        self.now = 0.0
        self.written = bytearray()
        self.inbound = bytearray(inbound)

    def clock(self):
        return self.now

    def write(self, data, timeout_ms):
        self.written += data
        return len(data)

    def read(self, size, timeout_ms):
        self.now += TICK_S
        chunk = bytes(self.inbound[:size])
        del self.inbound[:size]
        return chunk


class SessionTests(unittest.TestCase):
    def session(self, link, first_transaction=1, max_frame_bytes=1 << 16,
                max_receive_bytes=1 << 20):
        return Session(link, first_transaction, max_frame_bytes, max_receive_bytes,
                       clock=link.clock)

    def opened(self, phone, host_port=40000):
        s = self.session(phone)
        s.get_version()
        s.exchange(2, tcp_send_buffer_bytes=1 << 20)
        s.open_config(0x1234, UID, 15000)
        return s

    def test_happy_path(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        self.assertEqual(s.usb_buffer_bytes, 512)
        conn = s.connect(40000)
        self.assertEqual(conn.key, 1000)
        s.send(conn, b'x' * 1000)
        self.assertEqual(len(phone.host_data), 3)
        self.assertEqual(b''.join(phone.host_data), b'x' * 1000)
        phone.push_data(5, conn.host_port, b'reply-bytes')
        self.assertTrue(s.wait(1, until=lambda: conn.received == b'reply-bytes'))
        self.assertEqual(phone.acked_sizes[-1], 20 + 36 + len(b'reply-bytes'))
        self.assertEqual(s.disconnect(conn), 0)
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertEqual(s.close_config(UID), 0)
        self.assertIsNone(s.config_id)

    def test_version_before_exchange_required_for_open(self):
        phone = FakePhone()
        s = self.session(phone)
        with self.assertRaises(TunnelError):
            s.open_config(0x1234, UID, 15000)

    def test_bad_version_rejected(self):
        phone = FakePhone()
        phone.version_body = _version(major=3)
        s = self.session(phone)
        with self.assertRaises(TunnelError):
            s.get_version()

    def test_exchange_buffer_outside_host_limit(self):
        phone = FakePhone(usb_buffer_bytes=1 << 20)
        s = self.session(phone, max_frame_bytes=4096)
        s.get_version()
        with self.assertRaises(TunnelError):
            s.exchange(2, tcp_send_buffer_bytes=1 << 20)

    def test_partial_write_raises(self):
        phone = FakePhone()
        phone.fail_next_write = True
        s = self.session(phone)
        with self.assertRaises(TunnelError):
            s.get_version()

    def test_unsolicited_response_while_idle(self):
        phone = FakePhone()
        s = self.session(phone)
        phone.push_raw(Frame(2, 2, 99, _version()))
        with self.assertRaises(TunnelError):
            s.wait(1)

    def test_duplicate_host_port_refused(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        s.connect(40000)
        with self.assertRaises(TunnelError):
            s.connect(40000)

    def test_phone_data_unknown_connection(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        phone.push_data(5, 40000, b'data')
        with self.assertRaises(TunnelError):
            s.wait(1)

    def test_phone_data_wrong_key(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        phone.key = conn.key + 1
        phone.push_data(5, conn.host_port, b'data')
        with self.assertRaises(TunnelError):
            s.wait(1)

    def test_receive_limit_exceeded(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.session(phone, max_receive_bytes=5)
        s.get_version()
        s.exchange(2, tcp_send_buffer_bytes=1 << 20)
        s.open_config(0x1234, UID, 15000)
        conn = s.connect(40000)
        phone.push_data(5, conn.host_port, b'toolong')
        with self.assertRaises(TunnelError):
            s.wait(1)

    def test_phone_initiated_disconnect_then_send_refused(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        phone.push_disconnect(7, conn.host_port)
        self.assertTrue(s.wait(1, until=lambda: conn.closed_by_phone))
        self.assertEqual(phone.disconnect_acked, [7])
        with self.assertRaises(TunnelError):
            s.send(conn, b'late')
        self.assertEqual(s.disconnect(conn), 0)

    def test_idle_wait_times_out_without_data(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        self.assertFalse(s.wait(0.5, until=lambda: conn.received == b'never'))

    def test_mismatched_response_transaction_rejected(self):
        phone = FakePhone()
        phone.wrong_transaction = True
        s = self.session(phone)
        with self.assertRaises(TunnelError):
            s.get_version()

    # Review finding 1: phone requests sharing a read with the awaited reply.
    def test_banner_in_same_read_as_connect_reply(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        phone.after_reply[3] = lambda: phone.push_data(900, 40000, b'SSH-2.0-x\r\n')
        conn = s.connect(40000)
        self.assertTrue(s.wait(1, until=lambda: conn.received == b'SSH-2.0-x\r\n'))
        self.assertEqual(phone.acked_sizes, [20 + 36 + 11])

    def test_instant_phone_disconnect_in_same_read_as_connect_reply(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        phone.after_reply[3] = lambda: phone.push_disconnect(901, 40000)
        conn = s.connect(40000)
        self.assertTrue(s.wait(1, until=lambda: conn.closed_by_phone))
        self.assertEqual(phone.disconnect_acked, [901])

    def test_duplicate_response_is_not_swallowed(self):
        phone = FakePhone()
        s = self.session(phone)
        phone.after_reply[2] = lambda: phone.push_raw(Frame(2, 2, 1, _version()))
        s.get_version()
        with self.assertRaises(TunnelError):
            s.wait(1)

    def test_phone_data_during_send_is_acked(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        phone.before_reply[5] = lambda: phone.push_data(902, 40000, b'mid')
        s.send(conn, b'abc')
        self.assertEqual((bytes(conn.received), phone.host_data), (b'mid', [b'abc']))
        self.assertEqual(phone.acked_sizes, [20 + 36 + 3])

    # Review finding 2: every failure surfaces as TunnelError.
    def test_failures_surface_as_tunnel_error(self):
        cases = []
        phone = FakePhone(); s = self.session(phone)
        phone.push_raw(Frame(2, 2, 1, _version())); phone.inbound[0:4] = b'XXXX'
        cases.append(lambda: s.wait(1))                               # bad magic
        phone2 = FakePhone(); s2 = self.session(phone2); phone2.silent.add(2)
        cases.append(s2.get_version)                                  # no reply
        phone3 = FakePhone(); s3 = self.session(phone3)
        cases.append(lambda: s3.send(None, b'x'))                     # before exchange
        cases.append(lambda: s3.close_config(UID))                    # nothing open
        for case in cases:
            with self.assertRaises(TunnelError):
                case()

    def test_malformed_phone_data_surfaces_as_tunnel_error(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        body = struct.pack('<9I', 6, 0x1234, 2, 1000, 40000, 15000, 0, 56, 99) + b'short'
        phone.push_raw(Frame(5, 1, 903, body))
        with self.assertRaises(TunnelError):
            s.wait(1)
        self.assertEqual((bytes(conn.received), phone.acked_sizes), (b'', []))

    def test_second_disconnect_and_send_after_disconnect_refused(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        self.assertEqual(s.disconnect(conn), 0)
        for case in (lambda: s.disconnect(conn), lambda: s.send(conn, b'x'),
                     lambda: s.connect(40000)):
            with self.assertRaises(TunnelError):
                case()

    def test_phone_disconnect_from_non_loopback_refused(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        s.connect(40000)
        phone.push_disconnect(904, 40000, address=b'10.0.0.1')
        with self.assertRaises(TunnelError):
            s.wait(1)
        self.assertEqual(phone.disconnect_acked, [])

    # Review finding 3: data in flight while the host closes a connection.
    def test_data_in_flight_during_host_disconnect_is_acked_and_dropped(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        phone.before_reply[4] = lambda: phone.push_data(905, 40000, b'late1')
        self.assertEqual(s.disconnect(conn), 0)
        phone.push_data(906, 40000, b'late2')
        self.assertFalse(s.wait(0.3))
        self.assertEqual(phone.acked_sizes, [20 + 36 + 5, 20 + 36 + 5])
        self.assertEqual((bytes(conn.received), s.received_bytes), (b'', 0))

    # Review finding 4: deadlines hold while answering a flood with slow writes.
    def test_deadline_bounded_under_flood_and_slow_writes(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        s.connect(40000)
        for i in range(50):
            phone.push_data(1000 + i, 40000, b'x')
        phone.write_delay_s = 0.9
        start = phone.now
        self.assertFalse(s.wait(0.1))
        # At most one read tick plus one ack write past the deadline.
        self.assertLessEqual(phone.now - start, 0.1 + TICK_S + 0.9 + 1e-9)
        self.assertLess(len(phone.acked_sizes), 50)

    def test_request_deadline_is_respected(self):
        phone = FakePhone()
        phone.silent.add(2)
        s = self.session(phone)
        with self.assertRaises(TunnelError):
            s.get_version(timeout_s=0.5)
        self.assertLessEqual(phone.now, 0.5 + TICK_S + 1e-9)
        # A real blocking read must never outlast the remaining time.
        self.assertTrue(all(0 < t <= 500 for t in phone.read_timeouts_ms))
        long = FakePhone()
        long.silent.add(2)
        with self.assertRaises(TunnelError):
            self.session(long).get_version(timeout_s=3)
        self.assertLessEqual(max(long.read_timeouts_ms), 1000)

    # Review finding 5: the captured app-start notification ends a session.
    @unittest.skipUnless(SAVED_CAPTURES, "saved capture is kept outside the repository")
    def test_saved_notification_mid_session_stops(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        phone.inbound += (Path(__file__).with_name('bootstrap-20261101T201318Z')
                          / 'notification.bin').read_bytes()
        with self.assertRaises(TunnelError):
            s.wait(1)

    # Review finding 6: order misuse is refused.
    def test_exchange_after_open_and_open_twice_refused(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        for case in (lambda: s.exchange(2, tcp_send_buffer_bytes=1 << 20),
                     lambda: s.open_config(0x1234, UID, 15000)):
            with self.assertRaises(TunnelError):
                case()

    def test_send_accepts_bytearray_and_close_retires_connections(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        conn = s.connect(40000)
        s.send(conn, bytearray(b'ba'))
        self.assertEqual(s.close_config(UID), 0)
        self.assertEqual((s.connections, s.retired), ({}, {40000: 1000}))
        with self.assertRaises(TunnelError):
            s.send(conn, b'x')

    def test_connect_key_above_reference_range_refused(self):
        phone = FakePhone(usb_buffer_bytes=512, key=0xfffa)
        s = self.opened(phone)
        with self.assertRaises(TunnelError):
            s.connect(40000)
        # The phone may hold the connection: it stays recorded for teardown.
        conn = s.connections[40000]
        self.assertIsNone(conn.key)
        with self.assertRaises(TunnelError):
            s.disconnect(conn)
        self.assertEqual(phone.disconnect_ports, [])
        self.assertEqual((s.connections, s.retired), ({}, {40000: None}))

    def test_lost_open_reply_keeps_config_for_close(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.session(phone)
        s.get_version()
        s.exchange(2, tcp_send_buffer_bytes=1 << 20)
        original = phone._handle
        phone._handle = lambda frame: None if frame.command == 0x14 else original(frame)
        with self.assertRaises(TunnelError):
            s.open_config(0x1234, UID, 15000)
        self.assertEqual(s.config_id, 0x1234)
        self.assertEqual(s.close_config(UID), 0)

    def test_refused_open_records_nothing(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.session(phone)
        s.get_version()
        s.exchange(2, tcp_send_buffer_bytes=1 << 20)
        original = phone._handle
        def refuse(frame):
            if frame.command == 0x14:
                phone._reply(0x14, frame.transaction, _open(0x1234, status=3))
            else:
                original(frame)
        phone._handle = refuse
        with self.assertRaises(TunnelError):
            s.open_config(0x1234, UID, 15000)
        self.assertIsNone(s.config_id)

    def test_refused_connect_records_nothing(self):
        phone = FakePhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        original = phone._handle
        def refuse(frame):
            if (frame.command, frame.kind) == (3, 1):
                phone._reply(3, frame.transaction, _connect(0x1234, 0, status=1, net_error=111))
            else:
                original(frame)
        phone._handle = refuse
        with self.assertRaises(TunnelError):
            s.connect(40000)
        self.assertEqual((s.connections, s.retired), ({}, {}))

    @unittest.skipUnless(SAVED_CAPTURES, "saved capture is kept outside the repository")
    def test_replays_saved_s20_version(self):
        request = (SAVED / 'request.bin').read_bytes()
        response = (SAVED / 'response.bin').read_bytes()
        transaction = struct.unpack_from('<I', response, 16)[0]
        link = CannedLink(response)
        s = self.session(link, first_transaction=transaction)
        self.assertEqual(s.get_version(), '2.17.21.0')
        self.assertEqual(bytes(link.written), request)


if __name__ == '__main__':
    unittest.main()
