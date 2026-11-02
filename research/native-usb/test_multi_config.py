"""Multi-config Session tests: concurrent configs, per-config routing, per-config close.

Uses a purpose-built fake daemon (not the single-config FakePhone) so several
configs and connections exist at once. Not proof of S20+ behaviour.
"""
import struct
import unittest

from conn_frames import Decoder, Frame, encode
from usb_tunnel import Session, TunnelError
from test_usb_tunnel import _version, _exchange, UID

TICK = 0.001


class MultiPhone:
    def __init__(self, usb_buffer_bytes=4096):
        self.now = 0.0
        self.decoder = Decoder(1 << 20)
        self.inbound = bytearray()
        self.usb_buffer_bytes = usb_buffer_bytes
        self.cfgs = {}                 # config_id -> (port, operation)
        self.keys = {}                 # (config_id, host_port) -> key
        self.next_key = 1000
        self.host_data = []            # (config_id, host_port, payload)
        self.disconnect_ports = []
        self.closed = []

    def clock(self):
        return self.now

    def write(self, data, timeout_ms):
        for frame in self.decoder.feed(data):
            self._handle(frame)
        return len(data)

    def read(self, size, timeout_ms):
        self.now += TICK
        chunk = bytes(self.inbound[:size])
        del self.inbound[:size]
        return chunk

    def _reply(self, command, t, body):
        self.inbound += encode(Frame(command, 2, t, body))

    def push_data(self, config_id, host_port, payload):
        key = self.keys[(config_id, host_port)]
        body = struct.pack('<9I', 6, config_id, 2, key, host_port,
                           self.cfgs[config_id][0], 0, 56, len(payload)) + payload
        self.inbound += encode(Frame(5, 1, 70000 + len(self.host_data), body))

    def _handle(self, frame):
        t = frame.transaction
        if frame.kind == 2:
            return
        c = frame.command
        if c == 2:
            self._reply(2, t, _version())
        elif c == 0x16:
            self._reply(0x16, t, _exchange(self.usb_buffer_bytes))
        elif c == 0x14:
            cfg = struct.unpack_from('<I', frame.body, 0)[0]
            operation, _, _, port = struct.unpack_from('<4I', frame.body, 72)
            self.cfgs[cfg] = (port, operation)
            bound = port if operation == 1 else 0
            self._reply(0x14, t, struct.pack('<IIII', 0, cfg, bound, 0))
        elif c == 3:
            cfg, host_port = struct.unpack_from('<I16xI', frame.body, 0)
            assert cfg in self.cfgs, 'connect on unopened config'
            key = self.next_key
            self.next_key += 1
            self.keys[(cfg, host_port)] = key
            self._reply(3, t, struct.pack('<III16sI', 0, 0, cfg, b'127.0.0.1'.ljust(16, b'\0'), key))
        elif c == 5:
            # offsets: cfg@4, host_port@12, key@16, port@20
            cfg = struct.unpack_from('<I', frame.body, 4)[0]
            host_port = struct.unpack_from('<I', frame.body, 12)[0]
            key = struct.unpack_from('<I', frame.body, 16)[0]
            port = struct.unpack_from('<I', frame.body, 20)[0]
            assert self.keys.get((cfg, host_port)) == key, 'host data wrong key'
            assert port == self.cfgs[cfg][0], 'host data wrong port'
            self.host_data.append((cfg, host_port, bytes(frame.body[36:])))
            self._reply(5, t, struct.pack('<III', 0, 20 + len(frame.body), 0))
        elif c == 4:
            cfg = struct.unpack_from('<I', frame.body, 0)[0]
            key = struct.unpack_from('<I', frame.body, 20)[0]
            self.disconnect_ports.append((cfg, key))
            ok = key in [v for (cc, _), v in self.keys.items() if cc == cfg]
            self._reply(4, t, struct.pack('<I', 0 if ok else 1))
        elif c == 0x15:
            cfg = struct.unpack_from('<I', frame.body, 64)[0]
            self.closed.append(cfg)
            self._reply(0x15, t, struct.pack('<I', 0))
        else:
            raise AssertionError('unexpected command %d' % c)


class Tests(unittest.TestCase):
    def opened(self, phone):
        s = Session(phone, 1, 1 << 16, 1 << 20, clock=phone.clock)
        s.get_version()
        s.exchange(0, tcp_send_buffer_bytes=0)
        return s

    def test_three_configs_route_and_close_independently(self):
        phone = MultiPhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        a = s.open_config(0x100, UID, 15000)                    # primary, connect
        self.assertEqual(s.config_id, 0x100)                    # property = first
        self.assertEqual(s.config_port, 15000)
        conn_a = s.connect(40000)
        b = s.open_config(0x200, UID, 7000, operation=1)        # listener
        self.assertEqual(b['port'], 7000)                       # bound port returned
        c = s.open_config(0x300, UID, 7246)                     # second connect cfg
        conn_c = s.connect(40001, config_id=0x300)
        self.assertNotEqual(conn_a.key, conn_c.key)
        self.assertEqual((conn_a.config_id, conn_c.config_id), (0x100, 0x300))
        self.assertEqual(set(s.configs), {0x100, 0x200, 0x300})

        s.send(conn_c, b'to-7246')
        self.assertEqual(phone.host_data[-1], (0x300, 40001, b'to-7246'))

        phone.push_data(0x100, 40000, b'from-main')
        phone.push_data(0x300, 40001, b'from-7246')
        self.assertTrue(s.wait(1, until=lambda: conn_a.received and conn_c.received))
        self.assertEqual(bytes(conn_a.received), b'from-main')
        self.assertEqual(bytes(conn_c.received), b'from-7246')

        self.assertEqual(s.disconnect(conn_c), 0)
        self.assertEqual(s.close_config(UID, config_id=0x300), 0)
        self.assertEqual(set(s.configs), {0x100, 0x200})
        self.assertEqual(s.config_id, 0x100)                    # primary unchanged
        self.assertEqual(s.close_config(UID, config_id=0x200), 0)
        self.assertEqual(s.disconnect(conn_a), 0)
        self.assertEqual(s.close_config(UID), 0)                # default = primary
        self.assertEqual(set(s.configs), set())
        self.assertIsNone(s.config_id)

    def test_data_on_wrong_config_is_rejected(self):
        phone = MultiPhone(usb_buffer_bytes=512)
        s = self.opened(phone)
        s.open_config(0x100, UID, 15000)
        conn = s.connect(40000)
        s.open_config(0x300, UID, 7246)
        # A Data frame tagged with config 0x300 but the main connection's port.
        key = phone.keys[(0x100, 40000)]
        body = struct.pack('<9I', 6, 0x300, 2, key, 40000, 7246, 0, 56, 3) + b'bad'
        phone.inbound += encode(Frame(5, 1, 71000, body))
        with self.assertRaises(TunnelError):
            s.wait(1, until=lambda: False)

    def test_exchange_after_open_refused_and_duplicate_open(self):
        phone = MultiPhone()
        s = self.opened(phone)
        s.open_config(0x100, UID, 15000)
        with self.assertRaises(TunnelError):
            s.exchange(0, tcp_send_buffer_bytes=0)
        with self.assertRaises(TunnelError):
            s.open_config(0x100, UID, 15000)


if __name__ == "__main__":
    unittest.main()
