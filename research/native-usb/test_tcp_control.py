import struct
import unittest
from conn_frames import Decoder, Frame, encode
import tcp_control as tcp


class TcpControlTests(unittest.TestCase):
    def test_connect_literal_layout(self):
        frame = tcp.connect_request(0x11223344, 0x1234, '127.0.0.1', 15000)
        raw = encode(frame)
        self.assertEqual(raw[:24], bytes.fromhex(
            '434f4e4e030000002c000000010000004433221134120000'))
        self.assertEqual(raw[24:40], b'127.0.0.1' + bytes(7))
        self.assertEqual(raw[40:], b'\x98\x3a\0\0')
        self.assertEqual(len(raw), 44)

    def test_disconnect_literal_command_and_layout(self):
        raw = encode(tcp.disconnect_request(1, 2, '255.255.255.255', 65535))
        self.assertEqual(raw[4:16], bytes.fromhex('040000002c00000001000000'))
        self.assertEqual(raw[24:40], b'255.255.255.255\0')
        self.assertEqual(raw[40:], b'\xff\xff\0\0')

    def test_invalid_outgoing_values(self):
        for tx in (0, -1, 0x100000000, True, 1.5):
            with self.assertRaises(ValueError):
                tcp.connect_request(tx, 1, '127.0.0.1', 0)
        for cfg in (0, -1, 65530, 65536, True, 1.5):
            with self.assertRaises(ValueError):
                tcp.connect_request(1, cfg, '127.0.0.1', 0)
        for port in (-1, 65536, True, 1.5):
            with self.assertRaises(ValueError):
                tcp.connect_request(1, 1, '127.0.0.1', port)
        for address in ('::1', '127.0.0.1\0', 'a' * 17, '999.0.0.1', 1):
            with self.assertRaises(ValueError):
                tcp.connect_request(1, 1, address, 0)

    def reply(self, *, status=0, error=0, cfg=42, address=b'127.0.0.1', port=15000):
        return Frame(3, 2, 19, struct.pack('<III16sI', status, error, cfg, address, port))

    def test_connect_reply_independent_literal_fixture_fragmented(self):
        #52-byte layout taken from the native stores, not production constants.
        raw = (bytes.fromhex('434f4e4e03000000340000000200000013000000') +
               bytes.fromhex('00000000000000002a000000') +
               b'127.0.0.1' + bytes(7) + b'\x98\x3a\0\0')
        decoder = Decoder(256)
        frames = []
        for byte in raw:
            frames.extend(decoder.feed(bytes([byte])))
        decoder.finish()
        result = tcp.connect_reply(frames[0], 19, 42)
        self.assertEqual((result.status, result.network_error, result.config_id,
                          result.address, result.port), (0, 0, 42, '127.0.0.1', 15000))

    def test_failed_reply_preserves_native_status_and_error(self):
        result = tcp.connect_reply(self.reply(status=9, error=111, address=b''), 19, 42)
        self.assertEqual((result.status, result.network_error, result.address), (9, 111, None))

    def test_wrong_response_identity_or_length(self):
        good = self.reply()
        for frame in (Frame(4, 2, 19, good.body), Frame(3, 1, 19, good.body),
                      Frame(3, 2, 20, good.body), Frame(3, 2, 19, good.body[:-1]),
                      Frame(3, 2, 19, good.body + b'x')):
            with self.assertRaises(ValueError):
                tcp.connect_reply(frame, 19, 42)

    def test_wrong_identifier_port_or_address(self):
        for frame in (self.reply(cfg=43), self.reply(port=65536), self.reply(address=b''),
                      self.reply(address=b'not-an-ip'), self.reply(address=bytes([255])),
                      self.reply(address=b'127.0.0.1\0x'),
                      self.reply(address=b'1234567890123456')):
            with self.assertRaises(ValueError):
                tcp.connect_reply(frame, 19, 42)

    def test_open_reply_and_close_reply(self):
        frame = Frame(20, 2, 19, bytes.fromhex('000000002a0000000000000000000000'))
        self.assertEqual(tcp.open_reply(frame, 19, 42),
                         {'status': 0, 'config_id': 42, 'port': 0, 'client_port': 0})
        self.assertEqual(tcp.close_reply(Frame(21, 2, 19, b'\0' * 4), 19), 0)
        self.assertEqual(tcp.close_reply(Frame(21, 2, 19, b'\x09\0\0\0'), 19), 9)
        for bad in (Frame(21, 2, 19, b''), Frame(20, 2, 19, b'\0' * 4)):
            with self.assertRaises(ValueError):
                tcp.close_reply(bad, 19)
        with self.assertRaises(ValueError):
            tcp.open_reply(frame, 19, 43)


    def test_configuration_literal_offsets(self):
        raw = encode(tcp.configuration_request(19, 42, b'X' + bytes(63), 15000))
        self.assertEqual(len(raw), 116)
        self.assertEqual(raw[:24], bytes.fromhex(
            '434f4e4e140000007400000001000000130000002a000000'))
        self.assertEqual(raw[24:88], b'X' + bytes(63))
        self.assertEqual(raw[88:], bytes.fromhex(
            '01011c00' '02000000' '02000000' '06000000'
            '983a0000' '00000000' '00000000'))

    def test_configuration_close_literal_offsets(self):
        raw = encode(tcp.configuration_close_request(19, 42, b'X' + bytes(63)))
        self.assertEqual(len(raw), 88)
        self.assertEqual(raw[:20], bytes.fromhex(
            '434f4e4e15000000580000000100000013000000'))
        self.assertEqual(raw[20:84], b'X' + bytes(63))
        self.assertEqual(raw[84:], bytes.fromhex('2a000000'))

    def test_configuration_refuses_invalid_service_or_target(self):
        for uid in (bytes(63), bytes(65), 'x' * 64, None):
            with self.assertRaises(ValueError):
                tcp.configuration_request(1, 1, uid, 15000)
            with self.assertRaises(ValueError):
                tcp.configuration_close_request(1, 1, uid)
        for port in (0, -1, 65536, True):
            with self.assertRaises(ValueError):
                tcp.configuration_request(1, 1, bytes(64), port)


    def test_data_request_literal_offsets(self):
        raw = encode(tcp.data_request(19, 42, 0x3039, 0xbeef, 15000, b'hello', 61))
        self.assertEqual(len(raw), 61)
        self.assertEqual(raw[:20], bytes.fromhex(
            '434f4e4e050000003d0000000100000013000000'))
        self.assertEqual(raw[20:56], bytes.fromhex(
            '06000000' '2a000000' '02000000' '39300000' 'efbe0000'
            '983a0000' '00000000' '38000000' '05000000'))
        self.assertEqual(raw[56:], b'hello')

    def test_data_request_refuses_oversize_and_bad_values(self):
        with self.assertRaises(ValueError):
            tcp.data_request(1, 1, 1, 1, 1, b'x' * 6, 61)
        for args in ((0, 1, 1, 1, 1, b'x'), (1, 0, 1, 1, 1, b'x'), (1, 1, 0, 1, 1, b'x'),
                     (1, 1, 1, 0, 1, b'x'), (1, 1, 1, 65536, 1, b'x'), (1, 1, 1, 1, 0, b'x'),
                     (1, 1, 1, 1, 1, b''), (1, 1, 1, 1, 1, 'x')):
            with self.assertRaises(ValueError):
                tcp.data_request(*args, 4096)

    def test_data_message_independent_fixture_fragmented(self):
        # 58 bytes: header20, protocol6 cfg42 family2 key1000 host_port0x3039
        # port15000 value44=0 offset56 length2, payload.
        raw = bytes.fromhex(
            '434f4e4e' '05000000' '3a000000' '01000000' '07000000'
            '06000000' '2a000000' '02000000' 'e8030000' '39300000'
            '983a0000' '00000000' '38000000' '02000000') + b'ok'
        decoder = Decoder(256)
        frames = []
        for byte in raw:
            frames.extend(decoder.feed(bytes([byte])))
        decoder.finish()
        message = tcp.data_message(frames[0], 42)
        self.assertEqual((message.transaction, message.connection_key, message.host_port,
                          message.port, message.payload), (7, 1000, 0x3039, 15000, b'ok'))

    def test_data_message_rejects_inconsistent_frames(self):
        good = tcp.data_request(7, 42, 5, 6, 15000, b'abc', 4096)
        self.assertEqual(tcp.data_message(good, 42).payload, b'abc')
        body = good.body
        bad = [Frame(5, 2, 7, body), Frame(6, 1, 7, body), Frame(5, 1, 7, body[:35]),
               Frame(5, 1, 7, body + b'x'), Frame(5, 1, 7, b'\x11' + body[1:]),
               Frame(5, 1, 7, body[:28] + b'\x39' + body[29:]),
               Frame(5, 1, 7, body[:12] + bytes(4) + body[16:])]
        for frame in bad:
            with self.assertRaises(ValueError):
                tcp.data_message(frame, 42)
        with self.assertRaises(ValueError):
            tcp.data_message(good, 43)

    def test_data_reply_status_size_and_error(self):
        frame = Frame(5, 2, 19, bytes.fromhex('09000000' '3d000000' '68000000'))
        self.assertEqual(tcp.data_reply(frame, 19, 61), (9, 104))
        for bad, size in ((frame, 60), (Frame(5, 2, 19, frame.body[:-1]), 61),
                          (Frame(5, 2, 20, frame.body), 61)):
            with self.assertRaises(ValueError):
                tcp.data_reply(bad, 19, size)


    def test_host_acknowledgement_literals(self):
        self.assertEqual(encode(tcp.data_ack(7, 58)), bytes.fromhex(
            '434f4e4e' '05000000' '20000000' '02000000' '07000000'
            '00000000' '3a000000' '00000000'))
        self.assertEqual(encode(tcp.disconnect_ack(8)), bytes.fromhex(
            '434f4e4e' '04000000' '18000000' '02000000' '08000000' '00000000'))
        for bad in ((0, 58), (1, 0), (1, -1)):
            with self.assertRaises(ValueError):
                tcp.data_ack(*bad)

    def test_phone_disconnect_independent_fixture(self):
        raw = (bytes.fromhex('434f4e4e' '04000000' '2c000000' '01000000' '09000000'
                             '2a000000') + b'127.0.0.1' + bytes(7) + bytes.fromhex('39300000'))
        decoder = Decoder(256)
        frame, = decoder.feed(raw)
        self.assertEqual(tcp.disconnect_message(frame, 42),
                         tcp.Disconnect(9, 42, '127.0.0.1', 12345))
        for bad in (Frame(4, 2, 9, frame.body), Frame(3, 1, 9, frame.body),
                    Frame(4, 1, 9, frame.body[:-1])):
            with self.assertRaises(ValueError):
                tcp.disconnect_message(bad, 42)
        with self.assertRaises(ValueError):
            tcp.disconnect_message(frame, 43)


    def test_exchange_literal_unaligned_offsets(self):
        raw = encode(tcp.exchange_request(19, 0x0102, usb_buffer_bytes=0x11223344,
                                          tcp_send_buffer_bytes=0x00100000))
        self.assertEqual(len(raw), 74)
        self.assertEqual(raw[16:22], bytes.fromhex('13000000' '0201'))
        self.assertEqual(raw[22:26], bytes(4))
        self.assertEqual(raw[26:30], bytes.fromhex('44332211'))
        self.assertEqual(raw[42:46], bytes.fromhex('00001000'))
        self.assertEqual(raw[46:74], bytes(28))
        for bad in (dict(os_type=-1), dict(os_type=0x10000), dict(os_type=1, bogus=1),
                    dict(os_type=1, usb_buffer_bytes=-1), dict(os_type=1, usb_buffer_bytes=1 << 31)):
            with self.assertRaises((ValueError, TypeError)):
                tcp.exchange_request(1, **bad)

    def test_exchange_reply_independent_fixture(self):
        body = bytes.fromhex('00000000' '0300') + struct.pack('<13I', *range(1, 14))
        status, os_type, fields = tcp.exchange_reply(Frame(0x16, 2, 19, body), 19)
        self.assertEqual((status, os_type, fields['usb_buffer_bytes'],
                          fields['usb_udp_sending_low_bytes']), (0, 3, 2, 13))
        for bad in (Frame(0x16, 2, 19, body[:-1]), Frame(0x16, 2, 18, body)):
            with self.assertRaises(ValueError):
                tcp.exchange_reply(bad, 19)

    def test_version_and_disconnect_replies(self):
        self.assertEqual(encode(tcp.version_request(7)),
                         bytes.fromhex('434f4e4e' '02000000' '14000000' '01000000' '07000000'))
        body = struct.pack('<III', 0, 2, 0) + b'2.17.21.0' + bytes(55)
        self.assertEqual(tcp.version_reply(Frame(2, 2, 7, body), 7), (0, 2, 0, '2.17.21.0'))
        self.assertEqual(tcp.disconnect_reply(Frame(4, 2, 7, b'\x09\0\0\0'), 7), 9)
        with self.assertRaises(ValueError):
            tcp.disconnect_reply(Frame(4, 2, 7, b''), 7)


if __name__ == '__main__':
    unittest.main()
