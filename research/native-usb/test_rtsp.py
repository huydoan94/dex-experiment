"""Offline framing, exact live fixture and full synthetic WFD continuation."""
import builtins
import contextlib
import io
import struct
from pathlib import Path
import unittest
from unittest.mock import patch

from conn_frames import Decoder
from usb_tunnel import TunnelError
import rtsp
import rtsp_hello as hello
import wfd_startup as wfd
import idc_handshake as handshake
from test_wfd_startup import WfdPhone
from test_idc_handshake import opened, KEY

LIVE = (b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
        b"Server: AllShareCast/Galaxy/Android13\r\nRequire: org.wfa.wfd1.0\r\n\r\n")
RESPONSE = (b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
            b"Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER\r\n\r\n")
BODY = b"wfd_video_formats\r\nwfd_audio_codecs\r\nwfd_client_rtp_ports\r\n"
QUERY = (b"GET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 2\r\n"
         b"Content-Type: text/parameters\r\nContent-Length: " +
         str(len(BODY)).encode() + b"\r\n\r\n" + BODY)


class HelloPhone(WfdPhone):
    def __init__(self, answer=RESPONSE+QUERY, fragment=False):
        super().__init__(header=LIVE)
        self.answer, self.fragment = answer, fragment
        self.rtsp_sent = []

    def _handle(self, frame):
        super()._handle(frame)
        if frame.kind == 1 and frame.command == 5 and self.host_data[-1][0] == 1204:
            self.rtsp_sent.append(self.host_data[-1][2])
            if len(self.rtsp_sent) == 2:
                if self.fragment:
                    for byte in self.answer:
                        self.push_data(1204, 50004, bytes([byte]))
                else:
                    self.push_data(1204, 50004, self.answer)


def run(phone, result):
    session, main = opened(phone)
    def startup(*args):
        return wfd.startup(*args, after_rtsp=hello.exchange)
    handshake.handshake(session, main, KEY, result, after_handshake=startup)
    return session


class Framing(unittest.TestCase):
    def test_live_fixture_all_fragment_boundaries(self):
        self.assertEqual(len(LIVE), 95)
        for i in range(len(LIVE)):
            self.assertIsNone(rtsp.parse(LIVE[:i]))
        message, length = rtsp.parse(LIVE)
        rtsp.initial_options(message)
        self.assertEqual(length, 95)
        self.assertEqual(message["cseq"], 1)

    def test_content_length_and_coalescing(self):
        for i in range(len(QUERY)):
            self.assertIsNone(rtsp.parse(QUERY[:i]))
        item, consumed = rtsp.parse(QUERY+RESPONSE)
        self.assertEqual(consumed, len(QUERY))
        self.assertEqual(rtsp.query_names(item),
                         ["wfd_video_formats", "wfd_audio_codecs", "wfd_client_rtp_ports"])
        self.assertEqual(rtsp.parse((QUERY+RESPONSE)[consumed:])[0]["status"], 200)

    def test_bad_framing(self):
        for data in (b"$abc", b"x"*8192, b"x"*16385,
                     LIVE.replace(b"CSeq: 1", b"CSeq: -1"),
                     LIVE.replace(b"CSeq: 1", b"CSeq: 2147483648"),
                     LIVE.replace(b"CSeq: 1", b"CSeq: 1\r\ncseq: 1"),
                     LIVE.replace(b"CSeq: 1", b"NoSeq: 1"),
                     LIVE.replace(b"CSeq: 1", b" CSeq: 1"),
                     LIVE.replace(b"CSeq: 1", b"CSeq: 1\nX: y"),
                     LIVE.replace(b"CSeq: 1", b"CSeq: 1\r\nContent-Length: 8193"),
                     LIVE.replace(b"CSeq: 1", b"CSeq: 1\r\nContent-Length: -1")):
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                rtsp.parse(data)

    def test_bad_initial_and_query(self):
        message, _ = rtsp.parse(LIVE.replace(b"OPTIONS", b"GET_PARAMETER"))
        with self.assertRaises(ValueError):
            rtsp.initial_options(message)
        message, _ = rtsp.parse(QUERY)
        for body in (b"name: value\r\n", b"a\r\na\r\n", b"a", b"\r\n",
                     b"x"*129+b"\r\n"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                rtsp.query_names(dict(message, body=body))

    def test_exact_two_outbound_messages(self):
        self.assertEqual(rtsp.options_reply(7),
            b"RTSP/1.0 200 OK\r\nCSeq: 7\r\n"
            b"Public: org.wfa.wfd1.0, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n\r\n")
        self.assertEqual(rtsp.options_request(),
            b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nRequire: org.wfa.wfd1.0\r\n\r\n")


class Exchange(unittest.TestCase):
    def test_coalesced_and_fragmented_both_orders(self):
        for answer, fragment in ((RESPONSE+QUERY, False), (QUERY+RESPONSE, False),
                                 (RESPONSE+QUERY, True)):
            with self.subTest(fragment=fragment, query_first=answer.startswith(b"GET")):
                phone, result = HelloPhone(answer, fragment), {}
                session = run(phone, result)
                self.assertTrue(result["rtsp_hello_verified"])
                self.assertEqual(phone.rtsp_sent, [rtsp.options_reply(1),rtsp.options_request()])
                self.assertEqual(len(phone.host_data), 4)
                self.assertEqual(result["wfd_cleanup_errors"], [])
                self.assertEqual(set(session.configs), {256})
                self.assertNotIn(KEY.hex(), str(result))

    def test_invalid_exchange_never_sends_capability_reply(self):
        for answer in (RESPONSE.replace(b"200 OK", b"403 Denied")+QUERY,
                       RESPONSE.replace(b"CSeq: 1", b"CSeq: 5")+QUERY,
                       RESPONSE+QUERY.replace(b"GET_PARAMETER", b"SET_PARAMETER"),
                       RESPONSE+RESPONSE, QUERY+QUERY, RESPONSE+QUERY+b"x",
                       RESPONSE+QUERY.replace(b"CSeq: 2", b"CSeq: 1"),
                       RESPONSE.replace(b"org.wfa.wfd1.0", b"unknown")+QUERY):
            with self.subTest(answer=answer[:80]):
                phone, result = HelloPhone(answer), {}
                with self.assertRaises(ValueError):
                    run(phone, result)
                self.assertNotIn("rtsp_hello_verified", result)
                self.assertEqual(len(phone.rtsp_sent), 2)
                self.assertEqual(result["wfd_close_statuses"], {"1204":0,"1203":0})
                self.assertEqual(result["idc_cleanup_errors"], [])

    def test_silent_source_deadline_and_cleanup(self):
        phone, result = HelloPhone(b""), {}
        with self.assertRaisesRegex(Exception, "hello deadline"):
            run(phone, result)
        self.assertEqual(len(phone.rtsp_sent), 2)
        self.assertEqual(result["wfd_cleanup_errors"], [])

    def test_main_close_during_first_send_blocks_second(self):
        phone, result = HelloPhone(), {}
        session, main = opened(phone)
        original = session.send
        def send(connection, payload, **kwargs):
            answer = original(connection, payload, **kwargs)
            if connection.config_id == 1204:
                main.closed_by_phone = True
            return answer
        session.send = send
        with self.assertRaisesRegex(Exception, "closed channel"):
            handshake.handshake(session, main, KEY, result,
                after_handshake=lambda *a: wfd.startup(*a, after_rtsp=hello.exchange))
        self.assertEqual(len(phone.rtsp_sent), 1)
        self.assertNotIn("rtsp_hello_verified", result)

    def test_late_send_blocks_second(self):
        phone, result = HelloPhone(), {}
        session, main = opened(phone)
        original = session.send
        def send(connection, payload, **kwargs):
            answer = original(connection, payload, **kwargs)
            if connection.config_id == 1204:
                phone.now += 6
            return answer
        session.send = send
        with self.assertRaisesRegex(Exception, "hello deadline"):
            handshake.handshake(session, main, KEY, result,
                after_handshake=lambda *a: wfd.startup(*a, after_rtsp=hello.exchange))
        self.assertEqual(len(phone.rtsp_sent), 1)

    def test_transport_overshoot_rejects_late_success_and_cleans(self):
        phone, result = HelloPhone(), {}
        session, main = opened(phone)
        original = session.send
        count = 0
        def send(connection, payload, **kwargs):
            nonlocal count
            answer = original(connection, payload, **kwargs)
            if connection.config_id == 1204:
                count += 1
                phone.now += 2.9 if count == 1 else 3.0
            return answer
        session.send = send
        with self.assertRaisesRegex(Exception, "hello deadline"):
            handshake.handshake(session, main, KEY, result,
                after_handshake=lambda *a: wfd.startup(*a, after_rtsp=hello.exchange))
        self.assertEqual(count, 2)
        self.assertNotIn("rtsp_hello_verified", result)
        self.assertEqual(result["wfd_cleanup_errors"], [])
        self.assertEqual(set(session.configs), {256})

    def test_real_request_write_precedes_reply_timeout(self):
        class SlowPhone(HelloPhone):
            def __init__(self):
                super().__init__(answer=b"")
                self.phase = 0
                self.held = b""
                self.delays = []
                self.hello_start = None
                self.hello_end = None

            def write(self, data, timeout_ms):
                frames = Decoder(65536).feed(data)
                for frame in frames:
                    if frame.kind == 1 and frame.command == 4 and self.phase == 2:
                        self.hello_end = self.now
                        self.phase = 3
                    if (frame.kind == 1 and frame.command == 5
                            and struct.unpack_from("<I", frame.body, 4)[0] == 1204):
                        self.phase += 1
                        if self.hello_start is None:
                            self.hello_start = self.now
                        self.now += timeout_ms / 1000
                answer = super().write(data, timeout_ms)
                if self.phase == 1 and not self.delays:
                    self.held = bytes(self.inbound)
                    self.inbound.clear()
                    self.delays = [1.0, 0.9]
                elif self.phase == 2:
                    self.inbound.clear()  # no second Data reply
                return answer

            def read(self, size, timeout_ms):
                if self.phase == 1 and self.delays:
                    delay = self.delays.pop(0)
                    assert delay <= timeout_ms / 1000
                    self.now += delay
                    if self.delays:
                        return b""
                    answer, self.held = self.held[:size], self.held[size:]
                    return answer
                if self.phase == 2:
                    self.now += timeout_ms / 1000
                    return b""
                return super().read(size, timeout_ms)

        phone, result = SlowPhone(), {}
        with self.assertRaisesRegex(TunnelError, "USB deadline expired"):
            run(phone, result)
        self.assertEqual(len(phone.rtsp_sent), 2)
        self.assertAlmostEqual(phone.hello_end - phone.hello_start, 5.9, places=2)
        self.assertNotIn("rtsp_hello_verified", result)
        self.assertEqual(result["wfd_cleanup_errors"], [])
        self.assertEqual(result["idc_cleanup_errors"], [])

    def test_plan_and_missing_grant_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB import without grant")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(hello.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                hello.main(["--approved-phone-rtsp-hello"])
