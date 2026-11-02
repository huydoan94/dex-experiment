"""Offline WFD startup tests. No phone API or native binaries execute."""
import builtins
import contextlib
import io
import struct
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import idc
import idc_handshake as h
import wfd_startup as w
from test_idc_handshake import Phone, opened, KEY

HEADER = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nRequire: org.wfa.wfd1.0\r\n\r\n"


class WfdPhone(Phone):
    def __init__(self, status=1, partial=False, header=HEADER):
        super().__init__()
        self.status = status
        self.partial = partial
        self.header = header
        self.waiting_event = False

    def read(self, size, timeout_ms):
        if not self.inbound:
            self.now += timeout_ms / 1000
        return super().read(size, timeout_ms)

    def _handle(self, frame):
        super()._handle(frame)
        if frame.kind == 2 and frame.command == 3 and self.waiting_event:
            self.waiting_event = False
            wire = b"\x00" if self.partial else idc.encode(KEY, idc.command_text(
                "SCR_SHR", "SCR_SHR_ENABLED", "EVENT", str(self.status) + "/&%0"))
            self.push_data(1201, 65535, wire)
        if frame.kind != 1:
            return
        if frame.command == 5 and self.host_data[-1][0] == 1203:
            self.control_text = idc.decode(KEY, self.host_data[-1][2])
            self.waiting_event = True
            self.inbound += encode(Frame(3, 1, 90, struct.pack("<I16sI", 1201, bytes(16), 2000)))
        elif frame.command == 3:
            config = struct.unpack_from("<I", frame.body)[0]
            if config == 1204:
                self.push_data(1204, 50004, self.header)


def run(phone, result):
    session, main = opened(phone)
    h.handshake(session, main, KEY, result, after_handshake=w.startup)
    return session


class Tests(unittest.TestCase):
    def test_startup_captures_header_without_rtsp_writes(self):
        phone, result = WfdPhone(), {}
        session = run(phone, result)
        self.assertTrue(result["wfd_startup_verified"])
        self.assertEqual(result["wfd_enable_event"], dict(result=1, previous_state=0))
        self.assertEqual(result["rtsp_initial"]["request_line"], "OPTIONS * RTSP/1.0")
        self.assertEqual(bytes.fromhex(result["rtsp_initial_hex"]), HEADER)
        self.assertEqual(len(phone.host_data), 2)
        self.assertTrue(phone.control_text.endswith("SCR_SHR ENABLE_SCR_SHR REQUEST null"))
        self.assertEqual({config for config, _, _ in phone.host_data}, {1202, 1203})
        self.assertEqual(set(session.configs), {256})
        self.assertEqual(result["wfd_cleanup_errors"], [])
        self.assertNotIn(KEY.hex(), str(result))

    def test_decline_skips_rtsp_and_cleans_control(self):
        phone, result = WfdPhone(status=-3), {}
        with self.assertRaisesRegex(Exception, "did not accept WFD enable"):
            run(phone, result)
        self.assertFalse(result["wfd_startup_verified"])
        self.assertNotIn(1204, phone.cfgs)
        self.assertEqual(set(phone.closed), {1201, 1202, 1203})
        self.assertEqual(len(phone.host_data), 2)

    def test_partial_event_obeys_deadline_without_busy_loop(self):
        phone, result = WfdPhone(partial=True), {}
        with self.assertRaisesRegex(Exception, "deadline expired"):
            run(phone, result)
        self.assertLess(phone.clock(), 35)
        self.assertNotIn(1204, phone.cfgs)
        self.assertFalse(result["wfd_startup_verified"])

    def test_bad_rtsp_header_fails_and_closes_both_wfd_configs(self):
        phone, result = WfdPhone(header=b"not RTSP\r\n\r\n"), {}
        with self.assertRaises(ValueError):
            run(phone, result)
        self.assertFalse(result["wfd_startup_verified"])
        self.assertEqual(result["wfd_close_statuses"], {"1204": 0, "1203": 0})
        self.assertEqual(len(phone.host_data), 2)

    def test_header_bounds_and_response_rejection(self):
        for data in (b"x"*8193 + b"\r\n\r\n",
                     b"RTSP/1.0 200 OK\r\n\r\n", b"OPTIONS * RTSP/1.0\r\n"):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                w.first_rtsp_header(data)

    def test_main_close_during_drain_prevents_rtsp_connection(self):
        phone, result = WfdPhone(), {}
        session, main = opened(phone)
        original = session.wait
        def wait(seconds, until=lambda: False):
            answer = original(seconds, until)
            if result.get("wfd_enable_event") and 1204 not in session.configs:
                main.closed_by_phone = True
            return answer
        session.wait = wait
        with self.assertRaisesRegex(Exception, "closed main channel before RTSP"):
            h.handshake(session, main, KEY, result, after_handshake=w.startup)
        self.assertNotIn(1204, phone.cfgs)

    def test_rtsp_header_after_deadline_is_rejected(self):
        phone, result = WfdPhone(), {}
        session, main = opened(phone)
        original = session.wait
        def wait(seconds, until=lambda: False):
            answer = original(seconds, until)
            if 1204 in session.configs:
                phone.now += 4
            return answer
        session.wait = wait
        with self.assertRaisesRegex(Exception, "RTSP header deadline expired"):
            h.handshake(session, main, KEY, result, after_handshake=w.startup)
        self.assertFalse(result["wfd_startup_verified"])

    def test_manual_event_decode_after_deadline_is_rejected(self):
        phone, result = WfdPhone(), {}
        original = w.collect_events
        def collect(session, *args):
            original(session, *args)
            if result.get("wfd_enable_event"):
                phone.now += 31
        with patch.object(w, "collect_events", collect):
            with self.assertRaisesRegex(Exception, "confirmation deadline expired"):
                run(phone, result)
        self.assertNotIn(1204, phone.cfgs)

    def test_oversized_received_rtsp_fails_without_exporting_body(self):
        phone, result = WfdPhone(header=HEADER + b"x"*8192), {}
        with self.assertRaisesRegex(Exception, "exceeds exported-header cap"):
            run(phone, result)
        self.assertNotIn("rtsp_initial_hex", result)
        self.assertFalse(result["wfd_startup_verified"])

    def test_closed_main_before_callback_sends_no_enable(self):
        phone, result = WfdPhone(), {}
        session, main = opened(phone)
        original = session.wait
        def wait(seconds, until=lambda: False):
            answer = original(seconds, until)
            if result.get("idc_handshake_verified") and not result.get("screen_share_request_attempted"):
                main.closed_by_phone = True
            return answer
        session.wait = wait
        with self.assertRaisesRegex(Exception, "before continuation"):
            h.handshake(session, main, KEY, result, after_handshake=w.startup)
        self.assertNotIn(1203, phone.cfgs)
        self.assertEqual(len(phone.host_data), 1)

    def test_main_close_during_control_connect_prevents_enable(self):
        phone, result = WfdPhone(), {}
        session, main = opened(phone)
        original = session.connect
        def connect(host, config_id=None, **kwargs):
            answer = original(host, config_id=config_id, **kwargs)
            if config_id == 1203:
                main.closed_by_phone = True
            return answer
        session.connect = connect
        with self.assertRaisesRegex(Exception, "before enable send"):
            h.handshake(session, main, KEY, result, after_handshake=w.startup)
        self.assertEqual(len(phone.host_data), 1)
        self.assertNotIn(1204, phone.cfgs)

    def test_main_close_during_rtsp_open_prevents_connect(self):
        phone, result = WfdPhone(), {}
        session, main = opened(phone)
        original = session.open_config
        def open_config(config_id, *args, **kwargs):
            answer = original(config_id, *args, **kwargs)
            if config_id == 1204:
                main.closed_by_phone = True
            return answer
        session.open_config = open_config
        with self.assertRaisesRegex(Exception, "before RTSP Connect"):
            h.handshake(session, main, KEY, result, after_handshake=w.startup)
        self.assertNotIn((1204, 50004), phone.keys)

    def test_default_and_incomplete_approval_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(w.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                w.main(["--approved-phone-wfd-startup", "--bus", "3",
                        "--address", "9", "--output", "unused"])
