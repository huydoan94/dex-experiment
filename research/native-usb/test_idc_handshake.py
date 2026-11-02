"""Offline IDC acceptance, rejection, main notice and accepted-key cleanup."""
import builtins
import contextlib
import io
import struct
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import idc
import idc_handshake as h
from loopback_transfer import TransferSession
from main_channel import ControlCodec, Frame as MainFrame, encode_frame
from test_multi_config import MultiPhone
from test_usb_tunnel import UID

KEY = bytes(range(32))


class Phone(MultiPhone):
    def __init__(self, reason=None, notify=False):
        super().__init__(usb_buffer_bytes=4095)
        self.reason = reason
        self.notify = notify
        self.pushed = False
        self.begin_cleanup = lambda: None

    def _handle(self, frame):
        if frame.kind == 2 and frame.command == 3:
            status, error, cfg, address, host = struct.unpack("<III16sI", frame.body)
            assert (status, error, cfg) == (0, 0, 1201)
            self.keys[(1201, host)] = 2000
            return
        super()._handle(frame)
        if frame.kind == 1 and frame.command == 5 and not self.pushed:
            cfg, host, data = self.host_data[-1]
            if cfg != 1202:
                return
            self.pushed = True
            self.asserted_request = idc.decode(KEY, data)
            info = self.reason or idc.connect_info(54321)
            reply = idc.encode(KEY, idc.command_text(
                "CONNECT", "SIDESYNC_CONN", "RESPONSE", info))
            self.push_data(1202, host, reply)
            notice = encode_frame(MainFrame(6, ControlCodec(KEY).encrypt(
                dict(TYPE="NOTI", MSG="ChangePSSState", PARAM=dict(PSS_STATE=2, PSS_MODE=0)))))
            self.push_data(256, 40000, notice)
            if self.notify:
                self.inbound += encode(Frame(3, 1, 90, struct.pack(
                    "<I16sI", 1201, bytes(16), 2000)))


def opened(phone):
    session = TransferSession(phone, 1, 65536, 65536, clock=phone.clock)
    session.get_version()
    session.exchange(0, tcp_send_buffer_bytes=0)
    session.open_config(256, UID, 15000)
    main = session.connect(40000)
    return session, main


class Tests(unittest.TestCase):
    def test_acceptance_saves_reply_and_main_state_without_extra_commands(self):
        phone, result = Phone(), {}
        session, main = opened(phone)
        h.handshake(session, main, KEY, result)
        self.assertTrue(result["idc_handshake_verified"])
        self.assertTrue(result["idc_response_verified"])
        self.assertEqual(result["idc_response"]["control_port"], 54321)
        self.assertEqual(result["main_notifications"],
                         [dict(sid=6, type="NOTI", msg="ChangePSSState", pss_state=2, pss_mode=0)])
        self.assertEqual(len(phone.host_data), 1)
        self.assertIn("CONNECT SIDESYNC_CONN REQUEST", phone.asserted_request)
        self.assertEqual(set(session.configs), {256})
        self.assertEqual(result["idc_cleanup_errors"], [])
        self.assertNotIn(KEY.hex(), str(result))

    def test_rejection_is_not_verified_and_configs_close(self):
        for reason in ("BUSY", "INVALID"):
            phone, result = Phone(reason=reason), {}
            session, main = opened(phone)
            with self.assertRaisesRegex(ValueError, "IDC request rejected"):
                h.handshake(session, main, KEY, result)
            self.assertFalse(result["idc_handshake_verified"])
            self.assertFalse(result["idc_response_verified"])
            self.assertEqual(result["idc_response"]["reason"], reason)
            self.assertEqual(set(session.configs), {256})

    def test_unsolicited_accept_is_acknowledged_and_key_cleaned(self):
        phone, result = Phone(notify=True), {}
        session, main = opened(phone)
        h.handshake(session, main, KEY, result)
        self.assertTrue(result["idc_handshake_verified"])
        self.assertEqual(result["accepted_connections"][0]["key"], 2000)
        self.assertIn((1201, 2000), phone.disconnect_ports)
        self.assertEqual(set(session.configs), {256})
        self.assertEqual(len(phone.host_data), 1)

    def test_failure_preserves_first_error_and_attempts_both_closes(self):
        phone, result = Phone(), {}
        session, main = opened(phone)
        original = session.send
        def fail(connection, payload, **kwargs):
            raise RuntimeError("synthetic send failure")
        session.send = fail
        with self.assertRaisesRegex(RuntimeError, "synthetic send failure"):
            h.handshake(session, main, KEY, result)
        self.assertEqual(set(session.configs), {256})
        self.assertFalse(result["idc_response_verified"])
        self.assertIn("synthetic send failure", result["first_error"])

    def test_default_and_missing_grants_do_not_import_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("unapproved USB import")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                h.main(["--approved-phone-idc-handshake", "--bus", "3",
                        "--address", "9", "--output", "unused"])
