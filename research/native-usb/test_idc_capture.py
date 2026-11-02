"""Tests for idc_capture: CaptureSession records unknown frames; idc_probe drives
the IDC connect and records the phone's connect-back; guards make no USB import.

The 'inbound' frame the fake pushes on the listener is a PLACEHOLDER to exercise
the record path — it is NOT the real wire layout (unknown until the live run)."""
import builtins
import contextlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from conn_frames import Frame, encode
import idc
import idc_capture as c
from main_channel import ControlCodec, Frame as MainFrame, encode_frame
from usb_tunnel import TunnelError
from test_multi_config import MultiPhone
from test_usb_tunnel import UID

KEY = bytes(range(32))


class IdcPhone(MultiPhone):
    """MultiPhone that, on receiving the SIDESYNC_CONN Data on the 7246 config,
    pushes placeholder phone->host frames on the listener config (the connect-back)."""
    def __init__(self, **kw):
        super().__init__(**kw)
        self.idc_payload = None
        self.pushed_inbound = False

    def _handle(self, frame):
        super()._handle(frame)
        if (frame.kind == 1 and frame.command == 5 and self.host_data
                and self.host_data[-1][0] == c.CONNECT_CONFIG and not self.pushed_inbound):
            self.pushed_inbound = True
            self.idc_payload = self.host_data[-1][2]
            info = idc.connect_info(54321)
            response = idc.encode(KEY, idc.command_text(
                "CONNECT", "SIDESYNC_CONN", "RESPONSE", info))
            self.push_data(c.CONNECT_CONFIG, c.C_HOST_PORT, response)
            # (a) a Connect-like kind-1 command-3 on the listener config.
            body3 = struct.pack('<I16sI', c.LISTENER_CONFIG, b'127.0.0.1'.ljust(16, b'\0'), 1234)
            self.inbound += encode(Frame(3, 1, 80001, body3))
            # (b) a Data(5) on the listener from an unknown key (unknown connection).
            body5 = struct.pack('<9I', 6, c.LISTENER_CONFIG, 2, 9999, 0,
                                c.LISTENER_PORT, 0, 56, 2) + b'hi'
            self.inbound += encode(Frame(5, 1, 80002, body5))


def driven(phone, main_host_port=40000):
    phone.begin_cleanup = lambda: None
    s = c.CaptureSession(phone, 1, 1 << 16, 1 << 20, clock=phone.clock)
    s.get_version()
    s.exchange(0, tcp_send_buffer_bytes=0)
    s.open_config(0x100, UID, 15000)
    conn = s.connect(main_host_port)
    return s, conn


class Tests(unittest.TestCase):
    def test_capture_session_records_unknown_instead_of_raising(self):
        phone = MultiPhone(usb_buffer_bytes=512)
        s, _ = driven(phone)
        s.open_config(c.LISTENER_CONFIG, UID, c.LISTENER_PORT, operation=1)
        phone.inbound += encode(Frame(3, 1, 9, struct.pack(
            '<I16sI', c.LISTENER_CONFIG, b'127.0.0.1'.ljust(16, b'\0'), 7)))
        s.wait(1, until=lambda: bool(s.captured))
        self.assertEqual(len(s.captured), 1)
        self.assertEqual((s.captured[0]['command'], s.captured[0]['kind']), (3, 1))

    def test_idc_probe_sends_request_and_records_connect_back(self):
        phone = IdcPhone(usb_buffer_bytes=512)
        s, main = driven(phone)
        result = {}
        with contextlib.redirect_stdout(io.StringIO()):
            c.idc_probe(s, main, KEY, result, clock=phone.clock)
        self.assertTrue(result['listener_opened'])
        self.assertEqual(result['listener_port'], c.LISTENER_PORT)
        self.assertTrue(result['idc_request_sent'])
        self.assertTrue(result['idc_response_verified'])
        self.assertEqual(result['idc_response']['control_port'], 54321)
        self.assertFalse(result['capture_goal_met'])
        self.assertTrue(result['unknown_frame_candidate_present'])
        self.assertGreaterEqual(result['inbound_frames'], 2)
        kinds = {(f['command'], f['kind']) for f in result['captured']}
        self.assertIn((3, 1), kinds)
        self.assertIn((5, 1), kinds)
        # The phone received a well-formed SIDESYNC_CONN with field0 = listener port.
        text = idc.decode(KEY, phone.idc_payload)
        info = text.split(' ', 5)[5]
        self.assertEqual(info.split('/&%')[0], str(c.LISTENER_PORT))
        self.assertIn('CONNECT SIDESYNC_CONN REQUEST', text)
        # Cleanup: C and L closed; main config 0x100 left for the caller's teardown.
        self.assertIn(c.CONNECT_CONFIG, phone.closed)
        self.assertIn(c.LISTENER_CONFIG, phone.closed)
        self.assertEqual(set(s.configs), {0x100})

    def test_idc_probe_cleans_up_when_request_fails(self):
        phone = IdcPhone(usb_buffer_bytes=512)
        s, main = driven(phone)
        # Force the 7246 connect to fail: refuse connects on CONNECT_CONFIG.
        orig = phone._handle
        def refuse(frame):
            if frame.kind == 1 and frame.command == 3 and \
                    struct.unpack_from('<I', frame.body, 0)[0] == c.CONNECT_CONFIG:
                phone._reply(3, frame.transaction, struct.pack(
                    '<III16sI', 1, 111, c.CONNECT_CONFIG, b''.ljust(16, b'\0'), 0))
                return
            orig(frame)
        phone._handle = refuse
        result = {}
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(TunnelError):
            c.idc_probe(s, main, KEY, result, clock=phone.clock)
        self.assertFalse(result['idc_request_sent'])
        self.assertNotIn(c.CONNECT_CONFIG, s.configs)   # removed on refused open/connect
        self.assertNotIn(c.LISTENER_CONFIG, s.configs)  # listener closed in cleanup
        self.assertEqual(set(s.configs), {0x100})

    def test_cleanup_uses_read_reserve_and_rejects_disconnect_failure(self):
        phone = IdcPhone(usb_buffer_bytes=512)
        s, main = driven(phone)
        phone.begin_cleanup = lambda: setattr(phone, "cleanup_started", True)
        phone.cleanup_started = False
        original = s.disconnect
        def failed_disconnect(connection):
            self.assertTrue(s.cleanup)
            self.assertTrue(phone.cleanup_started)
            original(connection)
            return 7
        s.disconnect = failed_disconnect
        result = {}
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
                TunnelError, "IDC disconnect status 7"):
            c.idc_probe(s, main, KEY, result, clock=phone.clock)
        self.assertEqual(result["idc_disconnect_status"], 7)
        self.assertEqual(result["idc_cleanup_errors"],
                         ["TunnelError: IDC disconnect status 7"])
        self.assertEqual(set(s.configs), {0x100})

    def test_observation_saves_only_protocol_fields(self):
        codec = ControlCodec(KEY)
        obj = dict(TYPE="NOTI", MSG="ChangePSSState", RESULT=True,
                   PARAM=dict(PSS_STATE=2, PSS_MODE=0, token="private-value"),
                   SessionKey=KEY.hex())
        main = encode_frame(MainFrame(6, codec.encrypt(obj)))
        response = idc.encode(KEY, idc.command_text(
            "CONNECT", "SIDESYNC_CONN", "RESPONSE", idc.connect_info(54321)))
        result = {}
        c.observe_replies(main, response, KEY, result)
        self.assertEqual(result["main_notifications"], [dict(
            sid=6, type="NOTI", msg="ChangePSSState", result=True, pss_state=2, pss_mode=0)])
        self.assertNotIn("private-value", str(result))
        self.assertNotIn(KEY.hex(), str(result))
        self.assertTrue(result["idc_response_verified"])

    def test_observation_reports_rejection_and_partial_main_notice(self):
        response = idc.encode(KEY, idc.command_text(
            "CONNECT", "SIDESYNC_CONN", "RESPONSE", "BUSY"))
        result = {}
        c.observe_replies(b"\x00", response, KEY, result)
        self.assertFalse(result["idc_response_verified"])
        self.assertEqual(result["idc_response"]["reason"], "BUSY")
        self.assertIn("main_notification_error", result)
        result = {}
        c.observe_replies(b"", b"truncated", KEY, result)
        self.assertFalse(result["idc_response_verified"])
        self.assertIn("idc_response_error", result)

    def test_default_and_guards_make_no_usb_import(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == 'usb' or name.startswith('usb.'):
                raise AssertionError('USB imported')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', guard):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(c.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    c.main(['--approved-phone-idc-capture', '--bus', '3',
                            '--address', '4', '--output', 'nope'])
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FileExistsError):
                    c.main(['--approved-phone-idc-capture', '--accept-persistent-preferences',
                            '--bus', '3', '--address', '4', '--output', tmp])


if __name__ == "__main__":
    unittest.main()
