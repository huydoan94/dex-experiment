"""UDP SETUP stage: RTP socket before SETUP, exact six RTSP sends, no PLAY."""
import builtins
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame, encode
import idc_handshake as handshake
import rtsp
import rtsp_capabilities as caps
import rtsp_hello
import rtsp_udp_setup as setup
import ui_confirm as ui
import udp_setup_launch as launch
import udp_setup_probe as probe
import wfd_startup as wfd
from test_idc_handshake import KEY
from test_rtsp_capabilities import m4
from test_rtsp_setup import TRIGGER
from test_udp_capabilities import UdpPhone
from test_ui_confirm import FakeRunner
from test_loopback_transfer import Device
from test_usb_tunnel import UID
from tunnel_probe import Link

REPLY = (b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 42;timeout=30\r\n"
         b"Transport: RTP/AVP/UDP;unicast;client_port=46002;server_port=33000\r\n\r\n")


class UdpSetupPhone(UdpPhone):
    def __init__(self, reply=REPLY, datagrams=0, trigger=TRIGGER, close_after_reply=False):
        super().__init__()
        self.reply, self.datagrams, self.trigger = reply, datagrams, trigger
        self.close_after_reply = close_after_reply

    def _handle(self, frame):
        super()._handle(frame)
        if frame.kind != 1 or frame.command != 5 or self.host_data[-1][0] != 1204:
            return
        count = len(self.rtsp_sent)
        if count == 4:
            self.push_data(1204, 50004, self.trigger)
        elif count == 6 and self.reply:
            self.push_data(1204, 50004, self.reply)
            for n in range(self.datagrams):
                payload = bytes([0x80, 33]) + n.to_bytes(2, "big") + bytes(8) + b"SCREEN"
                body = struct.pack("<9I", 17, 1205, 2, 46002, 33000, 46002, 46002,
                                   56, len(payload)) + payload
                self.inbound += encode(Frame(5, 1, 90000 + n, body))
            if self.close_after_reply:
                body = struct.pack("<I16sI", 1204, b"127.0.0.1".ljust(16, b"\0"), 50004)
                self.inbound += encode(Frame(4, 1, 95000, body))


def opened(phone, link=None):
    session = setup.WfdUdpSession(link or phone, 1, 65536, 65536, clock=phone.clock)
    session.get_version()
    session.exchange(0, tcp_send_buffer_bytes=0)
    session.open_config(256, UID, 15000)
    return session, session.connect(40000)


def startup_for(phone):
    return lambda *args: wfd.startup(
        *args, confirm=lambda s, m, r, log, deadline: phone.tap(),
        after_rtsp=lambda *a: rtsp_hello.exchange(*a, after_query=lambda *b:
            caps.exchange(*b, profile=caps.UDP_PROFILE, after_selection=setup.exchange)))


def run(phone, result, link=None):
    session, main = opened(phone, link)
    try:
        handshake.handshake(session, main, KEY, result, after_handshake=startup_for(phone))
    except Exception as error:
        result["error"] = str(error)
    return session


class HelperTests(unittest.TestCase):
    def test_exact_setup_request(self):
        self.assertEqual(setup.setup_request("rtsp://127.0.0.1/wfd1.0/streamid=0"),
            b"SETUP rtsp://127.0.0.1/wfd1.0/streamid=0 RTSP/1.0\r\nCSeq: 2\r\n"
            b"Transport: RTP/AVP/UDP;unicast;client_port=46002\r\n\r\n")

    def test_response_accepts_udp_and_records_server_ports(self):
        self.assertEqual(setup.setup_response(rtsp.parse(REPLY)[0]),
                         dict(session_id="42", timeout_seconds=30, server_ports=[33000],
                              transport="RTP/AVP/UDP;unicast;client_port=46002;server_port=33000"))
        minimal = REPLY.replace(b";server_port=33000", b"").replace(b";timeout=30", b"")
        self.assertEqual(setup.setup_response(rtsp.parse(minimal)[0])["server_ports"], None)
        ranged = REPLY.replace(b"server_port=33000", b"server_port=33000-33001;mode=play")
        self.assertEqual(setup.setup_response(rtsp.parse(ranged)[0])["server_ports"], [33000, 33001])

    def test_response_rejects_redirect_or_wrong_transport(self):
        for wire in (REPLY.replace(b"200 OK", b"461 Unsupported transport"),
                     REPLY.replace(b"CSeq: 2", b"CSeq: 3"),
                     REPLY.replace(b"Session: 42;timeout=30\r\n", b""),
                     REPLY.replace(b"RTP/AVP/UDP", b"RTP/AVP/TCP"),
                     REPLY.replace(b";unicast", b";multicast"),
                     REPLY.replace(b"client_port=46002", b"client_port=46004"),
                     REPLY.replace(b"client_port=46002", b"client_port=x"),
                     REPLY.replace(b";server_port", b";destination=10.0.0.1;server_port"),
                     REPLY.replace(b";server_port=33000", b";interleaved=0-1"),
                     REPLY.replace(b";server_port=33000", b";unicast"),
                     REPLY.replace(b"server_port=33000", b"server_port=33001-33000"),
                     REPLY.replace(b"server_port=33000", b"server_port"),
                     REPLY.replace(b"server_port=33000", b"mode=record")):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                setup.setup_response(rtsp.parse(wire)[0])

    def test_rtp_header_summary_never_contains_payload(self):
        summary = setup.rtp_header(bytes([0x80, 0xa1, 0, 7]) + bytes(8) + b"SECRET")
        self.assertEqual(summary, dict(size_bytes=18, rtp=True, payload_type=33,
                                       sequence=7, timestamp=0, ssrc=0))
        self.assertEqual(setup.rtp_header(b"abc"), dict(size_bytes=3, rtp=False))


class PathTests(unittest.TestCase):
    def test_full_path_binds_rtp_then_six_sends_and_no_play(self):
        phone, result = UdpSetupPhone(), {}
        session = run(phone, result)
        self.assertNotIn("error", result)
        self.assertTrue(result["rtsp_udp_setup_verified"])
        self.assertTrue(result["rtp_observation_completed"])
        self.assertEqual(result["rtp_open"]["port"], 46002)
        self.assertEqual(result["rtp_close_status"], 0)
        self.assertEqual(result["rtsp_udp_setup"]["server_ports"], [33000])
        self.assertEqual(len(phone.rtsp_sent), 6)
        self.assertEqual(rtsp.parse(phone.rtsp_sent[5])[0]["method"], "SETUP")
        self.assertIn(b"RTP/AVP/UDP;unicast;client_port=46002", phone.rtsp_sent[5])
        self.assertFalse(any(data.startswith(b"PLAY ") for data in phone.rtsp_sent))
        self.assertEqual(result["rtp_datagrams_before_play"], 0)
        self.assertEqual(result["rtsp_bytes_after_setup"], 0)
        self.assertEqual(phone.closed[:3], [1205, 1204, 1203])
        self.assertEqual(set(session.configs), {256})
        self.assertIn(1205, session.retired_udp)
        self.assertEqual(result["wfd_cleanup_errors"], [])
        self.assertEqual(result["idc_cleanup_errors"], [])
        self.assertNotIn(KEY.hex(), str(result))

    def test_rtp_config_opened_before_m4_ack(self):
        phone, result = UdpSetupPhone(), {}
        order = []
        original = setup.WfdUdpSession.open_udp
        def open_udp(self, *args, **kwargs):
            order.append(("open", len(phone.rtsp_sent)))
            return original(self, *args, **kwargs)
        with patch.object(setup.WfdUdpSession, "open_udp", open_udp):
            run(phone, result)
        self.assertEqual(order, [("open", 3)])

    def test_unexpected_datagrams_counted_acked_and_summarized_without_payload(self):
        phone, result = UdpSetupPhone(datagrams=2), {}
        run(phone, result)
        self.assertTrue(result["rtsp_udp_setup_verified"])
        self.assertEqual(result["rtp_datagrams_before_play"], 2)
        self.assertEqual([h["sequence"] for h in result["rtp_headers_before_play"]], [0, 1])
        self.assertNotIn("SCREEN", json.dumps(result))
        self.assertNotIn(b"SCREEN".hex(), json.dumps(result))

    def test_pre_play_flood_with_real_link_budgets_keeps_cleanup_in_sync(self):
        phone, result = UdpSetupPhone(datagrams=200), {}
        link = Link(Device(phone), TimeoutError, max_requests=probe.MAX_REQUESTS,
                    max_acks=64, max_reads=2000, cleanup_reads=200)
        session = run(phone, result, link)
        self.assertIn("ack budget", result["error"])
        self.assertTrue(result["rtsp_udp_setup_verified"])
        self.assertEqual(result["rtp_close_status"], 0)
        self.assertEqual(result["rtp_cleanup_errors"], [])
        self.assertEqual(result["wfd_cleanup_errors"], [])
        self.assertEqual(result["idc_cleanup_errors"], [])
        self.assertEqual(set(session.configs), {256})
        self.assertEqual(result["rtp_datagrams_before_play"], 200)
        self.assertEqual(len(result["rtp_headers_before_play"]), 16)

    def test_wrong_m5_trigger_rejected_without_setup(self):
        phone, result = UdpSetupPhone(trigger=TRIGGER.replace(b"SETUP", b"PLAY ")), {}
        session = run(phone, result)
        self.assertIn("M5", result["error"])
        self.assertEqual(len(phone.rtsp_sent), 4)
        self.assertNotIn("rtsp_udp_setup_attempted", result)
        self.assertNotIn(1205, session.configs)

    def test_trailing_rtsp_after_setup_reply_fails(self):
        phone, result = UdpSetupPhone(reply=REPLY + b"GET_PARAMETER"), {}
        run(phone, result)
        self.assertIn("trailing", result["error"])
        self.assertNotIn("rtsp_udp_setup_verified", result)
        self.assertEqual(result["rtp_close_status"], 0)

    def test_phone_close_during_observation_fails(self):
        phone, result = UdpSetupPhone(close_after_reply=True), {}
        run(phone, result)
        self.assertIn("closed channel", result["error"])
        self.assertNotIn("rtp_observation_completed", result)
        self.assertEqual(result["rtp_close_status"], 0)

    def test_stage_deadline_capped_by_absolute_latest(self):
        phone, result = UdpSetupPhone(reply=b""), {}
        captured = {}
        original = setup.exchange
        def capped(session, *args, **kwargs):
            captured["start"] = session.clock()
            return original(session, *args, latest=session.clock() + 2)
        with patch.object(setup, "exchange", capped):
            session = run(phone, result)
        self.assertIn("deadline", result["error"])
        self.assertLess(session.clock() - captured["start"], setup.SETUP_SECONDS)
        self.assertEqual(result["rtp_close_status"], 0)

    def test_missing_reply_fails_and_still_closes_rtp_config(self):
        phone, result = UdpSetupPhone(reply=b""), {}
        session = run(phone, result)
        self.assertIn("deadline", result["error"])
        self.assertFalse(result.get("rtsp_udp_setup_verified", False))
        self.assertEqual(result["rtp_close_status"], 0)
        self.assertNotIn(1205, session.configs)
        self.assertEqual(len(phone.rtsp_sent), 6)

    def test_wrong_bound_port_stops_before_m4_ack(self):
        phone, result = UdpSetupPhone(), {}
        with patch.object(setup.WfdUdpSession, "open_udp", return_value=dict(
                status=0, config_id=1205, port=46010, client_port=0)):
            run(phone, result)
        self.assertIn("advertised port", result["error"])
        self.assertEqual(len(phone.rtsp_sent), 3)
        self.assertNotIn("rtsp_m4_reply_attempted", result)


class MainTests(unittest.TestCase):
    def run_main(self, phone):
        session, connection = opened(phone)
        runner = FakeRunner(phone)
        original_confirm = ui.confirm
        def confirm(s, m, r, log, deadline, output, bus):
            return original_confirm(s, m, r, log, deadline, output, bus, runner=runner)
        def fake_probe(device, util, timeout, output, result, after_auth, **kwargs):
            self.assertEqual(kwargs["max_requests"], 48)
            self.assertIs(kwargs["session_class"], setup.WfdUdpSession)
            client = SimpleNamespace(codec=lambda: SimpleNamespace(_key=KEY))
            after_auth(session, connection, client, result, session.clock, lambda **kw: None)
        usb, core, util = ModuleType("usb"), ModuleType("usb.core"), ModuleType("usb.util")
        core.find = lambda **kwargs: [object()]
        core.USBTimeoutError = TimeoutError
        usb.core, usb.util = core, util
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
                os.environ, {"DEX_AUTO_UI_DEADLINE": str(time.monotonic() + 60)}):
            with patch.dict("sys.modules", {"usb": usb, "usb.core": core, "usb.util": util}), \
                    patch.object(probe.auth_probe, "probe", side_effect=fake_probe), \
                    patch.object(probe.cap, "capabilities"), \
                    patch.object(probe.pss_probe, "pss_ready"), \
                    patch.object(probe.ui_confirm, "confirm", side_effect=confirm), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = probe.main(["--approved-phone-udp-setup", "--accept-persistent-state",
                                   "--bus", "3", "--address", "10", "--output", tmp + "/run"])
            result = json.loads((Path(tmp) / "run" / "result.json").read_text())
            plan = json.loads((Path(tmp) / "run" / "plan.json").read_text())
        return code, result, plan, runner, session

    def test_full_auto_main_reaches_udp_setup_without_play(self):
        phone = UdpSetupPhone()
        code, result, plan, runner, session = self.run_main(phone)
        self.assertEqual(code, 0)
        self.assertTrue(result["auto_confirmation_verified"])
        self.assertTrue(result["rtsp_udp_setup_verified"])
        self.assertFalse(result["play"])
        self.assertEqual(len(runner.commands), 4)
        self.assertEqual(len(phone.rtsp_sent), 6)
        self.assertEqual(set(session.configs), {256})
        self.assertEqual((plan["rtp_config"], plan["rtp_port"], plan["play"]), (1205, 46002, False))

    def test_source_selecting_tcp_never_reaches_setup(self):
        phone = UdpSetupPhone()
        phone.next_message = m4()   # the old TCP-interleaved selection
        self.assertIn(b"RTP/AVP/TCP;interleaved", phone.next_message)
        code, result, plan, runner, session = self.run_main(phone)
        self.assertEqual(code, 1)
        self.assertIn("outside declared profile", result["error"])
        self.assertEqual(len(phone.rtsp_sent), 3)
        self.assertNotIn("rtp_open", result)

    def test_plan_only_never_imports_usb(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB not authorized")
            return original(name, *args, **kwargs)
        for main in (probe.main, launch.main):
            with patch("builtins.__import__", guard), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 0)

    def test_launcher_refuses_changed_source_before_usb(self):
        name = next(iter(launch.EXPECTED))
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(launch.EXPECTED, {name: "0" * 64}), \
                patch.object(launch.os, "execv") as execute, \
                self.assertRaisesRegex(RuntimeError, "approved source mismatch"):
            launch.main(["--approved-phone-udp-setup", "--accept-persistent-state",
                         "--output", tmp + "/new"])
        execute.assert_not_called()

    def test_launcher_execs_udp_setup_probe(self):
        usb, core = ModuleType("usb"), ModuleType("usb.core")
        core.find = lambda **kwargs: [SimpleNamespace(bus=3, address=10)]
        usb.core = core
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
                "sys.modules", {"usb": usb, "usb.core": core}), patch.object(
                launch.socket, "create_connection"), patch.object(launch.os, "execv") as execute:
            with contextlib.redirect_stdout(io.StringIO()):
                launch.main(["--approved-phone-udp-setup", "--accept-persistent-state",
                             "--output", tmp + "/new"])
        argv = execute.call_args.args[1]
        self.assertTrue(argv[1].endswith("udp_setup_probe.py"))
        self.assertIn("--approved-phone-udp-setup", argv)
        self.assertEqual(argv[argv.index("--bus") + 1], "3")


if __name__ == "__main__":
    unittest.main()
