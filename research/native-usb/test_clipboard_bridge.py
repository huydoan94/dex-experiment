"""Clipboard bridge, reader lines and cursor-FIFO output; no phone or USB."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest

import clipboard_bridge as cb
import idc
import kms_daemon_live as daemon
import kms_session_live as session
from main_channel import ControlCodec, Frame, FrameDecoder, encode_frame

KEY = bytes(range(32))


class Conn:
    def __init__(self):
        self.received = bytearray()
        self.closed_by_phone = False


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.codec = ControlCodec(KEY)
        self.main, self.idc_conn = Conn(), Conn()
        self.sent = []
        self.bridge = cb.ClipboardBridge(lambda c, d: self.sent.append((c, d)), self.main,
                                         self.codec, KEY, lambda d: self.sent.append((self.idc_conn, d)))

    def phone_says(self, message, sid=7):
        self.main.received += encode_frame(Frame(sid, self.codec.encrypt(message)))

    def test_to_phone_sends_an_encrypted_notice_on_the_main_channel(self):
        self.bridge.to_phone("héllo")
        connection, wire = self.sent[0]
        self.assertIs(connection, self.main)
        frame, = FrameDecoder().feed(wire)
        self.assertEqual(frame.sid, cb.FIRST_SID)
        self.assertEqual(self.codec.decrypt(frame.payload), {"TYPE": "NOTI", "MSG": "Clipboard", "PARAM": {
            "ClipboardType": "TXT", "ClipboardData": "héllo", "ClipboardResult": "None"}})

    def test_long_text_is_cut_and_marked_over_limit(self):
        self.bridge.to_phone("x" * (cb.MAX_TEXT + 5))
        decoder, wire, frames = FrameDecoder(), self.sent[0][1], []
        for start in range(0, len(wire), 65536):
            frames += decoder.feed(wire[start:start + 65536])
        param = self.codec.decrypt(frames[0].payload)["PARAM"]
        self.assertEqual((len(param["ClipboardData"]), param["ClipboardResult"]), (cb.MAX_TEXT - 1, "OverLimit"))

    def test_request_is_an_idc_skin_action(self):
        self.assertTrue(self.bridge.request_from_phone())
        connection, wire = self.sent[0]
        self.assertIs(connection, self.idc_conn)
        self.assertEqual(idc.decode(KEY, wire), "4 3 SKIN_ACT CLIPBOARD_SHR_REQ REQUEST null")
        no_idc = cb.ClipboardBridge(lambda c, d: None, self.main, self.codec)
        self.assertFalse(no_idc.request_from_phone())
        self.assertEqual(no_idc.counts["no_idc"], 1)

    def test_closed_main_channel_sends_nothing(self):
        self.main.closed_by_phone = True
        self.bridge.to_phone("a")
        self.assertEqual(self.sent, [])

    def test_poll_returns_the_latest_phone_text_only_once(self):
        self.assertIsNone(self.bridge.poll())
        self.phone_says({"TYPE": "NOTI", "MSG": "CheckConnect"})
        self.phone_says({"TYPE": "NOTI", "MSG": "Clipboard", "PARAM": {"ClipboardType": "TXT", "ClipboardData": "one"}})
        self.phone_says({"TYPE": "NOTI", "MSG": "Clipboard", "PARAM": {
            "ClipboardType": "HTML", "ClipboardData": "<b>two</b>", "ClipboardPlainText": "two"}})
        self.phone_says({"TYPE": "NOTI", "MSG": "Clipboard", "PARAM": {"ClipboardType": "URI", "ClipboardData": "f"}})
        self.assertEqual(self.bridge.poll(), "two")
        self.assertIsNone(self.bridge.poll())
        self.assertEqual(self.bridge.counts["from_phone"], 2)
        self.assertEqual(self.bridge.counts["from_phone_skipped"], 1)

    def test_file_clip_and_dragdrop_notice(self):
        self.bridge.files_to_phone(["a.txt", "b.png"])
        frame, = FrameDecoder().feed(self.sent[0][1])
        param = self.codec.decrypt(frame.payload)["PARAM"]
        self.assertEqual((param["ClipboardType"], param["ClipboardResult"], param["ClipboardUrl"]), ("FILE", "None", ["a.txt", "b.png"]))
        self.phone_says({"TYPE": "NOTI", "MSG": "DRAGDROP", "PARAM": {"DragDropID": 4}})
        self.phone_says({"TYPE": "NOTI", "MSG": "DRAGDROP", "PARAM": {"DragDropID": "x"}})
        self.assertIsNone(self.bridge.poll())
        self.assertEqual(self.bridge.dragdrops, [4])

    def test_frames_split_across_polls_and_startup_bytes_are_skipped(self):
        main = Conn()
        main.received += b"startup bytes already read"
        bridge = cb.ClipboardBridge(lambda c, d: None, main, self.codec)
        wire = encode_frame(Frame(9, self.codec.encrypt(
            {"TYPE": "NOTI", "MSG": "Clipboard", "PARAM": {"ClipboardType": "TXT", "ClipboardData": "z"}})))
        main.received += wire[:5]
        self.assertIsNone(bridge.poll())
        main.received += wire[5:]
        self.assertEqual(bridge.poll(), "z")

    def test_broken_framing_stops_reading_without_raising(self):
        self.main.received += b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.assertIsNone(self.bridge.poll())
        self.assertIn("main channel", self.bridge.summary()["error"])


class ReaderTests(unittest.TestCase):
    def test_parse_clipboard_lines(self):
        text = "a\nb é"
        line = b"P " + base64.b64encode(text.encode())
        self.assertEqual(session.InputReader.parse(line), ("P", text))
        self.assertEqual(session.InputReader.parse(b"P "), ("P", ""))
        self.assertEqual(session.InputReader.parse(b"R"), ("R",))
        for bad in (b"P !!", b"P " + base64.b64encode(b"\xff\xfe"), b"R x", b"Px"):
            self.assertIsNone(session.InputReader.parse(bad))

    def test_long_clipboard_line_passes_but_other_long_lines_do_not(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.fifo"
            os.mkfifo(path)
            reader = session.InputReader(str(path))
            writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            try:
                text = "x" * 30000
                data = b"P " + base64.b64encode(text.encode()) + b"\nK d 30\n" + b"Z" * 40 + b"\nR\n"
                events = []
                view = memoryview(data)
                while view:
                    count = os.write(writer, view[:4096])
                    view = view[count:]
                    events += reader.events()
                for _ in range(20):
                    events += reader.events()
            finally:
                os.close(writer)
                reader.close()
        self.assertEqual(events, [("P", text), ("K", 0, 30), ("R",)])
        self.assertEqual(reader.counts["invalid"], 1)


class PumpTests(unittest.TestCase):
    def test_clipboard_events_leave_the_kms_input_path(self):
        class Reader:
            counts = {}
            def events(self):
                return [("R",), (0, 5, 5), ("P", "t")]
        s = session.SessionInput.__new__(session.SessionInput)
        s.pending, s.dropped, s.input = [], __import__("collections").Counter(), Reader()
        seen = []
        s._clipboard = seen.extend
        s._usable = lambda: False
        s._pump_input()
        self.assertEqual(seen, [("R",), ("P", "t")])
        self.assertEqual(s.dropped["no_connection"], 1)


class SessionTests(unittest.TestCase):
    def session(self):
        s = daemon.DaemonSession.__new__(daemon.DaemonSession)
        s.calls, s.logs = [], []
        s.connect = lambda port, config_id, timeout_s: s.calls.append(("connect", port, config_id)) or Conn()
        s.send = lambda c, d, timeout_s: s.calls.append(("send", len(d)))
        s.disconnect = lambda c, timeout_s: s.calls.append(("disconnect",))
        s.log = lambda event, **f: s.logs.append(event)
        s.main_connection, s.main_codec, s.idc_key = Conn(), ControlCodec(KEY), KEY
        s.dropped = __import__("collections").Counter()
        return s

    def test_each_request_uses_a_fresh_control_connection(self):
        s = self.session()
        s._clipboard([("R",), ("R",), ("P", "hi")])
        ports = [c[1] for c in s.calls if c[0] == "connect"]
        self.assertEqual(ports, [daemon.IDC_HOST_FIRST, daemon.IDC_HOST_FIRST + 1])
        self.assertTrue(all(c[2] == daemon.wfd.CONTROL_CONFIG for c in s.calls if c[0] == "connect"))
        self.assertEqual([c[0] for c in s.calls], ["connect", "send", "disconnect"] * 2 + ["send"])
        self.assertEqual(s.logs, ["clipboard_request", "clipboard_request", "clipboard_to_phone"])

    def test_a_failed_request_is_logged_not_raised(self):
        s = self.session()
        def fail(*a, **k):
            raise daemon.TunnelError("connect status 1")
        s.connect = fail
        s._clipboard([("R",), ("P", "x")])
        self.assertEqual(s.logs, ["clipboard_error", "clipboard_to_phone"])
        self.assertEqual(s.clipboard.counts["send_errors"], 1)


class RelayTests(unittest.TestCase):
    def test_clip_lines_are_written_whole_and_cursor_lines_never_inside_them(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cursor.fifo"
            os.mkfifo(path)
            reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            relay = daemon.CursorRelay(str(path))
            text = "y" * 200000
            relay.clip(text)
            relay.pending = (1002, 0)
            out = bytearray()
            for _ in range(200):
                relay.flush()
                try:
                    out += os.read(reader, 1 << 20)
                except BlockingIOError:
                    pass
                if not relay.clip_out and relay.pending is None:
                    break
                relay.pending = relay.pending or None
            relay.close()
            os.close(reader)
        lines = bytes(out).split(b"\n")
        self.assertEqual(lines[0], b"C 1002 0")
        self.assertEqual(base64.b64decode(lines[1][2:]).decode(), text)
        self.assertEqual(relay.counts["clip_sent"], 1)

    def test_long_file_lines_survive_a_full_fifo(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cursor.fifo"
            os.mkfifo(path)
            reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            relay = daemon.CursorRelay(str(path))
            sent = [b"FB " + base64.b64encode(bytes([i]) * 49152) + b"\n" for i in range(4)]
            for line in sent:
                relay.line(line)
            out = bytearray()
            for _ in range(400):
                relay.flush()
                relay.pending = (1003, 1) if relay.line_started else None  # never inside a line
                try:
                    out += os.read(reader, 30000)
                except BlockingIOError:
                    pass
                if not relay.lines and relay.pending is None:
                    break
            relay.close()
            while True:
                try:
                    chunk = os.read(reader, 1 << 20)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                out += chunk
            os.close(reader)
        got = [line + b"\n" for line in bytes(out).split(b"\n") if line.startswith(b"FB ")]
        self.assertEqual(got, sent)
        self.assertGreater(relay.counts["partial"], 0)


if __name__ == "__main__":
    unittest.main()
