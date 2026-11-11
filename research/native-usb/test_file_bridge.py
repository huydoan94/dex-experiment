"""File bridge: packets, copy/drag sequence, chunk pull; no phone or USB."""
import base64
from collections import Counter
import json
import struct
import unittest

import file_bridge as fb
import kms_daemon_live as daemon
import kms_session_live as session


def packets(wire):
    out, offset = [], 0
    while offset < len(wire):
        version, kind, size = struct.unpack_from(">BBH", wire, offset)
        out.append((kind, wire[offset + 4:offset + size]))
        offset += size
    return out


def request_json(wire):
    parts = packets(wire)
    assert parts[0][0] == 0x64 and parts[-1] == (0x66, b"")
    message_id, length, zero = struct.unpack(">IQI", parts[0][1])
    data = b"".join(body for kind, body in parts[1:-1])
    assert len(data) == length and zero == 0
    return message_id, json.loads(data)


class Harness:
    def __init__(self):
        self.kms, self.clips, self.file_wire, self.asked, self.opened = [], [], [], [], 0
        self.reports = []
        self.bridge = fb.FileBridge(self.kms.append, self.clips.append, self.open,
                                    lambda c, d: self.file_wire.append(d),
                                    lambda i, c: self.asked.append((i, c)),
                                    report=lambda f, b, d: self.reports.append((f, b, d)))

    def open(self):
        self.opened += 1
        return object()


class BridgeTests(unittest.TestCase):
    def test_copy_sequence(self):
        h = Harness()
        h.bridge.offer(fb.COPY, [("a.txt", 5), ("empty", 0), ("b.bin", 60000)])
        self.assertEqual(h.clips, [["a.txt", "empty", "b.bin"]])
        self.assertEqual(h.kms, [])
        h.bridge.dragdrop(7)
        message_id, message = request_json(h.kms[0])
        self.assertEqual(message["MSG"], "InitFileTransfer")
        param = message["PARAM"]
        self.assertEqual((param["FileOperation"], param["DragDropID"], param["FileTransferErrorCodeFromPC"]), (0, 7, 0))
        self.assertEqual(param["FileInfo"], [{"Name": "a.txt", "Size": 5}, {"Name": "empty", "Size": 0}, {"Name": "b.bin", "Size": 60000}])
        h.bridge.phone_response({"TYPE": "RESP", "MSG": "InitFileTransfer", "PARAM": dict(param, TransferID=99), "RESULT": True})
        self.assertEqual(h.opened, 0)  # another transfer's response
        h.bridge.phone_response({"TYPE": "RESP", "MSG": "InitFileTransfer", "PARAM": param, "RESULT": True})
        self.assertEqual((h.opened, h.asked), (1, [(0, 0)]))
        h.bridge.viewer_chunk(b"hello")
        first = packets(h.file_wire[0])
        self.assertEqual([k for k, _ in first], [0x28, 0x29, 0x2a])
        size, offset = struct.unpack(">QQ", first[0][1][:16])
        self.assertEqual((size, offset, first[0][1][16:], first[1][1]), (5, 0, b"a.txt", b"hello"))
        # The empty file goes out at once (start + end), then file 2 chunk 0 is asked for.
        self.assertEqual([k for k, _ in packets(h.file_wire[1])], [0x28, 0x2a])
        self.assertEqual(h.asked[-1], (2, 0))
        h.bridge.viewer_chunk(b"x" * 49152)
        self.assertEqual([k for k, _ in packets(h.file_wire[2])], [0x28, 0x29, 0x29, 0x29])
        self.assertEqual(h.asked[-1], (2, 1))
        h.bridge.viewer_chunk(b"y" * (60000 - 49152))
        self.assertEqual([k for k, _ in packets(h.file_wire[3])], [0x29, 0x2a])
        self.assertEqual(h.bridge.summary()["state"], "idle")
        self.assertEqual(h.bridge.counts["transfers_done"], 1)
        self.assertEqual(h.reports, [(0, 5, True), (1, 0, True), (2, 49152, False), (2, 60000, True)])

    def test_unanswered_clip_is_resent_then_given_up(self):
        now = [0.0]
        h = Harness()
        h.bridge.clock = lambda: now[0]
        h.bridge.offer(fb.COPY, [("a", 1)])
        for step in range(1, 6):
            now[0] = step * fb.CLIP_RETRY_SECONDS + .1
            h.bridge.tick()
        self.assertEqual(len(h.clips), fb.CLIP_TRIES)
        self.assertEqual(h.bridge.state, "idle")
        h2 = Harness()
        h2.bridge.clock = lambda: now[0]
        h2.bridge.offer(fb.COPY, [("a", 1)])
        h2.bridge.dragdrop(3)
        now[0] += 100
        h2.bridge.tick()
        self.assertEqual(len(h2.clips), 1)

    def test_drag_sends_the_request_at_once_without_a_clip(self):
        h = Harness()
        h.bridge.offer(fb.DRAG, [("p.png", 3)])
        _, message = request_json(h.kms[0])
        self.assertEqual(message["PARAM"]["FileOperation"], 1)
        self.assertNotIn("DragDropID", message["PARAM"])
        self.assertEqual(h.clips, [])

    def test_cancelled_drag_empties_the_phone_list_and_sends_nothing(self):
        h = Harness()
        h.bridge.offer(fb.DRAG, [("p.png", 3)])
        first = h.bridge.transfer_id
        h.bridge.cancel_drag()
        _, message = request_json(h.kms[1])
        self.assertEqual((message["PARAM"]["FileOperation"], message["PARAM"]["FileInfo"]), (1, []))
        h.bridge.phone_response({"MSG": "InitFileTransfer", "PARAM": {"TransferID": first}, "RESULT": True})
        self.assertEqual((h.opened, h.asked, h.bridge.state), (0, [], "idle"))
        self.assertEqual(session.InputReader.parse(b"FC"), ("FC",))
        h.bridge.cancel_drag()
        self.assertEqual(len(h.kms), 2)  # nothing to cancel any more

    def test_refusal_and_bad_chunks_return_to_idle(self):
        h = Harness()
        h.bridge.offer(fb.DRAG, [("p", 3)])
        tid = h.bridge.transfer_id
        h.bridge.phone_response({"MSG": "InitFileTransfer", "PARAM": {"TransferID": tid}, "RESULT": False, "REASON": "413"})
        self.assertEqual((h.bridge.state, h.opened), ("idle", 0))
        h.bridge.offer(fb.DRAG, [("p", 3)])
        h.bridge.phone_response({"MSG": "InitFileTransfer", "PARAM": {"TransferID": h.bridge.transfer_id}, "RESULT": True})
        h.bridge.viewer_chunk(b"toolong")
        self.assertEqual(h.bridge.state, "idle")
        self.assertEqual(h.bridge.counts["failed"], 1)

    def test_limits(self):
        h = Harness()
        h.bridge.offer(fb.COPY, [])
        h.bridge.offer(5, [("a", 1)])
        h.bridge.offer(fb.COPY, [("a", 1)] * (fb.MAX_FILES + 1))
        self.assertEqual(h.bridge.counts["offers_refused"], 3)


class ReaderTests(unittest.TestCase):
    def test_file_lines(self):
        offer = base64.b64encode(json.dumps([["a b.txt", 5], ["c", 0]]).encode())
        self.assertEqual(session.InputReader.parse(b"FO 0 " + offer), ("FO", 0, [("a b.txt", 5), ("c", 0)]))
        self.assertEqual(session.InputReader.parse(b"B " + base64.b64encode(b"data")), ("B", b"data"))
        self.assertEqual(session.InputReader.parse(b"BX"), ("BX",))
        for bad in ([["../x", 1]], [["a/b", 1]], [["", 1]], [["a", -1]], [["a", "1"]], []):
            self.assertIsNone(session.InputReader.parse(b"FO 1 " + base64.b64encode(json.dumps(bad).encode())))
        self.assertIsNone(session.InputReader.parse(b"FO 2 " + offer))
        self.assertIsNone(session.InputReader.parse(b"B " + base64.b64encode(b"x" * 49153)))

    def test_file_drag_mouse_events_pass(self):
        for code in (13, 9, 10):
            self.assertEqual(session.InputReader.parse(b"M %d 960 540" % code)[0], code)


class RelayTests(unittest.TestCase):
    def test_relay_collects_init_responses_and_queues_requests(self):
        relay = daemon.CursorRelay("/nonexistent")
        body = json.dumps({"TYPE": "RESP", "MSG": "InitFileTransfer", "RESULT": True}).encode()
        wire = (struct.pack(">BBH", 3, 0x67, 20) + struct.pack(">IQI", 1, len(body), 0)
                + struct.pack(">BBH", 3, 0x68, 4 + len(body)) + body + struct.pack(">BBH", 3, 0x69, 4))
        relay.feed(wire)
        self.assertEqual(relay.file_messages[0]["MSG"], "InitFileTransfer")
        relay.line(b"G 0 0\n")
        self.assertEqual(list(relay.lines), [b"G 0 0\n"])


class SessionTests(unittest.TestCase):
    def test_file_events_reach_the_bridge_and_errors_stay_inside(self):
        s = daemon.DaemonSession.__new__(daemon.DaemonSession)
        s.dropped = Counter()
        seen = []

        class Bridge:
            def offer(self, op, files): seen.append(("FO", op, files))
            def viewer_chunk(self, data): raise daemon.TunnelError("usb gone")
            def viewer_failed(self, reason="viewer"): seen.append(("failed", reason))
        s.files = Bridge()
        s._files([("FO", 0, [("a", 1)]), ("B", b"z"), ("BX",)])
        self.assertEqual(seen, [("FO", 0, [("a", 1)]), ("failed", "send: usb gone"), ("failed", "viewer")])


if __name__ == "__main__":
    unittest.main()
