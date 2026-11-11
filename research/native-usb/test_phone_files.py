"""Drag out of the picture: phone files to the viewer; no phone or USB."""
import base64
import struct
import unittest

import idc
import kms_session_live as session
import phone_files as pf

KEY = bytes(range(32))


class Conn:
    def __init__(self, host_port=0, inbound=False, config_id=0):
        self.host_port, self.inbound, self.config_id = host_port, inbound, config_id
        self.received = bytearray()
        self.closed_by_phone = False


def enc(text):
    return base64.b64encode(idc._aes_encrypt(KEY, text)).decode()


class Harness:
    def __init__(self):
        self.now = 0.0
        self.idc, self.viewer, self.sent, self.closed, self.opened = [], [], [], [], []
        self.http = []
        self.backlog = 0
        self.bridge = pf.PhoneFiles(KEY, lambda *a: self.idc.append(a), self.open, self.send, self.closed.append,
                                    self.viewer.append, lambda: self.backlog, clock=lambda: self.now)

    def open(self, port, configs):
        conn = Conn(51000 + len(self.http))
        self.opened.append(port)
        self.http.append(conn)
        return conn

    def send(self, conn, data):
        self.sent.append((conn, data))

    def phone_event(self, conn, text):
        conn.received += idc.encode(KEY, text)


class Tests(unittest.TestCase):
    def test_file_urls_skip_folders_and_markers(self):
        info = idc.SEP.join(["http://127.0.0.1:8090/storage/a%20b.jpg", "", "!@#$%/storage/x",
                             "", "http://127.0.0.1:8090/storage/dir/side|sync/", "", "http://h:9/c.txt"])
        self.assertEqual(pf.file_urls(info), [(8090, "/storage/a%20b.jpg", "a b.jpg"), (9, "/c.txt", "c.txt")])
        self.assertEqual(pf.file_name("/storage/a%20b.jpg"), "a b.jpg")
        # The phone's registration ids: a MIME type in front, an unencoded query behind.
        ids = idc.SEP.join([
            "application/pdfhttp://127.0.0.1:41234/external/file/1234?ttl=My & doc?&fn=My & doc?.pdf&size=5120",
            "", "image/jpeghttp://0.0.0.0:41234/external/images/media/77?fn=../x/IMG 1.jpg",
            "", "http://null:41234/storage/emulated/0/Download/a.txt?ttl=a&size=3",
            "", "https://example.invalid/remote.bin", "", "text/plain"])
        self.assertEqual(pf.file_urls(ids), [(41234, "/external/file/1234", "My & doc_.pdf"),
                                             (41234, "/external/images/media/77", "IMG 1.jpg"),
                                             (41234, "/storage/emulated/0/Download/a.txt", "a.txt")])
        self.assertEqual(pf.file_name("/x/..%2F..%2Fevil"), "evil")
        self.assertEqual(pf.file_name("/x/"), "file")

    def test_download_parses_headers_and_length(self):
        d = pf.Download()
        self.assertEqual(d.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"), b"")
        self.assertEqual(d.feed(b"\r\nhel"), b"hel")
        self.assertFalse(d.complete(False))
        self.assertEqual(d.feed(b"lo"), b"lo")
        self.assertTrue(d.complete(False))
        bad = pf.Download()
        bad.feed(b"HTTP/1.1 404 Not Found\r\n\r\n")
        self.assertEqual(bad.error, "HTTP 404")

    def test_full_drag_out(self):
        h = Harness()
        startup = Conn(65535, True, pf.LISTENER_CONFIG)
        h.phone_event(startup, idc.command_text("SKIN_ACT", "DRAG_START", "EVENT", "9", 1))
        h.bridge.prime([startup])           # an old event is not an answer
        h.bridge.pull()
        self.assertEqual(h.idc[-1], ("SKIN_ACT", "DRAG_PULL", "REQUEST", "null"))
        h.bridge.idc_frames([startup])
        self.assertEqual(h.viewer, [])
        event = Conn(65534, True, pf.LISTENER_CONFIG)
        h.phone_event(event, idc.command_text("SKIN_ACT", "DRAG_START", "EVENT", "2", 5))
        h.bridge.idc_frames([startup, event])
        self.assertEqual(h.viewer, [b"DS 2\n"])
        h.bridge.drop()
        self.assertEqual(h.idc[-1], ("SKIN_ACT", "DRAG_DROP", "REQUEST", "null"))
        info = idc.SEP.join(["http://127.0.0.1:8090/p/one.txt", "", "http://127.0.0.1:8090/p/two.bin"])
        h.bridge.file_list({"TYPE": "NOTI", "MSG": "FILE_SHR", "SubCmd": "FILELIST_SHR",
                            "Info": enc(info), "FILE_SHR_TIMESTAMP": enc("20261111123000")})
        h.bridge.tick({})
        self.assertEqual(h.opened, [])      # waits for more list parts
        h.now += pf.LIST_QUIET_SECONDS + .1
        h.bridge.tick({})
        self.assertEqual(h.opened, [8090])
        self.assertTrue(h.sent[0][1].startswith(b"GET /p/one.txt HTTP/1.1\r\n"))
        h.http[0].received += b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + b"abc".translate(pf.UNMASK)
        h.bridge.tick({})
        self.assertEqual(h.viewer[1:4], [b"FN 0 3 " + base64.b64encode(b"one.txt") + b"\n",
                                         b"FB " + base64.b64encode(b"abc") + b"\n", b"FE\n"])
        self.assertEqual(h.closed, [h.http[0]])
        self.assertEqual(h.opened, [8090, 8090])
        body = bytes(range(256)) * 470
        h.http[1].received += b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body.translate(pf.UNMASK)
        h.backlog = pf.MAX_BACKLOG + 1
        h.bridge.tick({})
        self.assertEqual(len(h.viewer), 4)  # paused while the viewer is behind
        h.backlog = 0
        for _ in range(5):
            h.bridge.tick({})
        got = b"".join(base64.b64decode(line[3:-1]) for line in h.viewer if line.startswith(b"FB "))
        self.assertEqual(got, b"abc" + body)
        self.assertEqual(h.viewer[-2:], [b"FE\n", b"FA\n"])
        self.assertEqual(h.idc[-1], ("FILE_SHR", "FILE_SHR_FINISH", "EVENT", "2,20261111123000"))
        self.assertEqual(h.bridge.state, "idle")

    def test_no_drag_on_the_phone_and_failures(self):
        h = Harness()
        h.bridge.pull()
        h.now += pf.START_SECONDS + .1
        h.bridge.tick({})
        self.assertEqual(h.bridge.state, "idle")
        h.bridge.pull()
        conn = Conn(65530, True, pf.LISTENER_CONFIG)
        h.phone_event(conn, idc.command_text("SKIN_ACT", "DRAG_START", "EVENT", "0", 2))
        h.bridge.idc_frames([conn])
        self.assertEqual((h.bridge.state, h.viewer), ("idle", []))
        h.bridge.pull()
        conn2 = Conn(65529, True, pf.LISTENER_CONFIG)
        h.phone_event(conn2, idc.command_text("SKIN_ACT", "DRAG_START", "EVENT", "1", 3))
        h.bridge.idc_frames([conn, conn2])
        h.bridge.drop()
        h.now += pf.LIST_SECONDS + 1
        h.bridge.tick({})
        self.assertEqual(h.viewer[-1], b"FX no_file_list_from_the_phone\n")
        h.bridge.cancel()
        self.assertEqual(h.bridge.state, "idle")

    def test_reader_lines(self):
        for line in (b"DP", b"DD", b"DC"):
            self.assertEqual(session.InputReader.parse(line), (line.decode(),))


if __name__ == "__main__":
    unittest.main()
