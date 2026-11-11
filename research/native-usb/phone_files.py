"""Files dragged out of the DeX window: phone to the viewer's PC (docs/FILE_TRANSFER.md).

The viewer's pointer leaves the picture with the button held ("DP"): IDC
SKIN_ACT DRAG_PULL. If a phone drag of files is running the phone answers, on its
own connection to the IDC listener, SKIN_ACT DRAG_START EVENT <count>; the viewer
hears "DS <count>" and starts a Windows drag. On the drop ("DD"): IDC DRAG_DROP;
the phone sends KMS NOTI FILE_SHR (FILELIST_SHR) whose Info lists HTTP URLs of
its file server. Each file is fetched over the tunnel and streamed to the viewer
("FN <i> <size> <base64 name>", "FB <base64>" ..., "FE"), then "FA" when all are
done or "FX <reason>"; finally IDC FILE_SHR FILE_SHR_FINISH stops the phone's
server. Saved results hold counts and sizes, never names or contents.
"""
import base64
from collections import Counter
import re
import struct
import time
from urllib.parse import unquote, urlsplit

import idc

LISTENER_CONFIG = 1201              # idc_handshake.LISTENER_CONFIG (inbound IDC events)
HTTP_CONFIG_FIRST = 1220            # one tunnel config per phone HTTP port
HTTP_HOST_FIRST = 51000             # fresh host port per download, never reused
START_SECONDS = 3                   # wait for DRAG_START after DRAG_PULL
LIST_QUIET_SECONDS = 1              # FILE_SHR lists arrive in parts (100 URLs each)
LIST_SECONDS = 15                   # wait for the first list after DRAG_DROP
VIEWER_CHUNK = 49152                # bytes per "FB" line
MAX_BACKLOG = 1 << 20               # viewer lines queued before reading pauses
MAX_HEADER = 16384
# The phone's file server XORs every body byte with 9 unless the PC is a Mac
# (f2.j: bArr[i] ^ 9); this sink says Windows, so bodies are XORed back.
UNMASK = bytes(b ^ 9 for b in range(256))
MAX_FILES = 1000
URL = re.compile(r"https?://[^/\s:?]+:(\d{1,5})(/[^\s?]*)")


def decrypt(key, text):
    """FILE_SHR fields: base64 of AES-CBC (the session key, main-channel IV) UTF-8 text."""
    return idc._aes_decrypt(key, base64.b64decode(text, validate=True))


def parse_item(item):
    """(port, path, name) for one FILELIST_SHR item, or None.

    Items are the phone's registration ids: [mime type]http://<ip>:<port>/<encoded
    path>[?ttl=<title>&fn=<display name>&size=<bytes>]. Title and name are not
    encoded (spaces, "&" and "?" occur), so only the URL before "?" is matched;
    the file server looks files up by that path."""
    item = item.strip()
    if not item or item.startswith("!@#$%") or "/side|sync/" in item:
        return None
    start = item.find("http://")
    if start < 0:
        return None
    url, _, query = item[start:].partition("?")
    match = URL.fullmatch(url)
    if not match or not 1 <= int(match[1]) <= 65535:
        return None
    name = None
    at = query.rfind("&fn=")
    if at >= 0 or query.startswith("fn="):
        name = re.sub(r"&size=\d*$", "", query[at + 4 if at >= 0 else 3:])
    return int(match[1]), match[2], file_name(match[2]) if not name else safe_name(name)


def file_urls(info):
    """(port, path, name) for each file in a FILELIST_SHR Info; folders are skipped."""
    out = [parsed for parsed in map(parse_item, info.split(idc.SEP + idc.SEP)) if parsed]
    return out[:MAX_FILES]


def safe_name(name):
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name).strip(" .")
    return name[:200] or "file"


def file_name(path):
    # Decode first, then keep only the last part: an encoded "/" never reaches the PC path.
    return safe_name(unquote(urlsplit(path).path))


class Download:
    """One HTTP GET over a tunnel connection; feed() returns body bytes as they come."""

    def __init__(self):
        self.header = bytearray()
        self.headers_done = False
        self.length = None
        self.received = 0
        self.error = None

    def feed(self, data):
        if self.headers_done:
            self.received += len(data)
            return data
        self.header += data
        end = self.header.find(b"\r\n\r\n")
        if end < 0:
            if len(self.header) > MAX_HEADER:
                self.error = "header too long"
            return b""
        head, body = bytes(self.header[:end]).decode("latin-1"), bytes(self.header[end + 4:])
        self.header = bytearray()
        lines = head.split("\r\n")
        status = lines[0].split(" ")
        if len(status) < 2 or status[1] != "200":
            self.error = "HTTP " + (status[1] if len(status) > 1 else "?")
            return b""
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length" and value.strip().isdigit():
                self.length = int(value.strip())
            if name.strip().lower() == "transfer-encoding" and "chunked" in value.lower():
                self.error = "chunked transfer not supported"
                return b""
        self.headers_done = True
        self.received = len(body)
        return body

    def complete(self, closed):
        return self.headers_done and (self.received >= self.length if self.length is not None else closed)


class PhoneFiles:
    def __init__(self, key, idc_command, open_http, send, close, tell_viewer, backlog,
                 log=lambda event, **fields: None, clock=time.monotonic):
        self.key, self.idc_command = key, idc_command
        self.open_http, self.send, self.close = open_http, send, close
        self.tell_viewer, self.backlog, self.log, self.clock = tell_viewer, backlog, log, clock
        self.state = "idle"
        self.deadline = None
        self.files, self.index = [], 0
        self.timestamp = None
        self.connection, self.download, self.announced = None, None, False
        self.idc_offsets = {}
        self.counts = Counter()

    def prime(self, connections):
        """Skip events already on connections that exist now (startup's SCR_SHR_ENABLED)."""
        for connection in connections:
            if connection.inbound and connection.config_id == LISTENER_CONFIG:
                self.idc_offsets[connection.host_port] = len(connection.received)

    # Viewer lines ---------------------------------------------------------
    def pull(self):
        """"DP": the pointer left the picture with the button held."""
        if self.state not in ("idle", "pulled"):
            return
        self.idc_command("SKIN_ACT", "DRAG_PULL", "REQUEST", "null")
        self.state, self.deadline = "pulled", self.clock() + START_SECONDS
        self.counts["pulls"] += 1

    def drop(self):
        """"DD": the viewer's Windows drag was dropped."""
        if self.state != "offered":
            return
        self.idc_command("SKIN_ACT", "DRAG_DROP", "REQUEST", "null")
        self.state, self.deadline = "listing", self.clock() + LIST_SECONDS
        self.files, self.timestamp = [], None
        self.counts["drops"] += 1

    def cancel(self):
        """"DC": the viewer's Windows drag ended without a drop."""
        if self.state in ("pulled", "offered"):
            self.state = "idle"
            self.counts["cancelled"] += 1

    # Phone input ----------------------------------------------------------
    def idc_frames(self, connections):
        """New IDC events on the phone's inbound connections (DRAG_START)."""
        for connection in list(connections):
            if not connection.inbound or connection.config_id != LISTENER_CONFIG:
                continue
            data = connection.received
            offset = self.idc_offsets.get(connection.host_port, 0)
            while len(data) - offset >= 2:
                end = offset + 2 + struct.unpack_from(">H", data, offset)[0]
                if end > len(data):
                    break
                try:
                    self._idc_event(idc.encrypted_message(self.key, bytes(data[offset:end])))
                except ValueError:
                    self.counts["idc_errors"] += 1
                offset = end
            self.idc_offsets[connection.host_port] = offset

    def _idc_event(self, message):
        if (message["main"], message["sub"]) != ("SKIN_ACT", "DRAG_START") or self.state != "pulled":
            return
        try:
            count = int(message["info"])
        except ValueError:
            count = 0
        if count <= 0:
            self.state = "idle"
            return
        self.state, self.deadline = "offered", None
        self.counts["offers"] += 1
        self.tell_viewer(b"DS %d\n" % min(count, MAX_FILES))
        self.log("phone_files_offered", files=count)

    def file_list(self, message):
        """KMS NOTI FILE_SHR (FILELIST_SHR) from the phone."""
        if self.state != "listing" or message.get("SubCmd") != "FILELIST_SHR":
            return
        try:
            info = decrypt(self.key, message.get("Info", ""))
            stamp = decrypt(self.key, message.get("FILE_SHR_TIMESTAMP", ""))
        except (ValueError, TypeError) as error:
            self.counts["list_errors"] += 1
            self.log("phone_files_list_error", error=type(error).__name__)
            return
        self.timestamp = stamp
        items = [item for item in info.split(idc.SEP + idc.SEP) if item.strip()]
        found = file_urls(info)
        self.files = (self.files + found)[:MAX_FILES]   # parts never add up past the cap
        # Shapes only (no names or paths): how many items, how many were files.
        self.log("phone_files_list", items=len(items), files=len(found),
                 http=sum("http://" in item for item in items),
                 query=sum("?" in item for item in items))
        # More parts may follow, unless the list is already full.
        self.deadline = self.clock() + (0 if len(self.files) >= MAX_FILES else LIST_QUIET_SECONDS)

    # Periodic work --------------------------------------------------------
    def tick(self, configs):
        now = self.clock()
        if self.state == "pulled" and now >= self.deadline:
            self.state = "idle"
        elif self.state == "listing" and now >= self.deadline:
            if not self.files:
                return self._fail("no file list from the phone")
            self.state, self.index = "downloading", 0
            self.log("phone_files_downloading", files=len(self.files))
            self._start(configs)
        elif self.state == "downloading":
            self._pump(configs)

    def _start(self, configs):
        if self.index >= len(self.files):
            self.tell_viewer(b"FA\n")
            self._finish("FILE_SHR_FINISH")
            self.counts["transfers_done"] += 1
            self.log("phone_files_received", files=len(self.files))
            return
        port, path, name = self.files[self.index]
        self.connection = self.open_http(port, configs)
        self.download, self.announced = Download(), False
        self.send(self.connection, ("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                                    % (path, port)).encode("latin-1"))

    def _pump(self, configs):
        connection, download = self.connection, self.download
        if self.backlog() > MAX_BACKLOG:
            return   # the viewer is behind; the tunnel keeps the rest in connection.received
        data = bytes(connection.received[:VIEWER_CHUNK * 4])
        del connection.received[:len(data)]
        body = (download.feed(data) if data else b"").translate(UNMASK)
        if download.error:
            return self._fail(download.error)
        if download.headers_done and not self.announced:
            self.announced = True
            size = download.length if download.length is not None else -1
            name = self.files[self.index][2].encode("utf-8")
            self.tell_viewer(b"FN %d %d %s\n" % (self.index, size, base64.b64encode(name)))
        for offset in range(0, len(body), VIEWER_CHUNK):
            self.tell_viewer(b"FB " + base64.b64encode(body[offset:offset + VIEWER_CHUNK]) + b"\n")
        self.counts["bytes"] += len(body)
        drained = getattr(connection, "closed_by_phone", False) and not connection.received
        if download.complete(drained):
            self.tell_viewer(b"FE\n")
            self.counts["files"] += 1
            self.close(connection)
            self.index += 1
            self._start(configs)
        elif drained:
            self._fail("phone closed the download")

    def _fail(self, reason):
        self.tell_viewer(b"FX " + reason.replace(" ", "_").encode("ascii", "replace")[:60] + b"\n")
        self.log("phone_files_failed", reason=reason)
        self.counts["failed"] += 1
        if self.connection is not None:
            self.close(self.connection)
        self._finish("FILE_SHR_FINISH")

    def _finish(self, sub):
        self.state, self.connection, self.download = "idle", None, None
        if self.timestamp is not None:
            self.idc_command("FILE_SHR", sub, "EVENT", "%d,%s" % (len(self.files), self.timestamp))

    def summary(self):
        return dict(self.counts, state=self.state)
