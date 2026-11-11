"""Files from the viewer's PC to the phone, the way SamsungDeX.exe sends them.

See docs/FILE_TRANSFER.md. Copy (FileOperation 0): a main-channel FILE clip,
the phone's DRAGDROP id, then a KMS InitFileTransfer request the phone keeps
until the user pastes in a DeX-aware app. Drag (FileOperation 1): the request
goes out at once and the phone starts a drag of the named files. Either way the
phone's InitFileTransfer response (RESULT true) starts the transfer: per file a
start, 16 KiB data and end packet on the file socket (phone port 30831). File
bytes are pulled from the viewer chunk by chunk ("G <file> <chunk>" asked,
"B <base64>" answered), so the backend machine never holds a whole file.
Saved results hold counts and sizes, never names or contents.
"""
from collections import Counter
import json
import struct
import time

from sidesync_packets import encode

FILE_PORT = 30831
FILE_CONFIG, FILE_HOST = 1209, 50009     # clear of the startup configs and host ports
PHONE_CHUNK = 16384                       # 0x29 body, as the PC app sends
VIEWER_CHUNK = 49152                      # bytes per "B" line from the viewer
MAX_FILES = 1000                          # the PC app refuses more
COPY, DRAG = 0, 1
# A FILE clip sent before the phone is ready gets no DRAGDROP: resend it.
CLIP_RETRY_SECONDS, CLIP_TRIES = 3, 5
# The phone's DeX app keeps its drag operations (r2.k: a map by TransferID plus a
# 25-entry history whose eviction removes that ID from the map) for as long as its
# process lives, across our sessions. A TransferID reused soon after an earlier
# session's same ID is evicted together with that old entry, and the drop then fails
# ("FILE OPERATION ID DOESN'T EXIST", phone log 2026-11-11). IDs therefore continue
# across sessions (saved_transfer_id / save_transfer_id) instead of restarting at 1.
MAX_TRANSFER_ID = 999


def saved_transfer_id(path):
    """The last TransferID used, or 0 when none was saved (or it cannot be read)."""
    try:
        value = int(path.read_text().strip())
    except (OSError, ValueError, AttributeError):
        return 0
    return value if 0 <= value <= MAX_TRANSFER_ID else 0


def save_transfer_id(path, value):
    """Best effort: a failed save only means the next session may reuse recent IDs."""
    if path is None:
        return
    try:
        temporary = path.with_name(path.name + ".new")
        temporary.write_text("%d\n" % value)
        temporary.replace(path)
    except OSError:
        pass
COMMON_REQUEST = (0x64, 0x65, 0x66)       # start, body, end (commonMessageStart/Buffer/End)
FILE_START, FILE_DATA, FILE_END = 0x28, 0x29, 0x2a


def common_request(message_id, message):
    data = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    start, body, end = COMMON_REQUEST
    wire = [encode(start, struct.pack(">IQI", message_id, len(data), 0))]
    for offset in range(0, len(data), 16000):
        wire.append(encode(body, data[offset:offset + 16000]))
    wire.append(encode(end, b""))
    return b"".join(wire)


def file_start(size, name):
    # Protocol >= 2 (the event socket runs version 3): size, data offset (0 = new file), name.
    return encode(FILE_START, struct.pack(">QQ", size, 0) + name.encode("utf-8"))


class FileBridge:
    def __init__(self, send_kms, send_clip_files, open_file_socket, send_file, ask_viewer,
                 log=lambda event, **fields: None, clock=None, report=lambda file, delivered, done: None,
                 transfer_id=0, remember=lambda transfer_id: None):
        self.send_kms, self.send_clip_files = send_kms, send_clip_files
        self.open_file_socket, self.send_file = open_file_socket, send_file
        self.ask_viewer, self.log = ask_viewer, log
        # report(file, bytes delivered to the phone, file finished): after each USB send
        # the phone accepted, so the viewer's progress shows delivery, not disk reads.
        self.report = report
        self.state = "idle"
        self.files, self.op = [], COPY
        self.transfer_id, self.message_id = transfer_id, 0
        self.remember = remember   # remember(transfer_id) after each new TransferID
        self.dragdrop_id = None
        self.index = self.chunk = self.sent = 0
        self.connection = None
        self.counts = Counter()
        self.clock = clock or time.monotonic
        self.clip_due, self.clip_tries = None, 0

    def offer(self, op, files):
        """The viewer copied (op 0) or dropped (op 1) files: [(name, size), ...]."""
        if op not in (COPY, DRAG) or not 0 < len(files) <= MAX_FILES:
            self.counts["offers_refused"] += 1
            return
        self.files, self.op = list(files), op
        self._next_transfer_id()
        self.dragdrop_id = None
        self.counts["offers"] += 1
        self.log("files_offered", operation=op, files=len(files), bytes=sum(s for _, s in files))
        if op == COPY:
            self.state = "wait_dragdrop"
            self.clip_tries = 1
            self.clip_due = self.clock() + CLIP_RETRY_SECONDS
            self.send_clip_files([name for name, _ in files])
        else:
            self._init()

    def tick(self):
        """Resend an unanswered FILE clip (called with the session's periodic work)."""
        if self.state != "wait_dragdrop" or self.clip_due is None or self.clock() < self.clip_due:
            return
        if self.clip_tries >= CLIP_TRIES:
            self.state, self.clip_due = "idle", None
            self.counts["clip_unanswered"] += 1
            self.log("files_unanswered", tries=self.clip_tries)
            return
        self.clip_tries += 1
        self.clip_due = self.clock() + CLIP_RETRY_SECONDS
        self.counts["clip_resent"] += 1
        self.send_clip_files([name for name, _ in self.files])

    def dragdrop(self, dragdrop_id):
        """The phone's main-channel DRAGDROP notice after a FILE clip."""
        if self.state != "wait_dragdrop":
            return
        self.dragdrop_id = dragdrop_id
        self._init()

    def _init(self):
        param = {"FileOperation": self.op, "TransferID": self.transfer_id,
                 "FileTransferErrorCodeFromPC": 0,
                 "FileInfo": [{"Name": name, "Size": size} for name, size in self.files]}
        if self.op == COPY:
            param["DragDropID"] = self.dragdrop_id
        self.message_id = self.message_id % 999 + 1
        self.send_kms(common_request(self.message_id, {"TYPE": "REQ", "MSG": "InitFileTransfer", "PARAM": param}))
        self.state = "wait_phone"
        self.counts["init_requests"] += 1

    def phone_response(self, message):
        """The phone's KMS InitFileTransfer response: the user pasted or dropped."""
        param = message.get("PARAM") if isinstance(message.get("PARAM"), dict) else {}
        if self.state != "wait_phone" or param.get("TransferID") != self.transfer_id:
            self.counts["responses_ignored"] += 1
            return
        if message.get("RESULT") is not True:
            self.state = "idle"
            self.counts["refused_by_phone"] += 1
            self.log("files_refused", reason=str(message.get("REASON"))[:40])
            return
        if self.connection is None or getattr(self.connection, "closed_by_phone", False):
            self.connection = self.open_file_socket()
        self.state = "sending"
        self.index = self.chunk = self.sent = 0
        self.log("files_sending", files=len(self.files))
        self._next()

    def _next(self):
        while self.state == "sending":
            if self.index >= len(self.files):
                self.state = "idle"
                self.counts["transfers_done"] += 1
                self.log("files_sent", files=len(self.files))
                return
            name, size = self.files[self.index]
            if size == 0:
                self.send_file(self.connection, file_start(0, name) + encode(FILE_END, b""))
                self.report(self.index, 0, True)
                self.index += 1
                continue
            self.ask_viewer(self.index, self.chunk)
            return

    def viewer_chunk(self, data):
        """One "B" line: the next bytes of the current file."""
        if self.state != "sending":
            self.counts["chunks_ignored"] += 1
            return
        name, size = self.files[self.index]
        if not data or self.sent + len(data) > size:
            return self.viewer_failed("bad chunk")
        wire = file_start(size, name) if self.chunk == 0 else b""
        wire += b"".join(encode(FILE_DATA, data[i:i + PHONE_CHUNK]) for i in range(0, len(data), PHONE_CHUNK))
        self.sent += len(data)
        self.chunk += 1
        self.counts["bytes"] += len(data)
        file, delivered, done = self.index, self.sent, self.sent == size
        if done:
            wire += encode(FILE_END, b"")
            self.index, self.chunk, self.sent = self.index + 1, 0, 0
            self.counts["files"] += 1
        self.send_file(self.connection, wire)
        self.report(file, delivered, done)
        self._next()

    def cancel_drag(self):
        """The viewer's drag left the picture: empty the phone's drag list so the next drop
        (10) ends as a cancel (e2/h q: no files -> ACTION_CANCEL), and forget this transfer."""
        if self.op != DRAG or self.state not in ("wait_phone", "sending"):
            return
        self._next_transfer_id()
        self.message_id = self.message_id % 999 + 1
        self.send_kms(common_request(self.message_id, {"TYPE": "REQ", "MSG": "InitFileTransfer", "PARAM": {
            "FileOperation": DRAG, "TransferID": self.transfer_id, "FileTransferErrorCodeFromPC": 0, "FileInfo": []}}))
        self.state = "idle"
        self.counts["drags_cancelled"] += 1
        self.log("files_drag_cancelled")

    def _next_transfer_id(self):
        self.transfer_id = self.transfer_id % MAX_TRANSFER_ID + 1
        self.remember(self.transfer_id)

    def viewer_failed(self, reason="viewer"):
        if self.state != "idle":
            self.log("files_failed", reason=reason, at_file=self.index)
        self.state = "idle"
        self.counts["failed"] += 1

    def summary(self):
        return dict(self.counts, state=self.state)
