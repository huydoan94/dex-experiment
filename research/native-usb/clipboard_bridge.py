"""Clipboard text between the viewer and the phone, the way SamsungDeX.exe does it.

PC -> phone: a main-channel NOTI "Clipboard" with PARAM {ClipboardType "TXT",
  ClipboardData, ClipboardResult}. DeXonPC l2/g receiveMsg "Clipboard" -> l2/b.j
  sets the phone's primary clip ("None" sets it, "OverLimit" sets it with a
  "partly copied" notice, "ExceedSize" does not set it).
phone -> PC: the IDC command "SKIN_ACT CLIPBOARD_SHR_REQ" (o2/e skin action 6 ->
  l2/b.o) makes the phone send its latest clip as a main-channel NOTI "Clipboard"
  {ClipboardType TXT|HTML|URI, ClipboardData, ClipboardPlainText}. SamsungDeX.exe
  asks when the user leaves its window; the viewer does the same.
Text only. Saved results hold counts and sizes, never clipboard text.
"""
from collections import Counter

import idc
from main_channel import Frame, FrameDecoder, ProtocolError, encode_frame

# l2/b.o cuts phone text to 131071 characters; the PC side marks a longer text OverLimit.
MAX_TEXT = 131072
MSG = "Clipboard"
FIRST_SID, LAST_SID = 100, 999      # main-channel host SIDs after AUTH/TerminalInfo/PSS
FIRST_SEQ, LAST_SEQ = 3, 32760      # IDC sequence numbers after SIDESYNC_CONN (1), ENABLE_SCR_SHR (2)


class ClipboardBridge:
    def __init__(self, send, main, codec, idc_key=None, idc_send=None):
        self.send = send                # send(connection, data) -> raises on failure
        self.main, self.codec = main, codec
        # idc_send(payload): one IDC command on its own connection to the phone's
        # control port, as the phone's TcpServer takes one command per socket.
        self.idc_key, self.idc_send = idc_key, idc_send
        self.sid, self.seq = FIRST_SID, FIRST_SEQ
        # Only frames that arrive from now on; the startup exchange is already read.
        self.offset = len(main.received)
        self.decoder = FrameDecoder()
        self.counts = Counter()
        self.error = None
        self.last_text_bytes = 0
        self.dragdrops = []             # phone DRAGDROP ids after a FILE clip (file_bridge)

    def to_phone(self, text):
        """Set the phone's clipboard to text (the viewer copied it on the PC)."""
        if getattr(self.main, "closed_by_phone", False):
            self.counts["main_closed"] += 1
            return
        result = "None"
        if len(text) > MAX_TEXT:
            text, result = text[:MAX_TEXT - 1], "OverLimit"
            self.counts["truncated"] += 1
        message = {"TYPE": "NOTI", "MSG": MSG, "PARAM": {
            "ClipboardType": "TXT", "ClipboardData": text, "ClipboardResult": result}}
        wire = encode_frame(Frame(self.sid, self.codec.encrypt(message)))
        self.sid = self.sid + 1 if self.sid < LAST_SID else FIRST_SID
        self.send(self.main, wire)
        self.counts["to_phone"] += 1
        self.last_text_bytes = len(text.encode("utf-8"))

    def files_to_phone(self, names):
        """A FILE clip naming the viewer's copied files (file_bridge); the phone answers DRAGDROP."""
        message = {"TYPE": "NOTI", "MSG": MSG, "PARAM": {
            "ClipboardType": "FILE", "ClipboardData": "", "ClipboardResult": "None", "ClipboardUrl": list(names)}}
        wire = encode_frame(Frame(self.sid, self.codec.encrypt(message)))
        self.sid = self.sid + 1 if self.sid < LAST_SID else FIRST_SID
        self.send(self.main, wire)
        self.counts["file_clips"] += 1

    def request_from_phone(self):
        """Ask the phone to send its clipboard (the viewer left the DeX window)."""
        if self.idc_key is None or self.idc_send is None:
            self.counts["no_idc"] += 1
            return False
        wire = idc.encode(self.idc_key, idc.command_text(
            "SKIN_ACT", "CLIPBOARD_SHR_REQ", "REQUEST", "null", self.seq))
        self.seq = self.seq + 1 if self.seq < LAST_SEQ else FIRST_SEQ
        self.idc_send(wire)
        self.counts["requests"] += 1
        return True

    def poll(self):
        """The phone's latest clipboard text received since the last poll, or None."""
        if self.error is not None or len(self.main.received) <= self.offset:
            return None
        chunk = bytes(self.main.received[self.offset:])
        self.offset = len(self.main.received)
        latest = None
        try:
            for start in range(0, len(chunk), 65536):
                for frame in self.decoder.feed(chunk[start:start + 65536]):
                    text = self._text(frame)
                    if text is not None:
                        latest = text
        except ProtocolError as error:
            # Main-channel framing lost: stop reading it; the session itself is unaffected.
            self.error = "main channel: " + str(error)
        return latest

    def _text(self, frame):
        try:
            message = self.codec.decrypt(frame.payload)
        except ProtocolError:
            self.counts["undecodable"] += 1
            return None
        if not isinstance(message, dict) or message.get("TYPE") != "NOTI":
            return None
        if message.get("MSG") == "DRAGDROP":
            param = message.get("PARAM")
            dragdrop = param.get("DragDropID") if isinstance(param, dict) else None
            if type(dragdrop) is int:
                self.dragdrops.append(dragdrop)
            return None
        if message.get("MSG") != MSG:
            return None
        param = message.get("PARAM")
        if not isinstance(param, dict):
            return None
        kind = param.get("ClipboardType")
        text = param.get("ClipboardPlainText") if kind == "HTML" else param.get("ClipboardData")
        if kind not in ("TXT", "HTML") or not isinstance(text, str) or not text:
            self.counts["from_phone_skipped"] += 1
            return None
        self.counts["from_phone"] += 1
        return text[:MAX_TEXT]

    def summary(self):
        return dict(self.counts, error=self.error)
