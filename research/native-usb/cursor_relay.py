"""Phone notices to the viewer over cursor.fifo: cursor shapes, clipboard text,
file requests and file lines (moved from kms_daemon_live, 2026-11-11).
"""
import base64
from collections import Counter,deque
import errno
import json
import os
import stat
import time

from sidesync_packets import VERSION

# The phone app (DeXonPC e2/v MouseIconChangedListener -> e2/s.u) reports every
# pointer-shape change as a KMS common message {"TYPE":"NOTI","MSG":
# "MOUSE_CURSOR_CHANGE","PARAM":{"MOUSE_CURSOR_ID":<Android PointerIcon type>,
# "IS_NIGHT_MODE":bool}}, framed commonMessageStart/Buffer/End as kms_hover_live
# records them at startup (request 0x64-0x66, response 0x67-0x69).
CURSOR_MSG="MOUSE_CURSOR_CHANGE"
COMMON_START,COMMON_BODY,COMMON_END=(0x64,0x67),(0x65,0x68),(0x66,0x69)
MAX_COMMON_BYTES=16384
CURSOR_OPEN_RETRY_SECONDS=.5


class CursorRelay:
    """Forwards the phone's cursor-shape notices to cursor.fifo beside the input FIFO.

    Cosmetic only: it never raises into the session. Only the latest shape waits
    while no gateway reader is attached; saved results hold counts and the last id."""
    def __init__(self,path,clock=time.monotonic):
        self.path,self.clock=path,clock
        self.offset=0
        self.body=None
        self.error=None
        self.fd=None
        self.next_open=0
        self.pending=None
        self.last_sent=None
        self.counts=Counter()
        # Phone clipboard text for the viewer: one "V <base64>" line, written in pieces
        # (a FIFO takes at most its buffer at once); only the latest waits behind it.
        self.clip_out=bytearray()
        self.clip_started=False
        self.clip_next=None
        # File transfer (file_bridge): the phone's InitFileTransfer responses, and the
        # short "G <file> <chunk>" requests for the viewer, in order.
        self.file_messages=[]
        self.lines=deque()
        self.line_started=False
        self.seen=[]
        self.share_messages=[]

    def clip(self,text):
        line=b"V "+base64.b64encode(text.encode("utf-8"))+b"\n"
        if self.clip_started:
            self.clip_next=line
        else:
            self.clip_out=bytearray(line)
        self.counts["clip_queued"]+=1

    def feed(self,data):
        """Consume complete SideSync frames of the KMS byte stream from self.offset."""
        while self.error is None and len(data)-self.offset>=4:
            start=self.offset
            kind=data[start+1]
            size=int.from_bytes(data[start+2:start+4],"big")
            if data[start]!=VERSION or size<4:
                self.error="invalid frame header"
                return
            if len(data)-start<size:
                return
            if kind in COMMON_START:
                self.body=bytearray()
            elif kind in COMMON_BODY and self.body is not None:
                self.body+=data[start+4:start+size]
                if len(self.body)>MAX_COMMON_BYTES:
                    self.body=None
                    self.counts["oversized"]+=1
            elif kind in COMMON_END and self.body is not None:
                self._message(bytes(self.body))
                self.body=None
            self.offset=start+size

    def _message(self,raw):
        try:
            message=json.loads(raw.decode("utf-8"))
        except ValueError:
            return
        if isinstance(message,dict):
            # Names only (diagnostics for file transfer); never parameters.
            self.seen.append("%s %s"%(str(message.get("TYPE"))[:8],str(message.get("MSG"))[:40]))
        if isinstance(message,dict) and message.get("MSG")=="FILE_SHR":
            self.share_messages.append(message)
            return
        if isinstance(message,dict) and message.get("MSG")=="InitFileTransfer" and message.get("TYPE")=="RESP":
            self.file_messages.append(message)
            return
        if not isinstance(message,dict) or message.get("MSG")!=CURSOR_MSG:
            return
        param=message.get("PARAM")
        shape=param.get("MOUSE_CURSOR_ID") if isinstance(param,dict) else None
        if type(shape) is not int or not 0<=shape<=99999:
            self.counts["invalid"]+=1
            return
        self.counts["changes"]+=1
        self.pending=(shape,1 if param.get("IS_NIGHT_MODE") is True else 0)

    def line(self,data):
        self.lines.append(data)

    def flush(self):
        if (self.pending is None and not self.clip_out and not self.lines) or self.error is not None:
            return
        try:
            if self.fd is None:
                now=self.clock()
                if now<self.next_open:
                    return
                self.next_open=now+CURSOR_OPEN_RETRY_SECONDS
                try:
                    fd=os.open(self.path,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
                except OSError as error:
                    if error.errno in (errno.ENXIO,errno.ENOENT):
                        self.counts["no_reader"]+=1
                        return
                    raise
                if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                    os.close(fd)
                    raise OSError("cursor path is not a FIFO")
                self.fd=fd
            try:
                # A cursor line never goes inside a partly written clipboard line.
                if self.pending is not None and not self.clip_started and not self.line_started:
                    os.write(self.fd,b"C %d %d\n"%self.pending)
                    self.counts["sent"]+=1
                    self.last_sent,self.pending=self.pending,None
                # A file line can be 64 KiB: the FIFO may take part of it; the rest goes
                # first next time, before any other line.
                while self.lines and not self.clip_started:
                    head=self.lines[0]
                    count=os.write(self.fd,head)
                    if count<len(head):
                        self.lines[0]=head[count:]
                        self.line_started=True
                        self.counts["partial"]+=1
                        return
                    self.lines.popleft()
                    self.line_started=False
                    self.counts["lines_sent"]+=1
                while self.clip_out and not self.line_started:
                    count=os.write(self.fd,bytes(self.clip_out[:65536]))
                    del self.clip_out[:count]
                    self.clip_started=bool(self.clip_out)
                    if not self.clip_out:
                        self.counts["clip_sent"]+=1
                        if self.clip_next is not None:
                            self.clip_out,self.clip_next=bytearray(self.clip_next),None
            except BlockingIOError:
                self.counts["full"]+=1
                return
            except BrokenPipeError:
                self.close()
                self.counts["reader_left"]+=1
                # The next reader must not start inside a half-written line.
                if self.clip_started:
                    self.clip_out,self.clip_started=bytearray(),False
                if self.line_started:
                    self.lines.popleft()
                    self.line_started=False
                return
        except OSError as error:
            self.error=type(error).__name__
            self.close()

    def close(self):
        if self.fd is not None:
            fd,self.fd=self.fd,None
            try:
                os.close(fd)
            except OSError:
                pass

    def summary(self):
        return dict(self.counts,error=self.error,last_id=self.last_sent[0] if self.last_sent else None)
