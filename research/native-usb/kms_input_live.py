"""Viewer-driven SideSync KMS mouse input during long live video (user 2026-11-03).

Input comes only from the user's viewer through a FIFO in the backend machine: strict
"M EVENT X Y" lines in 1920x1080 DeX desktop pixels, validated, hover moves
coalesced, at most one KMS send per slice. Events follow e2/h
onReceiveMouseEvent: 0 hover/drag move, 2/1 left press/release, 4/3 right
press/release, 7/8 vertical and 11/12 horizontal scroll. No keyboard. A failed
send ends the run, as in the scripted runs. A button that may be held when the
media window ends is released once. Like the PC client
(SocketManager::heartbeatThreadFunc, 1 s sleep), a heartbeat request is sent
every second of the window; the phone (server) only runs the timeout thread.
Saved results hold counts only, never coordinates.
"""
from collections import Counter
import errno
import os
import re
import stat

import rtsp_udp_live as live
import rtsp_udp_long as long
import sidesync_packets
from usb_tunnel import TunnelError

BASE_SLICE_SECONDS,INPUT_SLICE_SECONDS=.2,.05
# One send per slice: 20/s for the 15 min cap.
MAX_INPUT_SENDS=18000
HEARTBEAT_SECONDS=1
MAX_HEARTBEATS=long.CAP_SECONDS+30
MAX_EVENTS_PER_SEND=32
MAX_PENDING_EVENTS=256
INPUT_READ_BYTES=4096
MAX_LINE_BYTES=24
WIDTH,HEIGHT=1920,1080
MOVE=0
PRESS={2:1,4:3}  # press event -> its release event
PRESS_OF={release:press for press,release in PRESS.items()}
SCROLL=frozenset((7,8,11,12))
EVENTS=frozenset((MOVE,*PRESS,*PRESS_OF,*SCROLL))
LINE=re.compile(rb"M ([0-9]{1,2}) ([0-9]{1,4}) ([0-9]{1,4})")


def configure():
    if live.KEEPALIVE_SLICE_SECONDS not in (BASE_SLICE_SECONDS,INPUT_SLICE_SECONDS):
        raise RuntimeError("live slice differs from the pinned base")
    live.KEEPALIVE_SLICE_SECONDS=INPUT_SLICE_SECONDS


def coalesce(events,counts):
    """Keep event order; a run of consecutive moves keeps only its last position."""
    kept=[]
    for event in events:
        if event[0]==MOVE and kept and kept[-1][0]==MOVE:
            kept[-1]=event
            counts["coalesced"]+=1
        else:
            kept.append(event)
    return kept


class InputReader:
    """Non-blocking reader of the viewer's input FIFO; never creates or reads a regular file."""
    def __init__(self,path):
        self.fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        if not stat.S_ISFIFO(os.fstat(self.fd).st_mode):
            os.close(self.fd)
            self.fd=None
            raise RuntimeError("input path is not a FIFO")
        self.buffer=bytearray()
        self.discarding=False
        self.counts=Counter()

    def events(self):
        """Validated (event,x,y) tuples in arrival order."""
        try:
            data=os.read(self.fd,INPUT_READ_BYTES)
        except OSError as error:
            if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):
                raise
            data=b""
        self.buffer+=data
        *lines,rest=self.buffer.split(b"\n")
        if self.discarding:
            # The rest of an overlong line, up to its newline, is dropped too.
            if lines:
                lines=lines[1:]
                self.discarding=False
            else:
                rest=b""
        if len(rest)>MAX_LINE_BYTES:
            self.counts["invalid"]+=1
            rest=b""
            self.discarding=True
        self.buffer=bytearray(rest)
        events=[]
        for line in lines:
            event=self.parse(line)
            if event is None:
                self.counts["invalid"]+=1
            else:
                events.append(event)
        return events

    @staticmethod
    def parse(line):
        match=LINE.fullmatch(line)
        if not match:
            return None
        event,x,y=int(match[1]),int(match[2]),int(match[3])
        return (event,x,y) if event in EVENTS and x<WIDTH and y<HEIGHT else None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd=None


class InputSession(long.LongSession):
    def __init__(self,link,*args,input_fifo,**kwargs):
        super().__init__(link,*args,**kwargs)
        self.input_fifo=input_fifo
        self.input=None
        self.kms_connection=None
        self.window_open=False
        self.pending=[]
        self.held={}
        self.last_position=None
        self.input_sends=0
        self.input_error=None
        self.sent=Counter()
        self.dropped=Counter()
        self.releases_sent=0
        self.heartbeats_sent=0
        self.last_heartbeat=None

    def wait(self,seconds,until=lambda: False):
        if not self.window_armed:
            return super().wait(seconds,until)
        # The media window: the viewer's FIFO is read only while it is open.
        try:
            self.input=InputReader(self.input_fifo)
        except Exception:
            # Do not re-enter the window for the TEARDOWN wait.
            self.window_armed=False
            raise
        self.window_open=True
        try:
            return super().wait(seconds,until)
        finally:
            self.window_open=False
            self._release_held()
            self.input.close()

    def _answer_keepalives(self):
        super()._answer_keepalives()
        if self.window_open and not self.cleanup:
            self._heartbeat()
            self._pump_input()

    def _usable(self):
        connection=self.kms_connection
        return (self.input_error is None and connection is not None
                and not connection.closed_by_phone)

    def _heartbeat(self):
        now=self.clock()
        if self.last_heartbeat is not None and now-self.last_heartbeat<HEARTBEAT_SECONDS:
            return
        self.last_heartbeat=now
        if not self._usable() or self.heartbeats_sent>=MAX_HEARTBEATS:
            return
        self.heartbeats_sent+=1
        try:
            self.send(self.kms_connection,sidesync_packets.heartbeat_request(),timeout_s=1)
        except TunnelError as error:
            # send() also serves media frames; any of its errors ends the run.
            self.input_error="heartbeat: "+type(error).__name__+": "+str(error)
            raise

    def _pump_input(self):
        self.pending=coalesce(self.pending+self.input.events(),self.input.counts)
        if len(self.pending)>MAX_PENDING_EVENTS:
            # Only under a flood: drop the oldest; held buttons are still released at the end.
            self.dropped["pending_overflow"]+=len(self.pending)-MAX_PENDING_EVENTS
            self.pending=self.pending[-MAX_PENDING_EVENTS:]
        if not self.pending:
            return
        if not self._usable():
            self.dropped["no_connection"]+=len(self.pending)
            self.pending=[]
            return
        if self.input_sends>=MAX_INPUT_SENDS:
            self.dropped["send_budget"]+=len(self.pending)
            self.pending=[]
            return
        batch=self.pending[:MAX_EVENTS_PER_SEND]
        self.pending=self.pending[MAX_EVENTS_PER_SEND:]
        self.input_sends+=1
        # A press may reach the phone even if its send then fails: count it held first.
        # The state after a successful send replays the batch in order.
        after=dict(self.held)
        for event,x,y in batch:
            self.last_position=(x,y)
            if event in PRESS:
                self.held[event]=after[event]=True
            elif event in PRESS_OF:
                after.pop(PRESS_OF[event],None)
        try:
            self.send(self.kms_connection,
                      b"".join(sidesync_packets.mouse_event(*event) for event in batch),timeout_s=1)
        except TunnelError as error:
            # send() also serves media frames; any of its errors ends the run.
            self.input_error="send: "+type(error).__name__+": "+str(error)
            raise
        for event,_,_ in batch:
            self.sent[event]+=1
        self.held=after

    def _release_held(self):
        if not self.held:
            return
        connection=self.kms_connection
        # Attempted even after a failed send: a timed-out link may still deliver it.
        if connection is None or connection.closed_by_phone or self.cleanup:
            self.dropped["release_skipped"]+=len(self.held)
            return
        presses=sorted(self.held)
        self.held.clear()
        try:
            self.send(self.kms_connection,b"".join(
                sidesync_packets.mouse_event(PRESS[p],*self.last_position) for p in presses),
                timeout_s=1)
            self.releases_sent=len(presses)
        # Runs in a finally: never mask the window's own error.
        except Exception as error:
            self.input_error="release: "+type(error).__name__+": "+str(error)

    def summary(self):
        return dict(super().summary(),kms_input=dict(
            sends=self.input_sends,heartbeats=self.heartbeats_sent,sent={str(k):v for k,v in sorted(self.sent.items())},
            dropped=dict(self.dropped),releases_sent=self.releases_sent,
            held_at_end=len(self.held),error=self.input_error,
            input=dict(self.input.counts) if self.input else None))


class InputOwner(long.LongOwner):
    def __init__(self,util,result,sink,stop_file,input_fifo):
        super().__init__(util,result,sink,stop_file)
        self.input_fifo=input_fifo

    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=long.MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=InputSession(link,first_transaction,max_frame_bytes,long.LONG_RECEIVE_BYTES,
            sink=self.sink,stop_file=self.stop_file,input_fifo=self.input_fifo,
            log=long.QuietLog(log),**kwargs)
        self.reader=live.duplex_link.ReadPump(link,session.log)
        return session
