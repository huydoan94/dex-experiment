"""Full SideSync KMS input during long live video: every mouse event plus keyboard.

Extends run 72 (kms_input_live, unchanged) with:
- mouse 6/5 middle, 15/14 back and 17/16 forward press/release (e2/h onReceiveMouseEvent);
- keyboard lines "K d|u CODE": CODE is a Linux evdev / PC set-1 scan code (1..767).
  These are sent as kind 0x15 with EVENT 0 down / 1 up and the code little-endian
  in the first two scan bytes (e2/h.a); the phone injects it into its
  "DeX keyboard" device.
Keys and buttons that may still be down when the media window ends are released
once. Saved results hold counts only, never coordinates or key codes.
"""
import base64
from collections import Counter
import errno
import json
import os
import re

import kms_input_live as base
import site_env
import sidesync_packets
from usb_tunnel import TunnelError

PRESS={**base.PRESS,6:5,15:14,17:16}  # press event -> its release event
PRESS_OF={release:press for press,release in PRESS.items()}
# File drag (e2/h onReceiveMouseEvent): 13 starts the phone's drag of the offered files,
# 9 moves it, 10 drops it at x,y (file_bridge, docs/FILE_TRANSFER.md).
FILE_DRAG=frozenset((13,9,10))
MOUSE_EVENTS=frozenset((base.MOVE,*PRESS,*PRESS_OF,*base.SCROLL,*FILE_DRAG))
KEY=re.compile(rb"K ([du]) ([0-9]{1,3})")
# A move one step past the picture's edge (-1 or the full width/height), sent while
# the left button drags out of the picture: the phone's drag leaves its screen
# instead of resting on whatever lies at the edge.
EDGE_MOVE=re.compile(rb"M 0 (-1|[0-9]{1,4}) (-1|[0-9]{1,4})")
# Latency: the media window reads input once per slice (run 72: 0.05 s, ~25 ms average).
SESSION_SLICE_SECONDS=.01
# One send per slice at most; the viewer sends moves at up to 60/s: 60000 covers the 15 min cap.
MAX_INPUT_SENDS=60000
MAX_KEY_CODE=0x2ff  # KEY_MAX
KEY_DOWN,KEY_UP=0,1


def configure():
    allowed=(base.BASE_SLICE_SECONDS,base.INPUT_SLICE_SECONDS,SESSION_SLICE_SECONDS)
    if base.live.KEEPALIVE_SLICE_SECONDS not in allowed:
        raise RuntimeError("live slice differs from the pinned base")
    base.live.KEEPALIVE_SLICE_SECONDS=SESSION_SLICE_SECONDS


def key_packet(event,code):
    return sidesync_packets.keyboard_event(event,0,code.to_bytes(2,"little")+b"\0\0")


def is_release(event):
    return event[1]==KEY_UP if event[0]=="K" else event[0] in PRESS_OF


def trim(events,limit,counts):
    """Bound the pending queue, dropping the oldest presses/moves first so releases survive."""
    excess=len(events)-limit
    if excess<=0:
        return events
    kept=[]
    for event in events:
        if excess and not is_release(event):
            excess-=1
            continue
        kept.append(event)
    counts["pending_overflow"]+=len(events)-len(kept[-limit:])
    return kept[-limit:]


def packet(event):
    if event[0]=="K":
        return key_packet(event[1],event[2])
    return sidesync_packets.mouse_event(*event)


# Clipboard lines (clipboard_bridge): "P <base64 UTF-8>" sets the phone's clipboard,
# "R" asks for it. Only a "P " line may be longer than the input line limit.
CLIPBOARD_SET=re.compile(rb"P ([A-Za-z0-9+/=]{0,%d})"%(4*((4*131072+2)//3)))
MAX_CLIPBOARD_LINE=2+4*((4*131072+2)//3)
# File lines (file_bridge): "FO <0|1> <base64 JSON [[name,size],..]>" offers copied (0) or
# dropped (1) files; "B <base64>" is one requested chunk (at most 49152 bytes); "BX"
# reports that the viewer could not read the file.
FILE_OFFER=re.compile(rb"FO ([01]) ([A-Za-z0-9+/=]{4,%d})"%(MAX_CLIPBOARD_LINE))
MAX_CHUNK_LINE=2+4*((49152+2)//3)
FILE_CHUNK=re.compile(rb"B ([A-Za-z0-9+/=]{4,%d})"%(MAX_CHUNK_LINE-2))
LONG_LINES={b"P ":MAX_CLIPBOARD_LINE,b"FO":MAX_CLIPBOARD_LINE,b"B ":MAX_CHUNK_LINE}
READ_BYTES=65536
SIDE_EVENTS=("P","R","FO","B","BX","FC","DP","DD","DC")


class InputReader(base.InputReader):
    """Mouse events as (event,x,y); keys as ("K",KEY_DOWN|KEY_UP,code); clipboard
    lines as ("P",text) or ("R",)."""
    def events(self):
        # kms_input_live's reader with one change: a line that starts "P " may grow to
        # MAX_CLIPBOARD_LINE before it counts as overlong.
        try:
            data=os.read(self.fd,READ_BYTES)
        except OSError as error:
            if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):
                raise
            data=b""
        self.buffer+=data
        *lines,rest=self.buffer.split(b"\n")
        if self.discarding:
            if lines:
                lines=lines[1:]
                self.discarding=False
            else:
                rest=b""
        limit=LONG_LINES.get(bytes(rest[:2]),base.MAX_LINE_BYTES)
        if len(rest)>limit:
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
        if line==b"R":
            return ("R",)
        if line==b"BX":
            return ("BX",)
        if line==b"FC":
            return ("FC",)
        if line in (b"DP",b"DD",b"DC"):
            # phone_files: drag out of the picture (pull), dropped, cancelled.
            return (line.decode(),)
        if line.startswith(b"B "):
            match=FILE_CHUNK.fullmatch(line)
            try:
                return ("B",base64.b64decode(match[1],validate=True)) if match else None
            except ValueError:
                return None
        if line.startswith(b"FO "):
            match=FILE_OFFER.fullmatch(line)
            try:
                files=json.loads(base64.b64decode(match[2],validate=True)) if match else None
            except ValueError:
                return None
            if (not isinstance(files,list) or not files or any(
                    not isinstance(f,list) or len(f)!=2 or not isinstance(f[0],str) or not f[0]
                    or "/" in f[0] or "\\" in f[0] or type(f[1]) is not int or f[1]<0 for f in files)):
                return None
            return ("FO",int(match[1]),[(name,size) for name,size in files])
        if line.startswith(b"P "):
            match=CLIPBOARD_SET.fullmatch(line)
            if not match:
                return None
            try:
                text=base64.b64decode(match[1],validate=True).decode("utf-8")
            except ValueError:
                return None
            return ("P",text)
        match=EDGE_MOVE.fullmatch(line)
        if match:
            x,y=int(match[1]),int(match[2])
            if (x<0 or y<0 or x==base.WIDTH or y==base.HEIGHT) and -1<=x<=base.WIDTH and -1<=y<=base.HEIGHT:
                return (base.MOVE,*site_env.to_desktop(x,y))
        match=base.LINE.fullmatch(line)
        if match:
            event,x,y=int(match[1]),int(match[2]),int(match[3])
            # Viewer space is 1920x1080; the phone takes DeX desktop pixels (site_env video mode).
            return (event,*site_env.to_desktop(x,y)) if event in MOUSE_EVENTS and x<base.WIDTH and y<base.HEIGHT else None
        match=KEY.fullmatch(line)
        if match:
            code=int(match[2])
            return ("K",KEY_DOWN if match[1]==b"d" else KEY_UP,code) if 1<=code<=MAX_KEY_CODE else None
        return None


class SessionInput(base.InputSession):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.keys_held=set()
        self.keys_released=0

    def wait(self,seconds,until=lambda: False):
        # kms_input_live's media window, with the keyboard-aware reader.
        if not self.window_armed:
            return base.long.LongSession.wait(self,seconds,until)
        try:
            self.input=InputReader(self.input_fifo)
        except Exception:
            # Do not re-enter the window for the TEARDOWN wait.
            self.window_armed=False
            raise
        self.window_open=True
        try:
            return base.long.LongSession.wait(self,seconds,until)
        finally:
            self.window_open=False
            self._release_held()
            self.input.close()

    def _clipboard(self,events):
        """Clipboard lines; a session without a clipboard bridge drops them."""
        self.dropped["clipboard"]+=len(events)

    def _pump_input(self):
        events=self.input.events()
        clipboard=[event for event in events if event[0] in SIDE_EVENTS]
        if clipboard:
            events=[event for event in events if event[0] not in SIDE_EVENTS]
            self._clipboard(clipboard)
        self.pending=trim(base.coalesce(self.pending+events,self.input.counts),
                          base.MAX_PENDING_EVENTS,self.dropped)
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
        batch=self.pending[:base.MAX_EVENTS_PER_SEND]
        self.pending=self.pending[base.MAX_EVENTS_PER_SEND:]
        log=getattr(self,"log",None)
        for event in batch:
            if event[0] in FILE_DRAG and log is not None:
                log("file_drag_event",code=event[0])
        self.input_sends+=1
        # Anything pressed may reach the phone even if the send then fails: hold it first.
        # The state after a successful send replays the batch in order.
        buttons,keys=dict(self.held),set(self.keys_held)
        for event in batch:
            if event[0]=="K":
                if event[1]==KEY_DOWN:
                    self.keys_held.add(event[2])
                    keys.add(event[2])
                else:
                    keys.discard(event[2])
                continue
            self.last_position=event[1:]
            if event[0] in PRESS:
                self.held[event[0]]=buttons[event[0]]=True
            elif event[0] in PRESS_OF:
                buttons.pop(PRESS_OF[event[0]],None)
        try:
            self.send(self.kms_connection,b"".join(packet(event) for event in batch),timeout_s=1)
        except TunnelError as error:
            # send() also serves media frames; any of its errors ends the run.
            self.input_error="send: "+type(error).__name__+": "+str(error)
            raise
        for event in batch:
            if event[0]=="K":
                self.sent["key_down" if event[1]==KEY_DOWN else "key_up"]+=1
            else:
                self.sent[str(event[0])]+=1
        self.held,self.keys_held=buttons,keys

    def _release_held(self):
        if not self.held and not self.keys_held:
            return
        connection=self.kms_connection
        if connection is None or connection.closed_by_phone or self.cleanup:
            self.dropped["release_skipped"]+=len(self.held)+len(self.keys_held)
            return
        wire=b"".join(key_packet(KEY_UP,code) for code in sorted(self.keys_held))
        if self.held:
            position=self.last_position or (0,0)
            wire+=b"".join(sidesync_packets.mouse_event(PRESS[p],*position) for p in sorted(self.held))
        buttons,keys=sorted(self.held),sorted(self.keys_held)
        self.held,self.keys_held={},set()
        try:
            self.send(connection,wire,timeout_s=1)
            self.releases_sent,self.keys_released=len(buttons),len(keys)
        # Runs in a finally: never mask the window's own error.
        except Exception as error:
            self.input_error="release: "+type(error).__name__+": "+str(error)

    def summary(self):
        result=super().summary()
        result["kms_input"].update(keys_released=self.keys_released,
                                   keys_held_at_end=len(self.keys_held))
        return result


class SessionOwner(base.InputOwner):
    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=base.long.MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=SessionInput(link,first_transaction,max_frame_bytes,base.long.LONG_RECEIVE_BYTES,
            sink=self.sink,stop_file=self.stop_file,input_fifo=self.input_fifo,
            log=base.long.QuietLog(log),**kwargs)
        self.reader=base.live.duplex_link.ReadPump(link,session.log)
        return session
