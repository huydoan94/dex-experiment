"""Run B (user 2026-11-03: "control it through here"): long live PLAY plus WFD UIBC generic input.

Advertises SamsungDeX.exe's UIBC entry (GENERIC: Keyboard, SingleTouch). After
PLAY the sink opens TCP to the source's M4 port through the native tunnel, as
for 7236. Input comes only from the user's viewer via a FIFO in the backend machine
(the phone gateway): strict text lines, validated, coalesced and rate bounded,
then encoded as WFD generic UIBC packets. Saved results hold input counts only,
never coordinates or keys.
"""
from collections import Counter
import errno
import os
import re
import stat

import rtsp
import rtsp_capabilities as caps
import rtsp_setup
import rtsp_udp_live as live
import rtsp_udp_long as long
from tunnel_probe import MAX_RECEIVE_BYTES,SERVICE_UID
from usb_tunnel import TunnelError

UIBC_CONFIG,UIBC_HOST=1207,50005
UIBC_CAPABILITY=("input_category_list=GENERIC;generic_cap_list=Keyboard, SingleTouch;"
                 "hidc_cap_list=none;port=none")
UIBC_PROFILE=dict(long.AUDIO_UDP_PROFILE,wfd_uibc_capability=UIBC_CAPABILITY)
GENERIC_CAPS=frozenset(("Keyboard","SingleTouch"))
# Selected wfd_video_formats CEA bit 7: 1920x1080p30, the UIBC coordinate space.
WIDTH,HEIGHT,CEA_1080P30=1920,1080,0x80
# Input latency: the media window checks input once per slice.
BASE_SLICE_SECONDS,UIBC_SLICE_SECONDS=.2,.05
# At most one send per slice: 20/s for the 15 min cap.
MAX_INPUT_SENDS=18000
MAX_UIBC_SETTINGS=8
INPUT_READ_BYTES=4096
MAX_LINE_BYTES=32
MAX_EVENTS_PER_SEND=64
TOUCH=re.compile(rb"T ([dmu]) ([0-9]{1,4}) ([0-9]{1,4})")
KEY=re.compile(rb"K ([du]) ([0-9]{1,3})")
# WFD generic input IE IDs.
TOUCH_IE={b"d":0,b"u":1,b"m":2}
KEY_IE={b"d":3,b"u":4}
_PINNED_SELECTED=caps.selected_parameters


def uibc_selection(value):
    """The phone's UIBC choice: None for "none", False if outside the advertised entry."""
    if value in (None,"none"):
        return None
    fields={}
    for part in value.split(";"):
        name,sep,item=part.partition("=")
        if not sep or name in fields:
            return False
        fields[name]=item
    if set(fields)!={"input_category_list","generic_cap_list","hidc_cap_list","port"}:
        return False
    generic=[item.strip() for item in fields["generic_cap_list"].split(",")]
    port=fields["port"]
    if (fields["input_category_list"].strip()!="GENERIC" or fields["hidc_cap_list"].strip()!="none"
            or not generic or not set(generic)<=GENERIC_CAPS or len(set(generic))!=len(generic)
            or not port.isdigit() or not 1<=int(port)<=65535):
        return False
    return dict(generic=sorted(generic),port=int(port))


def selection_compatible(values,profile=caps.PROFILE):
    if profile is UIBC_PROFILE:
        if uibc_selection(values.get("wfd_uibc_capability")) is False:
            return False
        if values.get("wfd_uibc_setting") not in (None,"enable","disable"):
            return False
        rest={name:value for name,value in values.items() if name!="wfd_uibc_setting"}
        return long.selection_compatible(dict(rest,wfd_uibc_capability="none"),long.AUDIO_UDP_PROFILE)
    return long.selection_compatible(values,profile)


def selected_parameters(message):
    """Pinned export plus wfd_uibc_setting when it is exactly enable/disable."""
    values,names=_PINNED_SELECTED(message)
    if "wfd_uibc_setting" in names:
        for line in message["body"].decode("ascii").split("\r\n"):
            name,_,value=line.partition(":")
            if name.lower()=="wfd_uibc_setting" and value.strip() in ("enable","disable"):
                values["wfd_uibc_setting"]=value.strip()
    return values,names


def apply():
    # long.apply() accepts only its own or the pinned check; hand ours back for a repeat call.
    if caps.selection_compatible is selection_compatible:
        caps.selection_compatible=long.selection_compatible
    long.apply()
    for name,ours,pinned in (("selection_compatible",selection_compatible,long.selection_compatible),
                             ("selected_parameters",selected_parameters,_PINNED_SELECTED)):
        if getattr(caps,name) not in (pinned,ours):
            raise RuntimeError("capability %s differs from the pinned base"%name)
        setattr(caps,name,ours)
    if live.KEEPALIVE_SLICE_SECONDS not in (BASE_SLICE_SECONDS,UIBC_SLICE_SECONDS):
        raise RuntimeError("live slice differs from the pinned base")
    live.KEEPALIVE_SLICE_SECONDS=UIBC_SLICE_SECONDS


def generic_packet(ie,describe):
    # Header: version 0, no timestamp, category GENERIC (0), total length.
    body=bytes([ie])+len(describe).to_bytes(2,"big")+describe
    return bytes([0,0])+(4+len(body)).to_bytes(2,"big")+body


def touch_packet(action,x,y):
    # One pointer, id 0.
    return generic_packet(TOUCH_IE[action],bytes([1,0])+x.to_bytes(2,"big")+y.to_bytes(2,"big"))


def key_packet(action,code):
    return generic_packet(KEY_IE[action],bytes([0])+code.to_bytes(2,"big")+bytes(2))


def uibc_setting_request(message):
    """"enable"/"disable" for an exact M14-style wfd_uibc_setting SET_PARAMETER, else None."""
    if (message["kind"]!="request" or message["method"]!="SET_PARAMETER"
            or message["headers"].get("content-type","").lower()!="text/parameters"):
        return None
    for setting in ("enable","disable"):
        if message["body"]==("wfd_uibc_setting: %s\r\n"%setting).encode():
            return setting
    return None


class UibcLog(long.QuietLog):
    """QuietLog that never writes UIBC payload: OUT Data on UIBC_CONFIG keeps only its 56-byte header.

    The recorder logs every OUT frame raw; UIBC data is the user's typing and
    touches. No digest either: one keystroke is trivially brute-forced.
    """
    def __call__(self,event,**fields):
        if event=="usb_raw" and fields.get("direction")=="out":
            raw=bytes.fromhex(fields.get("bytes_hex",""))
            if (raw[:4]==b"CONN" and len(raw)>=56 and int.from_bytes(raw[4:8],"little")==5
                    and int.from_bytes(raw[12:16],"little")==1
                    and int.from_bytes(raw[24:28],"little")==UIBC_CONFIG):
                fields=dict(fields,bytes_hex=raw[:56].hex(),uibc_payload_bytes=len(raw)-56,
                            redacted="uibc_input")
        super().__call__(event,**fields)


class InputReader:
    """Non-blocking reader of the viewer's input FIFO; never creates or reads a regular file."""
    def __init__(self,path):
        self.fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        if not stat.S_ISFIFO(os.fstat(self.fd).st_mode):
            os.close(self.fd)
            self.fd=None
            raise RuntimeError("input path is not a FIFO")
        self.buffer=bytearray()
        self.counts=Counter()

    def events(self):
        """Validated (kind,action,a,b) events, consecutive touch moves coalesced."""
        try:
            data=os.read(self.fd,INPUT_READ_BYTES)
        except OSError as error:
            if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):
                raise
            data=b""
        self.buffer+=data
        *lines,rest=self.buffer.split(b"\n")
        if len(rest)>MAX_LINE_BYTES:
            self.counts["invalid"]+=1
            rest=b""
        self.buffer=bytearray(rest)
        events=[]
        for line in lines:
            event=self.parse(line)
            if event is None:
                self.counts["invalid"]+=1
                continue
            if event[:2]==("T",b"m") and events and events[-1][:2]==("T",b"m"):
                events[-1]=event
                self.counts["coalesced"]+=1
                continue
            events.append(event)
        return events

    @staticmethod
    def parse(line):
        match=TOUCH.fullmatch(line)
        if match:
            x,y=int(match[2]),int(match[3])
            return ("T",match[1],x,y) if x<WIDTH and y<HEIGHT else None
        match=KEY.fullmatch(line)
        if match:
            code=int(match[2])
            # Generic key codes are ASCII.
            return ("K",match[1],code,0) if 1<=code<=0x7f else None
        return None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd=None


class UibcSession(long.LongSession):
    def __init__(self,link,*args,input_fifo,**kwargs):
        super().__init__(link,*args,**kwargs)
        self.input_fifo=input_fifo
        self.input=None
        self.uibc_port=None
        self.uibc_enabled=False
        self.uibc_connection=None
        self.uibc_attempted=False
        self.uibc_error=None
        self.uibc_sends=0
        self.uibc_settings=[]
        self.window_open=False
        self.sent=Counter()
        self.dropped=Counter()

    def wait(self,seconds,until=lambda: False):
        if not self.window_armed:
            return super().wait(seconds,until)
        self.window_open=True
        try:
            return super().wait(seconds,until)
        finally:
            self.window_open=False

    def _answer_keepalives(self):
        # rtsp_udp_live's loop, plus the source's wfd_uibc_setting requests.
        while True:
            parsed=rtsp.parse(bytes(self.rtsp_connection.received[self.keepalive_offset:]))
            if parsed is None:
                break
            message,size=parsed
            self.keepalive_offset+=size
            self.rtsp_seen.append(dict(kind=message["kind"],method=message.get("method"),
                                       cseq=message.get("cseq")))
            if message["kind"]!="request":
                continue
            setting=uibc_setting_request(message)
            if setting is not None:
                if len(self.uibc_settings)>=MAX_UIBC_SETTINGS:
                    raise live.play.TunnelError("wfd_uibc_setting count exceeded")
                self.uibc_settings.append(setting)
                self.uibc_enabled=setting=="enable"
                self.log("rtsp_uibc_setting_reply",cseq=message["cseq"],setting=setting)
                self.send(self.rtsp_connection,rtsp_setup.response(message["cseq"]),timeout_s=2)
                continue
            if message["method"]!="GET_PARAMETER" or message["body"]:
                raise live.play.TunnelError("unexpected RTSP request during live media")
            if self.keepalives>=live.MAX_KEEPALIVES:
                raise live.play.TunnelError("RTSP keep-alive count exceeded")
            self.keepalives+=1
            self.log("rtsp_keepalive_reply",cseq=message["cseq"])
            self.send(self.rtsp_connection,rtsp_setup.response(message["cseq"]),timeout_s=2)
        if self.window_open and not self.cleanup:
            self._pump_input()

    def _connect_uibc(self):
        self.uibc_attempted=True
        try:
            self.open_config(UIBC_CONFIG,SERVICE_UID,self.uibc_port,timeout_s=2)
            self.uibc_connection=self.connect(UIBC_HOST,config_id=UIBC_CONFIG,timeout_s=2)
        except TunnelError as error:
            # Video continues without input; the config, if recorded, is closed in cleanup.
            self.uibc_error="connect: "+type(error).__name__+": "+str(error)
        self.log("uibc_connect",port=self.uibc_port,connected=self.uibc_connection is not None,
                 error=self.uibc_error)

    def _pump_input(self):
        if self.uibc_port is None or self.input is None:
            return
        if not self.uibc_attempted:
            self._connect_uibc()
            return
        events=self.input.events()
        if not events:
            return
        if self.uibc_connection is None or self.uibc_error or self.uibc_connection.closed_by_phone:
            self.dropped["no_connection"]+=len(events)
            return
        if not self.uibc_enabled:
            self.dropped["disabled"]+=len(events)
            return
        if self.uibc_sends>=MAX_INPUT_SENDS:
            self.dropped["send_budget"]+=len(events)
            return
        events,extra=events[:MAX_EVENTS_PER_SEND],events[MAX_EVENTS_PER_SEND:]
        self.dropped["per_send"]+=len(extra)
        payload=b"".join(touch_packet(action,a,b) if kind=="T" else key_packet(action,a)
                         for kind,action,a,b in events)
        self.uibc_sends+=1
        try:
            self.send(self.uibc_connection,payload,timeout_s=1)
        except TunnelError as error:
            self.uibc_error="send: "+type(error).__name__+": "+str(error)
            self.log("uibc_send_failed",error=self.uibc_error)
            return
        for kind,action,_,_ in events:
            self.sent[kind+action.decode()]+=1

    def uibc_summary(self):
        return dict(port=self.uibc_port,enabled=self.uibc_enabled,settings=self.uibc_settings,
                    attempted=self.uibc_attempted,connected=self.uibc_connection is not None,
                    closed_by_phone=bool(self.uibc_connection and self.uibc_connection.closed_by_phone),
                    error=self.uibc_error,sends=self.uibc_sends,sent=dict(self.sent),
                    dropped=dict(self.dropped),
                    input=dict(self.input.counts) if self.input else None)


def exchange(session,main,connection,result,log,latest=None):
    values=result.get("rtsp_selected_values",{})
    selection=uibc_selection(values.get("wfd_uibc_capability"))
    result["uibc_selection"]=selection
    result["uibc_setting_m4"]=values.get("wfd_uibc_setting")
    video=values.get("wfd_video_formats","").split()
    if selection and "SingleTouch" in selection["generic"] and len(video)>4 and int(video[4],16)==CEA_1080P30:
        session.uibc_port=selection["port"]
        # M4 with a port and no setting is taken as enabled; an explicit disable waits for enable.
        session.uibc_enabled=values.get("wfd_uibc_setting","enable")=="enable"
    session.input=InputReader(session.input_fifo)
    try:
        return long.exchange(session,main,connection,result,log,latest=latest)
    finally:
        session.input.close()
        result["uibc_cleanup_errors"]=[]
        uibc=session.uibc_connection
        try:
            if uibc is not None and session.connections.get(uibc.host_port) is uibc:
                result["uibc_disconnect_status"]=session.disconnect(uibc)
        except Exception as error:
            result["uibc_cleanup_errors"].append(type(error).__name__+": "+str(error))
        try:
            if UIBC_CONFIG in session.configs:
                result["uibc_close_status"]=session.close_config(SERVICE_UID,config_id=UIBC_CONFIG)
        except Exception as error:
            result["uibc_cleanup_errors"].append(type(error).__name__+": "+str(error))
        result["uibc"]=session.uibc_summary()


class UibcOwner(long.LongOwner):
    def __init__(self,util,result,sink,stop_file,input_fifo):
        super().__init__(util,result,sink,stop_file)
        self.input_fifo=input_fifo

    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=UibcSession(link,first_transaction,max_frame_bytes,long.LONG_RECEIVE_BYTES,
                            sink=self.sink,stop_file=self.stop_file,input_fifo=self.input_fifo,
                            log=UibcLog(log),**kwargs)
        self.reader=live.duplex_link.ReadPump(link,session.log)
        return session
