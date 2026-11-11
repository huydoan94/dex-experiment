"""One viewer's session for dexd (user 2026-11-03, 77-DEXD_PIPELINE.md, revised).

dexd starts it when a viewer connects. Same startup, video, audio and KMS input
as kms_session_live (unchanged), with:
- every cap, budget and window limit lifted to effectively unlimited; the
  session ends when the viewer has been gone VIEWER_GRACE_SECONDS, when the
  phone closes KMS, on SIGTERM, the stop file or an error;
- a detachable sink: a viewer write failure detaches instead of failing;
- input from a FIFO: when its writer goes away, every held key and button is
  released and a partial line is dropped;
- the RTSP stream consumed during the window is compacted, so TEARDOWN still
  passes the pinned 16 KiB stream guard after days of keep-alives;
- after the first minute only protocol decisions are logged; per-frame USB
  traffic (media, ACKs, heartbeats, input) is counted, not written.
Saved results stay counts only.
"""
from collections import Counter,deque
import dataclasses
import os
from pathlib import Path
import select
import sys
import time

import clipboard_bridge
from cursor_relay import CURSOR_MSG,CursorRelay
from usb_engines import AsyncIn,AsyncOut,LibusbEngine,LibusbOutEngine,UsbTiming
import duplex_link
import file_bridge
import idc
import phone_files
from threaded_input import ThreadedInputReader,_DISCONNECT as DISCONNECT
import kms_input_live
import kms_session_live as base
import rtsp
import rtsp_udp_long as long
import rtsp_udp_play as play
import tcp_control
from usb_tunnel import TunnelError
import wfd_startup as wfd
from tunnel_probe import SERVICE_UID

# Ten years: "until stopped" without changing the pinned arithmetic.
FOREVER_SECONDS=10*365*86400
UNLIMITED=1<<62
# Session-wide TCP receive cap. KMS heartbeat answers and notices add ~1 MB/day
# (run kms-session-20261103T112339: 10 KB in 15 min) and stay in memory: ~3 months.
DAEMON_RECEIVE_BYTES=128<<20
DAEMON=dict(MEDIA_DATAGRAMS=UNLIMITED,MEDIA_SECONDS=FOREVER_SECONDS,MEDIA_BYTES=UNLIMITED,
            PLAY_ACKS=UNLIMITED,PLAY_READS=UNLIMITED,STAGE_SECONDS=FOREVER_SECONDS+30,
            RTCP_DATAGRAMS=UNLIMITED)
FULL_LOG_SECONDS=3
RTSP_SEEN_KEEP=64
# The window ends once no viewer has been attached this long (also if none ever attached).
VIEWER_GRACE_SECONDS=5
# Pause instead of ending (user 2026-11-07): once no viewer has been attached for
# VIEWER_GRACE_SECONDS the phone gets RTSP PAUSE on the live RTSP connection, and
# RTSP PLAY when a viewer attaches again. USB, KMS and RTSP stay up, so a
# reconnect skips the ~20 s replug cycle. The official PC app sends the same
# PAUSE/PLAY (SamsungDeX.exe RTSPSocket::wfd_send_pause/play, used by its
# RTSPErrorRecoverThread). A missing/failed reply or no media after PLAY ends the
# session the old way (TEARDOWN, cleanup, replug). No time limit while paused.
RTSP_REPLY_SECONDS=10
RESUME_MEDIA_SECONDS=30
PAUSE_CSEQ_START=100
PAUSE_LATENCY_KEEP=50
# After the first minute every per-frame USB event is counted instead of written.
QUIET_EVENTS=long.ROUTINE|{"usb_raw","usb_frame_in","usb_frame_in_data","usb_in_unparsed"}


def configure():
    """Apply the session limits, then lift them; refuses a changed base like its parents."""
    if long.CAP_SECONDS not in (900,FOREVER_SECONDS):
        raise RuntimeError("long cap differs from the pinned base")
    long.CAP_SECONDS=FOREVER_SECONDS
    long.LONG.update(DAEMON)
    long.LONG_KEEPALIVES=UNLIMITED
    long.LONG_RECEIVE_BYTES=DAEMON_RECEIVE_BYTES
    base.configure()
    long.apply()
    kms_input_live.MAX_HEARTBEATS=UNLIMITED
    base.MAX_INPUT_SENDS=UNLIMITED


class Head(list):
    """Keeps the first RTSP_SEEN_KEEP entries; total counts all."""
    total=0

    def append(self,item):
        self.total+=1
        if len(self)<RTSP_SEEN_KEEP:
            super().append(item)


class DaemonLog(long.QuietLog):
    @staticmethod
    def routine(event,fields):
        return event in QUIET_EVENTS


SWITCH_INTERVAL_SECONDS=.001


# Every event rtsp_udp_play.RedactingRecorder emits.
RECORDER_EVENTS=frozenset(("usb_raw","usb_in_chunk","usb_frame_in","usb_frame_in_data",
                           "usb_in_unparsed"))
if not RECORDER_EVENTS<=QUIET_EVENTS:
    raise RuntimeError("quiet recorder requires every recorder event to be quiet")


class DaemonRecorder(play.RedactingRecorder):
    """RedactingRecorder that skips work DaemonLog would discard.

    While the log is quiet every recorder event is counted, never written, so the
    digests, re-encoding and datagram parsing behind each one are skipped. The
    decoder still sees every read, so it stays in step for the logged teardown,
    and each event is counted exactly as QuietLog would count it."""
    timing=None

    def __call__(self,direction,data):
        if direction=="in" and self.timing is not None:
            self.timing.mark_consumed()
        log=self.log
        if not log.quiet:
            return super().__call__(direction,data)
        counts=log.suppressed
        if direction!="in":
            counts["usb_raw"]+=1
            return
        if self.failed:
            counts["usb_in_unparsed"]+=1
            return
        counts["usb_in_chunk"]+=1
        try:
            frames=self.decoder.feed(data)
        except ValueError:
            self.failed=True
            counts["usb_in_unparsed"]+=1
            return
        for frame in frames:
            counts["usb_frame_in_data" if (frame.command,frame.kind)==(5,1) else "usb_frame_in"]+=1


class InputReader(base.InputReader):
    """kms_session_live's reader; writer_gone() tells when a viewer's writer has closed.

    Linux reports POLLHUP on a FIFO's read end only after a writer was seen since
    open, so an input FIFO nobody ever wrote to is not "gone"."""
    def writer_gone(self):
        events=select.poll()
        events.register(self.fd,select.POLLIN)
        mask=dict(events.poll(0)).get(self.fd,0)
        if mask&select.POLLHUP and not mask&select.POLLIN:
            # A departed viewer's unfinished line must not join the next viewer's first one.
            self.buffer.clear()
            self.discarding=False
            return True
        return False


# Host ports for clipboard IDC requests: one fresh control connection each, clear of
# the startup ports (IDC 50002, control 50003, KMS 50008); never reused in a session.
IDC_HOST_FIRST,IDC_HOST_LAST=50100,50999


class WakingInputReader(ThreadedInputReader):
    """ThreadedInputReader whose worker sleeps in poll() on the FIFO, not a fixed interval.

    A move written by the gateway is collected at once instead of up to
    poll_seconds later. Once the writer has gone the FIFO reports POLLHUP
    continuously, so the worker then falls back to the plain interval."""
    def __init__(self,reader,**kwargs):
        self.poller=select.poll()
        self.poller.register(reader.fd,select.POLLIN)
        super().__init__(reader,**kwargs)

    def _pause(self):
        ready=dict(self.poller.poll(self.poll_seconds*1000)).get(self.reader.fd,0)
        if ready&select.POLLHUP and not ready&select.POLLIN:
            self.stop.wait(self.poll_seconds)

    def _run(self):
        # ThreadedInputReader._run with _pause() in place of stop.wait(poll_seconds).
        gone=False
        try:
            while not self.stop.is_set():
                events=self.reader.events()
                if events:
                    gone=False
                for event in events:
                    self._append(event)
                now_gone=self.reader.writer_gone()
                if now_gone and not gone:
                    self._append(DISCONNECT)
                gone=now_gone
                if not self.stop.is_set():
                    self._pause()
        except Exception as error:
            with self.lock:
                self.error=error
        finally:
            try:
                self.reader.close()
            except Exception as error:
                with self.lock:
                    self.error=error

    def queued_event(self):
        """True while a viewer event (not a disconnect barrier) waits for the owner."""
        queue=self.queue
        return bool(queue) and queue[0][0] is not DISCONNECT


class Descrambler:
    """Samsung RTP scrambling, receiver side.

    Official SamsungDeX.exe 2.4.1.27 RTPSocket receive (0x004fbd70): when the
    phone scrambles, every byte i >= 12 of a received RTP datagram is XORed with
    key[i % len(key)], where key is SUtil::_gSessionKey: the 32-byte AUTH session
    key as 64 uppercase hex characters (Crypto++ HexEncoder, no grouping). The
    phone app passes the same string as scramble_support (DeX app r2/r.p).

    The mode latches on the first datagram whose MPEG-TS sync byte decides it,
    so a phone that sends plain TS anyway still plays. The key is never logged.
    """
    HEADER_BYTES=12
    MAX_DATAGRAM_BYTES=1<<16

    def __init__(self,session_key):
        if not isinstance(session_key,bytes) or len(session_key)!=32:
            raise ValueError("session key must be 32 bytes")
        key=session_key.hex().upper().encode("ascii")
        self._stream=(key*(self.MAX_DATAGRAM_BYTES//len(key)+1))[:self.MAX_DATAGRAM_BYTES]
        self.mode=None
        self.undecided=self.descrambled=0

    def __repr__(self):
        return "Descrambler(mode=%r)"%(self.mode,)

    def descramble(self,packet):
        size=len(packet)
        if size<=self.HEADER_BYTES or size>self.MAX_DATAGRAM_BYTES:
            return bytes(packet)
        tail=size-self.HEADER_BYTES
        value=(int.from_bytes(packet[self.HEADER_BYTES:],"big")
               ^int.from_bytes(self._stream[self.HEADER_BYTES:size],"big"))
        return bytes(packet[:self.HEADER_BYTES])+value.to_bytes(tail,"big")

    @staticmethod
    def _synced(packet):
        ts=long.live.ts_payload(packet)
        return bool(ts) and ts[0]==0x47

    def packet(self,packet):
        if self.mode is None:
            if self._synced(packet):
                self.mode="plain"
            else:
                clear=self.descramble(packet)
                if not self._synced(clear):
                    self.undecided+=1
                    return packet
                self.mode="scrambled"
                self.descrambled+=1
                return clear
        if self.mode=="plain":
            return packet
        self.descrambled+=1
        return self.descramble(packet)

    def frame(self,frame):
        """The UDP data frame with its RTP payload descrambled; other frames unchanged."""
        body=frame.body
        header=tcp_control._DATA.size
        if (len(body)<=header or frame.command!=5 or frame.kind!=1
                or int.from_bytes(body[4:8],"little")!=play.RTP_CONFIG):
            return frame
        payload=body[header:]
        clear=self.packet(payload)
        if clear is payload:
            return frame
        return dataclasses.replace(frame,body=bytes(body[:header])+clear)

    def summary(self):
        return dict(mode=self.mode,descrambled=self.descrambled,undecided=self.undecided)


class PauseControl:
    """RTSP PAUSE/PLAY decisions for one session; the session sends what step() returns.

    States: playing -> pausing (PAUSE sent) -> paused -> resuming (PLAY sent) -> playing.
    A request is sent only after the previous one was answered, so the phone never
    sees two outstanding. The PLAY that started the media gives the URI and Session."""
    def __init__(self):
        self.uri=self.session_id=None
        self.state="playing"
        self.cseq=PAUSE_CSEQ_START
        self.pending=None          # (method,cseq,sent_at)
        self.resumed_at=None       # waiting for the first RTP after a PLAY
        self.rtp_at_resume=0
        self.failure=None
        self.pauses=self.resumes=0
        self.resume_ms=deque(maxlen=PAUSE_LATENCY_KEEP)
        self.paused_seconds=0.0
        self.paused_at=None
        self.notes=[]

    def learn_play(self,data):
        if self.uri is not None:
            return
        lines=data.decode("ascii","replace").split("\r\n")
        self.uri=lines[0].split(" ")[1] if len(lines[0].split(" "))>2 else None
        for line in lines[1:]:
            name,_,value=line.partition(":")
            if name.strip().lower()=="session":
                self.session_id=value.strip().split(";")[0]

    def request(self,method,cseq):
        return ("%s %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n\r\n"%(
            method,self.uri,cseq,self.session_id)).encode("ascii")

    def _fail(self,reason):
        self.failure=reason
        self.notes.append("pause_failed reason=%s"%reason)

    def step(self,now,attached,absent,responses,rtp_count):
        """Returns (method,cseq) to send now, or None."""
        if self.failure is not None or self.uri is None or self.session_id is None:
            return None
        if self.pending is not None:
            method,cseq,sent=self.pending
            status=next((st for cs,st in responses if cs==cseq),None)
            if status is None:
                if now-sent>=RTSP_REPLY_SECONDS:
                    self._fail("%s_no_reply"%method.lower())
                return None
            if status!=200:
                self._fail("%s_status_%d"%(method.lower(),status))
                return None
            self.pending=None
            if method=="PAUSE":
                self.state,self.paused_at="paused",now
                self.pauses+=1
                self.notes.append("paused")
            else:
                self.state,self.resumed_at,self.rtp_at_resume="playing",sent,rtp_count
                self.resumes+=1
                if self.paused_at is not None:
                    self.paused_seconds+=sent-self.paused_at
                    self.paused_at=None
                self.notes.append("resumed")
        if self.resumed_at is not None:
            if rtp_count>self.rtp_at_resume:
                self.resume_ms.append(round((now-self.resumed_at)*1000))
                self.notes.append("media_after_resume ms=%d"%self.resume_ms[-1])
                self.resumed_at=None
            elif now-self.resumed_at>=RESUME_MEDIA_SECONDS:
                self._fail("resume_no_media")
                return None
        if self.state=="playing" and absent and self.resumed_at is None:
            return self._send("PAUSE",now)
        if self.state=="paused" and attached:
            return self._send("PLAY",now)
        return None

    def _send(self,method,now):
        self.cseq+=1
        self.pending=(method,self.cseq,now)
        self.state="pausing" if method=="PAUSE" else "resuming"
        return (method,self.cseq)

    def take_notes(self):
        notes,self.notes=self.notes,[]
        return notes

    def summary(self):
        return dict(state=self.state,pauses=self.pauses,resumes=self.resumes,failure=self.failure,
                    paused_seconds=round(self.paused_seconds,1),resume_ms=list(self.resume_ms))


class DaemonSession(base.SessionInput):
    def __init__(self,*args,on_streaming=lambda:None,**kwargs):
        super().__init__(*args,**kwargs)
        self.rtsp_seen=Head()
        self.terminate_requested=False
        self.on_streaming=on_streaming
        self.window_rtsp_start=None
        self.writer_releases=0
        self.requesting=0
        self.input_wakes=0
        self.cursor=None
        # Set by kms_daemon_probe after AUTH when the scrambling profile is used.
        self.descrambler=None
        self.pause=PauseControl()

    def _phone_datagram(self,frame):
        descrambler=getattr(self,"descrambler",None)
        if descrambler is not None:
            frame=descrambler.frame(frame)
        super()._phone_datagram(frame)

    @property
    def collect_media(self):
        return self._collect_media

    @collect_media.setter
    def collect_media(self,value):
        long.LongSession.collect_media.fset(self,value)
        if value and self.keepalive_offset is not None and self.window_rtsp_start is None:
            self.window_rtsp_start=self.keepalive_offset

    def wait(self,seconds,until=lambda: False):
        if not self.window_armed:
            return super().wait(seconds,until)
        # base.SessionInput.wait opens kms_session_live's reader; this one adds writer_gone().
        original=base.InputReader
        base.InputReader=lambda path:WakingInputReader(InputReader(path))
        try:
            self.sink.arm()
            try:
                self.on_streaming()
            except Exception as error:
                # A notice only: it must not keep the window armed for the TEARDOWN wait.
                self.log("streaming_notice_failed",error_type=type(error).__name__)
            return super().wait(seconds,until)
        finally:
            base.InputReader=original
            self._compact_rtsp()

    def _relay_cursor(self):
        # Cosmetic pointer shape for the viewer; sessions built without __init__
        # (tests) or without a KMS connection simply have none.
        connection=getattr(self,"kms_connection",None)
        fifo=getattr(self,"input_fifo",None)
        if not self.window_open or self.cleanup or connection is None or fifo is None:
            return
        if getattr(self,"cursor",None) is None:
            self.cursor=CursorRelay(os.path.join(os.path.dirname(fifo),"cursor.fifo"))
        self.cursor.feed(connection.received)
        while self.cursor.seen:
            seen=self.cursor.seen.pop(0)
            if not seen.endswith(CURSOR_MSG):
                self.log("kms_common_message",message=seen)
            if seen=="REQ FeatureList" and not getattr(self,"features_sent",False):
                # SamsungDeX.exe tells the phone it takes file transfer over KMS; the phone
                # (KMSServiceManager.j) then sets KMS_FT_SUPPORTED and answers its features.
                self.features_sent=True
                try:
                    self.send(connection,file_bridge.common_request(900,{"TYPE":"REQ","MSG":"FeatureList",
                                                                         "PARAM":"KMS_FT_SUPPORTED"}),timeout_s=2)
                    self.log("kms_features_sent")
                except TunnelError as error:
                    self.log("kms_features_error",error=str(error)[:80])
        bridge=getattr(self,"clipboard",None)
        if bridge is not None:
            text=bridge.poll()
            if text is not None:
                self.cursor.clip(text)
                self.log("clipboard_from_phone",characters=len(text))
            files=getattr(self,"files",None)
            if files is not None:
                try:
                    files.tick()
                    while bridge.dragdrops:
                        files.dragdrop(bridge.dragdrops.pop(0))
                    while self.cursor.file_messages:
                        message=self.cursor.file_messages.pop(0)
                        param=message.get("PARAM") if isinstance(message.get("PARAM"),dict) else {}
                        self.log("files_phone_response",result=message.get("RESULT"),reason=str(message.get("REASON"))[:40],
                                 transfer=param.get("TransferID"),state=files.state,expected=files.transfer_id)
                        files.phone_response(message)
                except TunnelError as error:
                    files.viewer_failed("send: "+str(error)[:80])
        pulled=getattr(self,"phone_files",None)
        if pulled is not None:
            try:
                pulled.idc_frames(self.connections.values())
                while self.cursor.share_messages:
                    pulled.file_list(self.cursor.share_messages.pop(0))
                pulled.tick(self.configs)
            except TunnelError as error:
                try:
                    pulled._fail("tunnel: "+str(error)[:60])
                except TunnelError:
                    pulled.state="idle"
        self.cursor.flush()

    def _clipboard_bridge(self):
        """Created at the first clipboard line, from the connections kms_daemon_probe left here."""
        if getattr(self,"clipboard",None) is None:
            main=getattr(self,"main_connection",None)
            codec=getattr(self,"main_codec",None)
            if main is None or codec is None or main.closed_by_phone:
                return None
            self.clipboard=clipboard_bridge.ClipboardBridge(
                lambda connection,data: self.send(connection,data,timeout_s=1),main,codec,
                getattr(self,"idc_key",None),self._idc_command)
        return self.clipboard

    def _files(self,events):
        bridge=self._file_bridge()
        if bridge is None:
            self.dropped["files"]+=len(events)
            return
        for event in events:
            try:
                if event[0]=="FO":
                    bridge.offer(event[1],event[2])
                elif event[0]=="B":
                    bridge.viewer_chunk(event[1])
                elif event[0]=="FC":
                    bridge.cancel_drag()
                else:
                    bridge.viewer_failed()
            except TunnelError as error:
                bridge.viewer_failed("send: "+str(error)[:80])

    def _idc_command(self,payload):
        """One IDC command on a fresh connection to the phone's control port, then close it."""
        port=getattr(self,"next_idc_host",IDC_HOST_FIRST)
        if port>IDC_HOST_LAST:
            raise TunnelError("no IDC host port left in this session")
        self.next_idc_host=port+1
        connection=self.connect(port,config_id=wfd.CONTROL_CONFIG,timeout_s=2)
        try:
            self.send(connection,payload,timeout_s=1)
        finally:
            try:
                self.disconnect(connection,timeout_s=1)
            except TunnelError:
                pass

    def _file_bridge(self):
        if getattr(self,"files",None) is None:
            bridge=self._clipboard_bridge()
            kms=getattr(self,"kms_connection",None)
            if bridge is None or kms is None or getattr(self,"cursor",None) is None:
                return None
            self.files=file_bridge.FileBridge(
                lambda data: self.send(self.kms_connection,data,timeout_s=2),
                bridge.files_to_phone,self._open_file_socket,
                lambda connection,data: self.send(connection,data,timeout_s=2),
                lambda index,chunk: self.cursor.line(b"G %d %d\n"%(index,chunk)),self.log,
                report=lambda file,delivered,done: self.cursor.line(b"S %d %d %d\n"%(file,delivered,int(done))),
                transfer_id=file_bridge.saved_transfer_id(self.transfer_id_file),
                remember=lambda transfer_id: file_bridge.save_transfer_id(self.transfer_id_file,transfer_id))
        return self.files

    @property
    def transfer_id_file(self):
        """Where TransferIDs continue across sessions (file_bridge); None keeps them per session."""
        state=getattr(self,"state_dir",None)
        return None if state is None else Path(state)/"file-transfer-id"

    def _open_file_socket(self):
        """The phone's file socket (port 30831), opened when the phone first asks for files."""
        if file_bridge.FILE_CONFIG not in self.configs:
            self.open_config(file_bridge.FILE_CONFIG,SERVICE_UID,file_bridge.FILE_PORT,timeout_s=2)
        port=getattr(self,"next_file_host",file_bridge.FILE_HOST)
        self.next_file_host=port+100
        return self.connect(port,config_id=file_bridge.FILE_CONFIG,timeout_s=2)

    def _phone_files(self):
        if getattr(self,"phone_files",None) is None:
            key=getattr(self,"idc_key",None)
            if key is None or getattr(self,"cursor",None) is None:
                return None
            self.phone_files=phone_files.PhoneFiles(
                key,self._idc_text,self._open_http,
                lambda connection,data: self.send(connection,data,timeout_s=2),self._close_quietly,
                self.cursor.line,lambda: sum(len(line) for line in self.cursor.lines)+len(self.cursor.clip_out),
                self.log)
            self.phone_files.prime(self.connections.values())
        return self.phone_files

    def _idc_text(self,main,sub,kind,info):
        seq=getattr(self,"idc_seq",1000)
        self.idc_seq=seq+1 if seq<32760 else 1000
        self._idc_command(idc.encode(self.idc_key,idc.command_text(main,sub,kind,info,seq)))

    def _open_http(self,port,configs):
        """A fresh connection to the phone's file server port (one tunnel config per port)."""
        ports=getattr(self,"http_ports",{})
        self.http_ports=ports
        if port not in ports:
            ports[port]=phone_files.HTTP_CONFIG_FIRST+len(ports)
            self.open_config(ports[port],SERVICE_UID,port,timeout_s=2)
        host=getattr(self,"next_http_host",phone_files.HTTP_HOST_FIRST)
        self.next_http_host=host+1
        return self.connect(host,config_id=ports[port],timeout_s=2)

    def _close_quietly(self,connection):
        try:
            self.disconnect(connection,timeout_s=1)
        except TunnelError:
            pass

    def _clipboard(self,events):
        drag=[event for event in events if event[0] in ("DP","DD","DC")]
        if drag:
            events=[event for event in events if event[0] not in ("DP","DD","DC")]
            bridge=self._phone_files()
            for event in drag:
                if bridge is None:
                    self.dropped["phone_files"]+=1
                    continue
                try:
                    {"DP":bridge.pull,"DD":bridge.drop,"DC":bridge.cancel}[event[0]]()
                except TunnelError as error:
                    self.log("phone_files_error",error=str(error)[:80])
        if not events:
            return
        files=[event for event in events if event[0] in ("FO","B","BX","FC")]
        if files:
            events=[event for event in events if event[0] not in ("FO","B","BX","FC")]
            self._files(files)
        if not events:
            return
        bridge=self._clipboard_bridge()
        if bridge is None:
            self.dropped["clipboard"]+=len(events)
            return
        for event in events:
            # Clipboard is a convenience: a failure is logged and never ends the stream.
            try:
                if event[0]=="P":
                    bridge.to_phone(event[1])
                    self.log("clipboard_to_phone",characters=len(event[1]))
                else:
                    sent=bridge.request_from_phone()
                    self.log("clipboard_request",sent=sent)
            except TunnelError as error:
                bridge.counts["send_errors"]+=1
                self.log("clipboard_error",kind=event[0],error=str(error)[:120])

    def _request(self,*args,**kwargs):
        self.requesting+=1
        try:
            return super()._request(*args,**kwargs)
        finally:
            self.requesting-=1

    def _next_frame(self,deadline):
        # End the media slice early while viewer input is queued: usb_tunnel.wait
        # treats TimeoutError as the slice deadline, and rtsp_udp_live then pumps
        # input before the next slice. A request awaiting its reply is never cut.
        # The same conditions under which rtsp_udp_live's slice loop pumps input.
        if (not self.requesting and self.window_open and not self.cleanup
                and self.collect_media and self.keepalive_offset is not None):
            reader=getattr(self,"input",None)
            if isinstance(reader,WakingInputReader) and reader.queued_event():
                self.input_wakes+=1
                raise TimeoutError("viewer input queued")
        return super()._next_frame(deadline)

    def _compact_rtsp(self):
        """Drop the RTSP messages answered during the window, keeping the PLAY response.

        rtsp_udp_play.exchange re-reads the stream from just after its PLAY response
        and refuses TEARDOWN once the whole stream passes rtsp.STREAM_BYTES."""
        connection=self.rtsp_connection
        start=self.window_rtsp_start
        if connection is None or start is None or self.keepalive_offset is None:
            return
        # Only the first message is needed; the whole region may exceed the parser's limit.
        end=min(self.keepalive_offset,start+rtsp.STREAM_BYTES)
        parsed=rtsp.parse(bytes(connection.received[start:end]))
        if parsed is None:
            return
        play_end=start+parsed[1]
        del connection.received[play_end:self.keepalive_offset]
        self.keepalive_offset=play_end

    def stop_requested(self):
        if self.window_started is not None and self.clock()-self.window_started>=FULL_LOG_SECONDS:
            self.log.quiet=True
        if self.terminate_requested:
            self.stop_reason="sigterm"
        elif os.path.lexists(self.stop_file):
            self.stop_reason="stop_file"
        elif self.sink.error is not None:
            self.stop_reason="sink_error"
        elif self.kms_connection is not None and self.kms_connection.closed_by_phone:
            self.stop_reason="kms_closed"
        elif self._pause_control().failure is not None:
            self.stop_reason=self._pause_control().failure
        return self.stop_reason is not None

    def _pause_control(self):
        # Sessions built without __init__ (tests) get one on first use.
        if getattr(self,"pause",None) is None:
            self.pause=PauseControl()
        return self.pause

    def send(self,connection,payload,timeout_s=5):
        data=bytes(payload)
        if data.startswith(b"PLAY "):
            self._pause_control().learn_play(data)
        return super().send(connection,data,timeout_s=timeout_s)

    def _rtsp_responses(self):
        """(cseq,status) of RTSP responses not yet consumed by the keep-alive handler."""
        connection,offset=getattr(self,"rtsp_connection",None),getattr(self,"keepalive_offset",None)
        found=[]
        if connection is None or offset is None:
            return found
        while True:
            parsed=rtsp.parse(bytes(connection.received[offset:]))
            if parsed is None:
                return found
            message,size=parsed
            offset+=size
            if message["kind"]=="response":
                found.append((message["cseq"],message["status"]))

    def _pause_or_resume(self):
        control=self._pause_control()
        sink=getattr(self,"sink",None)
        if (sink is None or control.uri is None or not self.window_open or self.cleanup
                or control.failure is not None):
            return
        attached=bool(getattr(sink,"attached",False))
        absent=sink.unattached_seconds()>=VIEWER_GRACE_SECONDS
        rtp=self.media_counts.get(play.RTP_CONFIG,0) if hasattr(self,"media_counts") else 0
        request=control.step(self.clock(),attached,absent,self._rtsp_responses(),rtp)
        if request is not None:
            self.log("rtsp_%s_sent"%request[0].lower(),cseq=request[1])
            self.send(self.rtsp_connection,control.request(*request),timeout_s=RTSP_REPLY_SECONDS)
        for note in control.take_notes():
            notify=getattr(sink,"notify",None)
            if notify is not None:
                notify(note)

    def _answer_keepalives(self):
        # Peek replies first: the keep-alive handler below consumes them.
        self._pause_or_resume()
        super()._answer_keepalives()
        self._relay_cursor()
        # writer_gone() also drops a departed writer's partial line, so ask even when nothing is held.
        if (self.window_open and not self.cleanup and not self.pending
                and self.input.writer_gone() and (self.held or self.keys_held)):
            self._release_held()
            self.writer_releases+=1

    def summary(self):
        result=super().summary()
        result["rtsp_seen_total"]=self.rtsp_seen.total
        result["kms_input"]["writer_releases"]=self.writer_releases
        result["kms_input"]["input_wakes"]=self.input_wakes
        if getattr(self,"cursor",None) is not None:
            self.cursor.close()
            result["kms_input"]["cursor"]=self.cursor.summary()
        if getattr(self,"clipboard",None) is not None:
            result["kms_input"]["clipboard"]=self.clipboard.summary()
        if getattr(self,"files",None) is not None:
            result["kms_input"]["files"]=self.files.summary()
        if getattr(self,"phone_files",None) is not None:
            result["kms_input"]["phone_files"]=self.phone_files.summary()
        timing=getattr(self,"usb_timing",None)
        if timing is not None:
            result["usb_timing"]=timing.summary()
        descrambler=getattr(self,"descrambler",None)
        result["scramble"]=None if descrambler is None else descrambler.summary()
        result["pause"]=self._pause_control().summary()
        return result


class DaemonOwner(base.SessionOwner):
    def __init__(self,*args,on_streaming=lambda:None,**kwargs):
        super().__init__(*args,**kwargs)
        self.on_streaming=on_streaming
        self.current=None

    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=long.MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=DaemonSession(link,first_transaction,max_frame_bytes,long.LONG_RECEIVE_BYTES,
            sink=self.sink,stop_file=self.stop_file,input_fifo=self.input_fifo,
            log=DaemonLog(log),on_streaming=self.on_streaming,**kwargs)
        session.state_dir=getattr(self,"state_dir",None)
        # Before any I/O; conn_transfer.TransferSessions then installs its decoder.
        link.record=DaemonRecorder(session.log,session.max_frame_bytes)
        session.usb_timing=link.record.timing=UsbTiming(link.device,timeout_error=link.timeout_error,
            async_in=lambda device,endpoint,timeout_error:AsyncIn(LibusbEngine(device,endpoint),timeout_error),
            async_out=lambda device,on_done:AsyncOut(LibusbOutEngine(device),on_done=on_done))
        # A busy protocol thread must not hold the GIL 5 ms while the reader waits.
        sys.setswitchinterval(SWITCH_INTERVAL_SECONDS)
        link.device=session.usb_timing
        self.reader=duplex_link.ReadPump(link,session.log)
        self.current=session
        return session

    def _quiesce(self):
        timing=getattr(self.current,"usb_timing",None)
        if timing is not None and not self.quiesced:
            try:
                timing.stop_writer()
            except Exception as error:
                # A live writer or an OUT transfer that may be in flight forbids USB release.
                if timing.writer is not None and timing.writer.is_alive():
                    raise
                if timing.async_out is not None and timing.async_out.inflight>0:
                    raise
                self.quiesce_error=error
        error=super()._quiesce()
        if timing is not None and timing.async_in is not None and not timing.async_in.stopping:
            try:
                timing.async_in.stop()
            finally:
                self.result.setdefault("duplex_usb",{})["async_in"]=timing.async_in.summary()
        return error or self.quiesce_error

    def terminate(self):
        """SIGTERM: True if the running window will stop by itself (TEARDOWN, then cleanup)."""
        session=self.current
        if session is None or session.window_started is None:
            return False
        session.terminate_requested=True
        return True


class EventLog:
    """One timestamped line per daemon event, appended to dexd's log; never raises."""
    def __init__(self,path):
        self.path=path
        self.counts=Counter()

    def __call__(self,event):
        self.counts[event]+=1
        try:
            with open(self.path,"a") as log:
                log.write("%s session %s\n"%(time.strftime("%Y-%m-%dT%H:%M:%S%z"),event))
        except OSError:
            pass
