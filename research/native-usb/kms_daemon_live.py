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
from array import array
from collections import Counter,deque
import errno
import os
import select
import stat
import sys
import threading
import time

import duplex_link
from threaded_input import ThreadedInputReader
import kms_input_live
import kms_session_live as base
import live_sink
import rtsp
import rtsp_udp_long as long
import rtsp_udp_play as play

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
ATTACH_POLL_SECONDS=.5
# The window ends once no viewer has been attached this long (also if none ever attached).
VIEWER_GRACE_SECONDS=5
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


# Per-session USB timing (2026-11-06 latency investigation): sizes and monotonic times only.
TIMING_CAP=600000
# Pipelined OUT (2026-11-06): like the official PC library's overlapped I/O, the
# protocol thread queues each USB write instead of waiting for it.
WRITE_QUEUE_LIMIT=8192
WRITER_STOP_SECONDS=2
SWITCH_INTERVAL_SECONDS=.001


def _percentiles(values,points=(.5,.9,.99)):
    if not values:
        return {}
    values=sorted(values)
    result={("p%g"%(p*100)).replace(".","_"):round(values[min(len(values)-1,int(p*len(values)))],1) for p in points}
    result["max"]=round(values[-1],1)
    return result


def _peak_window_bytes(stamps,sizes,window_ns):
    best=total=start=0
    for end in range(len(stamps)):
        total+=sizes[end]
        while stamps[end]-stamps[start]>window_ns:
            total-=sizes[start]
            start+=1
        best=max(best,total)
    return best


class UsbTiming:
    """Wraps the PyUSB device: one ordered writer thread, plus timing; never keeps payload.

    write() queues the transfer for the single writer thread and returns at once,
    so every OUT keeps its order (including a full-packet write's ZLP) and USB
    still has one writer. A failed write is raised by the next read or write.
    The reader thread stamps each non-empty read; the recorder stamps the owner
    thread taking each chunk. ReadPump preserves FIFO order, so the k-th consumed
    chunk is the k-th read and their difference is that chunk's backlog wait."""
    def __init__(self,device,cap=TIMING_CAP,pipelined=True):
        self.device,self.cap,self.pipelined=device,cap,pipelined
        self.read_start,self.read_end,self.read_bytes=array("q"),array("q"),array("i")
        self.consumed=array("q")
        self.write_ns,self.write_bytes,self.write_queued_ns=array("q"),array("i"),array("q")
        self.condition=threading.Condition()
        self.pending=deque()
        self.queue_peak=0
        self.writer=None
        self.writer_error=None
        self.writer_stopping=False

    def __getattr__(self,name):
        return getattr(self.device,name)

    def _raise_writer_error(self):
        if self.writer_error is not None:
            raise duplex_link.TunnelError("pipelined USB write failed: %s: %s"%(
                type(self.writer_error).__name__,self.writer_error))

    def read(self,endpoint,size,timeout=None):
        self._raise_writer_error()
        start=time.monotonic_ns()
        data=self.device.read(endpoint,size,timeout=timeout)
        if len(data) and len(self.read_end)<self.cap:
            self.read_start.append(start)
            self.read_end.append(time.monotonic_ns())
            self.read_bytes.append(len(data))
        return data

    def _timed_write(self,endpoint,data,timeout,queued):
        start=time.monotonic_ns()
        try:
            return self.device.write(endpoint,data,timeout=timeout)
        finally:
            if len(self.write_ns)<self.cap:
                end=time.monotonic_ns()
                self.write_ns.append(end-start)
                self.write_bytes.append(len(data))
                self.write_queued_ns.append(end-queued)

    def write(self,endpoint,data,timeout=None):
        if not self.pipelined:
            return self._timed_write(endpoint,data,timeout,time.monotonic_ns())
        data=bytes(data)
        with self.condition:
            self._raise_writer_error()
            if self.writer_stopping:
                raise duplex_link.TunnelError("USB writer is stopped")
            if len(self.pending)>=WRITE_QUEUE_LIMIT:
                raise duplex_link.TunnelError("USB write queue limit exceeded")
            if self.writer is None:
                self.writer=threading.Thread(target=self._write_loop,name="dex-usb-out",daemon=True)
                self.writer.start()
            self.pending.append((endpoint,data,timeout,time.monotonic_ns()))
            self.queue_peak=max(self.queue_peak,len(self.pending))
            self.condition.notify_all()
        return len(data)

    def _write_loop(self):
        while True:
            with self.condition:
                while not self.pending and not self.writer_stopping:
                    self.condition.wait()
                if not self.pending:
                    return
                endpoint,data,timeout,queued=self.pending[0]
            try:
                written=self._timed_write(endpoint,data,timeout,queued)
                if written!=len(data):
                    raise duplex_link.TunnelError("partial USB write")
            except Exception as error:
                with self.condition:
                    self.writer_error=error
                    self.pending.clear()
                    self.condition.notify_all()
                return
            with self.condition:
                self.pending.popleft()
                self.condition.notify_all()

    def stop_writer(self,seconds=WRITER_STOP_SECONDS):
        """Drain queued writes, then stop; raises if the thread may still hold the handle."""
        with self.condition:
            self.writer_stopping=True
            self.condition.notify_all()
        if self.writer is not None:
            self.writer.join(seconds)
            if self.writer.is_alive():
                raise duplex_link.TunnelError("USB writer did not stop; USB resource release prohibited")
        self._raise_writer_error()

    def mark_consumed(self):
        if len(self.consumed)<self.cap:
            self.consumed.append(time.monotonic_ns())

    def summary(self):
        n=min(len(self.read_end),len(self.consumed))
        reads,writes=len(self.read_end),len(self.write_ns)
        span_s=(self.read_end[-1]-self.read_end[0])/1e9 if reads>1 else 0
        return dict(reads=reads,read_bytes=sum(self.read_bytes),consumed=len(self.consumed),capped=reads>=self.cap,
            span_seconds=round(span_s,3),pipelined=self.pipelined,
            read_call_us=_percentiles([(e-s)/1000 for s,e in zip(self.read_start,self.read_end)]),
            backlog_wait_us=_percentiles([(self.consumed[i]-self.read_end[i])/1000 for i in range(n)],(.5,.9,.99,.999)),
            backlog_over_20ms=sum(self.consumed[i]-self.read_end[i]>20_000_000 for i in range(n)),
            backlog_over_50ms=sum(self.consumed[i]-self.read_end[i]>50_000_000 for i in range(n)),
            read_peak_bytes_per_100ms=_peak_window_bytes(self.read_end,self.read_bytes,100_000_000),
            consume_peak_bytes_per_100ms=_peak_window_bytes(self.consumed[:n],self.read_bytes[:n],100_000_000),
            writes=writes,write_us=_percentiles([w/1000 for w in self.write_ns]),
            write_queue_to_done_us=_percentiles([w/1000 for w in self.write_queued_ns]),
            write_queue_peak=self.queue_peak,write_total_ms=round(sum(self.write_ns)/1e6,1),
            writer_error=type(self.writer_error).__name__ if self.writer_error else None)


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


class DetachableSink:
    """live_sink.TsSink's put/close/summary contract for a FIFO whose reader comes and goes.

    No reader: put() drops (counted). A reader appears: forward. Its write fails:
    detach and wait for the next one. error is set only for a fatal problem (the
    path is not a FIFO, or cannot be opened), which ends the session."""
    def __init__(self,path,queue_bytes=live_sink.QUEUE_BYTES,notify=lambda event:None,
                 poll_seconds=ATTACH_POLL_SECONDS):
        self.path,self.queue_limit,self.notify,self.poll_seconds=path,queue_bytes,notify,poll_seconds
        self.condition=threading.Condition()
        self.queue=deque()
        self.queued_bytes=self.peak_bytes=0
        self.forwarded_bytes=self.dropped_bytes=self.dropped_chunks=self.idle_bytes=0
        self.attached=False
        self.attaches=self.detaches=0
        self.idle_since=time.monotonic()
        self.armed_at=None
        self.error=None
        self.stopping=False
        self.thread=threading.Thread(target=self._run,name="dex-ts-sink",daemon=True)

    def start(self):
        self.thread.start()
        return self

    @property
    def opened(self):
        return self.attaches>0

    def arm(self):
        """Start counting viewer absence (the media window began)."""
        with self.condition:
            self.armed_at=time.monotonic()

    def unattached_seconds(self):
        with self.condition:
            if self.attached or self.armed_at is None:
                return 0
            return time.monotonic()-max(self.idle_since,self.armed_at)

    def put(self,data):
        with self.condition:
            if not self.attached or self.stopping:
                self.idle_bytes+=len(data)
                return
            if self.queued_bytes+len(data)>self.queue_limit:
                self.dropped_bytes+=len(data)
                self.dropped_chunks+=1
                return
            self.queue.append(bytes(data))
            self.queued_bytes+=len(data)
            self.peak_bytes=max(self.peak_bytes,self.queued_bytes)
            self.condition.notify()

    def _open(self):
        """A blocking fd once a reader is there; None while there is none."""
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        except OSError as error:
            # ENXIO: FIFO without a reader.
            if error.errno==errno.ENXIO:
                return None
            raise
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            os.close(fd)
            raise RuntimeError("live sink path is not a FIFO; refusing to persist media")
        os.set_blocking(fd,True)
        return fd

    def _detach(self,fd):
        os.close(fd)
        with self.condition:
            self.attached=False
            self.idle_since=time.monotonic()
            self.detaches+=1
            self.dropped_bytes+=self.queued_bytes
            self.dropped_chunks+=len(self.queue)
            self.queue.clear()
            self.queued_bytes=0
        self.notify("viewer_detached")

    def _run(self):
        fd=None
        try:
            while True:
                if fd is None:
                    with self.condition:
                        if self.stopping:
                            return
                    fd=self._open()
                    if fd is None:
                        with self.condition:
                            if not self.stopping:
                                self.condition.wait(self.poll_seconds)
                        continue
                    with self.condition:
                        self.attached=True
                        self.attaches+=1
                    self.notify("viewer_attached")
                with self.condition:
                    while not self.queue and not self.stopping:
                        self.condition.wait()
                    if not self.queue:
                        return
                    chunk=self.queue.popleft()
                    self.queued_bytes-=len(chunk)
                view=memoryview(chunk)
                try:
                    while view:
                        view=view[os.write(fd,view):]
                except OSError:
                    # EPIPE: the viewer went away. The session stays.
                    self._detach(fd)
                    fd=None
                    continue
                with self.condition:
                    self.forwarded_bytes+=len(chunk)
        except Exception as error:
            with self.condition:
                self.error=error
                self.attached=False
                self.queue.clear()
                self.queued_bytes=0
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        with self.condition:
            self.stopping=True
            self.condition.notify_all()
        if self.thread.is_alive():
            self.thread.join(live_sink.STOP_SECONDS)

    def summary(self):
        with self.condition:
            return dict(opened=self.opened,attaches=self.attaches,detaches=self.detaches,
                        attached_at_end=self.attached,forwarded_bytes=self.forwarded_bytes,
                        idle_dropped_bytes=self.idle_bytes,dropped_bytes=self.dropped_bytes,
                        dropped_chunks=self.dropped_chunks,queue_peak_bytes=self.peak_bytes,
                        stopped=not self.thread.is_alive(),
                        error_type=type(self.error).__name__ if self.error else None)


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


class DaemonSession(base.SessionInput):
    def __init__(self,*args,on_streaming=lambda:None,**kwargs):
        super().__init__(*args,**kwargs)
        self.rtsp_seen=Head()
        self.terminate_requested=False
        self.on_streaming=on_streaming
        self.window_rtsp_start=None
        self.writer_releases=0

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
        base.InputReader=lambda path:ThreadedInputReader(InputReader(path))
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
        elif self.sink.unattached_seconds()>=VIEWER_GRACE_SECONDS:
            self.stop_reason="viewer_left"
        return self.stop_reason is not None

    def _answer_keepalives(self):
        super()._answer_keepalives()
        # writer_gone() also drops a departed writer's partial line, so ask even when nothing is held.
        if (self.window_open and not self.cleanup and not self.pending
                and self.input.writer_gone() and (self.held or self.keys_held)):
            self._release_held()
            self.writer_releases+=1

    def summary(self):
        result=super().summary()
        result["rtsp_seen_total"]=self.rtsp_seen.total
        result["kms_input"]["writer_releases"]=self.writer_releases
        timing=getattr(self,"usb_timing",None)
        if timing is not None:
            result["usb_timing"]=timing.summary()
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
        # Before any I/O; conn_transfer.TransferSessions then installs its decoder.
        link.record=DaemonRecorder(session.log,session.max_frame_bytes)
        session.usb_timing=link.record.timing=UsbTiming(link.device)
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
                if timing.writer is not None and timing.writer.is_alive():
                    raise
                self.quiesce_error=error
        error=super()._quiesce()
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
