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
import dataclasses
import errno
import json
import os
import select
import stat
import sys
import threading
import time

import duplex_link
from threaded_input import ThreadedInputReader,_DISCONNECT as DISCONNECT
import kms_input_live
import kms_session_live as base
import live_sink
import rtsp
import rtsp_udp_long as long
import rtsp_udp_play as play
from sidesync_packets import VERSION
import tcp_control

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
# Asynchronous IN (2026-11-06): several large bulk transfers stay submitted, as the
# official library keeps overlapped reads queued; one-at-a-time 512-byte reads
# capped USB at ~3 MB/s. Completions are split into <=512-byte pieces in order,
# exactly what synchronous 512-byte reads of the same transfers return, so
# ReadPump and TransferDecoder (transfer boundaries) see identical input.
ASYNC_TRANSFERS=8
ASYNC_TRANSFER_BYTES=16384
ASYNC_PIECE_BYTES=512
ASYNC_READY_LIMIT=8<<20
ASYNC_STOP_SECONDS=2


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
    def __init__(self,device,cap=TIMING_CAP,pipelined=True,async_in=None,timeout_error=TimeoutError):
        self.device,self.cap,self.pipelined=device,cap,pipelined
        # async_in: None = synchronous reads; otherwise a factory(device,endpoint,timeout_error).
        self.async_factory,self.async_in,self.timeout_error=async_in,None,timeout_error
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
        if self.async_factory is not None:
            if self.async_in is None:
                self.async_in=self.async_factory(self.device,endpoint,self.timeout_error)
            data=self.async_in.read(size,timeout)
        else:
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
            writer_error=type(self.writer_error).__name__ if self.writer_error else None,
            async_in=self.async_in.summary() if self.async_in is not None else None)


class AsyncIn:
    """Keeps ASYNC_TRANSFERS bulk-IN transfers submitted; read() returns pieces in order.

    The transfer engine (submit/cancel/event handling) is injected so the ordering,
    splitting, error and stop rules are testable without a device; LibusbEngine is
    the real one. complete() runs for each finished transfer, on whichever thread
    libusb uses to handle events, and decides whether it is resubmitted."""
    def __init__(self,engine,timeout_error,transfers=ASYNC_TRANSFERS,transfer_bytes=ASYNC_TRANSFER_BYTES):
        self.engine,self.timeout_error=engine,timeout_error
        self.condition=threading.Condition()
        self.ready=deque()
        self.ready_bytes=self.ready_peak=0
        self.inflight=0
        self.error=None
        self.stopping=False
        self.completions=self.bytes_in=0
        engine.start(self,transfers,transfer_bytes)

    def submitting(self):
        """Counts a transfer in flight just before the engine submits it."""
        with self.condition:
            self.inflight+=1

    def complete(self,transfer,status,data):
        """Returns True to resubmit. status: 0 completed, 3 cancelled, other = failure."""
        with self.condition:
            self.completions+=1
            if data:
                self.bytes_in+=len(data)
                for offset in range(0,len(data),ASYNC_PIECE_BYTES):
                    self.ready.append(data[offset:offset+ASYNC_PIECE_BYTES])
                self.ready_bytes+=len(data)
                self.ready_peak=max(self.ready_peak,self.ready_bytes)
                if self.ready_bytes>ASYNC_READY_LIMIT and self.error is None:
                    self.error="async IN ready queue limit exceeded"
            if status==0 and not self.stopping and self.error is None:
                self.condition.notify_all()
                return True
            if status not in (0,3) and self.error is None:
                self.error="async IN transfer status %d"%status
            self.inflight-=1
            self.condition.notify_all()
            return False

    def resubmit_failed(self,code):
        with self.condition:
            self.inflight-=1
            if self.error is None:
                self.error="async IN resubmit failed %d"%code
            self.condition.notify_all()

    def read(self,size,timeout_ms):
        if size<ASYNC_PIECE_BYTES:
            raise duplex_link.TunnelError("async IN caller requested unsupported chunk size")
        deadline=time.monotonic()+(timeout_ms or 1000)/1000
        with self.condition:
            while not self.ready:
                if self.error is not None:
                    raise duplex_link.TunnelError(self.error)
                if self.stopping:
                    raise self.timeout_error("async IN stopped")
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise self.timeout_error("async IN timeout")
                self.condition.wait(remaining)
            piece=self.ready.popleft()
            self.ready_bytes-=len(piece)
            return piece

    def stop(self,seconds=ASYNC_STOP_SECONDS):
        """Cancel every transfer and wait for all completions; raises while any may be in flight."""
        with self.condition:
            self.stopping=True
            self.condition.notify_all()
        self.engine.cancel_all()
        deadline=time.monotonic()+seconds
        with self.condition:
            while self.inflight>0 and time.monotonic()<deadline:
                self.condition.wait(deadline-time.monotonic())
            pending=self.inflight
        if pending:
            raise duplex_link.TunnelError("async IN transfers still in flight; USB resource release prohibited")
        self.engine.close()

    def summary(self):
        with self.condition:
            return dict(transfers=ASYNC_TRANSFERS,transfer_bytes=ASYNC_TRANSFER_BYTES,completions=self.completions,
                        bytes_in=self.bytes_in,ready_peak_bytes=self.ready_peak,undelivered_bytes=self.ready_bytes,
                        inflight=self.inflight,error=self.error)


class LibusbEngine:
    """libusb-1.0 asynchronous bulk transfers on the handle PyUSB already opened and claimed.

    Uses PyUSB's own libusb context and device handle, so USB stays owned by this
    process and its claimed interface. Struct layout matches PyUSB's _libusb_transfer."""
    def __init__(self,device,endpoint):
        import ctypes,ctypes.util
        self.ct=ctypes
        lib=ctypes.CDLL(ctypes.util.find_library("usb-1.0") or "libusb-1.0.so.0")
        class Transfer(ctypes.Structure):
            pass
        self.Callback=ctypes.CFUNCTYPE(None,ctypes.POINTER(Transfer))
        Transfer._fields_=[("dev_handle",ctypes.c_void_p),("flags",ctypes.c_uint8),("endpoint",ctypes.c_uint8),
            ("type",ctypes.c_uint8),("timeout",ctypes.c_uint),("status",ctypes.c_int),("length",ctypes.c_int),
            ("actual_length",ctypes.c_int),("callback",self.Callback),("user_data",ctypes.c_void_p),
            ("buffer",ctypes.c_void_p),("num_iso_packets",ctypes.c_int)]
        class Timeval(ctypes.Structure):
            _fields_=[("tv_sec",ctypes.c_long),("tv_usec",ctypes.c_long)]
        lib.libusb_alloc_transfer.argtypes=[ctypes.c_int];lib.libusb_alloc_transfer.restype=ctypes.POINTER(Transfer)
        lib.libusb_free_transfer.argtypes=[ctypes.POINTER(Transfer)];lib.libusb_free_transfer.restype=None
        lib.libusb_submit_transfer.argtypes=[ctypes.POINTER(Transfer)];lib.libusb_submit_transfer.restype=ctypes.c_int
        lib.libusb_cancel_transfer.argtypes=[ctypes.POINTER(Transfer)];lib.libusb_cancel_transfer.restype=ctypes.c_int
        lib.libusb_handle_events_timeout_completed.argtypes=[ctypes.c_void_p,ctypes.POINTER(Timeval),ctypes.c_void_p]
        lib.libusb_handle_events_timeout_completed.restype=ctypes.c_int
        self.lib,self.Timeval=lib,Timeval
        resources=device._ctx
        resources.managed_open()
        self.handle=resources.handle.handle
        self.context=resources.backend.ctx
        self.endpoint=endpoint
        self.transfers,self.buffers=[],[]
        self.events=None
        self.events_stop=False

    def start(self,owner,count,size):
        ct=self.ct
        self.owner=owner
        self.callback=self.Callback(self._done)   # kept referenced for the transfers' lifetime
        for _ in range(count):
            transfer=self.lib.libusb_alloc_transfer(0)
            if not transfer:
                raise duplex_link.TunnelError("libusb_alloc_transfer failed")
            buffer=ct.create_string_buffer(size)
            t=transfer.contents
            t.dev_handle,t.flags,t.endpoint,t.type,t.timeout=self.handle,0,self.endpoint,2,0
            t.length,t.callback,t.buffer,t.num_iso_packets=size,self.callback,ct.addressof(buffer),0
            self.transfers.append(transfer);self.buffers.append(buffer)
        self.events=threading.Thread(target=self._handle_events,name="dex-usb-events",daemon=True)
        self.events.start()
        for transfer in self.transfers:
            owner.submitting()
            code=self.lib.libusb_submit_transfer(transfer)
            if code:
                owner.resubmit_failed(code)

    def _done(self,transfer):
        t=transfer.contents
        data=self.ct.string_at(t.buffer,t.actual_length) if t.actual_length>0 else b""
        if self.owner.complete(transfer,t.status,data):
            code=self.lib.libusb_submit_transfer(transfer)
            if code:
                self.owner.resubmit_failed(code)

    def _handle_events(self):
        timeout=self.Timeval(0,100000)
        while not self.events_stop:
            self.lib.libusb_handle_events_timeout_completed(self.context,self.ct.byref(timeout),None)

    def cancel_all(self):
        for transfer in self.transfers:
            self.lib.libusb_cancel_transfer(transfer)   # not-found codes for finished transfers are expected

    def close(self):
        self.events_stop=True
        if self.events is not None:
            self.events.join(1)
        for transfer in self.transfers:
            self.lib.libusb_free_transfer(transfer)
        self.transfers=[]


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
    detach and wait for the next one. dropped_* totals split into overflow (the
    queue was full while a viewer was attached: real loss) and detach (chunks
    still queued when the viewer left: nobody could receive them). error is set only for a fatal problem (the
    path is not a FIFO, or cannot be opened), which ends the session."""
    def __init__(self,path,queue_bytes=live_sink.QUEUE_BYTES,notify=lambda event:None,
                 poll_seconds=ATTACH_POLL_SECONDS):
        self.path,self.queue_limit,self.notify,self.poll_seconds=path,queue_bytes,notify,poll_seconds
        self.condition=threading.Condition()
        self.queue=deque()
        self.queued_bytes=self.peak_bytes=0
        self.forwarded_bytes=self.dropped_bytes=self.dropped_chunks=self.idle_bytes=0
        self.overflow_bytes=self.overflow_chunks=self.detach_bytes=self.detach_chunks=0
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
                self.overflow_bytes+=len(data)
                self.overflow_chunks+=1
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
            self.detach_bytes+=self.queued_bytes
            self.detach_chunks+=len(self.queue)
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
                        dropped_chunks=self.dropped_chunks,
                        overflow_dropped_bytes=self.overflow_bytes,overflow_dropped_chunks=self.overflow_chunks,
                        detach_dropped_bytes=self.detach_bytes,detach_dropped_chunks=self.detach_chunks,
                        queue_peak_bytes=self.peak_bytes,
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
        if not isinstance(message,dict) or message.get("MSG")!=CURSOR_MSG:
            return
        param=message.get("PARAM")
        shape=param.get("MOUSE_CURSOR_ID") if isinstance(param,dict) else None
        if type(shape) is not int or not 0<=shape<=99999:
            self.counts["invalid"]+=1
            return
        self.counts["changes"]+=1
        self.pending=(shape,1 if param.get("IS_NIGHT_MODE") is True else 0)

    def flush(self):
        if self.pending is None or self.error is not None:
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
                os.write(self.fd,b"C %d %d\n"%self.pending)
            except BlockingIOError:
                self.counts["full"]+=1
                return
            except BrokenPipeError:
                self.close()
                self.counts["reader_left"]+=1
                return
            self.counts["sent"]+=1
            self.last_sent,self.pending=self.pending,None
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
        self.cursor.flush()

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
        elif self.sink.unattached_seconds()>=VIEWER_GRACE_SECONDS:
            self.stop_reason="viewer_left"
        return self.stop_reason is not None

    def _answer_keepalives(self):
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
        timing=getattr(self,"usb_timing",None)
        if timing is not None:
            result["usb_timing"]=timing.summary()
        descrambler=getattr(self,"descrambler",None)
        result["scramble"]=None if descrambler is None else descrambler.summary()
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
        session.usb_timing=link.record.timing=UsbTiming(link.device,timeout_error=link.timeout_error,
            async_in=lambda device,endpoint,timeout_error:AsyncIn(LibusbEngine(device,endpoint),timeout_error))
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
