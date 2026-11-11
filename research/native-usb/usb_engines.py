"""USB bulk I/O for the daemon session: per-session timing, pipelined and
asynchronous OUT, asynchronous IN (moved from kms_daemon_live, 2026-11-11).
"""
from array import array
from collections import deque
import threading
import time

import duplex_link

# Per-session USB timing (2026-11-06 latency investigation): sizes and monotonic times only.
TIMING_CAP=600000
# Pipelined OUT (2026-11-06): like the official PC library's overlapped I/O, the
# protocol thread queues each USB write instead of waiting for it.
WRITE_QUEUE_LIMIT=8192
WRITER_STOP_SECONDS=2
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
# Asynchronous OUT (2026-11-06 backlog): session 232614 spent 30% of its time in
# one-at-a-time synchronous writes (151,723, nearly all per-datagram ACKs);
# queued-to-done p99 96 ms, max 258 ms, peak 376 queued, and viewer input waited
# behind them. Up to ASYNC_OUT_TRANSFERS stay submitted, strictly in queue order:
# the same transfers (one per frame, the ZLP its own) reach the phone in the same
# order; only the wait for each completion overlaps the next submission.
ASYNC_OUT_TRANSFERS=8


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
    def __init__(self,device,cap=TIMING_CAP,pipelined=True,async_in=None,timeout_error=TimeoutError,
                 async_out=None):
        self.device,self.cap,self.pipelined=device,cap,pipelined
        # async_out: None = synchronous writes on the writer thread; otherwise a
        # factory(device,on_done) -> AsyncOut, created by the writer thread.
        self.async_out_factory,self.async_out=async_out,None
        self.async_out_unavailable=None
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
        if self.writer_error is None and self.async_out is not None and self.async_out.error is not None:
            self.writer_error=duplex_link.TunnelError(self.async_out.error)
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

    def _async_done(self,token):
        submitted,queued,size=token
        if len(self.write_ns)<self.cap:
            end=time.monotonic_ns()
            self.write_ns.append(end-submitted)
            self.write_bytes.append(size)
            self.write_queued_ns.append(end-queued)

    def _async_write_loop(self):
        try:
            self.async_out=self.async_out_factory(self.device,self._async_done)
        except Exception as error:
            # Setup only (nothing submitted yet): keep the proven synchronous writer.
            self.async_out_unavailable="%s: %s"%(type(error).__name__,error)
            self.async_out_factory=None
            return self._write_loop()
        while True:
            with self.condition:
                while not self.pending and not self.writer_stopping:
                    self.condition.wait()
                if not self.pending:
                    return
                endpoint,data,timeout,queued=self.pending.popleft()
                self.condition.notify_all()
            try:
                self.async_out.send(endpoint,data,timeout,(time.monotonic_ns(),queued,len(data)))
            except Exception as error:
                with self.condition:
                    self.writer_error=error
                    self.pending.clear()
                    self.condition.notify_all()
                return

    def _write_loop(self):
        if self.async_out_factory is not None:
            return self._async_write_loop()
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
        if self.async_out is not None:
            self.async_out.stop(seconds)
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
            async_in=self.async_in.summary() if self.async_in is not None else None,
            async_out=self.async_out.summary() if self.async_out is not None else None,
            async_out_unavailable=self.async_out_unavailable)


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


class AsyncOut:
    """Bulk-OUT transfers submitted in queue order, at most `transfers` in flight.

    send() runs on the single writer thread only, so submission order is queue
    order; USB completes bulk transfers on one endpoint in submission order.
    complete() runs on the libusb event thread. The engine is injected (tests use
    a fake; LibusbOutEngine is the real one)."""
    def __init__(self,engine,transfers=ASYNC_OUT_TRANSFERS,on_done=lambda token:None):
        self.engine,self.transfers,self.on_done=engine,transfers,on_done
        self.condition=threading.Condition()
        self.inflight=self.inflight_peak=0
        self.submitted=self.completed=0
        self.error=None
        engine.start(self,transfers)

    def send(self,endpoint,data,timeout,token):
        with self.condition:
            while self.inflight>=self.transfers and self.error is None:
                self.condition.wait()
            if self.error is not None:
                raise duplex_link.TunnelError(self.error)
            self.inflight+=1
            self.submitted+=1
            self.inflight_peak=max(self.inflight_peak,self.inflight)
        code=self.engine.submit(endpoint,data,timeout,token)
        if code:
            with self.condition:
                self.inflight-=1
                if self.error is None:
                    self.error="async OUT submit failed %d"%code
                self.condition.notify_all()
            raise duplex_link.TunnelError(self.error)

    def complete(self,status,actual,length,token):
        """status: 0 completed; anything else (or a short transfer) fails the session's writes."""
        with self.condition:
            self.completed+=1
            self.inflight-=1
            if (status!=0 or actual!=length) and self.error is None:
                self.error="async OUT transfer status %d (%d of %d bytes)"%(status,actual,length)
            self.condition.notify_all()
        self.on_done(token)

    def drain(self,seconds):
        """Waits for every submitted transfer; returns how many may still be in flight."""
        deadline=time.monotonic()+seconds
        with self.condition:
            while self.inflight>0 and time.monotonic()<deadline:
                self.condition.wait(deadline-time.monotonic())
            return self.inflight

    def stop(self,seconds=WRITER_STOP_SECONDS):
        """After the writer thread ended: drain, else cancel; raises while any may be in flight."""
        if self.drain(seconds):
            self.engine.cancel_all()
            if self.drain(seconds):
                raise duplex_link.TunnelError("async OUT transfers still in flight; USB resource release prohibited")
        self.engine.close()

    def summary(self):
        with self.condition:
            return dict(transfers=self.transfers,submitted=self.submitted,completed=self.completed,
                        inflight=self.inflight,inflight_peak=self.inflight_peak,error=self.error)


class LibusbOutEngine(LibusbEngine):
    """libusb asynchronous bulk OUT on the claimed PyUSB handle; one transfer struct per slot."""
    def __init__(self,device):
        super().__init__(device,None)
        self.free=[]
        self.slots={}

    def start(self,owner,count):
        self.owner=owner
        self.callback=self.Callback(self._out_done)   # referenced for the transfers' lifetime
        for index in range(count):
            transfer=self.lib.libusb_alloc_transfer(0)
            if not transfer:
                raise duplex_link.TunnelError("libusb_alloc_transfer failed")
            t=transfer.contents
            t.dev_handle,t.flags,t.type,t.num_iso_packets=self.handle,0,2,0
            t.callback,t.user_data=self.callback,index
            self.transfers.append(transfer)
            self.free.append(index)
        self.events=threading.Thread(target=self._handle_events,name="dex-usb-out-events",daemon=True)
        self.events.start()

    def submit(self,endpoint,data,timeout,token):
        ct=self.ct
        index=self.free.pop()
        buffer=ct.create_string_buffer(bytes(data),max(1,len(data)))
        t=self.transfers[index].contents
        t.endpoint,t.timeout,t.length,t.buffer=endpoint,timeout or 0,len(data),ct.addressof(buffer)
        self.slots[index]=(buffer,len(data),token)   # buffer kept alive until completion
        code=self.lib.libusb_submit_transfer(self.transfers[index])
        if code:
            del self.slots[index]
            self.free.append(index)
        return code

    def _out_done(self,transfer):
        t=transfer.contents
        index=t.user_data or 0
        _,length,token=self.slots.pop(index)
        status,actual=t.status,t.actual_length
        self.free.append(index)
        self.owner.complete(status,actual,length,token)

    def cancel_all(self):
        for index in list(self.slots):
            self.lib.libusb_cancel_transfer(self.transfers[index])
