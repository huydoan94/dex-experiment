"""One bounded IN worker; protocol parsing, logging and every OUT remain on caller."""
from collections import deque
import struct
import threading
import time

from rtsp_udp_play import PlaySession
from tunnel_probe import READ_ENDPOINT,READ_BYTES
from usb_tunnel import TunnelError

QUEUE_BYTES=2<<20
READ_TIMEOUT_MS=200
STOP_SECONDS=1


class ReadPump:
    def __init__(self,link,log,queue_bytes=QUEUE_BYTES):
        self.link,self.log=link,log
        self.queue_limit=queue_bytes
        self.condition=threading.Condition()
        self.queue=deque()
        self.queued_bytes=0
        self.peak_bytes=0
        self.read_calls=0
        self.raw_bytes=0
        self.timeouts=0
        self.inflight=False
        self.error=None
        self.stopping=False
        self.thread=None
        self.stop_done=False
        self.join_attempted=False
        self.tail_chunks=0
        self.tail_bytes=0
        self.stop_error=None
        self.original_write=link.write
        link.read=self.read
        link.write=self.write
        link.begin_cleanup=self.begin_cleanup

    def _run(self):
        try:
            while True:
                with self.condition:
                    if self.stopping:
                        return
                    reserve=0 if self.link.cleanup else self.link.cleanup_reads
                    if self.link.reads_left<=reserve:
                        # Exhaustion fails only an owner read(), as in the single-thread Link.
                        self.condition.wait()
                        continue
                    if self.queued_bytes+READ_BYTES>self.queue_limit:
                        raise TunnelError("duplex IN queue byte limit exceeded")
                    self.link.reads_left-=1
                    self.read_calls+=1
                    self.inflight=True
                try:
                    chunk=bytes(self.link.device.read(READ_ENDPOINT,READ_BYTES,timeout=READ_TIMEOUT_MS))
                except self.link.timeout_error:
                    with self.condition:
                        self.timeouts+=1
                        self.inflight=False
                        self.condition.notify_all()
                        # Also avoids a spin with an immediate timeout backend.
                        if not self.stopping:
                            self.condition.wait(.02)
                    continue
                if len(chunk)>READ_BYTES:
                    raise TunnelError("duplex read exceeded requested size")
                with self.condition:
                    self.inflight=False
                    self.raw_bytes+=len(chunk)
                    if chunk:
                        self.queue.append(chunk)
                        self.queued_bytes+=len(chunk)
                        self.peak_bytes=max(self.peak_bytes,self.queued_bytes)
                        self.condition.notify_all()
                    elif not self.stopping:
                        self.condition.wait(.02)
        except Exception as error:
            with self.condition:
                self.inflight=False
                self.error=error
                self.condition.notify_all()

    def read(self,size,timeout_ms):
        if size<READ_BYTES:
            raise TunnelError("duplex caller requested unsupported chunk size")
        deadline=time.monotonic()+timeout_ms/1000
        with self.condition:
            if self.thread is None:
                if self.stopping:
                    raise TunnelError("duplex reader is stopped")
                self.thread=threading.Thread(target=self._run,name="dex-usb-in",daemon=True)
                self.thread.start()
            while not self.queue:
                if self.error is not None:
                    raise self.error
                if self.stopping:
                    raise TunnelError("duplex reader is stopped")
                reserve=0 if self.link.cleanup else self.link.cleanup_reads
                if self.link.reads_left<=reserve and not self.inflight:
                    raise TunnelError("duplex USB read budget exhausted")
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    return b""
                self.condition.wait(remaining)
            chunk=self.queue.popleft()
            self.queued_bytes-=len(chunk)
            self.condition.notify_all()
        # Only the owner thread logs/reframes; worker never calls the recorder.
        self.link.record("in",chunk)
        return chunk

    def write(self,data,timeout_ms):
        command,kind,transaction=struct.unpack_from("<I4xII",data,4)
        started=time.monotonic()
        budgets=(self.link.acks_left,self.link.requests_left)
        try:
            count=self.original_write(data,timeout_ms)
        except Exception as error:
            try:
                self.log("duplex_write_failed",command=command,kind=kind,
                         transaction=transaction,elapsed_seconds=round(time.monotonic()-started,6),
                         error_type=type(error).__name__,error=str(error))
            finally:
                raise
        # Link suppresses over-budget cleanup ACKs without a device write or budget change.
        written=(self.link.acks_left,self.link.requests_left)!=budgets
        self.log("duplex_write_completed" if written else "duplex_write_suppressed",command=command,kind=kind,transaction=transaction,
                 elapsed_seconds=round(time.monotonic()-started,6),size_bytes=count)
        return count

    def begin_cleanup(self):
        with self.condition:
            self.link.cleanup=True
            self.condition.notify_all()

    def alive(self):
        return self.thread is not None and self.thread.is_alive()

    def stop(self):
        if self.stop_done:
            if self.stop_error is not None:
                raise self.stop_error
            return
        with self.condition:
            self.stopping=True
            self.condition.notify_all()
        if not self.join_attempted:
            self.join_attempted=True
            if self.thread is not None:
                self.thread.join(STOP_SECONDS)
        if self.alive():
            self.stop_error=TunnelError("duplex reader did not stop; USB resource release prohibited")
            raise self.stop_error
        self.stop_done=True
        try:
            # Retain metadata for all worker-consumed bytes, without more protocol ACKs.
            while self.queue:
                chunk=self.queue.popleft()
                self.queued_bytes-=len(chunk)
                self.tail_chunks+=1
                self.tail_bytes+=len(chunk)
                self.link.record("in",chunk)
            if self.stop_error is not None:
                raise self.stop_error
            if self.error is not None:
                raise self.error
        except Exception as error:
            self.stop_error=error
            raise

    def summary(self):
        return dict(read_calls=self.read_calls,raw_in_bytes=self.raw_bytes,
                    read_timeouts=self.timeouts,queue_peak_bytes=self.peak_bytes,
                    reader_stopped=not self.alive(),metadata_tail_chunks=self.tail_chunks,
                    metadata_tail_bytes=self.tail_bytes,
                    error_type=type(self.error).__name__ if self.error else None)


class UsbOwner:
    """Own reader lifetime across unchanged auth_probe's release/disposal finally."""
    def __init__(self,util,result):
        self.util,self.result=util,result
        self.reader=None
        self.quiesced=False
        self.quiesce_error=None

    def session(self,link,*args,**kwargs):
        session=PlaySession(link,*args,**kwargs)
        self.reader=ReadPump(link,session.log)
        return session

    def claim_interface(self,device,interface):
        return self.util.claim_interface(device,interface)

    def _quiesce(self):
        if not self.quiesced:
            self.quiesced=True
            if self.reader is not None:
                try:
                    self.reader.stop()
                except Exception as error:
                    self.quiesce_error=error
                finally:
                    self.result["duplex_usb"]=self.reader.summary()
        elif self.reader is not None and not self.reader.alive() and not self.reader.stop_done:
            # A driver that missed join's deadline may finish before disposal.
            # Finalize metadata without another read/join; still report the original failure.
            try:
                self.reader.stop()
            except Exception:
                pass
            self.result["duplex_usb"]=self.reader.summary()
        if self.reader is not None and self.reader.alive():
            raise self.quiesce_error or TunnelError("duplex reader still owns USB handle")
        return self.quiesce_error

    def release_interface(self,device,interface):
        error=self._quiesce()
        self.util.release_interface(device,interface)
        self.result["usb_released"]=True
        if error is not None:
            raise error

    def dispose_resources(self,device):
        error=self._quiesce()
        self.util.dispose_resources(device)
        self.result["usb_disposed"]=True
        if error is not None:
            raise error
