"""The detachable viewer sink: the stream FIFO a viewer may attach to and
leave at any time (moved from kms_daemon_live, 2026-11-11).
"""
from collections import deque
import errno
import os
import stat
import threading
import time

import live_sink

ATTACH_POLL_SECONDS=.5


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
