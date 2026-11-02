"""Bounded MPEG-TS forwarder to an existing FIFO; never creates or writes a regular file."""
from collections import deque
import errno
import os
import stat
import threading
import time

QUEUE_BYTES=8<<20
OPEN_SECONDS=5
STOP_SECONDS=1


class TsSink:
    """put() never blocks or raises on the protocol thread; overflow drops data and counts it."""
    def __init__(self,path,queue_bytes=QUEUE_BYTES,open_seconds=OPEN_SECONDS):
        self.path,self.queue_limit,self.open_seconds=path,queue_bytes,open_seconds
        self.condition=threading.Condition()
        self.queue=deque()
        self.queued_bytes=self.peak_bytes=0
        self.forwarded_bytes=self.dropped_bytes=self.dropped_chunks=0
        self.opened=False
        self.error=None
        self.stopping=False
        self.thread=threading.Thread(target=self._run,name="dex-ts-sink",daemon=True)

    def start(self):
        self.thread.start()
        return self

    def put(self,data):
        with self.condition:
            if self.stopping or self.error is not None or self.queued_bytes+len(data)>self.queue_limit:
                self.dropped_bytes+=len(data)
                self.dropped_chunks+=1
                return
            self.queue.append(bytes(data))
            self.queued_bytes+=len(data)
            self.peak_bytes=max(self.peak_bytes,self.queued_bytes)
            self.condition.notify()

    def _open(self):
        deadline=time.monotonic()+self.open_seconds
        while True:
            try:
                fd=os.open(self.path,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
            except OSError as error:
                # ENXIO: FIFO without a reader yet.
                if error.errno!=errno.ENXIO or time.monotonic()>=deadline or self.stopping:
                    raise
                time.sleep(.05)
                continue
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                os.close(fd)
                raise RuntimeError("live sink path is not a FIFO; refusing to persist media")
            os.set_blocking(fd,True)
            return fd

    def _run(self):
        fd=None
        try:
            fd=self._open()
            with self.condition:
                self.opened=True
            while True:
                with self.condition:
                    while not self.queue and not self.stopping:
                        self.condition.wait()
                    if not self.queue:
                        return
                    chunk=self.queue.popleft()
                    self.queued_bytes-=len(chunk)
                view=memoryview(chunk)
                while view:
                    view=view[os.write(fd,view):]
                with self.condition:
                    self.forwarded_bytes+=len(chunk)
        except Exception as error:
            with self.condition:
                self.error=error
                self.dropped_bytes+=self.queued_bytes
                self.dropped_chunks+=len(self.queue)
                self.queue.clear()
                self.queued_bytes=0
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        """Stop accepting data, let queued data flush for up to STOP_SECONDS, never hang."""
        with self.condition:
            self.stopping=True
            self.condition.notify_all()
        if self.thread.is_alive():
            self.thread.join(STOP_SECONDS)

    def summary(self):
        with self.condition:
            return dict(opened=self.opened,forwarded_bytes=self.forwarded_bytes,
                        dropped_bytes=self.dropped_bytes,dropped_chunks=self.dropped_chunks,
                        queue_peak_bytes=self.peak_bytes,stopped=not self.thread.is_alive(),
                        error_type=type(self.error).__name__ if self.error else None)
