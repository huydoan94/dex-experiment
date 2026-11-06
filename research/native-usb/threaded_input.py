"""Collect validated FIFO input independently; the protocol owner alone sends USB.

Wrap the actual daemon InputReader, retaining its parser, path checks and partial
line handling. Disconnect barriers prevent a replacement writer's events from
crossing the previous writer's release-all boundary.
"""
from collections import deque
import threading
import time

_DISCONNECT = object()


class ThreadedInputReader:
    def __init__(self, reader, *, limit=256, max_age=.5, poll_seconds=.01):
        if limit < 1 or max_age <= 0 or not 0 < poll_seconds <= .1:
            raise ValueError('invalid input queue bounds')
        self.reader = reader
        self.counts = reader.counts
        self.limit, self.max_age, self.poll_seconds = limit, max_age, poll_seconds
        self.queue = deque()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.error = None
        self.peak = 0
        self.thread = threading.Thread(target=self._run, name='dex-fifo-input', daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.reader.close()
            raise

    def _append(self, event):
        with self.lock:
            # Only adjacent hover moves may replace one another; preserve age.
            if (event is not _DISCONNECT and event[0] == 0 and self.queue
                    and self.queue[-1][0] is not _DISCONNECT and self.queue[-1][0][0] == 0):
                self.queue[-1] = event, self.queue[-1][1]
                self.counts['worker_coalesced_moves'] += 1
                return
            if len(self.queue) >= self.limit:
                self.counts['worker_overflows'] += 1
                raise OSError('input worker queue overflow')
            self.queue.append((event, time.monotonic()))
            self.peak = max(self.peak, len(self.queue))
            self.counts['worker_queue_peak'] = self.peak

    def _run(self):
        gone = False
        try:
            while not self.stop.is_set():
                events = self.reader.events()
                if events:
                    # A short-lived replacement writer can open/write/close between polls.
                    gone = False
                for event in events:
                    self._append(event)
                now_gone = self.reader.writer_gone()
                if now_gone and not gone:
                    self._append(_DISCONNECT)
                gone = now_gone
                self.stop.wait(self.poll_seconds)
        except Exception as error:
            with self.lock:
                self.error = error
        finally:
            try:
                self.reader.close()
            except Exception as error:
                with self.lock:
                    self.error = error

    def _check(self):
        if self.error is not None:
            raise OSError('input worker failed') from self.error
        if self.queue and time.monotonic()-self.queue[0][1] > self.max_age:
            raise OSError('input worker queue expired')

    def events(self):
        with self.lock:
            self._check()
            events = []
            while self.queue and self.queue[0][0] is not _DISCONNECT:
                events.append(self.queue.popleft()[0])
            return events

    def writer_gone(self):
        with self.lock:
            self._check()
            if self.queue and self.queue[0][0] is _DISCONNECT:
                self.queue.popleft()
                return True
            return False

    def close(self):
        self.stop.set()
        self.thread.join(1)
        self.counts['worker_stopped'] = int(not self.thread.is_alive())
        if self.thread.is_alive():
            raise RuntimeError('input worker did not stop')


def install(daemon):
    """Opt in within one process; leave deployed modules/pins unchanged on disk."""
    reader_type = daemon.InputReader
    if getattr(reader_type, '_threaded_input', False):
        raise RuntimeError('input worker already installed')
    class Reader(ThreadedInputReader):
        _threaded_input = True

        def __init__(self, path):
            super().__init__(reader_type(path))
    daemon.InputReader = Reader
