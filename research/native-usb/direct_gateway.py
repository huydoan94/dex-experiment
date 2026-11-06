"""Authenticated TLS relay for dexd's existing FIFOs; no USB or phone API.

A session pairs two independent TLS sockets before claiming either FIFO lock.
Each direction has its own relay thread. EOF/error closes both directions and
releases the exact same ownership as the Python viewer's two SSH processes.
"""
import errno
import fcntl
import hmac
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import stat
import threading
import time
import uuid

PAIR_SECONDS = 15
STARTUP_SECONDS = 120
WRITE_SECONDS = .5
MAX_GREETING = 1024


def response(sock, status):
    sock.sendall((json.dumps({'version': 1, 'status': status})+'\n').encode())


def fifo(path, flags):
    fd = os.open(path, flags | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    if not stat.S_ISFIFO(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError('path is not a FIFO')
    return fd


class Pair:
    def __init__(self, server, identity):
        self.server, self.identity = server, identity
        self.sockets = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.done = threading.Event()
        self.worker = None
        self.created = time.monotonic()
        self.reason = None
        self.counts = {'media_bytes': 0, 'input_bytes': 0}

    def attach(self, role, sock):
        with self.lock:
            if role in self.sockets or self.stop.is_set():
                return False
            self.sockets[role] = sock
            if len(self.sockets) == 2:
                self.worker = threading.Thread(target=self.run, name='dex-direct-session', daemon=True)
                self.worker.start()
            return True

    def cancel(self, reason):
        with self.lock:
            self.reason = self.reason or reason
            self.stop.set()
            sockets = tuple(self.sockets.values())
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def wait(self):
        while not self.done.wait(.1):
            unpaired_end = False
            with self.lock:
                if self.worker is None:
                    sockets = tuple(self.sockets.values())
                    lost = any(sock.pending() or select.select([sock], [], [], 0)[0] for sock in sockets)
                    if self.stop.is_set() or lost or time.monotonic()-self.created > PAIR_SECONDS:
                        self.reason = self.reason or ('unpaired_peer_closed' if lost else 'pair_timeout')
                        self.stop.set()
                        unpaired_end = True
            if unpaired_end:
                self.cancel(self.reason)
                self.finish()

    def finish(self):
        for sock in tuple(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        with self.server.pair_lock:
            if self.server.active is self:
                self.server.active = None
        self.done.set()

    def run(self):
        locks, threads = [], []
        try:
            for name in ['input.fifo', 'ts.fifo']:
                if not stat.S_ISFIFO((self.server.run_dir/name).lstat().st_mode):
                    raise OSError('missing FIFO')
            # Acquire input first; a media lock is what starts dexd's session.
            for name in ['input.lock', 'viewer.lock']:
                fd = os.open(self.server.run_dir/name, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                locks.append(fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError('invalid lock file')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for sock in self.sockets.values():
                sock.settimeout(WRITE_SECONDS)
                response(sock, 'ready')
            self.server.log(dict(event='direct_session_started', transports=2))
            for role, relay in [('input', self.input), ('media', self.media)]:
                thread = threading.Thread(target=self.guard, args=(relay,), name='dex-direct-'+role, daemon=True)
                threads.append(thread)
                thread.start()
            self.stop.wait()
        except BlockingIOError:
            for sock in self.sockets.values():
                try:
                    response(sock, 'busy')
                except OSError:
                    pass
            self.cancel('busy')
        except Exception as error:
            self.cancel(type(error).__name__)
        finally:
            self.cancel(self.reason or 'session_closed')
            for thread in threads:
                thread.join(2)
            if any(t.is_alive() for t in threads):
                # Fail closed: retain locks and active ownership until process exit.
                self.server.log(dict(event='direct_relay_stop_failed', locks_retained=True))
                self.done.set()
                return
            # Every relay uses bounded socket/file operations and closes its fd.
            for fd in reversed(locks):
                os.close(fd)
            self.server.log(dict(event='direct_session_closed', reason=self.reason,
                                 relays_stopped=all(not t.is_alive() for t in threads), **self.counts))
            self.finish()

    def guard(self, relay):
        try:
            relay()
        except Exception as error:
            self.cancel(type(error).__name__)
        finally:
            self.cancel('peer_closed')

    def media(self):
        sock = self.sockets['media']
        fd = fifo(self.server.run_dir/'ts.fifo', os.O_RDONLY)
        started, seen = time.monotonic(), False
        try:
            poll = select.poll()
            poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            while not self.stop.is_set():
                events = dict(poll.poll(50)).get(fd, 0)
                if events & select.POLLIN:
                    data = os.read(fd, 32768)
                    if data:
                        seen = True
                        sock.sendall(data)
                        self.counts['media_bytes'] += len(data)
                if events & (select.POLLHUP | select.POLLERR) and not events & select.POLLIN:
                    return
                if not seen and time.monotonic()-started > STARTUP_SECONDS:
                    raise TimeoutError('media startup')
        finally:
            os.close(fd)

    def input(self):
        sock = self.sockets['input']
        pending, fd = bytearray(), None
        started, progress = time.monotonic(), None
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                if fd is None:
                    if now-started > STARTUP_SECONDS:
                        raise TimeoutError('input startup')
                    try:
                        fd = fifo(self.server.run_dir/'input.fifo', os.O_WRONLY)
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            raise
                if pending and progress is not None and now-progress > WRITE_SECONDS:
                    raise TimeoutError('input FIFO stalled')
                if fd is not None and pending:
                    try:
                        count = os.write(fd, pending)
                        del pending[:count]
                        self.counts['input_bytes'] += count
                        progress = time.monotonic() if pending else None
                    except BlockingIOError:
                        pass
                # Never wait for input on the media thread. TLS may already have
                # decrypted bytes buffered even when the socket fd is not readable.
                if len(pending) < 65536 and (sock.pending() or select.select([sock], [], [], .01)[0]):
                    data = sock.recv(min(4096, 65536-len(pending)))
                    if not data:
                        return
                    if not pending:
                        progress = time.monotonic()
                    pending.extend(data)
                elif pending:
                    self.stop.wait(.005)
        finally:
            if fd is not None:
                os.close(fd)


class Gateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, *, context, token, run_dir, log=lambda event: None):
        if len(token) < 32:
            raise ValueError('gateway token too short')
        self.context, self.token, self.run_dir, self.log = context, token, Path(run_dir), log
        self.pair_lock, self.active = threading.Lock(), None
        self.slots = threading.BoundedSemaphore(16)
        self.thread = None
        self.closing = False
        super().__init__(address, Handler)

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': .1}, name='dex-direct-listener', daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.closing = True
        self.shutdown()
        with self.pair_lock:
            active = self.active
        if active is not None:
            active.cancel('gateway_stopped')
            active.wait()
        self.server_close()
        if self.thread is not None:
            self.thread.join(2)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        if not server.slots.acquire(blocking=False):
            return
        sock = None
        pair = None
        attached = False
        try:
            self.request.settimeout(5)
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock = server.context.wrap_socket(self.request, server_side=True)
            line = bytearray()
            while len(line) <= MAX_GREETING:
                byte = sock.recv(1)
                if not byte:
                    return
                if byte == b'\n':
                    break
                line.extend(byte)
            else:
                return
            greeting = json.loads(line)
            if not isinstance(greeting, dict):
                return
            token = greeting.get('token', '')
            if (greeting.get('version') != 1 or not isinstance(token, str)
                    or not hmac.compare_digest(token, server.token)):
                return
            role, identity = greeting.get('role'), greeting.get('session')
            if role == 'probe':
                response(sock, 'authenticated')
                return
            if role not in ('input', 'media') or not isinstance(identity, str) or uuid.UUID(identity).hex != identity:
                return
            with server.pair_lock:
                if server.closing:
                    return
                if server.active is None:
                    server.active = Pair(server, identity)
                if server.active.identity == identity:
                    pair = server.active
            attached = pair is not None and pair.attach(role, sock)
            if not attached:
                response(sock, 'busy')
                return
            pair.wait()
        except (OSError, ValueError, TypeError):
            pass
        finally:
            if not attached and sock is not None:
                sock.close()
            server.slots.release()


def configured(config_path, run_dir, log=lambda event: None):
    settings = json.loads(Path(config_path).read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(settings['certificate'], settings['private_key'])
    return Gateway(('0.0.0.0', settings.get('port', 7443)), context=context,
                   token=Path(settings['token_file']).read_text().strip(), run_dir=run_dir, log=log)


if __name__ == '__main__':
    import signal
    import sys
    gateway = configured(sys.argv[1], sys.argv[2], lambda event: print(json.dumps(event), flush=True)).start()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    stopped.wait()
    gateway.close()
