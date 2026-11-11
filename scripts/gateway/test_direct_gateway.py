import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'research/native-usb'))
from direct_gateway import Gateway


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = tempfile.TemporaryDirectory()
        root = Path(cls.assets.name)
        cls.cert, cls.key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.key),'-out',str(cls.cert),'-days','1','-subj','/CN=localhost'],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls): cls.assets.cleanup()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ['input.fifo','ts.fifo','cursor.fifo']: os.mkfifo(self.root/name)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key)
        self.token=secrets.token_urlsafe(32)
        self.events=[]
        self.server=Gateway(('127.0.0.1',0),context=context,token=self.token,run_dir=self.root,log=self.events.append).start()
        self.clients=[]
    def tearDown(self):
        for c in self.clients:
            try:c.close()
            except OSError:pass
        self.server.close();self.temp.cleanup()
    def connect(self,role,identity=None,token=None):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        s=context.wrap_socket(socket.create_connection(self.server.server_address),server_hostname='localhost');s.settimeout(2)
        self.clients.append(s)
        s.sendall((json.dumps(dict(version=1,role=role,session=identity or uuid.uuid4().hex,token=token or self.token))+'\n').encode())
        return s
    def line(self,s):
        data=b''
        while not data.endswith(b'\n'):
            part=s.recv(1)
            if not part:raise EOFError()
            data+=part
        return json.loads(data)
    def locks_free(self):
        for name in ['input.lock','viewer.lock']:
            with open(self.root/name,'ab') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
    def until(self,condition):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if condition():return
            time.sleep(.01)
        self.fail('condition timeout')
    def open_media(self):
        deadline=time.monotonic()+3
        while True:
            try:return os.open(self.root/'ts.fifo',os.O_WRONLY|os.O_NONBLOCK)
            except OSError as error:
                if error.errno != 6 or time.monotonic()>=deadline:raise
                time.sleep(.005)
    def pair(self):
        identity=uuid.uuid4().hex
        a=self.connect('input',identity);b=self.connect('media',identity)
        self.assertEqual(self.line(a)['status'],'ready');self.assertEqual(self.line(b)['status'],'ready')
        return a,b
    def test_auth_probe_does_not_claim_fifos(self):
        c=self.connect('probe');self.assertEqual(self.line(c)['status'],'authenticated');self.locks_free();self.assertIsNone(self.server.active)
    def test_client_traffic_is_marked_dscp_41(self):
        marks=[];wrap=self.server.context.wrap_socket
        def recording(sock,**kw):
            marks.append(sock.getsockopt(socket.IPPROTO_IP,socket.IP_TOS));return wrap(sock,**kw)
        self.server.context.wrap_socket=recording
        c=self.connect('probe');self.assertEqual(self.line(c)['status'],'authenticated')
        self.assertEqual(marks,[41<<2])
    def test_bad_token_cannot_start_session(self):
        c=self.connect('media',token='incorrect');self.assertEqual(c.recv(1),b'');self.locks_free();self.assertIsNone(self.server.active)
    def test_partial_pair_disconnect_releases_admission_without_fifo_claim(self):
        c=self.connect('input');self.locks_free();c.close();self.until(lambda:self.server.active is None);self.locks_free()
    def test_exact_relay_and_disconnect_cleanup(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        media_fd=self.open_media()
        try:
            wire=b'K d 42\nM 0 10 20\nK u 42\n'
            input_client.sendall(wire)
            received=bytearray()
            def collected():
                try:received.extend(os.read(input_fd,4096))
                except BlockingIOError:pass
                return bytes(received)==wire
            self.until(collected)
            media=b'fixture-media'*100
            os.write(media_fd,media)
            data=bytearray()
            while len(data)<len(media):data.extend(media_client.recv(len(media)-len(data)))
            self.assertEqual(data,media)
            input_client.close();self.until(lambda:self.server.active is None);self.locks_free()
            self.assertTrue(self.events[-1]['relays_stopped'])
        finally:os.close(input_fd);os.close(media_fd)
    def cursor_writer(self):
        deadline=time.monotonic()+3
        while True:
            try:return os.open(self.root/'cursor.fifo',os.O_WRONLY|os.O_NONBLOCK)
            except OSError as error:
                if error.errno != 6 or time.monotonic()>=deadline:raise
                time.sleep(.005)
    def fifo_bytes(self,fd,expected):
        received=bytearray()
        def collected():
            try:received.extend(os.read(fd,4096))
            except BlockingIOError:pass
            return bytes(received)==expected
        self.until(collected)
    def test_opted_in_client_gets_valid_cursor_lines_and_opt_in_is_stripped(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        try:
            input_client.sendall(b'X cur');time.sleep(.05);input_client.sendall(b'sor\nM 0 1 2\n')
            self.fifo_bytes(input_fd,b'M 0 1 2\n')
            cursor_fd=self.cursor_writer()
            try:
                os.write(cursor_fd,b'C 1002 0\nbogus line\nC 1008 1\nC 99x 0\nC 1000 0')
                data=b''
                while data.count(b'\n')<2:data+=input_client.recv(64)
                self.assertEqual(data,b'C 1002 0\nC 1008 1\n')
                os.write(cursor_fd,b'\n')
                data=b''
                while not data.endswith(b'\n'):data+=input_client.recv(64)
                self.assertEqual(data,b'C 1000 0\n')
            finally:os.close(cursor_fd)
            self.until(lambda:self.server.active.counts['cursor_lines']==3 and self.server.active.counts['cursor_dropped']==2)
        finally:os.close(input_fd)
    def test_clipboard_lines_pass_both_ways_and_bad_ones_are_dropped(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        try:
            text=base64.b64encode(os.urandom(60000))
            input_client.sendall(b'X cursor\nP '+text+b'\nR\n')
            got=b''
            deadline=time.monotonic()+5
            while not got.endswith(b'R\n') and time.monotonic()<deadline:
                try:got+=os.read(input_fd,1<<20)
                except BlockingIOError:time.sleep(.01)
            self.assertEqual(got,b'P '+text+b'\nR\n')
            cursor_fd=self.cursor_writer()
            try:
                clip=b'V '+base64.b64encode(os.urandom(150000))
                os.write(cursor_fd,b'V not*base64\n')
                def write_all(view=memoryview(clip+b'\nC 1002 0\n')):
                    while view:
                        try:view=view[os.write(cursor_fd,view[:65536]):]
                        except BlockingIOError:time.sleep(.005)
                writer=threading.Thread(target=write_all,daemon=True);writer.start()
                data=b''
                input_client.settimeout(5)
                while data.count(b'\n')<2:data+=input_client.recv(1<<16)
                writer.join(5)
                self.assertEqual(data,clip+b'\nC 1002 0\n')
            finally:os.close(cursor_fd)
            self.until(lambda:self.server.active.counts['clipboard_lines']==1 and self.server.active.counts['cursor_dropped']==1)
        finally:os.close(input_fd)
    def test_file_chunk_requests_reach_the_client(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        try:
            input_client.sendall(b'X cursor\nM 0 1 2\n')
            self.fifo_bytes(input_fd,b'M 0 1 2\n')
            cursor_fd=self.cursor_writer()
            try:
                os.write(cursor_fd,b'G 12345 1\nG 3 x\nS 0 49152 0\nS 0 5 2\nG 0 7\n')
                data=b''
                input_client.settimeout(5)
                while data.count(b'\n')<2:data+=input_client.recv(64)
                self.assertEqual(data,b'S 0 49152 0\nG 0 7\n')
            finally:os.close(cursor_fd)
            self.until(lambda:self.server.active.counts['file_requests']==1 and self.server.active.counts['file_progress']==1 and self.server.active.counts['cursor_dropped']==3)
        finally:os.close(input_fd)
    def test_phone_file_lines_pass_and_bad_ones_drop(self):
        from direct_gateway import Pair
        ok=[b'DS 2',b'FE',b'FA',b'FX no_file_list',b'FN 0 3 b25lLnR4dA==',b'FN 1 -1 YQ==',b'FB '+base64.b64encode(b'x'*49152)]
        bad=[b'DS x',b'FX bad reason!',b'FN 0 3 not*b64',b'FB '+base64.b64encode(b'x'*49155),b'FE 1',b'FZ']
        for line in ok:self.assertTrue(Pair.phone_file_line(line.split(b' '),line),line[:20])
        for line in bad:self.assertFalse(Pair.phone_file_line(line.split(b' '),line),line[:20])
    def test_opt_in_before_the_daemon_reads_input_does_not_stall_the_session(self):
        # 2026-11-06 0.0.7 session A: an older gateway ended a session whose early opt-in
        # could not drain into a not-yet-read input FIFO. The opt-in never enters the FIFO.
        input_client,media_client=self.pair()
        input_client.sendall(b'X cursor\n')
        time.sleep(.8)  # > WRITE_SECONDS with no FIFO reader
        self.assertIsNotNone(self.server.active)
        self.assertEqual(self.server.active.counts['input_bytes'],0)
    def test_client_without_opt_in_never_receives_cursor_bytes(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        try:
            input_client.sendall(b'X\nM 0 1 2\n')
            self.fifo_bytes(input_fd,b'X\nM 0 1 2\n')
            with self.assertRaises(OSError):
                os.close(os.open(self.root/'cursor.fifo',os.O_WRONLY|os.O_NONBLOCK))  # ENXIO: no reader
            input_client.settimeout(.2)
            with self.assertRaises(socket.timeout):input_client.recv(1)
        finally:os.close(input_fd)
    def test_stalled_input_does_not_serialize_media_relay(self):
        input_client,media_client=self.pair()
        input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
        media_fd=self.open_media()
        try:
            # Fill the FIFO without draining it. The independent relay must keep
            # forwarding media until the intentional 500ms ownership deadline.
            input_client.sendall(b'K d 42\n'*12000)
            start=time.monotonic();count=0
            while time.monotonic()-start<.2:
                os.write(media_fd,b'media')
                self.assertEqual(media_client.recv(5),b'media');count+=1
                time.sleep(.01)
            self.assertGreater(count,5)
            self.until(lambda:self.server.active is None);self.locks_free()
            self.assertEqual(self.events[-1]['reason'],'TimeoutError')
        finally:os.close(input_fd);os.close(media_fd)
    def test_busy_viewer_is_refused_without_stealing_locks(self):
        a,b=self.pair();c=self.connect('input');self.assertEqual(self.line(c)['status'],'busy')
        with self.assertRaises(BlockingIOError):self.locks_free()
        a.close();self.until(lambda:self.server.active is None);self.locks_free()
    def test_missing_or_symlink_fifo_fails_closed(self):
        (self.root/'ts.fifo').unlink();(self.root/'ts.fifo').symlink_to(self.root/'input.fifo')
        identity=uuid.uuid4().hex;a=self.connect('input',identity);b=self.connect('media',identity)
        self.assertEqual(a.recv(1),b'');self.until(lambda:self.server.active is None);self.locks_free()

    def native_config(self):
        token=self.root/'token';token.write_text(self.token);token.chmod(0o600)
        pin=base64.b64encode(hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).digest()).decode()
        config=self.root/'native.json';config.write_text(json.dumps(dict(Host='localhost',Port=self.server.server_address[1],TokenFile=str(token),CertificateSha256=pin,NativeDirectory=str(self.root))))
        return config
    def native_command(self,mode):
        dll=Path(__file__).resolve().parents[2]/'windows/DexClient.TransportChecks/bin/Release/net10.0/DexClient.TransportChecks.dll'
        return ['dotnet',str(dll),str(self.native_config()),mode]
    @unittest.skipIf(os.environ.get('DEX_SKIP_NATIVE') == '1', 'native interop runs on WSL/Windows')
    def test_native_pinned_tls_probe_wrong_pin_and_cancel(self):
        for mode in ['probe','wrong-pin','cancel']:
            result=subprocess.run(self.native_command(mode),capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.until(lambda:self.server.active is None);self.locks_free()
    @unittest.skipIf(os.environ.get('DEX_SKIP_NATIVE') == '1', 'native interop runs on WSL/Windows')
    def test_native_pair_media_input_and_complete_cleanup(self):
        with subprocess.Popen(self.native_command('pair'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as child:
            input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
            media_fd=None
            try:
                received=bytearray()
                wire=b'K d 42\nM 0 10 20\nK u 42\n'
                def collected():
                    try:received.extend(os.read(input_fd,4096))
                    except BlockingIOError:pass
                    return bytes(received)==wire
                self.until(collected)
                media_fd=self.open_media()
                os.write(media_fd,b'synthetic-media')
                stdout,stderr=child.communicate(timeout=10)
                self.assertEqual(child.returncode,0,stdout+stderr)
                self.until(lambda:self.server.active is None);self.locks_free()
                self.assertTrue(self.events[-1]['relays_stopped'])
            finally:
                os.close(input_fd)
                if media_fd is not None:os.close(media_fd)
                if child.poll() is None:child.kill();child.wait()

    def test_native_client_opts_in_and_receives_cursor_shape(self):
        with subprocess.Popen(self.native_command('cursor'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as child:
            input_fd=os.open(self.root/'input.fifo',os.O_RDONLY|os.O_NONBLOCK)
            cursor_fd=None
            try:
                self.until(lambda:self.server.active is not None and self.server.active.counts.get('cursor_lines') is not None)
                cursor_fd=self.cursor_writer()
                os.write(cursor_fd,b'garbage\nC 1002 0\n')
                stdout,stderr=child.communicate(timeout=10)
                self.assertEqual(child.returncode,0,stdout+stderr)
                self.assertIn('PASS direct TLS cursor',stdout)
                leftover=b''
                try:leftover=os.read(input_fd,4096)
                except BlockingIOError:pass
                self.assertNotIn(b'X cursor',leftover)  # the opt-in never reaches the daemon FIFO
            finally:
                os.close(input_fd)
                if cursor_fd is not None:os.close(cursor_fd)
                if child.poll() is None:child.kill();child.wait()

if __name__=='__main__':unittest.main()
