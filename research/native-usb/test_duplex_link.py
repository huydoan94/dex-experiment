"""Bounded concurrent IN mechanics and lifetime; no hardware access."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame,encode
import duplex_link as d
from tunnel_probe import Link
from usb_tunnel import TunnelError
from test_udp_play import datagram,SECRET


class FifoDevice:
    def __init__(self,chunks):
        self.chunks=list(chunks)
        self.drained=threading.Event()
        self.read_started=threading.Event()
    def read(self,endpoint,size,timeout):
        if endpoint!=0x85 or size!=512 or timeout!=200:
            raise AssertionError("unexpected USB read parameters")
        self.read_started.set()
        if self.chunks:
            chunk=self.chunks.pop(0)
            if not self.chunks:self.drained.set()
            return chunk
        self.drained.wait(.01)
        raise TimeoutError()
    def write(self,endpoint,data,timeout):
        if not self.drained.wait(.04):
            raise TimeoutError("synthetic OUT blocked behind undrained IN")
        return len(data)


def setup(device,queue_bytes=d.QUEUE_BYTES,reads=100):
    events=[]
    link=Link(device,TimeoutError,max_requests=48,max_reads=reads,cleanup_reads=2,
              record=lambda direction,data:events.append((direction,data)))
    pump=d.ReadPump(link,lambda *a,**kw:None,queue_bytes=queue_bytes)
    return link,pump,events


class Tests(unittest.TestCase):
    def test_duplex_drains_fifo_while_control_thread_writes(self):
        raw=encode(Frame(2,1,9,b""))
        sequential=FifoDevice([b"x"]*12)
        # Minimal reproduction model: synchronous host cannot drain while writing.
        sequential.read(0x85,512,200)
        with self.assertRaises(TimeoutError):sequential.write(3,raw,40)
        device=FifoDevice([b"x"]*12)
        link,pump,events=setup(device)
        try:
            self.assertEqual(link.read(512,200),b"x")
            self.assertEqual(link.write(raw,40),len(raw))
            self.assertTrue(device.drained.is_set())
        finally:pump.stop()
        self.assertFalse(pump.alive())
        self.assertEqual(pump.raw_bytes,12)

    def test_owner_stops_reader_before_release_and_flushes_only_metadata(self):
        raw=encode(datagram(1205,46002,19000,1))
        device=FifoDevice([raw[:40],raw[40:]])
        events,result,calls=[],{},[]
        owner=None
        def released(*args):
            self.assertFalse(owner.reader.alive());calls.append("release")
        def disposed(*args):
            self.assertFalse(owner.reader.alive());calls.append("dispose")
        util=SimpleNamespace(claim_interface=lambda *a:None,release_interface=released,
                             dispose_resources=disposed)
        owner=d.UsbOwner(util,result)
        link=Link(device,TimeoutError,record=lambda *a:(_ for _ in ()).throw(
            AssertionError("unredacted recorder")))
        owner.session(link,1,65536,65536,log=lambda event,**kw:events.append(dict(event=event,**kw)))
        link.read(512,200)
        self.assertTrue(device.drained.wait(.5))
        owner.release_interface(device,3);owner.dispose_resources(device)
        saved=json.dumps(events)
        self.assertNotIn(SECRET.decode(),saved)
        self.assertNotIn(SECRET.hex(),saved)
        self.assertIn("payload_sha256",saved)
        self.assertEqual(calls,["release","dispose"])
        self.assertEqual(result["duplex_usb"]["raw_in_bytes"],len(raw))
        self.assertGreater(result["duplex_usb"]["metadata_tail_bytes"],0)

    def test_queue_byte_limit_fails_closed(self):
        link,pump,events=setup(FifoDevice([b"x"*512]*20),queue_bytes=512)
        link.read(512,200)
        pump.thread.join(.5)
        self.assertFalse(pump.alive())
        with self.assertRaisesRegex(TunnelError,"queue byte limit"):pump.stop()
        self.assertLessEqual(pump.peak_bytes,512)

    def test_active_read_reserve_and_cleanup_budget(self):
        device=FifoDevice([b"x"]*10)
        link,pump,events=setup(device,reads=4)
        try:
            self.assertEqual(link.read(512,200),b"x")
            self.assertEqual(link.read(512,200),b"x")
            with self.assertRaisesRegex(TunnelError,"read budget"):link.read(512,20)
            self.assertEqual(pump.read_calls,2)
            link.begin_cleanup()
            self.assertEqual(link.read(512,200),b"x")
            self.assertEqual(link.read(512,200),b"x")
            with self.assertRaisesRegex(TunnelError,"read budget"):link.read(512,200)
            self.assertEqual(pump.read_calls,4)
        finally:
            with contextlib.suppress(TunnelError):pump.stop()

    def test_idle_cleanup_exhaustion_does_not_fail_stop(self):
        link,pump,events=setup(FifoDevice([b"x"]*10),reads=4)
        self.assertEqual(link.read(512,200),b"x")
        link.begin_cleanup()
        deadline=time.monotonic()+1
        with pump.condition:
            while (link.reads_left or pump.inflight) and time.monotonic()<deadline:
                pump.condition.wait(.05)
        self.assertEqual(link.reads_left,0)
        pump.stop()
        self.assertIsNone(pump.error)
        self.assertEqual(pump.tail_chunks,3)
        with self.assertRaisesRegex(TunnelError,"stopped"):link.read(512,20)

    def test_suppressed_cleanup_ack_is_not_logged_as_written(self):
        link,pump,_=setup(FifoDevice([]))
        events=[]
        pump.log=lambda event,**kw:events.append(event)
        link.device.drained.set()
        ack=encode(Frame(5,2,7,bytes(12)))
        link.write(ack,40)
        link.acks_left=0
        link.begin_cleanup()
        link.write(ack,40)
        self.assertEqual(events,["duplex_write_completed","duplex_write_suppressed"])
        pump.stop()

    def test_failed_write_reports_exact_operation(self):
        class Device(FifoDevice):
            def write(self,*a,**kw):raise RuntimeError("synthetic")
        link,pump,_=setup(Device([]))
        events=[]
        pump.log=lambda event,**kw:events.append(dict(event=event,**kw))
        raw=encode(Frame(5,2,123,bytes(12)))
        with self.assertRaises(RuntimeError):link.write(raw,40)
        self.assertEqual(events[0]["event"],"duplex_write_failed")
        self.assertEqual((events[0]["command"],events[0]["kind"],events[0]["transaction"]),(5,2,123))
        pump.stop()

    def test_stuck_reader_never_frees_live_handle(self):
        gate=threading.Event()
        class Stuck(FifoDevice):
            def read(self,*a,**kw):
                self.read_started.set()
                gate.wait(2)
                raise TimeoutError()
        device=Stuck([])
        calls,result=[],{}
        util=SimpleNamespace(claim_interface=lambda *a:None,
            release_interface=lambda *a:calls.append("release"),
            dispose_resources=lambda *a:calls.append("dispose"))
        owner=d.UsbOwner(util,result)
        link=Link(device,TimeoutError)
        owner.session(link,1,65536,65536)
        self.assertEqual(link.read(512,10),b"")
        try:
            with patch.object(d,"STOP_SECONDS",.01):
                with self.assertRaisesRegex(TunnelError,"did not stop"):owner.release_interface(device,3)
                with self.assertRaises(TunnelError):owner.dispose_resources(device)
            self.assertEqual(calls,[])
        finally:
            gate.set()
            owner.reader.thread.join(.5)
        with self.assertRaises(TunnelError):owner.dispose_resources(device)
        self.assertEqual(calls,["dispose"])
        self.assertFalse(owner.reader.alive())

    def test_error_and_quiet_do_not_spin_or_leak_worker(self):
        class Broken(FifoDevice):
            def read(self,*a,**kw):raise RuntimeError("synthetic read failed")
        link,pump,_=setup(Broken([]))
        try:
            with self.assertRaisesRegex(RuntimeError,"read failed"):link.read(512,200)
        finally:
            with contextlib.suppress(RuntimeError):pump.stop()
        link,pump,_=setup(FifoDevice([]))
        try:
            self.assertEqual(link.read(512,50),b"")
            self.assertLess(pump.read_calls,6)
        finally:pump.stop()

if __name__=="__main__":unittest.main()
