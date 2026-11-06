"""Quiet daemon recorder: same counts and decoder state as RedactingRecorder; synthetic bytes only."""
from collections import Counter
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame,PAD_BYTE,encode
import conn_transfer
import kms_daemon_live as daemon
import rtsp_udp_play as play
import tcp_control as tcp
from tunnel_probe import Link


def media(transaction,payload_bytes=1316):
    rtp=struct.pack(">BBHII",0x80,33,transaction&0xffff,transaction*3000,7)
    payload=rtp+b"\x47"*(payload_bytes-12)
    body=tcp._DATA.pack(17,play.RTP_CONFIG,2,play.RTP_PORT,50000,play.RTP_PORT,play.RTP_PORT,
                        tcp._DATA_HEADER_BYTES,len(payload))+payload
    return encode(Frame(5,1,transaction,body))


def sized(size,transaction):
    # Non-UDP Data request of an exact frame size, as in test_conn_transfer.
    return encode(Frame(5,1,transaction,b"b"*(size-20)))


def reads(transfer):
    return [transfer[i:i+512] for i in range(0,len(transfer),512)]


def stream():
    """(direction,data) records covering every recorder branch except a parse failure."""
    batch=sized(1384,1)+sized(1008,2)+sized(1384,3)
    assert len(batch)%64==0
    transfers=[batch+bytes([PAD_BYTE]),media(4),encode(Frame(7,3,None,b"note")),
               encode(Frame(2,2,5,b"\0"*8)),media(6,1316+64)]
    records=[("in",chunk) for transfer in transfers for chunk in reads(transfer)]
    ack=tcp.data_ack(9,1384)
    return records+[("out",encode(ack)),("out_zlp",b""),("ack_suppressed",encode(ack))]


def recorder(kind,quiet):
    written=[]
    log=daemon.DaemonLog(lambda event,**fields:written.append(dict(event=event,**fields)))
    log.quiet=quiet
    record=kind(log,65536)
    record.decoder=conn_transfer.TransferDecoder(65536)
    return record,log,written


def state(record):
    decoder=record.decoder
    return (record.failed,bytes(decoder._buffer),decoder._expected,decoder._pad_pending,
            decoder._failed,decoder.transfer_bytes,decoder.transfer_pads)


class Tests(unittest.TestCase):
    def run_both(self,records,quiet):
        results=[]
        for kind in (play.RedactingRecorder,daemon.DaemonRecorder):
            record,log,written=recorder(kind,quiet)
            for direction,data in records:
                record(direction,data)
            results.append((Counter(log.suppressed),written,state(record)))
        return results

    def test_quiet_counts_and_decoder_state_match_the_redacting_recorder(self):
        original,quiet=self.run_both(stream(),quiet=True)
        self.assertEqual(quiet,original)
        counts,written,(failed,*_,pads)=quiet
        self.assertEqual(written,[])
        self.assertFalse(failed)
        self.assertEqual(pads,1)
        self.assertEqual(counts["usb_frame_in_data"],5)
        self.assertEqual(counts["usb_frame_in"],2)
        self.assertEqual(counts["usb_raw"],3)

    def test_quiet_parse_failure_counts_and_poisons_like_the_original(self):
        records=[("in",media(1)[:30]),("in",b"XXXX"+bytes(12)),("in",media(2))]
        original,quiet=self.run_both([("in",b"BAD!"+bytes(12))]+records,quiet=True)
        self.assertEqual(quiet,original)
        self.assertTrue(quiet[2][0])
        self.assertEqual(quiet[0]["usb_in_unparsed"],4)
        self.assertEqual(quiet[0]["usb_in_chunk"],1)

    def test_verbose_output_is_the_redacting_recorders(self):
        original,verbose=self.run_both(stream(),quiet=False)
        self.assertEqual(verbose,original)
        self.assertTrue(any(e["event"]=="usb_frame_in_data" and "payload_sha256" in e
                            for e in verbose[1]))

    def test_decoder_stays_in_step_when_quiet_ends_mid_frame(self):
        frames=[media(1),media(2),media(3)]
        chunks=[chunk for frame in frames for chunk in reads(frame)]
        split=len(reads(frames[0]))+1   # inside the second frame
        logs=[]
        for kind in (play.RedactingRecorder,daemon.DaemonRecorder):
            record,log,written=recorder(kind,quiet=True)
            for index,chunk in enumerate(chunks):
                log.quiet=index<split
                record("in",chunk)
            logs.append(written)
        self.assertEqual(logs[1],logs[0])
        data=[e for e in logs[1] if e["event"]=="usb_frame_in_data"]
        self.assertEqual(len(data),2)
        self.assertTrue(all("media_header" in e for e in data))

    def test_every_recorder_event_is_quiet(self):
        self.assertLessEqual(daemon.RECORDER_EVENTS,daemon.QUIET_EVENTS)

    def test_owner_installs_it_before_transfer_sessions_replace_decoders(self):
        class FakeSession:
            def __init__(self,link,*args,log,**kwargs):
                self.log,self.max_frame_bytes=log,65536
                self.decoder=SimpleNamespace(max_frame_bytes=65536)
                link.record=play.RedactingRecorder(log,65536)
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.sink=owner.stop_file=owner.input_fifo=None
        owner.on_streaming=lambda:None
        link=Link(SimpleNamespace(),TimeoutError)
        with patch.object(daemon,"DaemonSession",FakeSession):
            session=conn_transfer.TransferSessions(owner).session(
                link,1,65536,daemon.long.MAX_RECEIVE_BYTES,log=lambda event,**fields:None)
        self.assertIs(type(link.record),daemon.DaemonRecorder)
        self.assertIs(link.device,session.usb_timing)
        self.assertIs(link.record.timing,session.usb_timing)
        self.assertIs(link.record.log,session.log)
        self.assertIsInstance(link.record.decoder,conn_transfer.TransferDecoder)
        self.assertIsInstance(session.decoder,conn_transfer.TransferDecoder)
        self.assertIs(owner.reader.link,link)


class FakeUsb:
    def __init__(self,chunks):self.chunks,self.written=list(chunks),[]
    def read(self,endpoint,size,timeout=None):
        if not self.chunks:raise TimeoutError
        return self.chunks.pop(0)
    def write(self,endpoint,data,timeout=None):self.written.append(len(data));return len(data)
    def get_active_configuration(self):return "config"


class TimingTests(unittest.TestCase):
    def test_reads_writes_and_fifo_backlog_are_timed_without_payload(self):
        timing=daemon.UsbTiming(FakeUsb([b"a"*512,b"",b"b"*100]))
        self.assertEqual(timing.get_active_configuration(),"config")
        self.assertEqual(bytes(timing.read(133,512)),b"a"*512)
        self.assertEqual(len(timing.read(133,512)),0)
        timing.read(133,512)
        with self.assertRaises(TimeoutError):timing.read(133,512)
        timing.write(3,b"x"*32)
        timing.stop_writer()
        record,log,_=recorder(daemon.DaemonRecorder,quiet=True)
        record.timing=timing
        for chunk in (media(1)[:512],media(1)[512:]):record("in",chunk)
        record("out",b"ack")
        summary=timing.summary()
        self.assertEqual((summary["reads"],summary["read_bytes"],summary["consumed"]),(2,612,2))
        self.assertEqual((summary["writes"],timing.write_bytes.tolist()),(1,[32]))
        self.assertGreaterEqual(summary["backlog_wait_us"]["max"],0)
        self.assertEqual(summary["read_peak_bytes_per_100ms"],612)
        self.assertFalse(any(isinstance(v,(bytes,bytearray)) for v in vars(timing).values()))

    def test_pipelined_writes_keep_order_and_return_without_waiting(self):
        import threading,time as clock
        gate=threading.Event()
        class Slow(FakeUsb):
            def write(self,endpoint,data,timeout=None):
                gate.wait(2);return super().write(endpoint,data,timeout)
        device=Slow([]);timing=daemon.UsbTiming(device)
        started=clock.monotonic()
        for size in (32,512,0,24):self.assertEqual(timing.write(3,b"x"*size,1000),size)
        self.assertLess(clock.monotonic()-started,.5)
        self.assertEqual(device.written,[])
        gate.set();timing.stop_writer()
        self.assertEqual(device.written,[32,512,0,24])
        self.assertEqual(timing.summary()["write_queue_peak"],4)
        with self.assertRaisesRegex(Exception,"writer is stopped"):timing.write(3,b"late")

    def test_failed_write_surfaces_on_next_read_and_write(self):
        class Broken(FakeUsb):
            def write(self,endpoint,data,timeout=None):raise OSError("pipe")
        timing=daemon.UsbTiming(Broken([b"r"]))
        timing.write(3,b"x")
        timing.writer.join(2)
        with self.assertRaisesRegex(Exception,"pipelined USB write failed: OSError"):timing.read(133,512)
        with self.assertRaisesRegex(Exception,"pipelined USB write failed"):timing.write(3,b"y")
        with self.assertRaisesRegex(Exception,"pipelined USB write failed"):timing.stop_writer()

    def test_stuck_writer_refuses_release(self):
        import threading
        never=threading.Event()
        class Stuck(FakeUsb):
            def write(self,endpoint,data,timeout=None):never.wait(5);return len(data)
        timing=daemon.UsbTiming(Stuck([]));timing.write(3,b"x")
        with self.assertRaisesRegex(Exception,"USB writer did not stop"):timing.stop_writer(.2)
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.current=SimpleNamespace(usb_timing=timing);owner.quiesced=False;owner.quiesce_error=None;owner.reader=None
        released=[];owner.util=SimpleNamespace(release_interface=lambda *a:released.append(a));owner.result={}
        with self.assertRaisesRegex(Exception,"USB writer did not stop"):owner.release_interface("dev",3)
        self.assertEqual(released,[])
        never.set();timing.writer.join(2)
        owner.release_interface("dev",3)
        self.assertEqual(released,[("dev",3)])

    def test_owner_drains_writer_before_reader_stop(self):
        order=[]
        timing=daemon.UsbTiming(FakeUsb([]))
        timing.write(3,b"x")
        stop=timing.stop_writer
        timing.stop_writer=lambda *a:(order.append("writer"),stop(*a))
        reader=SimpleNamespace(stop=lambda:order.append("reader"),alive=lambda:False,stop_done=True,summary=lambda:{})
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.current=SimpleNamespace(usb_timing=timing);owner.quiesced=False;owner.quiesce_error=None;owner.reader=reader
        owner.util=SimpleNamespace(release_interface=lambda *a:order.append("release"));owner.result={}
        owner.release_interface("dev",3)
        self.assertEqual(order,["writer","reader","release"])

    def test_cap_bounds_memory_and_keeps_pairs_aligned(self):
        timing=daemon.UsbTiming(FakeUsb([b"z"]*5),cap=3)
        for _ in range(5):timing.read(133,512);timing.mark_consumed()
        self.assertEqual((len(timing.read_end),len(timing.consumed)),(3,3))
        self.assertTrue(timing.summary()["capped"])

    def test_empty_summary(self):
        summary=daemon.UsbTiming(FakeUsb([])).summary()
        self.assertEqual((summary["reads"],summary["backlog_wait_us"],summary["write_us"]),(0,{},{}))

    def test_peak_window(self):
        self.assertEqual(daemon._peak_window_bytes([0,50,100,250],[1,2,4,8],100),8)
        self.assertEqual(daemon._peak_window_bytes([0,50,100,101],[1,2,4,8],100),14)


class FakeEngine:
    def __init__(self,fail_submit=None):self.started=None;self.cancelled=False;self.closed=False;self.fail_submit=fail_submit
    def start(self,owner,count,size):
        self.owner=owner;self.started=(count,size)
        for i in range(count):
            owner.submitting()
            if self.fail_submit==i:owner.resubmit_failed(-1)
    def cancel_all(self):self.cancelled=True
    def close(self):self.closed=True


class AsyncInTests(unittest.TestCase):
    def test_completions_split_in_order_like_512_byte_reads(self):
        engine=FakeEngine();reader=daemon.AsyncIn(engine,TimeoutError,transfers=3,transfer_bytes=16384)
        self.assertEqual((engine.started,reader.inflight),((3,16384),3))
        transfer=sized(1384,1)+sized(1008,2)+sized(1384,3)+bytes([PAD_BYTE])
        long_transfer=bytes(range(256))*80   # 20480 bytes: one 16384 completion then 4096
        self.assertTrue(reader.complete(0,0,transfer))
        self.assertTrue(reader.complete(1,0,long_transfer[:16384]))
        self.assertTrue(reader.complete(2,0,long_transfer[16384:]))
        pieces=[]
        while reader.ready:pieces.append(reader.read(512,10))
        expected=reads(transfer)+reads(long_transfer)
        self.assertEqual(pieces,expected)
        decoder=conn_transfer.TransferDecoder(65536)
        frames=[f for chunk in reads(transfer) for f in decoder.feed(chunk)]
        self.assertEqual([f.transaction for f in frames],[1,2,3])
        with self.assertRaises(TimeoutError):reader.read(512,10)

    def test_failure_status_stops_resubmitting_and_raises_after_data(self):
        reader=daemon.AsyncIn(FakeEngine(),TimeoutError,transfers=2,transfer_bytes=1024)
        self.assertFalse(reader.complete(0,5,b"tail"))
        self.assertEqual(reader.read(512,10),b"tail")
        with self.assertRaisesRegex(Exception,"status 5"):reader.read(512,10)
        self.assertEqual(reader.inflight,1)

    def test_failed_submit_is_counted_and_reported(self):
        reader=daemon.AsyncIn(FakeEngine(fail_submit=1),TimeoutError,transfers=3,transfer_bytes=1024)
        self.assertEqual(reader.inflight,2)
        with self.assertRaisesRegex(Exception,"resubmit failed"):reader.read(512,10)

    def test_stop_waits_for_cancellations_and_refuses_while_in_flight(self):
        engine=FakeEngine();reader=daemon.AsyncIn(engine,TimeoutError,transfers=2,transfer_bytes=1024)
        with self.assertRaisesRegex(Exception,"still in flight"):reader.stop(.05)
        self.assertTrue(engine.cancelled);self.assertFalse(engine.closed)
        self.assertFalse(reader.complete(0,3,b""));self.assertFalse(reader.complete(1,0,b"late"))
        reader.stop(.05)
        self.assertTrue(engine.closed);self.assertEqual(reader.summary()["inflight"],0)

    def test_ready_queue_is_bounded(self):
        reader=daemon.AsyncIn(FakeEngine(),TimeoutError,transfers=1,transfer_bytes=1024)
        with patch.object(daemon,"ASYNC_READY_LIMIT",1000):
            self.assertFalse(reader.complete(0,0,b"x"*1500))
        while reader.ready:reader.read(512,10)
        with self.assertRaisesRegex(Exception,"limit exceeded"):reader.read(512,10)

    def test_timing_uses_async_reader_and_owner_stops_it_after_reader(self):
        engine=FakeEngine();made=[]
        def factory(device,endpoint,timeout_error):
            made.append(endpoint);return daemon.AsyncIn(engine,timeout_error,transfers=1,transfer_bytes=1024)
        timing=daemon.UsbTiming(FakeUsb([]),async_in=factory,timeout_error=TimeoutError)
        def feed():timing.async_in.complete(0,0,b"z"*600)
        threading_timer=__import__("threading").Timer(.05,feed)
        with self.assertRaises(TimeoutError):timing.read(133,512,1)
        threading_timer.start();self.assertEqual(len(timing.read(133,512,1000)),512)
        self.assertEqual(made,[133])
        order=[]
        reader=SimpleNamespace(stop=lambda:order.append("reader"),alive=lambda:False,stop_done=True,summary=lambda:{})
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.current=SimpleNamespace(usb_timing=timing);owner.quiesced=False;owner.quiesce_error=None;owner.reader=reader
        owner.util=SimpleNamespace(release_interface=lambda *a:order.append("release"));owner.result={}
        stop=timing.async_in.stop
        def async_stop(*a):
            order.append("async");timing.async_in.complete(0,3,b"");return stop(.5)
        timing.async_in.stop=async_stop
        owner.release_interface("dev",3)
        self.assertEqual(order,["reader","async","release"])
        self.assertEqual(owner.result["duplex_usb"]["async_in"]["inflight"],0)


if __name__=="__main__":
    unittest.main()
