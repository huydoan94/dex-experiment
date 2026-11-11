"""Quiet daemon recorder: same counts and decoder state as RedactingRecorder; synthetic bytes only."""
from collections import Counter
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from conn_frames import Frame,PAD_BYTE,encode
import conn_transfer
import kms_daemon_live as daemon
import cursor_relay
import daemon_sink
import usb_engines
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
        timing=usb_engines.UsbTiming(FakeUsb([b"a"*512,b"",b"b"*100]))
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
        device=Slow([]);timing=usb_engines.UsbTiming(device)
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
        timing=usb_engines.UsbTiming(Broken([b"r"]))
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
        timing=usb_engines.UsbTiming(Stuck([]));timing.write(3,b"x")
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
        timing=usb_engines.UsbTiming(FakeUsb([]))
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
        timing=usb_engines.UsbTiming(FakeUsb([b"z"]*5),cap=3)
        for _ in range(5):timing.read(133,512);timing.mark_consumed()
        self.assertEqual((len(timing.read_end),len(timing.consumed)),(3,3))
        self.assertTrue(timing.summary()["capped"])

    def test_empty_summary(self):
        summary=usb_engines.UsbTiming(FakeUsb([])).summary()
        self.assertEqual((summary["reads"],summary["backlog_wait_us"],summary["write_us"]),(0,{},{}))

    def test_peak_window(self):
        self.assertEqual(usb_engines._peak_window_bytes([0,50,100,250],[1,2,4,8],100),8)
        self.assertEqual(usb_engines._peak_window_bytes([0,50,100,101],[1,2,4,8],100),14)


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
        engine=FakeEngine();reader=usb_engines.AsyncIn(engine,TimeoutError,transfers=3,transfer_bytes=16384)
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
        reader=usb_engines.AsyncIn(FakeEngine(),TimeoutError,transfers=2,transfer_bytes=1024)
        self.assertFalse(reader.complete(0,5,b"tail"))
        self.assertEqual(reader.read(512,10),b"tail")
        with self.assertRaisesRegex(Exception,"status 5"):reader.read(512,10)
        self.assertEqual(reader.inflight,1)

    def test_failed_submit_is_counted_and_reported(self):
        reader=usb_engines.AsyncIn(FakeEngine(fail_submit=1),TimeoutError,transfers=3,transfer_bytes=1024)
        self.assertEqual(reader.inflight,2)
        with self.assertRaisesRegex(Exception,"resubmit failed"):reader.read(512,10)

    def test_stop_waits_for_cancellations_and_refuses_while_in_flight(self):
        engine=FakeEngine();reader=usb_engines.AsyncIn(engine,TimeoutError,transfers=2,transfer_bytes=1024)
        with self.assertRaisesRegex(Exception,"still in flight"):reader.stop(.05)
        self.assertTrue(engine.cancelled);self.assertFalse(engine.closed)
        self.assertFalse(reader.complete(0,3,b""));self.assertFalse(reader.complete(1,0,b"late"))
        reader.stop(.05)
        self.assertTrue(engine.closed);self.assertEqual(reader.summary()["inflight"],0)

    def test_ready_queue_is_bounded(self):
        reader=usb_engines.AsyncIn(FakeEngine(),TimeoutError,transfers=1,transfer_bytes=1024)
        with patch.object(usb_engines,"ASYNC_READY_LIMIT",1000):
            self.assertFalse(reader.complete(0,0,b"x"*1500))
        while reader.ready:reader.read(512,10)
        with self.assertRaisesRegex(Exception,"limit exceeded"):reader.read(512,10)

    def test_timing_uses_async_reader_and_owner_stops_it_after_reader(self):
        engine=FakeEngine();made=[]
        def factory(device,endpoint,timeout_error):
            made.append(endpoint);return usb_engines.AsyncIn(engine,timeout_error,transfers=1,transfer_bytes=1024)
        timing=usb_engines.UsbTiming(FakeUsb([]),async_in=factory,timeout_error=TimeoutError)
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



KEY=bytes(range(32))


def official_scramble(packet,key=KEY):
    """Independent reference: SamsungDeX.exe RTPSocket receive XOR, byte by byte."""
    text=bytearray(packet)
    ascii_key=b"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    assert ascii_key==key.hex().upper().encode()
    for i in range(12,len(text)):
        text[i]^=ascii_key[i%len(ascii_key)]
    return bytes(text)


def rtp(sequence,payload_bytes=1316):
    header=struct.pack(">BBHII",0x80,33,sequence,sequence*3000,7)
    ts=b"".join(b"\x47"+bytes([sequence&0xff,i])*93+b"\x01" for i in range((payload_bytes-12)//188))
    return header+ts


def data_frame(payload,config=None):
    config=play.RTP_CONFIG if config is None else config
    body=tcp._DATA.pack(17,config,2,play.RTP_PORT,50000,play.RTP_PORT,play.RTP_PORT,
                        tcp._DATA_HEADER_BYTES,len(payload))+payload
    return Frame(5,1,9,body)


class DescramblerTests(unittest.TestCase):
    def test_known_vector_uses_uppercase_hex_key_from_byte_twelve(self):
        packet=bytes(12)+b"\x00"*4
        # Bytes 12..15 XOR key[12..15] = b"0607" ("06","07" of the uppercase hex key).
        self.assertEqual(daemon.Descrambler(KEY).descramble(packet),bytes(12)+b"0607")
        self.assertEqual(daemon.Descrambler(KEY).descramble(bytes(12)),bytes(12))
        tail=bytes(12)+b"\x00"*(64-12+8)
        # Index i keeps the absolute packet offset: offset 64 restarts the key at "00".
        self.assertEqual(daemon.Descrambler(KEY).descramble(tail)[64:72],b"00010203")

    def test_scrambled_stream_latches_and_matches_the_reference(self):
        d=daemon.Descrambler(KEY)
        for sequence,size in enumerate((1316,1328,200,1500)):
            clear=rtp(sequence,size)
            self.assertEqual(d.packet(official_scramble(clear)),clear)
        self.assertEqual(d.summary(),dict(mode="scrambled",descrambled=4,undecided=0))

    def test_plain_stream_is_left_untouched(self):
        d=daemon.Descrambler(KEY)
        for sequence in range(3):
            clear=rtp(sequence)
            self.assertIs(d.packet(clear),clear)
        self.assertEqual(d.summary(),dict(mode="plain",descrambled=0,undecided=0))

    def test_undecidable_packets_pass_until_one_decides(self):
        d=daemon.Descrambler(KEY)
        junk=struct.pack(">BBHII",0x80,33,1,0,7)+b"\x00"*40
        self.assertIs(d.packet(junk),junk)
        self.assertIsNone(d.mode)
        clear=rtp(2)
        self.assertEqual(d.packet(official_scramble(clear)),clear)
        self.assertEqual(d.summary(),dict(mode="scrambled",descrambled=1,undecided=1))

    def test_frame_descrambles_only_rtp_data_and_keeps_the_header(self):
        d=daemon.Descrambler(KEY)
        clear=rtp(5)
        frame=d.frame(data_frame(official_scramble(clear)))
        self.assertEqual(frame.body,data_frame(clear).body)
        self.assertEqual((frame.command,frame.kind,frame.transaction),(5,1,9))
        other=data_frame(official_scramble(clear),config=play.RTCP_CONFIG)
        self.assertIs(d.frame(other),other)

    def test_key_is_validated_and_never_shown(self):
        with self.assertRaises(ValueError):
            daemon.Descrambler(KEY[:16])
        d=daemon.Descrambler(KEY)
        self.assertNotIn("0A0B",repr(d)+str(d.summary()))

    def test_session_descrambles_before_the_inherited_handler(self):
        seen=[]
        session=object.__new__(daemon.DaemonSession)
        session.descrambler=daemon.Descrambler(KEY)
        clear=rtp(7)
        with patch.object(daemon.base.SessionInput,"_phone_datagram",create=True,
                          side_effect=lambda frame: seen.append(frame.body)):
            daemon.DaemonSession._phone_datagram(session,data_frame(official_scramble(clear)))
            session.descrambler=None
            daemon.DaemonSession._phone_datagram(session,data_frame(clear))
        self.assertEqual(seen,[data_frame(clear).body]*2)



class WakingInputTests(unittest.TestCase):
    def setUp(self):
        import os,tempfile
        self.os=os
        self.dir=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.dir.name,"input.fifo")
        os.mkfifo(self.path,0o600)

    def tearDown(self):
        self.dir.cleanup()

    def reader(self,poll_seconds):
        return daemon.WakingInputReader(daemon.InputReader(self.path),poll_seconds=poll_seconds)

    def test_worker_collects_a_write_without_waiting_for_the_poll_interval(self):
        import time
        worker=self.reader(.1)
        try:
            time.sleep(.15)  # worker now asleep in poll() for up to 100 ms
            fd=self.os.open(self.path,self.os.O_WRONLY|self.os.O_NONBLOCK)
            try:
                started=time.monotonic()
                self.os.write(fd,b"M 0 10 20\n")
                while not worker.queued_event() and time.monotonic()-started<1:
                    time.sleep(.0005)
                elapsed=time.monotonic()-started
                self.assertTrue(worker.queued_event())
                self.assertLess(elapsed,.03)
                self.assertEqual(worker.events(),[(0,10,20)])
            finally:
                self.os.close(fd)
        finally:
            worker.close()
        self.assertEqual(worker.counts["worker_stopped"],1)

    def test_departed_writer_neither_spins_nor_counts_as_an_event(self):
        import time
        worker=self.reader(.05)
        try:
            fd=self.os.open(self.path,self.os.O_WRONLY|self.os.O_NONBLOCK)
            self.os.write(fd,b"M 0 1 2\n")
            self.os.close(fd)
            time.sleep(.05)
            self.assertEqual(worker.events(),[(0,1,2)])
            calls=[]
            original=worker.reader.events
            worker.reader.events=lambda:calls.append(1) or original()
            time.sleep(.3)
            self.assertLessEqual(len(calls),10)  # ~6 at 50 ms; a spin would be thousands
            self.assertFalse(worker.queued_event())  # only the disconnect barrier is queued
            self.assertTrue(worker.writer_gone())
        finally:
            worker.close()


class SliceWakeTests(unittest.TestCase):
    def session(self,queued=True,**state):
        class Reader(daemon.WakingInputReader):
            def __init__(self):
                pass
            def queued_event(self):
                return queued
        session=object.__new__(daemon.DaemonSession)
        fields=dict(requesting=0,input_wakes=0,window_open=True,cleanup=False,
                    _collect_media=True,keepalive_offset=0,input=Reader())
        fields.update(state)
        session.__dict__.update(fields)
        return session

    def frames(self,session):
        with patch.object(daemon.base.SessionInput,"_next_frame",create=True,return_value="frame"):
            return daemon.DaemonSession._next_frame(session,0)

    def test_queued_input_ends_the_media_slice(self):
        session=self.session()
        with self.assertRaises(TimeoutError):
            self.frames(session)
        self.assertEqual(session.input_wakes,1)

    def test_no_wake_without_input_or_outside_the_pumping_window(self):
        cases=[dict(queued=False),dict(requesting=1),dict(window_open=False),dict(cleanup=True),
               dict(_collect_media=False),dict(keepalive_offset=None),dict(input=object())]
        for state in cases:
            with self.subTest(state=state):
                session=self.session(**state)
                self.assertEqual(self.frames(session),"frame")
                self.assertEqual(session.input_wakes,0)

    def test_request_replies_are_never_cut(self):
        session=self.session()
        seen=[]
        def reply(self,*args,**kwargs):
            seen.append(self.requesting)
            return daemon.DaemonSession._next_frame(self,0)
        with patch.object(daemon.base.SessionInput,"_request",create=True,new=reply), \
             patch.object(daemon.base.SessionInput,"_next_frame",create=True,return_value="reply"):
            self.assertEqual(daemon.DaemonSession._request(session),"reply")
        self.assertEqual((seen,session.requesting,session.input_wakes),([1],0,0))


def common(message,response=False):
    """One JSON common message framed as the phone's commonMessageStart/Buffer/End."""
    import json as _json
    import sidesync_packets
    start,body,end=(0x67,0x68,0x69) if response else (0x64,0x65,0x66)
    raw=_json.dumps(message).encode()
    return (sidesync_packets.encode(start,b"\0"*16)+sidesync_packets.encode(body,raw[:20])
            +sidesync_packets.encode(body,raw[20:])+sidesync_packets.encode(end,b""))


def cursor(shape,night=False):
    return common({"TYPE":"NOTI","MSG":"MOUSE_CURSOR_CHANGE","PARAM":{"MOUSE_CURSOR_ID":shape,"IS_NIGHT_MODE":night}})


class CursorRelayTests(unittest.TestCase):
    def setUp(self):
        import os,tempfile
        self.os=os
        self.dir=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.dir.name,"cursor.fifo")
        os.mkfifo(self.path,0o600)
        self.now=[0.0]
        self.relay=cursor_relay.CursorRelay(self.path,clock=lambda:self.now[0])

    def tearDown(self):
        self.relay.close()
        self.dir.cleanup()

    def reader(self):
        return self.os.open(self.path,self.os.O_RDONLY|self.os.O_NONBLOCK)

    def test_split_stream_yields_only_cursor_shapes_in_order(self):
        import sidesync_packets
        stream=(sidesync_packets.connect_confirmed()+common({"TYPE":"REQ","MSG":"FeatureList"})
                +cursor(1002)+sidesync_packets.heartbeat_response()+cursor(1008,True))
        fd=self.reader()
        try:
            received=bytearray()
            for end in range(0,len(stream)+1,7):  # arbitrary split points, partial frames
                self.relay.feed(stream[:end])
                self.relay.flush()
                try:received+=self.os.read(fd,64)
                except BlockingIOError:pass
            self.relay.feed(stream);self.relay.flush()
            try:received+=self.os.read(fd,64)
            except BlockingIOError:pass
            # Only the latest pending shape is written per flush; both arrive here.
            self.assertEqual(bytes(received),b"C 1002 0\nC 1008 1\n")
            self.assertEqual(self.relay.summary()["changes"],2)
            self.assertIsNone(self.relay.error)
        finally:
            self.os.close(fd)

    def test_without_reader_only_latest_shape_waits_and_open_is_rate_limited(self):
        self.relay.feed(cursor(1002)+cursor(1000));self.relay.flush();self.relay.flush()
        self.assertEqual(self.relay.counts["no_reader"],1)
        fd=self.reader()
        try:
            self.relay.flush()
            self.assertEqual(self.os.read(fd,64),b"")  # no writer opened yet: nothing sent
            self.now[0]+=cursor_relay.CURSOR_OPEN_RETRY_SECONDS
            self.relay.flush()
            self.assertEqual(self.os.read(fd,64),b"C 1000 0\n")
            self.assertEqual(self.relay.summary()["last_id"],1000)
        finally:
            self.os.close(fd)

    def test_departed_reader_and_bad_input_never_raise(self):
        fd=self.reader()
        self.relay.feed(cursor(1002));self.relay.flush()
        self.os.close(fd)
        self.relay.feed(cursor(1002)+cursor(1008));self.relay.flush()
        self.assertEqual(self.relay.counts["reader_left"],1)
        for bad in ({"MSG":"MOUSE_CURSOR_CHANGE","PARAM":{"MOUSE_CURSOR_ID":"1002"}},
                    {"MSG":"MOUSE_CURSOR_CHANGE","PARAM":{"MOUSE_CURSOR_ID":-1}},
                    {"MSG":"MOUSE_CURSOR_CHANGE"},
                    {"TYPE":"NOTI","MSG":"OTHER","PARAM":{"MOUSE_CURSOR_ID":1002}}):
            relay=cursor_relay.CursorRelay(self.path)
            relay.feed(common(bad));relay.flush()
            self.assertIsNone(relay.pending)
        broken=cursor_relay.CursorRelay(self.path)
        broken.feed(b"\x09\x64\x00\x08xxxx"+cursor(1002))
        self.assertEqual((broken.error,broken.pending),("invalid frame header",None))



class ProfileTests(unittest.TestCase):
    def setUp(self):
        import capabilities_probe as cap
        import kms_daemon_probe as probe
        self.cap,self.probe=cap,probe
        saved=cap.PROFILE
        self.addCleanup(setattr,cap,"PROFILE",saved)

    def test_scrambled_profile_reports_the_official_version_even_after_a_plain_probe(self):
        live=self.probe.rtsp_udp_live
        for start in (live.BASE_PC_VERSION,live.PLAIN_PC_VERSION):
            self.cap.PROFILE=dict(self.cap.PROFILE,PcVer=start)
            with patch.object(self.probe,"SCRAMBLED",True):
                self.probe.select_profile()
            self.assertEqual(self.cap.PROFILE["PcVer"],live.BASE_PC_VERSION)
        with patch.object(self.probe,"SCRAMBLED",False):
            self.probe.select_profile()
        self.assertEqual(self.cap.PROFILE["PcVer"],live.PLAIN_PC_VERSION)

    def test_other_profiles_are_refused(self):
        for change in (dict(PcVer="2.5.0.0"),dict(SinkType="MAC")):
            self.cap.PROFILE={**self.cap.PROFILE,"PcVer":self.probe.rtsp_udp_live.BASE_PC_VERSION,**change}
            with self.subTest(change=change),self.assertRaises(RuntimeError):
                self.probe.select_profile()



class SinkDropTests(unittest.TestCase):
    def test_overflow_and_detach_drops_are_counted_apart(self):
        import os
        sink=daemon_sink.DetachableSink("/nonexistent/ts.fifo",queue_bytes=2000)
        sink.attached=True
        sink.put(b"a"*1316)
        sink.put(b"b"*1316)          # queue full while attached: real loss
        sink._detach(os.open(os.devnull,os.O_WRONLY))  # the queued chunk had no receiver
        sink.put(b"c"*188)           # no viewer: idle, not a drop
        summary=sink.summary()
        self.assertEqual((summary["dropped_chunks"],summary["dropped_bytes"]),(2,2632))
        self.assertEqual((summary["overflow_dropped_chunks"],summary["overflow_dropped_bytes"]),(1,1316))
        self.assertEqual((summary["detach_dropped_chunks"],summary["detach_dropped_bytes"]),(1,1316))
        self.assertEqual(summary["idle_dropped_bytes"],188)



class FakeOutEngine:
    """Holds every submitted OUT transfer until the test completes it."""
    def __init__(self,fail_submit=0):
        self.submitted=[];self.held=[];self.cancelled=0;self.closed=False;self.fail_submit=fail_submit
        import threading;self.lock=threading.Lock()
    def start(self,owner,count):self.owner,self.count=owner,count
    def submit(self,endpoint,data,timeout,token):
        if self.fail_submit:return self.fail_submit
        with self.lock:self.submitted.append((endpoint,bytes(data)));self.held.append((len(data),token))
        return 0
    def finish(self,n=None,status=0,short=False):
        with self.lock:batch,self.held=(self.held,[]) if n is None else (self.held[:n],self.held[n:])
        for length,token in batch:self.owner.complete(status,length-1 if short and length else length,length,token)
        return len(batch)
    def cancel_all(self):self.cancelled+=1
    def close(self):self.closed=True


def wait_for(predicate,seconds=2):
    import time as clock
    deadline=clock.monotonic()+seconds
    while not predicate() and clock.monotonic()<deadline:clock.sleep(.005)
    return predicate()


class AsyncOutTests(unittest.TestCase):
    def timing(self,engine,transfers=3):
        made=[]
        def factory(device,on_done):
            made.append(device);return usb_engines.AsyncOut(engine,transfers=transfers,on_done=on_done)
        device=FakeUsb([])
        return usb_engines.UsbTiming(device,async_out=factory),device,made

    def test_queue_order_with_a_bounded_window_and_zlp_kept_in_place(self):
        engine=FakeOutEngine();timing,device,made=self.timing(engine)
        frames=[b"a"*512,b"",b"ack1",b"input",b"ack2"]
        for frame in frames:self.assertEqual(timing.write(1,frame,1000),len(frame))
        self.assertTrue(wait_for(lambda:len(engine.submitted)==3))
        self.assertEqual(timing.async_out.inflight,3)          # window full: the rest waits
        self.assertEqual(len(engine.submitted),3)
        while len(engine.submitted)<len(frames) or engine.held:
            engine.finish(1);wait_for(lambda:len(engine.submitted)==len(frames) or engine.held)
        timing.stop_writer()
        self.assertEqual(engine.submitted,[(1,f) for f in frames])
        self.assertEqual(device.written,[])                   # nothing through the synchronous path
        self.assertEqual(made,[device])
        summary=timing.summary()
        self.assertEqual((summary["writes"],timing.write_bytes.tolist()),(5,[512,0,4,5,4]))
        self.assertEqual(summary["async_out"],dict(transfers=3,submitted=5,completed=5,inflight=0,
                                                   inflight_peak=3,error=None))
        self.assertTrue(engine.closed)

    def test_failed_or_short_transfer_fails_the_next_read_and_write(self):
        for kwargs,pattern in ((dict(status=1),"status 1"),(dict(short=True),"3 of 4 bytes")):
            with self.subTest(kwargs=kwargs):
                engine=FakeOutEngine();timing,device,_=self.timing(engine)
                device.chunks=[b"r"]
                timing.write(1,b"abcd")
                self.assertTrue(wait_for(lambda:engine.held))
                engine.finish(**kwargs)
                with self.assertRaisesRegex(Exception,pattern):timing.read(133,512)
                with self.assertRaisesRegex(Exception,pattern):timing.write(1,b"y")
                with self.assertRaisesRegex(Exception,pattern):timing.stop_writer()

    def test_submit_failure_stops_the_writer(self):
        engine=FakeOutEngine(fail_submit=-4);timing,_,_=self.timing(engine)
        timing.write(1,b"x")
        self.assertTrue(wait_for(lambda:timing.writer_error is not None))
        with self.assertRaisesRegex(Exception,"submit failed -4"):timing.write(1,b"y")
        self.assertEqual(timing.async_out.inflight,0)

    def test_transfer_in_flight_forbids_usb_release_until_it_completes(self):
        engine=FakeOutEngine();timing,_,_=self.timing(engine)
        timing.write(1,b"x")
        self.assertTrue(wait_for(lambda:engine.held))
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        reader=SimpleNamespace(stop=lambda:None,alive=lambda:False,stop_done=True,summary=lambda:{})
        owner.current=SimpleNamespace(usb_timing=timing);owner.quiesced=False;owner.quiesce_error=None;owner.reader=reader
        released=[];owner.util=SimpleNamespace(release_interface=lambda *a:released.append(a));owner.result={}
        with patch.object(usb_engines,"WRITER_STOP_SECONDS",.05):
            stop=timing.async_out.stop
            timing.async_out.stop=lambda seconds:stop(.05)
            with self.assertRaisesRegex(Exception,"still in flight; USB resource release prohibited"):
                owner.release_interface("dev",3)
        self.assertEqual((released,engine.cancelled),([],1))
        engine.finish(status=3)                              # the cancellation completes
        # Released now; the undelivered (cancelled) write is still reported.
        with self.assertRaisesRegex(Exception,"status 3"):owner.release_interface("dev",3)
        self.assertEqual(released,[("dev",3)])
        self.assertTrue(engine.closed)

    def test_engine_setup_failure_keeps_synchronous_writes(self):
        def factory(device,on_done):raise OSError("no libusb")
        device=FakeUsb([]);timing=usb_engines.UsbTiming(device,async_out=factory)
        for frame in (b"a",b"bc"):timing.write(1,frame)
        timing.stop_writer()
        self.assertEqual(device.written,[1,2])
        summary=timing.summary()
        self.assertEqual((summary["async_out"],summary["async_out_unavailable"]),(None,"OSError: no libusb"))

    def test_owner_session_uses_async_out(self):
        class FakeSession:
            def __init__(self,link,*args,log,**kwargs):
                self.log,self.max_frame_bytes=log,65536
                self.decoder=SimpleNamespace(max_frame_bytes=65536)
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.sink=owner.stop_file=owner.input_fifo=None
        owner.on_streaming=lambda:None
        link=Link(SimpleNamespace(),TimeoutError)
        made=[]
        with patch.object(daemon,"DaemonSession",FakeSession), \
                patch.object(daemon,"LibusbOutEngine",lambda device:made.append(device) or FakeOutEngine()):
            session=owner.session(link,1,65536,daemon.long.MAX_RECEIVE_BYTES,log=lambda event,**fields:None)
            session.usb_timing.write(1,b"x")
            self.assertTrue(wait_for(lambda:session.usb_timing.async_out is not None
                                     and session.usb_timing.async_out.engine.held))
        self.assertEqual(len(made),1)
        self.assertIsInstance(session.usb_timing.async_out,usb_engines.AsyncOut)
        session.usb_timing.async_out.engine.finish()
        session.usb_timing.stop_writer()



PLAY_REQ=b"PLAY rtsp://phone.invalid/wfd1.0/streamid=0 RTSP/1.0\r\nCSeq: 3\r\nSession: 6B8B4567\r\n\r\n"


def rtsp_reply(cseq,status=200):
    return ("RTSP/1.0 %d OK\r\nCSeq: %d\r\n\r\n"%(status,cseq)).encode()


class PauseControlTests(unittest.TestCase):
    def control(self):
        c=daemon.PauseControl();c.learn_play(PLAY_REQ);return c

    def test_learns_uri_and_session_and_builds_requests(self):
        c=self.control()
        self.assertEqual((c.uri,c.session_id),("rtsp://phone.invalid/wfd1.0/streamid=0","6B8B4567"))
        self.assertEqual(c.request("PAUSE",101),
            b"PAUSE rtsp://phone.invalid/wfd1.0/streamid=0 RTSP/1.0\r\nCSeq: 101\r\nSession: 6B8B4567\r\n\r\n")
        self.assertIsNone(daemon.PauseControl().step(0,False,True,[],0))   # no PLAY seen: never acts

    def test_full_pause_resume_cycle(self):
        c=self.control()
        self.assertIsNone(c.step(0,True,False,[],10))                     # viewer there
        self.assertEqual(c.step(1,False,True,[],10),("PAUSE",101))        # gone past grace
        self.assertIsNone(c.step(1.5,True,False,[],10))                    # one request at a time
        self.assertIsNone(c.step(1.6,False,True,[(101,200)],10))
        self.assertEqual((c.state,c.pauses,c.take_notes()),("paused",1,["paused"]))
        self.assertEqual(c.step(9,True,False,[],10),("PLAY",102))
        self.assertIsNone(c.step(9.1,True,False,[(102,200)],10))
        self.assertEqual((c.state,c.resumes,c.take_notes()),("playing",1,["resumed"]))
        self.assertIsNone(c.step(9.4,True,False,[],11))                    # first RTP after PLAY
        self.assertEqual(c.summary()["resume_ms"],[400])
        self.assertEqual(c.take_notes(),["media_after_resume ms=400"])
        self.assertEqual(c.summary()["paused_seconds"],7.4)
        self.assertEqual(c.step(20,False,True,[],50),("PAUSE",103))        # leaves again

    def test_viewer_back_while_pausing_resumes_right_after_the_reply(self):
        c=self.control();c.step(0,False,True,[],0)
        self.assertEqual(c.step(.2,True,False,[(101,200)],0),("PLAY",102))

    def test_failures_end_the_session_the_old_way(self):
        c=self.control();c.step(0,False,True,[],0)
        self.assertIsNone(c.step(daemon.RTSP_REPLY_SECONDS,False,True,[],0))
        self.assertEqual(c.failure,"pause_no_reply")
        c=self.control();c.step(0,False,True,[],0);c.step(.1,False,True,[(101,455)],0)
        self.assertEqual(c.failure,"pause_status_455")
        c=self.control();c.step(0,False,True,[],0);c.step(.1,False,True,[(101,200)],0)
        c.step(1,True,False,[],0);c.step(1.1,True,False,[(102,200)],0)
        self.assertIsNone(c.failure)
        c.step(1+daemon.RESUME_MEDIA_SECONDS,True,False,[],0)
        self.assertEqual(c.failure,"resume_no_media")
        self.assertIsNone(c.step(99,False,True,[],0))                      # nothing after a failure


class PauseSessionTests(unittest.TestCase):
    def session(self,attached,absent_seconds):
        sent=[];notes=[]
        session=object.__new__(daemon.DaemonSession)
        session.window_open,session.cleanup=True,False
        session.rtsp_connection=SimpleNamespace(received=bytearray())
        session.keepalive_offset=0
        session.media_counts=Counter({play.RTP_CONFIG:5})
        session.sink=SimpleNamespace(attached=attached,unattached_seconds=lambda:absent_seconds,
                                     notify=notes.append,error=None)
        session.clock=lambda:session.now
        session.now=100.0
        session.log=lambda event,**fields:None
        session.stop_file="/nonexistent/stop";session.terminate_requested=False;session.stop_reason=None
        session.window_started=None;session.kms_connection=None
        with patch.object(daemon.base.SessionInput,"send",create=True,
                          side_effect=lambda conn,data,timeout_s=5:sent.append(bytes(data))):
            daemon.DaemonSession.send(session,session.rtsp_connection,PLAY_REQ)
        return session,sent,notes

    def run_slice(self,session,sent):
        with patch.object(daemon.base.SessionInput,"send",create=True,
                          side_effect=lambda conn,data,timeout_s=5:sent.append(bytes(data))):
            session._pause_or_resume()

    def test_absent_viewer_pauses_and_returning_viewer_resumes(self):
        session,sent,notes=self.session(False,daemon.VIEWER_GRACE_SECONDS)
        self.run_slice(session,sent)
        self.assertTrue(sent[-1].startswith(b"PAUSE rtsp://phone.invalid/wfd1.0/streamid=0 RTSP/1.0\r\nCSeq: 101"))
        session.rtsp_connection.received+=rtsp_reply(101)
        session.sink.attached=True;session.sink.unattached_seconds=lambda:0
        self.run_slice(session,sent)
        self.assertEqual(notes,["paused"])
        self.assertTrue(sent[-1].startswith(b"PLAY ") and b"CSeq: 102" in sent[-1])
        self.assertFalse(daemon.DaemonSession.stop_requested(session))   # a viewer leaving no longer ends it

    def test_a_failed_pause_stops_the_window(self):
        session,sent,notes=self.session(False,daemon.VIEWER_GRACE_SECONDS)
        self.run_slice(session,sent)
        session.rtsp_connection.received+=rtsp_reply(101,500)
        self.run_slice(session,sent)
        self.assertTrue(daemon.DaemonSession.stop_requested(session))
        self.assertEqual(session.stop_reason,"pause_status_500")
        self.assertEqual(notes,["pause_failed reason=pause_status_500"])


if __name__=="__main__":
    unittest.main()
