"""Focused daemon-session checks: limits, detachable sink and input FIFO (real FIFOs), RTSP
compaction, stop path, quiet log; no phone or ADB."""
from collections import Counter
import contextlib
import io
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kms_daemon_live as daemon
import kms_daemon_probe as probe
import kms_input_live
import kms_session_live as ks
import rtsp
import rtsp_udp_live as live
import rtsp_udp_long as long
import rtsp_udp_play as play
import sidesync_packets


def wait_for(condition,seconds=3):
    deadline=time.monotonic()+seconds
    while not condition():
        if time.monotonic()>=deadline:
            raise AssertionError("condition not reached")
        time.sleep(.02)


def read_all(fd,size):
    data=b""
    deadline=time.monotonic()+3
    while len(data)<size and time.monotonic()<deadline:
        try:
            data+=os.read(fd,size-len(data))
        except BlockingIOError:
            time.sleep(.02)
    return data


def session():
    s=daemon.DaemonSession.__new__(daemon.DaemonSession)
    s.kms_connection=SimpleNamespace(closed_by_phone=False)
    s.window_open=True
    s.cleanup=False
    s.pending=[]
    s.held={}
    s.keys_held=set()
    s.last_position=None
    s.input_error=None
    s.dropped=Counter()
    s.releases_sent=s.keys_released=s.writer_releases=0
    s.terminate_requested=False
    s.wires=[]
    s.send=lambda connection,payload,**kw:s.wires.append(payload)
    return s


def request(cseq):
    return ("GET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: %d\r\n\r\n"%cseq).encode()


PLAY_RESPONSE=b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 1\r\n\r\n"


class Tests(unittest.TestCase):
    def test_configure_lifts_every_bound_and_refuses_a_changed_base(self):
        daemon.configure()
        daemon.configure()
        for name,value in daemon.DAEMON.items():
            self.assertEqual(getattr(play,name),value,name)
        self.assertEqual((live.MAX_KEEPALIVES,kms_input_live.MAX_HEARTBEATS,ks.MAX_INPUT_SENDS),
                         (daemon.UNLIMITED,)*3)
        self.assertEqual((long.CAP_SECONDS,long.LONG_RECEIVE_BYTES,live.KEEPALIVE_SLICE_SECONDS),
                         (daemon.FOREVER_SECONDS,daemon.DAEMON_RECEIVE_BYTES,ks.SESSION_SLICE_SECONDS))
        with patch.object(long,"CAP_SECONDS",30):
            with self.assertRaisesRegex(RuntimeError,"pinned base"):
                daemon.configure()

    def test_sink_drops_without_reader_then_attaches_detaches_and_reattaches(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"ts.fifo"
            os.mkfifo(path,0o600)
            notes=[]
            sink=daemon.DetachableSink(path,notify=notes.append,poll_seconds=.05).start()
            try:
                sink.put(b"x"*188)
                self.assertEqual(sink.summary()["idle_dropped_bytes"],188)
                for viewer in range(2):
                    reader=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
                    wait_for(lambda:sink.attached)
                    sink.put(b"%d"%viewer*376)
                    self.assertEqual(read_all(reader,376),b"%d"%viewer*376)
                    os.close(reader)
                    # The next write fails with EPIPE: detach, never an error.
                    wait_for(lambda:(sink.put(b"z"*188),not sink.attached)[1])
                summary=sink.summary()
                self.assertEqual((summary["attaches"],summary["detaches"],summary["error_type"]),(2,2,None))
                self.assertEqual(notes,["viewer_attached","viewer_detached"]*2)
                self.assertIsNone(sink.error)
            finally:
                sink.close()
            self.assertTrue(sink.summary()["stopped"])

    def test_sink_never_writes_a_regular_file_and_reports_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"ts.fifo"
            path.write_bytes(b"")
            sink=daemon.DetachableSink(path,poll_seconds=.05).start()
            wait_for(lambda:sink.error is not None)
            sink.put(b"x"*188)
            sink.close()
            self.assertEqual(path.read_bytes(),b"")
            self.assertEqual(sink.summary()["error_type"],"RuntimeError")

    def test_viewer_absence_counts_only_after_the_window_is_armed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"ts.fifo"
            os.mkfifo(path,0o600)
            sink=daemon.DetachableSink(path,poll_seconds=.05).start()
            try:
                time.sleep(.2)
                self.assertEqual(sink.unattached_seconds(),0)
                sink.arm()
                time.sleep(.2)
                self.assertGreaterEqual(sink.unattached_seconds(),.15)
                reader=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
                wait_for(lambda:sink.attached)
                self.assertEqual(sink.unattached_seconds(),0)
                os.close(reader)
                wait_for(lambda:(sink.put(b"z"*188),not sink.attached)[1])
                self.assertLess(sink.unattached_seconds(),.5)
            finally:
                sink.close()

    def test_sink_close_returns_while_waiting_for_a_reader(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"ts.fifo"
            os.mkfifo(path,0o600)
            sink=daemon.DetachableSink(path,poll_seconds=5).start()
            started=time.monotonic()
            sink.close()
            self.assertLess(time.monotonic()-started,1)
            self.assertTrue(sink.summary()["stopped"])

    def test_input_writer_gone_only_after_a_writer_left(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.fifo"
            os.mkfifo(path,0o600)
            reader=daemon.InputReader(path)
            try:
                self.assertEqual(reader.events(),[])
                self.assertFalse(reader.writer_gone())
                writer=os.open(path,os.O_WRONLY)
                os.write(writer,b"K d 30\nM 0 1")
                self.assertEqual(reader.events(),[("K",0,30)])
                self.assertFalse(reader.writer_gone())
                os.close(writer)
                self.assertEqual(reader.events(),[])
                self.assertTrue(reader.writer_gone())
                # The departed viewer's partial "M 0 1" is gone; the next viewer starts clean.
                writer=os.open(path,os.O_WRONLY)
                self.assertFalse(reader.writer_gone())
                os.write(writer,b"0 5\n")
                self.assertEqual(reader.events(),[])
                self.assertEqual(reader.counts["invalid"],1)
                os.close(writer)
            finally:
                reader.close()

    def test_writer_gone_releases_held_keys_and_buttons_once(self):
        s=session()
        gone=[False]
        s.input=SimpleNamespace(writer_gone=lambda:gone[0])
        s.keys_held={30}
        s.held={2:True}
        s.last_position=(5,6)
        with patch.object(kms_input_live.InputSession,"_answer_keepalives",lambda self:None):
            s._answer_keepalives()
            self.assertEqual(s.wires,[])
            gone[0]=True
            s.pending=[("K",1,30)]
            s._answer_keepalives()
            self.assertEqual(s.wires,[])
            s.pending=[]
            s._answer_keepalives()
            s._answer_keepalives()
        self.assertEqual(s.wires,[ks.key_packet(1,30)+sidesync_packets.mouse_event(1,5,6)])
        self.assertEqual((s.writer_releases,s.held,s.keys_held),(1,{},set()))

    def test_rtsp_compaction_keeps_play_response_and_passes_the_stream_guard(self):
        s=session()
        received=bytearray(b"SETUP-era bytes")
        start=len(received)
        received+=PLAY_RESPONSE
        for cseq in range(5,600):
            received+=request(cseq)
        self.assertGreater(len(received),rtsp.STREAM_BYTES)
        s.rtsp_connection=SimpleNamespace(received=received)
        s.window_rtsp_start=start
        s.keepalive_offset=len(received)
        received+=b"GET_PAR"   # unprocessed tail survives
        s._compact_rtsp()
        self.assertEqual(bytes(received),b"SETUP-era bytes"+PLAY_RESPONSE+b"GET_PAR")
        self.assertEqual(s.keepalive_offset,start+len(PLAY_RESPONSE))
        self.assertLessEqual(len(received),rtsp.STREAM_BYTES)
        # rtsp_udp_play.exchange's own offset (after PLAY) now sees only the tail.
        self.assertIsNone(rtsp.parse(bytes(received[start+len(PLAY_RESPONSE):])))

    def test_window_uses_daemon_reader_and_compacts(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.fifo"
            os.mkfifo(path,0o600)
            s=session()
            s.input=None
            s.input_fifo=path
            s.window_armed=True
            streamed=[]
            s.on_streaming=lambda:streamed.append(True)
            s.sink=SimpleNamespace(arm=lambda:streamed.append("armed"))
            s.rtsp_connection=SimpleNamespace(received=bytearray(PLAY_RESPONSE+request(5)))
            s.window_rtsp_start=0
            s.keepalive_offset=len(s.rtsp_connection.received)
            def window(self,seconds,until):
                self.window_armed=False
                return True
            with patch.object(long.LongSession,"wait",window):
                self.assertTrue(s.wait(5))
            self.assertIsInstance(s.input,daemon.InputReader)
            self.assertIsNot(ks.InputReader,daemon.InputReader)
            self.assertEqual((streamed,bytes(s.rtsp_connection.received)),(["armed",True],PLAY_RESPONSE))

    def test_failing_streaming_notice_still_disarms_the_window(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.fifo"
            os.mkfifo(path,0o600)
            s=session()
            s.input_fifo=path
            s.window_armed=True
            s.sink=SimpleNamespace(arm=lambda:None)
            s.rtsp_connection=None
            s.window_rtsp_start=None
            s.keepalive_offset=None
            logged=[]
            s.log=lambda event,**f:logged.append(event)
            def raising():
                raise OSError("full disk")
            s.on_streaming=raising
            def window(self,seconds,until):
                self.window_armed=False
                return True
            with patch.object(long.LongSession,"wait",window):
                self.assertTrue(s.wait(5))
            self.assertFalse(s.window_armed)
            self.assertEqual(logged,["streaming_notice_failed"])

    def test_partial_line_is_dropped_even_with_nothing_held(self):
        s=session()
        asked=[]
        s.input=SimpleNamespace(writer_gone=lambda:asked.append(1) or True)
        with patch.object(kms_input_live.InputSession,"_answer_keepalives",lambda self:None):
            s._answer_keepalives()
        self.assertEqual((asked,s.wires),([1],[]))

    def test_stop_reasons(self):
        with tempfile.TemporaryDirectory() as d:
            s=session()
            s.window_started=None
            s.stop_reason=None
            s.stop_file=Path(d)/"stop"
            away=[0]
            s.sink=SimpleNamespace(error=None,unattached_seconds=lambda:away[0])
            self.assertFalse(s.stop_requested())
            away[0]=daemon.VIEWER_GRACE_SECONDS-.1
            self.assertFalse(s.stop_requested())
            away[0]=daemon.VIEWER_GRACE_SECONDS
            self.assertTrue(s.stop_requested())
            self.assertEqual(s.stop_reason,"viewer_left")
            s.stop_reason=None
            s.kms_connection.closed_by_phone=True
            self.assertTrue(s.stop_requested())
            self.assertEqual(s.stop_reason,"kms_closed")
            s.stop_reason=None
            s.sink.error=RuntimeError("not a FIFO")
            self.assertTrue(s.stop_requested())
            self.assertEqual(s.stop_reason,"sink_error")
            s.stop_reason=None
            s.terminate_requested=True
            self.assertTrue(s.stop_requested())
            self.assertEqual(s.stop_reason,"sigterm")

    def test_owner_terminate_only_inside_the_window(self):
        owner=daemon.DaemonOwner.__new__(daemon.DaemonOwner)
        owner.current=None
        self.assertFalse(owner.terminate())
        owner.current=SimpleNamespace(window_started=None,terminate_requested=False)
        self.assertFalse(owner.terminate())
        owner.current.window_started=12.0
        self.assertTrue(owner.terminate())
        self.assertTrue(owner.current.terminate_requested)

    def test_quiet_log_counts_per_frame_usb_but_keeps_decisions(self):
        written=[]
        log=daemon.DaemonLog(lambda event,**fields:written.append(event))
        log.quiet=True
        for event in ("usb_raw","usb_frame_in","usb_frame_in_data","usb_read","usb_write"):
            log(event,direction="out",bytes_hex="00")
        log("rtsp_keepalive_reply",cseq=5)
        log("usb_in_unparsed",size_bytes=3)
        self.assertEqual(written,["rtsp_keepalive_reply"])
        self.assertEqual(sum(log.suppressed.values()),6)

    def test_rtsp_seen_keeps_a_bounded_head(self):
        seen=daemon.Head()
        for i in range(200):
            seen.append(i)
        self.assertEqual((len(seen),seen.total,seen[-1]),(daemon.RTSP_SEEN_KEEP,200,63))

    def test_probe_plan_only_never_selects_usb(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),patch.dict("sys.modules",{"usb":None,"usb.core":None}):
            self.assertEqual(probe.main([]),0)
        self.assertIn("PLAN_ONLY",out.getvalue())

    def test_probe_requires_every_path(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            probe.main(["--approved-phone-kms-daemon","--accept-persistent-state","--bus","3",
                        "--address","9","--output","/nonexistent/x"])


if __name__=="__main__":
    unittest.main()
