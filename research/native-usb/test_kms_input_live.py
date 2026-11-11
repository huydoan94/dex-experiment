"""Focused FIFO, validation, pump, release and pin checks; no phone or real ADB server."""
from collections import Counter
import contextlib
import hashlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kms_input_live as kin
import rtsp_udp_long as long
import sidesync_packets
from usb_tunnel import TunnelError


def wire(event,x,y):
    return sidesync_packets.mouse_event(event,x,y)


class Fifo:
    def __enter__(self):
        self.dir=tempfile.TemporaryDirectory()
        self.path=Path(self.dir.name)/"input.fifo"
        os.mkfifo(self.path,0o600)
        self.reader=kin.InputReader(self.path)
        self.writer=os.open(self.path,os.O_WRONLY|os.O_NONBLOCK)
        return self

    def write(self,data):
        os.write(self.writer,data)

    def __exit__(self,*exc):
        os.close(self.writer)
        self.reader.close()
        self.dir.cleanup()


def session(reader=None):
    s=kin.InputSession.__new__(kin.InputSession)
    s.input=reader or SimpleNamespace(events=lambda:[],counts=Counter(),close=lambda:None)
    s.kms_connection=SimpleNamespace(closed_by_phone=False)
    s.window_open=True
    s.cleanup=False
    s.pending=[]
    s.held={}
    s.last_position=None
    s.input_sends=0
    s.input_error=None
    s.sent=Counter()
    s.dropped=Counter()
    s.releases_sent=0
    s.heartbeats_sent=0
    s.last_heartbeat=None
    s.now=0
    s.clock=lambda:s.now
    s.log=lambda *a,**k:None
    s.wires=[]
    s.send=lambda connection,payload,**kw:s.wires.append(payload)
    return s


def feed(s,events):
    s.input=SimpleNamespace(events=lambda:list(events),counts=Counter(),close=lambda:None)


class Tests(unittest.TestCase):
    def test_parse_accepts_only_known_events_inside_the_desktop(self):
        ok={b"M 0 0 0":(0,0,0),b"M 2 1919 1079":(2,1919,1079),b"M 12 5 6":(12,5,6)}
        for line,event in ok.items():
            self.assertEqual(kin.InputReader.parse(line),event)
        for line in [b"M 5 1 1",b"M 9 1 1",b"M 99 1 1",b"M 0 1920 0",b"M 0 0 1080",
                     b"M 0 -1 0",b"M 0 1 1 ",b"K d 65",b"T d 1 1",b"M 0 01 1x",b""]:
            self.assertIsNone(kin.InputReader.parse(line),line)

    def test_fifo_reader_splits_lines_and_counts_invalid_and_overlong(self):
        with Fifo() as f:
            f.write(b"M 0 10 20\nbad\nM 2 10 2")
            self.assertEqual(f.reader.events(),[(0,10,20)])
            f.write(b"0\n"+b"x"*40)
            self.assertEqual(f.reader.events(),[(2,10,20)])
            self.assertEqual(f.reader.counts["invalid"],2)
            self.assertEqual(f.reader.events(),[])

    def test_reader_refuses_a_regular_file(self):
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaisesRegex(RuntimeError,"not a FIFO"):
                kin.InputReader(f.name)

    def test_moves_coalesce_but_buttons_and_order_stay(self):
        counts=Counter()
        got=kin.coalesce([(0,1,1),(0,2,2),(2,2,2),(0,3,3),(0,4,4),(1,4,4),(7,4,4)],counts)
        self.assertEqual(got,[(0,2,2),(2,2,2),(0,4,4),(1,4,4),(7,4,4)])
        self.assertEqual(counts["coalesced"],2)

    def test_one_send_per_slice_with_concatenated_packets(self):
        s=session()
        feed(s,[(0,5,6),(2,5,6),(1,5,6)])
        s._pump_input()
        self.assertEqual(s.wires,[wire(0,5,6)+wire(2,5,6)+wire(1,5,6)])
        self.assertEqual((s.input_sends,s.held,s.last_position),(1,{},(5,6)))
        self.assertEqual(dict(s.sent),{0:1,2:1,1:1})

    def test_overflow_waits_for_next_slice_instead_of_dropping(self):
        s=session()
        events=[(7,1,1)]*(kin.MAX_EVENTS_PER_SEND+3)
        feed(s,events)
        s._pump_input()
        feed(s,[])
        s._pump_input()
        self.assertEqual([len(w)//14 for w in s.wires],[kin.MAX_EVENTS_PER_SEND,3])
        self.assertEqual(s.dropped,Counter())

    def test_flood_beyond_pending_limit_is_counted(self):
        s=session()
        feed(s,[(7,1,1)]*(kin.MAX_PENDING_EVENTS+10))
        s._pump_input()
        self.assertEqual(s.dropped["pending_overflow"],10)

    def test_nothing_sent_when_kms_closed_failed_or_budget_spent(self):
        for case in ("closed","error","budget"):
            with self.subTest(case=case):
                s=session()
                if case=="closed":s.kms_connection.closed_by_phone=True
                if case=="error":s.input_error="send: x"
                if case=="budget":s.input_sends=kin.MAX_INPUT_SENDS
                feed(s,[(0,1,1)])
                s._pump_input()
                self.assertEqual(s.wires,[])
                self.assertEqual(sum(s.dropped.values()),1)

    def test_send_failure_ends_the_run_and_still_attempts_one_release(self):
        s=session()
        calls=[]
        def fail(connection,payload,**kw):
            calls.append(payload)
            raise TunnelError("gone")
        s.send=fail
        feed(s,[(2,1,1)])
        with self.assertRaisesRegex(TunnelError,"gone"):
            s._pump_input()
        self.assertIn("send: TunnelError: gone",s.input_error)
        # The press may have reached the phone: it counts as held.
        self.assertEqual(s.held,{2:True})
        s._release_held()
        self.assertEqual(calls,[wire(2,1,1),wire(1,1,1)])
        self.assertIn("release",s.input_error)

    def test_held_state_replays_batch_order(self):
        s=session()
        s.held={2:True}
        feed(s,[(1,1,1),(2,2,2),(4,3,3),(3,3,3)])
        s._pump_input()
        self.assertEqual(s.held,{2:True})

    def test_release_after_failure_is_sent_when_link_still_works(self):
        s=session()
        s.input_error="send: TunnelError: timeout"
        s.held={2:True}
        s.last_position=(4,5)
        s._release_held()
        self.assertEqual((s.wires,s.releases_sent),([wire(1,4,5)],1))

    def test_overlong_line_is_discarded_up_to_its_newline(self):
        with Fifo() as f:
            f.write(b"x"*30)
            self.assertEqual(f.reader.events(),[])
            f.write(b"M 2 5 5\nM 0 3 3\n")
            self.assertEqual(f.reader.events(),[(0,3,3)])
            self.assertEqual(f.reader.counts["invalid"],1)

    def test_fifo_open_failure_disarms_the_window(self):
        s=session()
        s.input=None
        s.input_fifo="/nonexistent/input.fifo"
        s.window_armed=True
        with self.assertRaises(OSError):
            s.wait(5)
        self.assertFalse(s.window_armed)

    def test_held_buttons_released_once_at_window_end(self):
        s=session()
        feed(s,[(2,9,8),(4,9,8),(0,30,40)])
        s._pump_input()
        s._release_held()
        s._release_held()
        self.assertEqual(s.wires[-1],wire(1,30,40)+wire(3,30,40))
        self.assertEqual((len(s.wires),s.releases_sent,s.held),(2,2,{}))

    def test_release_skipped_when_kms_unusable_and_never_raises(self):
        s=session()
        s.held={2:True}
        s.last_position=(1,1)
        s.kms_connection.closed_by_phone=True
        s._release_held()
        self.assertEqual((s.wires,s.dropped["release_skipped"]),([],1))
        s=session()
        s.held={2:True}
        s.last_position=(1,1)
        s.send=lambda *a,**k:(_ for _ in ()).throw(RuntimeError("budget"))
        s._release_held()
        self.assertIn("budget",s.input_error)

    def test_window_opens_fifo_only_for_media_and_releases_on_error(self):
        with Fifo() as f:
            s=session()
            s.input=None
            s.input_fifo=f.path
            s.window_armed=True
            def window(self,seconds,until):
                s.held={2:True}
                s.last_position=(3,4)
                raise TunnelError("phone closed")
            with patch.object(long.LongSession,"wait",window):
                with self.assertRaisesRegex(TunnelError,"phone closed"):
                    s.wait(5)
            self.assertFalse(s.window_open)
            self.assertIsNone(s.input.fd)
            self.assertEqual(s.wires,[wire(1,3,4)])

    def test_heartbeat_once_per_second_until_budget_or_failure(self):
        s=session()
        for step in range(0,41):
            s.now=step*.05
            s._heartbeat()
        self.assertEqual(s.wires,[sidesync_packets.heartbeat_request()]*3)
        s.heartbeats_sent=kin.MAX_HEARTBEATS
        s.now=10
        s._heartbeat()
        self.assertEqual(len(s.wires),3)
        s=session()
        s.send=lambda *a,**k:(_ for _ in ()).throw(TunnelError("gone"))
        with self.assertRaisesRegex(TunnelError,"gone"):
            s._heartbeat()
        self.assertIn("heartbeat",s.input_error)
        feed(s,[(0,1,1)])
        s._pump_input()
        self.assertEqual(s.dropped["no_connection"],1)

    def test_each_slice_heartbeats_and_pumps_only_while_window_open(self):
        s=session()
        feed(s,[(0,7,8)])
        with patch.object(long.LongSession,"_answer_keepalives",lambda self:None):
            s._answer_keepalives()
            self.assertEqual(s.wires,[sidesync_packets.heartbeat_request(),wire(0,7,8)])
            s.window_open=False
            s.now=5
            s._answer_keepalives()
        self.assertEqual(len(s.wires),2)

    def test_slice_guard(self):
        with patch.object(kin.live,"KEEPALIVE_SLICE_SECONDS",.2):
            kin.configure()
            self.assertEqual(kin.live.KEEPALIVE_SLICE_SECONDS,.05)
        with patch.object(kin.live,"KEEPALIVE_SLICE_SECONDS",.3):
            with self.assertRaises(RuntimeError):
                kin.configure()




if __name__=='__main__':
    unittest.main()
