"""Focused keyboard, extra-button, release, pin and session-script checks; no phone or real ADB server."""
from collections import Counter
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kms_input_live as base
import kms_session_live as ks
import rtsp_udp_long as long
import sidesync_packets
from usb_tunnel import TunnelError

HERE=Path(__file__).parent


def session():
    s=ks.SessionInput.__new__(ks.SessionInput)
    s.input=SimpleNamespace(events=lambda:[],counts=Counter(),close=lambda:None)
    s.kms_connection=SimpleNamespace(closed_by_phone=False)
    s.window_open=True
    s.cleanup=False
    s.pending=[]
    s.held={}
    s.keys_held=set()
    s.last_position=None
    s.input_sends=0
    s.input_error=None
    s.sent=Counter()
    s.dropped=Counter()
    s.releases_sent=s.keys_released=0
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
    def test_key_packet_is_little_endian_scan_code_in_kind_0x15(self):
        self.assertEqual(ks.key_packet(ks.KEY_DOWN,30),bytes.fromhex("03 15 00 0b 00 00 00 1e 00 00 00"))
        self.assertEqual(ks.key_packet(ks.KEY_UP,0x2ff),bytes.fromhex("03 15 00 0b 00 01 00 ff 02 00 00"))

    def test_parse_accepts_keys_and_every_mapped_mouse_event(self):
        # 9, 10 and 13 are the file drag move/drop/start (file_bridge).
        for event in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17):
            self.assertEqual(ks.InputReader.parse(b"M %d 1 2"%event),(event,1,2))
        self.assertEqual(ks.InputReader.parse(b"K d 30"),("K",0,30))
        self.assertEqual(ks.InputReader.parse(b"K u 767"),("K",1,767))
        for line in (b"M 18 1 1",b"K d 0",b"K d 768",
                     b"K x 30",b"K d 30 ",b"K d -1",b"M 0 1921 0",b"M 0 -2 5",b"M 9 -1 5",b"M 1 1920 5"):
            self.assertIsNone(ks.InputReader.parse(line),line)

    def test_parse_accepts_one_step_past_the_edge_for_moves_only(self):
        import site_env
        for x,y in ((-1,500),(500,-1),(1920,500),(500,1080),(-1,-1)):
            self.assertEqual(ks.InputReader.parse(b"M 0 %d %d"%(x,y)),(0,*site_env.to_desktop(x,y)),(x,y))
        self.assertLess(site_env.to_desktop(-1,500)[0],0)
        self.assertGreaterEqual(site_env.to_desktop(1920,500)[0],site_env.desktop_size()[0])

    def test_mixed_batch_tracks_keys_and_buttons_in_order(self):
        s=session()
        feed(s,[("K",0,29),(6,5,5),("K",0,46),("K",1,46),(5,5,5),(15,7,7)])
        s._pump_input()
        self.assertEqual(s.wires,[ks.key_packet(0,29)+sidesync_packets.mouse_event(6,5,5)
                                  +ks.key_packet(0,46)+ks.key_packet(1,46)
                                  +sidesync_packets.mouse_event(5,5,5)+sidesync_packets.mouse_event(15,7,7)])
        self.assertEqual((s.keys_held,s.held,s.last_position),({29},{15:True},(7,7)))
        self.assertEqual(dict(s.sent),{"key_down":2,"key_up":1,"6":1,"5":1,"15":1})

    def test_window_end_releases_keys_then_buttons_once(self):
        s=session()
        s.keys_held={56,29}
        s.held={2:True,17:True}
        s.last_position=(3,4)
        s._release_held()
        s._release_held()
        self.assertEqual(s.wires,[ks.key_packet(1,29)+ks.key_packet(1,56)
                                  +sidesync_packets.mouse_event(1,3,4)+sidesync_packets.mouse_event(16,3,4)])
        self.assertEqual((s.keys_released,s.releases_sent,s.keys_held,s.held),(2,2,set(),{}))

    def test_failed_send_holds_pressed_keys_for_the_final_release(self):
        s=session()
        calls=[]
        def fail(connection,payload,**kw):
            calls.append(payload)
            raise TunnelError("gone")
        s.send=fail
        feed(s,[("K",0,42)])
        with self.assertRaisesRegex(TunnelError,"gone"):
            s._pump_input()
        self.assertEqual(s.keys_held,{42})
        s._release_held()
        self.assertEqual(calls[-1],ks.key_packet(1,42))
        self.assertIn("release",s.input_error)

    def test_release_failure_of_any_kind_never_raises(self):
        s=session()
        s.keys_held={30}
        s.send=lambda *a,**k:(_ for _ in ()).throw(RuntimeError("request budget"))
        s._release_held()
        self.assertIn("budget",s.input_error)

    def test_release_skipped_when_kms_closed(self):
        s=session()
        s.keys_held={30}
        s.kms_connection.closed_by_phone=True
        s._release_held()
        self.assertEqual((s.wires,s.dropped["release_skipped"]),([],1))

    def test_window_uses_keyboard_reader_and_releases_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.fifo"
            os.mkfifo(path,0o600)
            writer=None
            s=session()
            s.input=None
            s.input_fifo=path
            s.window_armed=True
            def window(self,seconds,until):
                self.window_armed=False
                self.keys_held={30}
                raise TunnelError("phone closed")
            try:
                with patch.object(long.LongSession,"wait",window):
                    with self.assertRaisesRegex(TunnelError,"phone closed"):
                        s.wait(5)
            finally:
                if writer is not None:
                    os.close(writer)
            self.assertIsInstance(s.input,ks.InputReader)
            self.assertIsNone(s.input.fd)
            self.assertEqual(s.wires,[ks.key_packet(1,30)])
            self.assertIs(base.InputReader.parse(b"K d 30"),None)

    def test_overflow_drops_oldest_presses_and_moves_but_keeps_releases(self):
        counts=Counter()
        events=[("K",0,30),(2,1,1)]+[(0,i,i) for i in range(5)]+[("K",1,30),(1,1,1)]
        kept=ks.trim(events,4,counts)
        self.assertEqual(kept,[(0,3,3),(0,4,4),("K",1,30),(1,1,1)])
        self.assertEqual(counts["pending_overflow"],5)
        self.assertEqual(ks.trim(events,20,counts),events)
        # A release among the oldest events survives too.
        early=[(1,1,1),("K",1,29)]+[(0,i,i) for i in range(6)]
        self.assertEqual(ks.trim(early,4,Counter()),[(1,1,1),("K",1,29),(0,4,4),(0,5,5)])

    def test_session_slice_is_10_ms_and_guarded(self):
        for start in (.2,.05,.01):
            with patch.object(base.live,"KEEPALIVE_SLICE_SECONDS",start):
                ks.configure()
                self.assertEqual(base.live.KEEPALIVE_SLICE_SECONDS,.01)
        with patch.object(base.live,"KEEPALIVE_SLICE_SECONDS",.3):
            with self.assertRaises(RuntimeError):
                ks.configure()

    def test_session_send_budget_applies(self):
        s=session()
        s.input_sends=ks.MAX_INPUT_SENDS
        feed(s,[(0,1,1)])
        s._pump_input()
        self.assertEqual((s.wires,s.dropped["send_budget"]),([],1))
        s=session()
        s.input_sends=base.MAX_INPUT_SENDS
        feed(s,[(0,1,1)])
        s._pump_input()
        self.assertEqual(len(s.wires),1)

    def test_summary_counts_only(self):
        s=session()
        with patch.object(base.InputSession,"summary",lambda self:dict(kms_input=dict(sends=1))):
            self.assertEqual(s.summary()["kms_input"],dict(sends=1,keys_released=0,keys_held_at_end=0))








if __name__=='__main__':
    unittest.main()
