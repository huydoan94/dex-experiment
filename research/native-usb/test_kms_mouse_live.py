"""Focused scheduling, gates and lifetime checks; no phone or real ADB server."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import kms_mouse_live as mouse
import kms_handshake as kms
from test_kms_handshake import Session,Codec


class Tests(unittest.TestCase):
    def session(self):
        s=mouse.MouseSession.__new__(mouse.MouseSession)
        s.now=10
        s.clock=lambda:s.now
        s.window_armed=True
        s.stage_latest=100
        s.kms_connection=SimpleNamespace(closed_by_phone=False)
        s.stop_requested=lambda:False
        s.log=lambda **kw:None
        s.sent=[]
        s.send=lambda connection,wire,**kw:s.sent.append(wire)
        return s

    @staticmethod
    def window(session,seconds,until):
        session.window_armed=False
        for at in [10,12.9,13,13.1,16,16.1,20]:
            session.now=at
            if until():return True
        return False

    def test_two_literal_move_packets_once_only_during_media_window(self):
        s=self.session()
        with patch.object(mouse.long.LongSession,'wait',self.window):
            self.assertFalse(s.wait(30))
        self.assertEqual(s.sent,[bytes.fromhex('03 14 00 0e 00 00 00 00 01 e0 00 00 02 1c'),
                                 bytes.fromhex('03 14 00 0e 00 00 00 00 05 a0 00 00 02 1c')])
        self.assertEqual((s.mouse_attempted,s.mouse_sent),(2,2))

    def test_no_input_before_media_after_stop_close_or_deadline(self):
        for case in ['before','stop','closed','deadline','caller_stop']:
            with self.subTest(case=case):
                s=self.session()
                if case=='before':s.window_armed=False
                if case=='stop':s.stop_requested=lambda:True
                if case=='closed':s.kms_connection.closed_by_phone=True
                if case=='deadline':s.stage_latest=10
                until=lambda:case=='caller_stop'
                # Before-media path simply delegates, without installing the injection hook.
                def window(session,seconds,predicate):
                    if case=='before':return False
                    return self.window(session,seconds,predicate)
                with patch.object(mouse.long.LongSession,'wait',window):
                    if case=='closed':
                        with self.assertRaisesRegex(Exception,'KMS closed'):s.wait(30,until)
                    else:s.wait(30,until)
                self.assertEqual(s.sent,[])

    def test_failed_mouse_send_is_attempted_once_without_retry(self):
        s=self.session()
        def fail(connection,wire,**kw):
            s.sent.append(wire)
            raise RuntimeError('send failed')
        s.send=fail
        with patch.object(mouse.long.LongSession,'wait',self.window):
            with self.assertRaisesRegex(RuntimeError,'send failed'):s.wait(30)
        self.assertEqual((len(s.sent),s.mouse_attempted,s.mouse_sent),(1,1,0))

    def test_verified_callback_runs_while_kms_open_then_cleanup_on_callback_error(self):
        session=Session()
        codec=Codec()
        client=SimpleNamespace(codec=lambda:codec)
        main=SimpleNamespace(closed_by_phone=False)
        def callback(s,m,r,connection,res,log):
            self.assertTrue(res['kms_handshake_verified'])
            self.assertEqual(connection.config_id,1208)
            self.assertNotIn('cleanup',s.calls)
            raise RuntimeError('callback failed')
        with self.assertRaisesRegex(RuntimeError,'callback failed'):
            kms.handshake(session,main,main,{},lambda **k:None,client=client,
                          latest=10,after_verified=callback)
        self.assertEqual(session.calls[-2:],[('disconnect',50008),('close',1208)])

    def test_startup_binds_live_callback_to_verified_kms_connection(self):
        session=SimpleNamespace()
        connection=SimpleNamespace(received=bytearray())
        calls=[]
        def fake(s,m,r,res,log,client,latest,after_verified):
            after_verified(s,m,r,connection,res,log)
        with patch.object(mouse.kms_handshake,'handshake',side_effect=fake):
            mouse.startup(session,None,None,{},None,client=object(),latest=5,
                          after_kms=lambda *args:calls.append(args))
        self.assertIs(session.kms_connection,connection)
        self.assertEqual(len(calls),1)

    def test_stage_deadline_end_is_not_reported_as_exchange_condition(self):
        s=self.session()
        s.stage_latest=10
        s.stop_reason=None
        with patch.object(mouse.long.LongSession,'wait',self.window):
            self.assertTrue(s.wait(30))
        self.assertEqual((s.stop_reason,s.sent),('stage_deadline',[]))

    def test_kms_frames_during_live_are_summarized_even_on_error(self):
        handshake=bytes.fromhex('0304000500 0305000500')
        for fail in (False,True):
            with self.subTest(fail=fail):
                connection=SimpleNamespace(received=bytearray(handshake))
                result={}
                def after(s,m,r,res,log):
                    connection.received+=bytes.fromhex('0305000500 0314000e0000')
                    if fail:raise RuntimeError('live failed')
                def fake(s,m,r,res,log,client,latest,after_verified):
                    after_verified(s,m,r,connection,res,log)
                with patch.object(mouse.kms_handshake,'handshake',side_effect=fake):
                    run=lambda:mouse.startup(SimpleNamespace(),None,None,result,None,
                                             client=object(),latest=5,after_kms=after)
                    if fail:
                        with self.assertRaisesRegex(RuntimeError,'live failed'):run()
                    else:run()
                self.assertEqual(result['kms_live_received'],dict(bytes=11,
                    packets=[dict(kind=5,bytes=5)],unparsed_bytes=6,error=None))
        self.assertEqual(mouse.received_summary(b'\x07\x05\x00\x05\x00',0)['error'],
                         'invalid frame header')


