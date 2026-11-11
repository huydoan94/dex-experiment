"""Focused path, schedule, notice-decoding and pin checks; no phone or real ADB server."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kms_hover_live as hover
import kms_mouse_live as mouse
import sidesync_packets


def common(message,response=False):
    raw=json.dumps(message,separators=(',',':')).encode()
    base=0x67 if response else 0x64
    return (sidesync_packets.encode(base,bytes(16))+sidesync_packets.encode(base+1,raw)
            +sidesync_packets.encode(base+2,b''))


class Tests(unittest.TestCase):
    def test_path_stays_on_screen_and_is_slower_than_wait_slices(self):
        self.assertEqual(len(hover.MOVES),35)
        for at,x,y in hover.MOVES:
            self.assertTrue(0<=x<1920 and 0<=y<1080,(x,y))
        times=[at for at,_,_ in hover.MOVES]
        self.assertEqual(times[0],3)
        self.assertTrue(all(b-a>=.4-1e-9 for a,b in zip(times,times[1:])))
        self.assertLess(times[-1],mouse.CAP_SECONDS-5)

    def test_every_point_sent_once_in_order_as_hover_event0(self):
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
        def window(session,seconds,until):
            session.window_armed=False
            for step in range(0,151):
                session.now=10+step*.2
                if until():return True
            return False
        with patch.object(mouse,'MOVES',mouse.MOVES),\
             patch.object(mouse.long,'CAP_SECONDS',mouse.long.CAP_SECONDS),\
             patch.object(mouse.long,'LONG',dict(mouse.long.LONG)),\
             patch.object(mouse.long,'LONG_KEEPALIVES',mouse.long.LONG_KEEPALIVES):
            hover.configure()
            with patch.object(mouse.long.LongSession,'wait',window):
                s.wait(30)
        self.assertEqual(s.sent,[sidesync_packets.mouse_event(0,x,y) for _,x,y in hover.MOVES])
        self.assertEqual(s.sent[0],bytes.fromhex('03 14 00 0e 00 00 00 00 00 14 00 00 04 1f'))

    def test_notices_keep_type_msg_and_only_cursor_params(self):
        handshake=bytes.fromhex('0304000500 0305000500')
        data=(handshake+common({'TYPE':'REQ','MSG':'FeatureList'})
              +common({'TYPE':'NOTI','MSG':'StartStreaming','PARAM':{'info':1}})
              +common({'TYPE':'NOTI','MSG':'MOUSE_CURSOR_CHANGE',
                       'PARAM':{'MOUSE_CURSOR_ID':1016,'IS_NIGHT_MODE':False}},response=True)
              +sidesync_packets.encode(0x64,bytes(16))+sidesync_packets.encode(0x65,b'\xff{')
              +sidesync_packets.encode(0x66,b'')+sidesync_packets.encode(0x33,bytes(9))+b'\x03')
        got=hover.notices(data,len(handshake))
        self.assertIsNone(got['error'])
        self.assertEqual([(n.get('MSG'),n.get('PARAM'),n['response'],n['decoded'])
                          for n in got['notices']],
                         [('FeatureList',None,False,True),('StartStreaming',None,False,True),
                          ('MOUSE_CURSOR_CHANGE',{'MOUSE_CURSOR_ID':1016,'IS_NIGHT_MODE':False},True,True),
                          (None,None,False,False)])
        self.assertEqual(got['notices'][0]['bytes'],34)
        self.assertEqual(hover.notices(b'\x07\x64\x00\x05\x00',0)['error'],'invalid frame header')

    def test_notices_recorded_after_live_error(self):
        connection=SimpleNamespace(received=bytearray(bytes.fromhex('0304000500 0305000500')))
        result={}
        def after(s,m,r,res,log):
            connection.received+=common({'TYPE':'NOTI','MSG':'StartStreaming','PARAM':{'info':2}})
            raise RuntimeError('live failed')
        def fake(s,m,r,res,log,client,latest,after_verified):
            after_verified(s,m,r,connection,res,log)
        with patch.object(mouse.kms_handshake,'handshake',side_effect=fake):
            with self.assertRaisesRegex(RuntimeError,'live failed'):
                hover.startup(SimpleNamespace(),None,None,result,None,client=object(),
                              latest=5,after_kms=after)
        self.assertEqual([n['MSG'] for n in result['kms_live_notices']['notices']],['StartStreaming'])
        self.assertEqual(result['kms_live_received']['packets'][0],dict(kind=0x64,bytes=20))




if __name__=='__main__':
    unittest.main()
