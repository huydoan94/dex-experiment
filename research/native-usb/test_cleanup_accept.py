"""Replay observed cleanup race; final main-close response is explicitly synthetic."""
from pathlib import Path
import json
import struct
import unittest

from conn_frames import Decoder, Frame, encode
import tcp_control as tcp
import usb_tunnel
from usb_tunnel import Session, Config, Connection, TunnelError
from test_usb_tunnel import CannedLink, UID


class Tests(unittest.TestCase):
    def test_observed_late_connect_does_not_desynchronize_cleanup(self):
        fixture = json.loads(Path(__file__).with_name("fixtures").joinpath(
            "rtsp-cleanup-20261102.json").read_text())
        # Live capture ends before this final reply; do not call it live evidence.
        last_reply = encode(Frame(21,2,801837119,struct.pack("<I",0)))
        link = CannedLink(bytes.fromhex(fixture["observed_in_hex"])+last_reply)
        logs = []
        session = Session(link,801837117,65536,65536,clock=link.clock,
                          accept_inbound=True,log=lambda event,**kw: logs.append((event,kw)))
        session.usb_buffer_bytes = 4095
        session.configs = {580:Config(580,15000,2),1201:Config(1201,46001,1)}
        main = Connection(1028,42195,580)
        session.connections[42195] = main
        session.begin_cleanup()
        self.assertEqual(session.close_config(UID,config_id=1201),0)
        self.assertEqual(session.disconnect(main),0)
        self.assertEqual(session.close_config(UID,config_id=580),0)
        frames = Decoder(65536).feed(bytes(link.written))
        self.assertEqual([(f.command,f.kind) for f in frames],[(21,1),(3,2),(4,1),(21,1)])
        self.assertEqual(encode(frames[1]),bytes.fromhex(fixture["expected_reject_hex"]))
        self.assertEqual([f.transaction for f in frames],[801837117,71,801837118,801837119])
        self.assertEqual(session.connections,{})
        self.assertEqual(session.configs,{})
        self.assertEqual(session.inbound_count,1)
        self.assertTrue(any(event=="inbound_rejected_cleanup" for event,_ in logs))
        self.assertNotIn("inbound_connected",[event for event,_ in logs])

    def test_late_announcement_after_listener_close_is_refused(self):
        late = Frame(3,1,71,struct.pack("<I16sI",1201,bytes(16),1032))
        reply = Frame(4,2,10,struct.pack("<I",0))
        link = CannedLink(encode(late)+encode(reply))
        session = Session(link,10,65536,65536,clock=link.clock,accept_inbound=True)
        session.usb_buffer_bytes=4095
        session.configs={580:Config(580,15000,2)}
        session.retired_listeners.add(1201)
        main=Connection(1028,42195,580); session.connections[42195]=main
        session.begin_cleanup()
        self.assertEqual(session.disconnect(main),0)
        self.assertEqual(len(session.connections),0)

    def test_duplicate_wrong_listener_and_limit_remain_errors(self):
        link=CannedLink(b"")
        session=Session(link,1,65536,65536,clock=link.clock,accept_inbound=True)
        session.configs={1201:Config(1201,46001,1)}
        session.begin_cleanup()
        def announce(cfg=1201,key=1032,transaction=71):
            session._phone_request(Frame(3,1,transaction,struct.pack("<I16sI",cfg,bytes(16),key)))
        announce()
        with self.assertRaisesRegex(TunnelError,"already used"):
            announce()
        with self.assertRaises(ValueError):
            announce(cfg=1202,key=1033)
        session.rejected_inbound_keys.update(range(5000,5000+usb_tunnel.MAX_ACTIVE_INBOUND))
        with self.assertRaisesRegex(TunnelError,"count exceeded"):
            announce(key=1034)
        self.assertEqual(len(Decoder(65536).feed(bytes(link.written))),1)
        self.assertEqual(session.connections,{})

    def test_failure_reply_layout_and_argument_validation(self):
        frame=tcp.inbound_connect_reject(71,1201)
        self.assertEqual(len(encode(frame)),52)
        self.assertEqual(struct.unpack("<III16sI",frame.body),
                         (1,0,1201,b"127.0.0.1".ljust(16,b"\0"),0))
        for args in ((0,1201),(71,0)):
            with self.assertRaises(ValueError):
                tcp.inbound_connect_reject(*args)

    def test_failed_refusal_write_remains_a_failure(self):
        class Failing(CannedLink):
            def write(self,*args):
                raise TimeoutError("failed refusal")
        link=Failing(b"")
        session=Session(link,1,65536,65536,clock=link.clock,accept_inbound=True)
        session.configs={1201:Config(1201,46001,1)}
        session.begin_cleanup()
        with self.assertRaisesRegex(TimeoutError,"failed refusal"):
            session._phone_request(Frame(3,1,71,struct.pack("<I16sI",1201,bytes(16),1032)))
        self.assertEqual(session.connections,{})
