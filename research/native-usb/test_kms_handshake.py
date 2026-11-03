"""Focused KMS discovery tests with synthetic sessions only."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import kms_handshake as kms
import kms_handshake_launch as launch
import kms_handshake_probe as probe


class Codec:
    def encrypt(self,obj):
        self.request=obj
        return b"encrypted"


class Session:
    def __init__(self,payload=bytes.fromhex("03 05 00 05 00"),fail=None):
        self.now=1
        self.payload=payload
        self.fail=fail
        self.configs={}
        self.connections={}
        self.usb_buffer_bytes=1024
        self.calls=[]
        self.link=SimpleNamespace(begin_cleanup=lambda:self.calls.append("link_cleanup"))
    def clock(self):
        return self.now
    def send(self,connection,wire,**kwargs):
        self.calls.append(("send",connection,wire))
        if self.fail=="send":
            raise RuntimeError("send failed")
    def wait(self,seconds,until):
        self.now+=seconds
        if self.connections:
            connection=next(iter(self.connections.values()))
            connection.received.extend(self.payload)
        return until()
    def open_config(self,config,uid,port,**kwargs):
        self.calls.append(("open",config,port))
        self.configs[config]=object()
        if self.fail=="open":
            raise RuntimeError("open failed")
    def connect(self,host_port,config_id,**kwargs):
        connection=SimpleNamespace(config_id=config_id,host_port=host_port,
                                   received=bytearray(),closed_by_phone=False)
        self.connections[host_port]=connection
        self.calls.append(("connect",host_port,config_id))
        if self.fail=="connect":
            raise RuntimeError("connect failed")
        return connection
    def begin_cleanup(self):
        self.calls.append("cleanup")
    def disconnect(self,connection):
        self.calls.append(("disconnect",connection.host_port))
        if self.fail=="disconnect":
            raise RuntimeError("disconnect failed")
        return 0
    def close_config(self,uid,config_id):
        self.calls.append(("close",config_id))
        return 1 if self.fail=="close" else 0


def run(session,latest=10,main_closed=False):
    codec=Codec()
    client=SimpleNamespace(codec=lambda:codec)
    main=SimpleNamespace(closed_by_phone=main_closed)
    rtsp=SimpleNamespace(closed_by_phone=False)
    result={}
    try:
        kms.handshake(session,main,rtsp,result,lambda **kw:None,client=client,latest=latest)
    except Exception as error:
        return result,codec,error
    return result,codec,None


class Tests(unittest.TestCase):
    def test_confirm_and_heartbeat_sent_once_after_encrypted_kms_start(self):
        session=Session()
        result,codec,error=run(session)
        self.assertIsNone(error)
        self.assertTrue(result["kms_handshake_verified"])
        self.assertEqual(codec.request,{"TYPE":"REQ","MSG":"ChangeKMSState",
                                        "PARAM":{"KMS_STATE":1}})
        sends=[c for c in session.calls if isinstance(c,tuple) and c[0]=="send"]
        self.assertEqual(len(sends),3)
        self.assertEqual([x[2] for x in sends[1:]],[bytes.fromhex("03 04 00 05 00"),bytes.fromhex("03 01 00 05 00")])
        self.assertTrue(all(x[1].config_id==1208 for x in sends[1:]))
        self.assertEqual(sends[0][2],bytes.fromhex("00 00 00 09 00 00 00 06")+b"encrypted")
        self.assertIn(("open",1208,30830),session.calls)
        self.assertEqual(session.calls[-2:],[("disconnect",50008),("close",1208)])
        self.assertEqual(result["kms_application_packets_sent"],2)
        self.assertEqual(result["kms_received_packets"],[{"kind":5,"bytes":5}])

    def test_bad_first_packet_or_trailing_frame_fails_and_cleans(self):
        for data in (b"",b"\x03\x04",bytes.fromhex("03 5a 00 05 00"),
                     bytes.fromhex("03 05 00 05 00")+b"x",b"x"*513):
            with self.subTest(data=data[:6]):
                session=Session(payload=data)
                result,codec,error=run(session)
                self.assertIsNotNone(error)
                self.assertFalse(result["kms_handshake_verified"])
                self.assertIn(("close",1208),session.calls)

    def test_fragmented_heartbeat_and_coalesced_metadata(self):
        class Fragmented(Session):
            def wait(self,seconds,until):
                if not self.connections:
                    self.now+=seconds
                    return until()
                connection=next(iter(self.connections.values()))
                for chunk in [b"\x03",b"\x01\x00\x05\x00\x03\x05",b"\x00\x05\x00"]:
                    self.now+=.01
                    connection.received.extend(chunk)
                    if until():return True
                self.now+=seconds
                return until()
        session=Fragmented()
        result,codec,error=run(session)
        self.assertIsNone(error)
        self.assertEqual(result["kms_received_packets"],[{"kind":1,"bytes":5},{"kind":5,"bytes":5}])
        # Incoming heartbeat request is recorded; no automatic application reply.
        self.assertEqual(len([c for c in session.calls if isinstance(c,tuple) and c[0]=="send"]),3)

    def test_malformed_length_version_heartbeat_and_packet_count_refused(self):
        for payload in [bytes.fromhex("03 05 00 03"),bytes.fromhex("02 05 00 05 00"),
                        bytes.fromhex("03 05 00 05 01"),bytes.fromhex("03 01 00 05 00")*17,
                        bytes.fromhex("03 05 02 01")]:
            with self.subTest(payload=payload[:8]):
                session=Session(payload=payload)
                result,codec,error=run(session)
                self.assertIsNotNone(error)
                self.assertFalse(result["kms_handshake_verified"])
                self.assertEqual(session.calls[-2:],[("disconnect",50008),("close",1208)])

    def test_failed_confirmation_never_sends_heartbeat_or_retries(self):
        class FailedConfirmation(Session):
            def send(self,connection,wire,**kwargs):
                super().send(connection,wire,**kwargs)
                if getattr(connection,"config_id",None)==1208:
                    raise RuntimeError("confirmation failed")
        session=FailedConfirmation()
        result,codec,error=run(session)
        self.assertEqual(str(error),"confirmation failed")
        sends=[c for c in session.calls if isinstance(c,tuple) and c[0]=="send"]
        self.assertEqual(len(sends),2)
        self.assertEqual(sends[-1][2],bytes.fromhex("03 04 00 05 00"))
        self.assertIn(("close",1208),session.calls)

    def test_invalid_data_during_confirmation_prevents_heartbeat(self):
        for payload in [b"x"*513, bytes.fromhex("03 05 00 03"),
                        bytes.fromhex("03 01 00 05 00")*17]:
            with self.subTest(payload=payload[:8]):
                class DataDuringConfirmation(Session):
                    def send(self,connection,wire,**kwargs):
                        super().send(connection,wire,**kwargs)
                        if getattr(connection,"config_id",None)==1208:
                            connection.received.extend(payload)
                session=DataDuringConfirmation()
                result,codec,error=run(session)
                self.assertIsNotNone(error)
                sends=[c for c in session.calls if isinstance(c,tuple) and c[0]=="send"]
                self.assertEqual(len(sends),2)
                self.assertEqual(result["kms_application_packets_sent"],1)
                self.assertEqual(session.calls[-2:],[("disconnect",50008),("close",1208)])

    def test_send_failure_does_not_connect(self):
        session=Session(fail="send")
        result,codec,error=run(session)
        self.assertEqual(str(error),"send failed")
        self.assertTrue(result["kms_start_attempted"])
        self.assertFalse(session.configs)

    def test_open_failure_closes_unconfirmed_config(self):
        session=Session(fail="open")
        result,codec,error=run(session)
        self.assertEqual(str(error),"open failed")
        self.assertIn(("close",1208),session.calls)

    def test_connect_timeout_attempts_retained_connection_cleanup(self):
        session=Session(fail="connect")
        result,codec,error=run(session)
        self.assertEqual(str(error),"connect failed")
        self.assertEqual(session.calls[-2:],[("disconnect",50008),("close",1208)])

    def test_disconnect_failure_still_closes_config(self):
        session=Session(fail="disconnect")
        result,codec,error=run(session)
        self.assertEqual(str(error),"disconnect failed")
        self.assertIn(("close",1208),session.calls)
        self.assertEqual(len(result["kms_cleanup_errors"]),1)

    def test_failed_config_close_fails_run(self):
        result,codec,error=run(Session(fail="close"))
        self.assertIsNotNone(error)
        self.assertTrue(result["kms_handshake_verified"])
        self.assertEqual(result["kms_close_status"],1)

    def test_expired_or_closed_main_sends_nothing(self):
        for latest,closed in ((1,False),(10,True),(1.1,False)):
            with self.subTest(latest=latest,closed=closed):
                session=Session()
                result,codec,error=run(session,latest=latest,main_closed=closed)
                self.assertIsNotNone(error)
                self.assertFalse(session.configs)

    def test_plan_only_does_not_check_adb_or_select_usb(self):
        with patch.object(launch.socket,"create_connection",
                          side_effect=AssertionError("ADB check")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(launch.main([]),0)
            self.assertEqual(probe.main([]),0)

    def test_pinned_sources_and_tamper_rejection(self):
        launch.verify_sources(Path(__file__).parent)
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)
            for name in launch.EXPECTED:
                (target/name).write_bytes((Path(__file__).parent/name).read_bytes())
            (target/"kms_handshake.py").write_text("changed")
            with self.assertRaisesRegex(RuntimeError,"source mismatch"):
                launch.verify_sources(target)

    def test_real_session_constructor_with_callable_raw_recorder(self):
        from tunnel_probe import Link
        from conn_transfer import TransferDecoder
        recorded=[]
        recorder=lambda *args:recorded.append(args)
        link=Link(object(),TimeoutError,record=recorder)
        session=probe.DiscoverySession(link,1,65536,65536)
        self.assertIsInstance(session.decoder,TransferDecoder)
        self.assertIs(link.record,recorder)
        self.assertEqual(recorded,[])

    def test_callback_uses_display0_confirmation_and_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"out"
            session=Session()
            main=SimpleNamespace(closed_by_phone=False)
            codec=SimpleNamespace(_key=b"k"*32)
            client=SimpleNamespace(codec=lambda:codec)
            calls=[]
            def auth_probe(device,util,timeout,out,result,**kwargs):
                self.assertIs(kwargs["session_class"],probe.DiscoverySession)
                kwargs["after_auth"](session,main,client,result,session.clock,lambda **k:None)
                result["kms_handshake_verified"]=True
            def handshake(s,m,key,r,log,after_handshake):
                self.assertEqual(key,b"k"*32)
                after_handshake(s,m,key,r,log)
            def startup(s,m,key,r,log,confirm,after_rtsp):
                confirm(s,m,r,log,70)
                after_rtsp(s,m,SimpleNamespace(closed_by_phone=False),r,log)
            fakeusb=SimpleNamespace(core=SimpleNamespace(
                find=lambda **k:[object()],USBTimeoutError=TimeoutError),util=object())
            import sys
            with patch.dict(sys.modules,{"usb":fakeusb,"usb.core":fakeusb.core,
                                         "usb.util":fakeusb.util}),\
                 patch.dict(probe.os.environ,{"DEX_AUTO_UI_DEADLINE":"75"}),\
                 patch.object(probe.time,"monotonic",return_value=1),\
                 patch.object(probe.signal,"signal"),\
                 patch.object(probe.cap,"capabilities"),\
                 patch.object(probe.pss_probe,"pss_ready"),\
                 patch.object(probe.auth_probe,"probe",side_effect=auth_probe),\
                 patch.object(probe.idc_handshake,"handshake",side_effect=handshake),\
                 patch.object(probe.wfd,"startup",side_effect=startup),\
                 patch.object(probe.ui,"confirm",side_effect=lambda *a:calls.append("display0")),\
                 patch.object(probe.kms_handshake,"handshake",side_effect=lambda *a,**k:
                              calls.append(("discovery",k["client"] is client))),\
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(["--approved-phone-kms-handshake",
                    "--accept-persistent-state","--bus","3","--address","4",
                    "--output",str(output)]),0)
            self.assertEqual(calls,["display0",("discovery",True)])


if __name__=="__main__":
    unittest.main()
