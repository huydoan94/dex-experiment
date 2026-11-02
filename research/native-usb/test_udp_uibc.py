"""Run B UIBC: selection, packets, input FIFO, M14 setting, redaction, cleanup and wiring; synthetic phone, no USB/ADB."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

import idc_handshake
import rtsp_capabilities as caps
import rtsp_hello
import rtsp_udp_live as live
import rtsp_udp_long as long
import rtsp_udp_play as play
import rtsp_udp_uibc as uibc
import udp_uibc_launch as launch
import udp_uibc_probe as probe
import wfd_startup as wfd
from test_idc_handshake import KEY
from test_loopback_transfer import Device
from test_rtsp_capabilities import m4
from test_udp_capabilities import UDP_SELECTED
from test_udp_live import LivePhone
from test_usb_tunnel import UID
from tunnel_probe import Link,MAX_RECEIVE_BYTES

CAPABILITY=b"input_category_list=GENERIC;generic_cap_list=Keyboard, SingleTouch;hidc_cap_list=none;port=7239"
M4_UIBC=(UDP_SELECTED+b"wfd_audio_codecs: AAC 00000001 00\r\nwfd_uibc_capability: "+CAPABILITY+b"\r\n")
M14=(b"SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0\r\nCSeq: 9\r\nContent-Type: text/parameters\r\n"
     b"Content-Length: 26\r\n\r\nwfd_uibc_setting: enable\r\n")
VALUES={"wfd_video_formats":"00 00 02 04 00000080 00000000 00000000 00 0000 0000 00 none none",
        "wfd_client_rtp_ports":"RTP/AVP/UDP;unicast 46002 0 mode=play",
        "wfd_presentation_url":"rtsp://127.0.0.1/wfd1.0/streamid=0 none",
        "wfd_audio_codecs":"AAC 00000001 00","wfd_uibc_capability":CAPABILITY.decode()}
INPUT=b"T d 1234 567\nT m 1240 570\nT m 1250 575\nT u 1250 575\nK d 65\nK u 65\nbogus\nT d 1920 5\n"


class FakeSink:
    def __init__(self):self.data,self.error=[],None
    def put(self,data):self.data.append(bytes(data))
    def summary(self):return dict(chunks=len(self.data))


class UibcPhone(LivePhone):
    def __init__(self,body=M4_UIBC+b"wfd_uibc_setting: enable\r\n",**kwargs):
        super().__init__(**kwargs)
        self.next_message=m4(body)


def run(phone,tmp,input_bytes=INPUT):
    result,events=[{}],[]
    fifo=Path(tmp)/"input.fifo"
    os.mkfifo(fifo,0o600)
    # A held read-write end keeps queued lines readable however the probe opens it.
    holder=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
    os.write(holder,input_bytes)
    link=Link(Device(phone),TimeoutError,max_requests=200,
              record=lambda *args:(_ for _ in ()).throw(AssertionError("raw recorder not replaced")))
    session=uibc.UibcSession(link,1,65536,65536,sink=FakeSink(),stop_file=Path(tmp)/"stop",
                             input_fifo=fifo,clock=phone.clock,
                             log=uibc.UibcLog(lambda event,**kw:events.append(dict(event=event,**kw))))
    session.get_version();session.exchange(0,tcp_send_buffer_bytes=0)
    session.open_config(256,UID,15000)
    main=session.connect(40000)
    callback=lambda *args:wfd.startup(*args,confirm=lambda *a:phone.tap(),
        after_rtsp=lambda *a:rtsp_hello.exchange(*a,after_query=lambda *b:
            caps.exchange(*b,profile=uibc.UIBC_PROFILE,after_selection=uibc.exchange)))
    try:
        idc_handshake.handshake(session,main,KEY,result[0],after_handshake=callback)
    except Exception as error:
        result[0]["error"]=str(error)
    finally:
        os.close(holder)
    return result[0],events,session


def expected_packets():
    return (uibc.touch_packet(b"d",1234,567)+uibc.touch_packet(b"m",1250,575)
            +uibc.touch_packet(b"u",1250,575)+uibc.key_packet(b"d",65)+uibc.key_packet(b"u",65))


class Tests(unittest.TestCase):
    def setUp(self):
        for target,values in ((play,live.BASE),):
            patcher=patch.multiple(target,**values);patcher.start();self.addCleanup(patcher.stop)
        for target,name,value in ((live,"MAX_KEEPALIVES",long.BASE_KEEPALIVES),
                                  (live,"KEEPALIVE_SLICE_SECONDS",uibc.BASE_SLICE_SECONDS),
                                  (caps,"selection_compatible",long._PINNED_SELECTION),
                                  (caps,"selected_parameters",uibc._PINNED_SELECTED),
                                  (long,"CAP_SECONDS",2)):
            patcher=patch.object(target,name,value);patcher.start();self.addCleanup(patcher.stop)
        profile=patch.object(probe.cap,"PROFILE",dict(probe.cap.PROFILE))
        profile.start();self.addCleanup(profile.stop)
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.tmp=tmp.name

    def test_apply_patches_selection_export_and_slice_and_refuses_changed_base(self):
        uibc.apply();uibc.apply()
        self.assertIs(caps.selection_compatible,uibc.selection_compatible)
        self.assertIs(caps.selected_parameters,uibc.selected_parameters)
        self.assertEqual(live.KEEPALIVE_SLICE_SECONDS,.05)
        self.assertEqual(play.MEDIA_SECONDS,long.LONG["MEDIA_SECONDS"])
        for target,name,value in ((live,"KEEPALIVE_SLICE_SECONDS",1.0),
                                  (caps,"selected_parameters",lambda m:({},[]))):
            with patch.object(target,name,value):
                with self.assertRaisesRegex(RuntimeError,"pinned base"):uibc.apply()

    def test_uibc_selection_accepts_only_the_advertised_generic_entry(self):
        self.assertIsNone(uibc.uibc_selection("none"))
        self.assertEqual(uibc.uibc_selection(CAPABILITY.decode()),
                         dict(generic=["Keyboard","SingleTouch"],port=7239))
        self.assertEqual(uibc.uibc_selection(CAPABILITY.decode().replace("Keyboard, ","")),
                         dict(generic=["SingleTouch"],port=7239))
        good=CAPABILITY.decode()
        for value in (good.replace("GENERIC","HIDC"),good.replace("SingleTouch","Mouse"),
                      good.replace("hidc_cap_list=none","hidc_cap_list=Keyboard/USB"),
                      good.replace("port=7239","port=none"),good.replace("port=7239","port=0"),
                      good.replace("port=7239","port=70000"),good+";port=1",
                      good.replace("SingleTouch","Keyboard"),good.replace(";hidc_cap_list=none","")):
            self.assertIs(uibc.uibc_selection(value),False,value)

    def test_selection_and_export_handle_uibc_and_setting(self):
        for setting in (None,"enable","disable"):
            values=dict(VALUES) if setting is None else dict(VALUES,wfd_uibc_setting=setting)
            self.assertTrue(uibc.selection_compatible(values,uibc.UIBC_PROFILE))
        self.assertFalse(uibc.selection_compatible(dict(VALUES,wfd_uibc_setting="maybe"),uibc.UIBC_PROFILE))
        self.assertFalse(uibc.selection_compatible(dict(VALUES,wfd_uibc_capability="input_category_list=HIDC"),
                                                   uibc.UIBC_PROFILE))
        self.assertFalse(uibc.selection_compatible(dict(VALUES,wfd_audio_codecs="LPCM 00000001 00"),
                                                   uibc.UIBC_PROFILE))
        # Run A's profile still refuses any UIBC selection.
        self.assertFalse(uibc.selection_compatible(VALUES,long.AUDIO_UDP_PROFILE))
        message=dict(kind="request",method="SET_PARAMETER",uri="rtsp://localhost/wfd1.0",
                     headers={"content-type":"text/parameters"},
                     body=M4_UIBC+b"wfd_uibc_setting: enable\r\n")
        values,names=uibc.selected_parameters(message)
        self.assertEqual((values["wfd_uibc_setting"],values["wfd_uibc_capability"]),("enable",CAPABILITY.decode()))
        message["body"]=M4_UIBC+b"wfd_uibc_setting: sometimes\r\n"
        self.assertNotIn("wfd_uibc_setting",uibc.selected_parameters(message)[0])

    def test_generic_packets_match_wfd_layout(self):
        self.assertEqual(uibc.touch_packet(b"d",0x0102,0x0304),bytes.fromhex("0000000d"+"00"+"0006"+"0100"+"0102"+"0304"))
        self.assertEqual(uibc.touch_packet(b"m",1,2)[4],2)
        self.assertEqual(uibc.touch_packet(b"u",1,2)[4],1)
        self.assertEqual(uibc.key_packet(b"d",0x41),bytes.fromhex("0000000c"+"03"+"0005"+"00"+"0041"+"0000"))
        self.assertEqual(uibc.key_packet(b"u",0x41)[4],4)

    def test_input_reader_validates_coalesces_and_refuses_regular_files(self):
        regular=Path(self.tmp)/"regular";regular.write_bytes(b"T d 1 1\n")
        with self.assertRaisesRegex(RuntimeError,"not a FIFO"):uibc.InputReader(regular)
        fifo=Path(self.tmp)/"in.fifo";os.mkfifo(fifo,0o600)
        holder=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
        try:
            reader=uibc.InputReader(fifo)
            self.assertEqual(reader.events(),[])
            os.write(holder,INPUT+b"T m 1 1\nT m 2 2\nT m 3 3\nK d 128\nK d 0\nT d 5 1080\nT d 5")
            self.assertEqual(reader.events(),[("T",b"d",1234,567),("T",b"m",1250,575),("T",b"u",1250,575),
                                              ("K",b"d",65,0),("K",b"u",65,0),("T",b"m",3,3)])
            self.assertEqual(reader.counts,{"invalid":5,"coalesced":3})
            os.write(holder,b" 6\n"+b"x"*100)
            self.assertEqual(reader.events(),[("T",b"d",5,6)])
            self.assertEqual(reader.counts["invalid"],6)
            reader.close();reader.close()
        finally:
            os.close(holder)

    def test_m4_uibc_connects_after_play_and_sends_validated_input_then_closes(self):
        uibc.apply()
        phone=UibcPhone(count=30)
        result,events,session=run(phone,self.tmp)
        self.assertNotIn("error",result)
        self.assertEqual(result["uibc_selection"],dict(generic=["Keyboard","SingleTouch"],port=7239))
        self.assertEqual(result["uibc_setting_m4"],"enable")
        sent=b"".join(data for config,_,data in phone.host_data if config==uibc.UIBC_CONFIG)
        self.assertEqual(sent,expected_packets())
        summary=result["uibc"]
        self.assertTrue(summary["connected"] and summary["enabled"])
        self.assertEqual(summary["sent"],{"Td":1,"Tm":1,"Tu":1,"Kd":1,"Ku":1})
        self.assertEqual(summary["input"],{"invalid":2,"coalesced":1})
        self.assertEqual((result["uibc_disconnect_status"],result["uibc_close_status"],result["uibc_cleanup_errors"]),
                         (0,0,[]))
        self.assertEqual(result["live"]["stop_reason"],"cap")
        # The PLAY happens before the UIBC connect.
        play_sent=next(i for i,e in enumerate(events) if e["event"]=="usb_raw"
                       and b"PLAY rtsp://".hex() in e["bytes_hex"])
        self.assertLess(play_sent,[e["event"] for e in events].index("uibc_connect"))
        # Neither the input text nor the UIBC packets reach any saved record.
        saved=json.dumps(dict(result=result,events=events))
        for packet in (uibc.touch_packet(b"d",1234,567),uibc.key_packet(b"d",65)):
            self.assertNotIn(packet.hex(),saved)
        self.assertNotIn("T d 1234",saved)
        self.assertTrue(any(e.get("redacted")=="uibc_input" for e in events))

    def test_disabled_m4_waits_for_m14_enable_which_is_answered(self):
        uibc.apply()
        phone=UibcPhone(body=M4_UIBC+b"wfd_uibc_setting: disable\r\n",count=30,after_play=M14)
        result,events,session=run(phone,self.tmp)
        self.assertNotIn("error",result)
        self.assertIn(b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n",phone.rtsp_sent)
        self.assertEqual(result["uibc"]["settings"],["enable"])
        sent=b"".join(data for config,_,data in phone.host_data if config==uibc.UIBC_CONFIG)
        self.assertEqual(sent,expected_packets())

    def test_disabled_uibc_drops_input_and_no_uibc_never_connects(self):
        uibc.apply()
        phone=UibcPhone(body=M4_UIBC+b"wfd_uibc_setting: disable\r\n",count=30)
        result,events,session=run(phone,self.tmp)
        self.assertNotIn("error",result)
        self.assertEqual(result["uibc"]["dropped"],{"disabled":5})
        self.assertFalse(any(config==uibc.UIBC_CONFIG for config,_,_ in phone.host_data))
        with tempfile.TemporaryDirectory() as tmp:
            phone=UibcPhone(body=UDP_SELECTED+b"wfd_audio_codecs: AAC 00000001 00\r\n",count=30)
            result,events,session=run(phone,tmp)
        self.assertNotIn("error",result)
        self.assertIsNone(result["uibc_selection"])
        self.assertFalse(result["uibc"]["attempted"])
        self.assertNotIn("uibc_close_status",result)

    def test_uibc_log_redacts_only_uibc_out_data(self):
        written=[]
        log=uibc.UibcLog(lambda event,**kw:written.append(kw))
        def frame(config):
            body=(6).to_bytes(4,"little")+config.to_bytes(4,"little")+bytes(28)+b"SECRET-KEYS"
            return (b"CONN"+(5).to_bytes(4,"little")+(20+len(body)).to_bytes(4,"little")
                    +(1).to_bytes(4,"little")+(7).to_bytes(4,"little")+body)
        log("usb_raw",direction="out",bytes_hex=frame(uibc.UIBC_CONFIG).hex())
        log("usb_raw",direction="out",bytes_hex=frame(1204).hex())
        self.assertNotIn(b"SECRET-KEYS".hex(),written[0]["bytes_hex"])
        self.assertEqual((written[0]["uibc_payload_bytes"],written[0]["redacted"]),(11,"uibc_input"))
        self.assertIn(b"SECRET-KEYS".hex(),written[1]["bytes_hex"])

    def test_owner_builds_uibc_session_with_redacting_log(self):
        owner=uibc.UibcOwner(SimpleNamespace(),{},FakeSink(),Path(self.tmp)/"stop",Path(self.tmp)/"in.fifo")
        session=owner.session(Link(Device(LivePhone()),TimeoutError),1,65536,MAX_RECEIVE_BYTES,
                              clock=time.monotonic,log=lambda *a,**k:None)
        self.assertIsInstance(session,uibc.UibcSession)
        self.assertIsInstance(session.log,uibc.UibcLog)
        self.assertEqual(session.input_fifo,Path(self.tmp)/"in.fifo")
        self.assertEqual(session.max_receive_bytes,long.LONG_RECEIVE_BYTES)

    def test_probe_plan_and_wiring_use_uibc_owner_profile_and_fifos(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        seen={}
        def fake_probe(device,owner,timeout,out,result,**kwargs):
            seen.update(owner=owner,max_requests=kwargs["max_requests"],after_auth=kwargs["after_auth"])
            result.update(ui_tap_command_succeeded=True,wfd_startup_verified=True,rtp_media_verified=True)
        tmp=self.tmp
        with patch.dict(os.environ,{"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),\
                patch.dict("sys.modules",{"usb":usb,"usb.core":core,"usb.util":util}),\
                patch.object(probe.auth_probe,"probe",side_effect=fake_probe),\
                patch.object(probe.live_sink,"TsSink") as sink_class,contextlib.redirect_stdout(io.StringIO()):
            sink_class.return_value.start.return_value=sink_class.return_value
            sink_class.return_value.summary.return_value={"opened":True,"forwarded_bytes":1316}
            self.assertEqual(probe.main(["--approved-phone-udp-uibc","--accept-persistent-state",
                "--bus","3","--address","13","--output",tmp+"/new","--ts-fifo",tmp+"/ts.fifo",
                "--stop-file",tmp+"/stop","--input-fifo",tmp+"/input.fifo"]),0)
            plan=json.loads(Path(tmp+"/new/plan.json").read_text())
        self.assertIsInstance(seen["owner"],uibc.UibcOwner)
        self.assertEqual((seen["owner"].stop_file,seen["owner"].input_fifo),(Path(tmp+"/stop"),Path(tmp+"/input.fifo")))
        self.assertEqual(seen["max_requests"],40+8+48+8+4+18000)
        self.assertEqual(plan["diagnostic_wfd_profile"]["wfd_uibc_capability"],uibc.UIBC_CAPABILITY)
        self.assertEqual(plan["diagnostic_wfd_profile"]["wfd_audio_codecs"],"AAC 00000001 00")
        self.assertEqual((plan["input_saved"],plan["max_input_sends"],plan["outer_seconds"]),("counts_only",18000,990))
        # after_auth wires the UIBC profile and exchange into the M3/M4 chain.
        chain={}
        def fake_handshake(session,connection,key,result,log,after_handshake):
            chain["after_rtsp"]=after_handshake.keywords["after_rtsp"]
        client=SimpleNamespace(codec=lambda:SimpleNamespace(_key=KEY))
        with patch.object(probe.cap,"capabilities"),patch.object(probe.pss_probe,"pss_ready"),\
                patch.object(probe.idc_handshake,"handshake",side_effect=fake_handshake):
            seen["after_auth"](None,None,client,{},None,None)
        query=chain["after_rtsp"].keywords["after_query"]
        self.assertIs(query.keywords["profile"],uibc.UIBC_PROFILE)
        self.assertIs(query.keywords["after_selection"].func,uibc.exchange)

    def test_launch_requires_input_fifo_beside_media_fifo_and_execs_uibc_probe(self):
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[SimpleNamespace(bus=3,address=13)]
        usb.core=core
        tmp=self.tmp
        with patch.dict("sys.modules",{"usb":usb,"usb.core":core}),patch.object(launch,"require_adb_server"),\
                patch.object(launch.os,"execv") as execute,contextlib.redirect_stdout(io.StringIO()):
            fifo=Path(tmp)/"ts.fifo";os.mkfifo(fifo,0o600)
            base=["--approved-phone-udp-uibc","--accept-persistent-state","--output",tmp+"/new",
                  "--ts-fifo",str(fifo),"--stop-file",tmp+"/stop"]
            regular=Path(tmp)/"input.fifo";regular.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError,"input-fifo"):
                launch.main(base+["--input-fifo",str(regular)])
            regular.unlink()
            with tempfile.TemporaryDirectory() as other:
                elsewhere=Path(other)/"input.fifo";os.mkfifo(elsewhere,0o600)
                with self.assertRaisesRegex(RuntimeError,"input-fifo"):
                    launch.main(base+["--input-fifo",str(elsewhere)])
            os.mkfifo(regular,0o600)
            execute.assert_not_called()
            launch.main(base+["--input-fifo",str(regular)])
            args=execute.call_args.args[1]
        self.assertIn("research/native-usb/udp_uibc_probe.py",args)
        self.assertEqual(args[-2:],["--input-fifo",str(regular)])
        for name in ("rtsp_udp_uibc.py","udp_uibc_probe.py","rtsp_udp_long.py","rtsp_udp_live.py"):
            self.assertIn(name,launch.EXPECTED)
        self.assertNotIn("udp_long_probe.py",launch.EXPECTED)

if __name__=="__main__":unittest.main()
