"""Long live PLAY: stop conditions, bounded media/log retention, audio selection, limits and wiring; synthetic phone, no USB/ADB."""
import contextlib
import io
import json
import os
from pathlib import Path
import random
import tempfile
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

import conn_transfer
import idc_handshake
import rtsp_capabilities as caps
import rtsp_hello
import rtsp_udp_live as live
import rtsp_udp_long as long
import rtsp_udp_play as play
import udp_long_launch as launch
import udp_long_probe as probe
import wfd_startup as wfd
from test_idc_handshake import KEY
from test_loopback_transfer import Device
from test_udp_live import LivePhone,TS,MARK,M16
from test_usb_tunnel import UID
from tunnel_probe import Link,MAX_RECEIVE_BYTES

M4_VALUES={"wfd_video_formats":"00 00 02 04 00000080 00000000 00000000 00 0000 0000 00 none none",
           "wfd_client_rtp_ports":"RTP/AVP/UDP;unicast 46002 0 mode=play",
           "wfd_presentation_url":"rtsp://127.0.0.1/wfd1.0/streamid=0 none"}


class FakeSink:
    def __init__(self):self.data,self.error=[],None
    def put(self,data):self.data.append(bytes(data))
    def summary(self):return dict(chunks=len(self.data))


def keepalive(cseq):
    return M16.replace(b"CSeq: 9",b"CSeq: %d"%cseq)


def run(phone,sink,stop_file):
    result,events={},[]
    link=Link(Device(phone),TimeoutError,max_requests=96,
              record=lambda *args:(_ for _ in ()).throw(AssertionError("raw recorder not replaced")))
    session=long.LongSession(link,1,65536,65536,sink=sink,stop_file=stop_file,clock=phone.clock,
                             log=long.QuietLog(lambda event,**kw:events.append(dict(event=event,**kw))))
    session.get_version();session.exchange(0,tcp_send_buffer_bytes=0)
    session.open_config(256,UID,15000)
    main=session.connect(40000)
    callback=lambda *args:wfd.startup(*args,confirm=lambda *a:phone.tap(),
        after_rtsp=lambda *a:rtsp_hello.exchange(*a,after_query=lambda *b:
            caps.exchange(*b,profile=long.AUDIO_UDP_PROFILE,after_selection=long.exchange)))
    try:
        idc_handshake.handshake(session,main,KEY,result,after_handshake=callback)
    except Exception as error:
        result["error"]=str(error)
    return result,events,session


class Tests(unittest.TestCase):
    def setUp(self):
        patcher=patch.multiple(play,**live.BASE)
        patcher.start()
        self.addCleanup(patcher.stop)
        for target,name,value in ((live,"MAX_KEEPALIVES",long.BASE_KEEPALIVES),
                                  (caps,"selection_compatible",long._PINNED_SELECTION)):
            patcher=patch.object(target,name,value)
            patcher.start()
            self.addCleanup(patcher.stop)
        profile=patch.object(probe.cap,"PROFILE",dict(probe.cap.PROFILE))
        profile.start()
        self.addCleanup(profile.stop)
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.stop_file=Path(tmp.name)/"stop"

    def test_apply_sets_long_limits_keepalives_and_audio_check_and_refuses_changed_base(self):
        long.apply();long.apply()
        self.assertEqual({name:getattr(play,name) for name in long.LONG},long.LONG)
        self.assertEqual(live.MAX_KEEPALIVES,48)
        self.assertIs(caps.selection_compatible,long.selection_compatible)
        for target,name,value in ((play,"PLAY_ACKS",1),(live,"MAX_KEEPALIVES",9),
                                  (caps,"selection_compatible",lambda *a:True)):
            with patch.object(target,name,value):
                with self.assertRaisesRegex(RuntimeError,"pinned base"):long.apply()

    def test_audio_selection_accepts_only_advertised_aac(self):
        self.assertIsNone(long.audio_selection("none"))
        self.assertIsNone(long.audio_selection(None))
        self.assertEqual(long.audio_selection("AAC 00000001 02"),dict(codec="AAC",modes=1,latency=2))
        for value in ("AAC 00000002 00","AAC 00000000 00","LPCM 00000003 00","LPCM 00000001 00","AAC 1 00",
                      "AAC 00000001 00, LPCM 00000003 00","AAC 0000000g 00"):
            self.assertIs(long.audio_selection(value),False,value)
        audio=dict(M4_VALUES,wfd_audio_codecs="AAC 00000001 00")
        self.assertTrue(long.selection_compatible(audio,long.AUDIO_UDP_PROFILE))
        self.assertTrue(long.selection_compatible(dict(M4_VALUES),long.AUDIO_UDP_PROFILE))
        self.assertFalse(long.selection_compatible(dict(audio,wfd_audio_codecs="LPCM 00000003 00"),
                                                   long.AUDIO_UDP_PROFILE))
        # Video/ports still go through the pinned check.
        self.assertFalse(long.selection_compatible(dict(audio,wfd_client_rtp_ports="RTP/AVP/TCP;interleaved mode=play"),
                                                   long.AUDIO_UDP_PROFILE))
        # Other profiles keep the pinned behaviour: audio must be none.
        self.assertFalse(long.selection_compatible(audio,caps.UDP_PROFILE))
        self.assertTrue(long.selection_compatible(dict(M4_VALUES),caps.UDP_PROFILE))

    def test_bounded_media_summary_matches_pinned_summary_over_every_datagram(self):
        rng=random.Random(7)
        full,bounded=[],long.BoundedMedia()
        for n in range(3*long.MEDIA_KEEP):
            if rng.random()<.1:
                item=dict(size_bytes=rng.randrange(60),rtcp=True,packet_type=200,config_id=play.RTCP_CONFIG,
                          source_port=19001,at=n/10)
            else:
                item=dict(rtp=rng.random()>.05,size_bytes=rng.randrange(1,1400),ssrc=rng.choice((5,5,6)),
                          payload_type=33,marker=rng.random()<.2,sequence=n&0xffff,
                          timestamp=(n*3000)%(1<<32),config_id=play.RTP_CONFIG,source_port=19000,at=n/10)
            full.append(item);bounded.append(item)
        self.assertEqual(len(bounded),long.MEDIA_KEEP)
        expected=play.media_summary(full,-1.0)
        self.assertEqual(bounded.summary(play.media_summary(bounded,-1.0)),expected)

    def test_quiet_log_counts_only_routine_media_events(self):
        written=[]
        log=long.QuietLog(lambda event,**kw:written.append(event))
        ack="434f4e4e05000000200000000200000001000000"+"00"*12
        events=[("usb_in_chunk",{}),("usb_write",{}),("duplex_write_completed",{}),("usb_read",{}),
                ("usb_frame_in_data",dict(media_header={})),("usb_raw",dict(direction="out",bytes_hex=ack))]
        kept=[("usb_frame_in_data",dict(header_hex="00")),("usb_frame_in",{}),
              ("usb_raw",dict(direction="out",bytes_hex="434f4e4e05000000540000000100000001")),
              ("rtsp_keepalive_reply",dict(cseq=5)),("inbound_connected",{})]
        for event,fields in events+kept:log(event,**fields)
        self.assertEqual(len(written),len(events+kept))
        written.clear();log.quiet=True
        for event,fields in events+kept:log(event,**fields)
        self.assertEqual(written,[event for event,_ in kept])
        self.assertEqual(sum(log.suppressed.values()),len(events))

    def test_window_is_capped_at_15_minutes_and_before_the_stage_deadline(self):
        long.apply()
        for latest,expected in ((2000.0,900),(500.0,395.0),(103.0,1)):
            session=long.LongSession(Link(Device(LivePhone()),TimeoutError),1,65536,65536,
                                     sink=FakeSink(),stop_file=self.stop_file,clock=lambda:100.0,
                                     log=long.QuietLog(lambda *a,**k:None))
            session.rtsp_connection=SimpleNamespace(received=bytearray(b"OLD"))
            session.stage_latest=latest
            session.collect_media=True
            self.assertEqual((session.window_seconds,play.MEDIA_SECONDS),(expected,expected))
            self.assertEqual(session.keepalive_offset,3)

    def test_stop_file_ends_window_then_tears_down_and_saves_no_payload(self):
        long.apply()
        self.stop_file.write_bytes(b"")
        sink=FakeSink()
        phone=LivePhone(count=50)
        result,events,session=run(phone,sink,self.stop_file)
        self.assertNotIn("error",result)
        self.assertEqual(result["live"]["stop_reason"],"stop_file")
        self.assertEqual(result["rtsp_teardown_status"],200)
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"TEARDOWN "))
        self.assertTrue(result["rtp_media_verified"])
        saved=json.dumps(dict(result=result,events=events))
        self.assertNotIn(MARK.decode(),saved)
        self.assertNotIn(MARK.hex(),saved)

    def test_viewer_exit_ends_window(self):
        long.apply()
        sink=FakeSink();sink.error=BrokenPipeError()
        result,events,session=run(LivePhone(count=20),sink,self.stop_file)
        self.assertNotIn("error",result)
        self.assertEqual(result["live"]["stop_reason"],"viewer_closed")
        self.assertEqual(result["rtsp_teardown_status"],200)

    def test_cap_ends_window_and_many_keepalives_are_answered(self):
        long.apply()
        after=b"".join(keepalive(cseq) for cseq in range(10,30))
        phone=LivePhone(count=40,after_play=after)
        with patch.object(long,"CAP_SECONDS",3):
            result,events,session=run(phone,FakeSink(),self.stop_file)
        self.assertNotIn("error",result)
        self.assertEqual(result["live"]["stop_reason"],"cap")
        self.assertEqual(result["live"]["window_seconds"],3)
        self.assertEqual(result["live"]["keepalives_answered"],20)
        self.assertTrue(phone.rtsp_sent[-1].startswith(b"TEARDOWN "))

    def test_long_run_keeps_bounded_media_and_quiet_log_but_counts_everything(self):
        long.apply()
        sink=FakeSink()
        with patch.object(long,"MEDIA_KEEP",10),patch.object(long,"FULL_LOG_SECONDS",0),\
                patch.object(long,"CAP_SECONDS",2):
            result,events,session=run(LivePhone(count=120),sink,self.stop_file)
        self.assertNotIn("error",result)
        self.assertEqual(len(session.media),10)
        self.assertTrue(result["media_summary_aggregated"])
        self.assertEqual(result["media_summary"]["rtp_datagrams"],120)
        self.assertEqual(result["media_summary"]["last_sequence"],119)
        self.assertEqual(b"".join(sink.data),TS*120)
        suppressed=result["live"]["suppressed_events"]
        # Every media frame is either logged (before quiet) or counted, and quiet did engage.
        logged=sum(e["event"]=="usb_frame_in_data" and "media_header" in e for e in events)
        self.assertGreater(suppressed.get("usb_frame_in_data",0),0)
        self.assertEqual(logged+suppressed["usb_frame_in_data"],120)
        teardown=next(i for i,e in enumerate(events) if e["event"]=="usb_raw"
                      and b"TEARDOWN".hex() in e["bytes_hex"])
        # Logging is full again for TEARDOWN and cleanup.
        self.assertIn("usb_in_chunk",[e["event"] for e in events[teardown:]])
        self.assertEqual(result["live"]["ts"]["sync_ok"],840)

    def test_owner_raises_only_the_pinned_receive_limit(self):
        owner=long.LongOwner(SimpleNamespace(),{},FakeSink(),self.stop_file)
        link=Link(Device(LivePhone()),TimeoutError)
        session=owner.session(link,1,65536,MAX_RECEIVE_BYTES,clock=time.monotonic,log=lambda *a,**k:None)
        self.assertIsInstance(session,long.LongSession)
        self.assertEqual(session.max_receive_bytes,long.LONG_RECEIVE_BYTES)
        self.assertIsInstance(session.log,long.QuietLog)
        self.assertIs(owner.reader.log,session.log)
        with self.assertRaisesRegex(RuntimeError,"pinned base"):
            owner.session(link,1,65536,MAX_RECEIVE_BYTES+1,log=lambda *a,**k:None)

    def test_probe_plan_and_wiring_use_long_owner_audio_profile_and_stop_file(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        seen={}
        def fake_probe(device,owner,timeout,out,result,**kwargs):
            sessions=kwargs["session_class"].__self__
            seen.update(owner=owner,sessions=sessions,max_requests=kwargs["max_requests"])
            result.update(ui_tap_command_succeeded=True,wfd_startup_verified=True,rtp_media_verified=True)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),patch.dict("sys.modules",
                {"usb":usb,"usb.core":core,"usb.util":util}),patch.object(probe.auth_probe,
                "probe",side_effect=fake_probe),patch.object(probe.live_sink,"TsSink") as sink_class,\
                contextlib.redirect_stdout(io.StringIO()):
            sink_class.return_value.start.return_value=sink_class.return_value
            sink_class.return_value.summary.return_value={"opened":True,"forwarded_bytes":1316}
            self.assertEqual(probe.main(["--approved-phone-udp-long","--accept-persistent-state",
                "--bus","3","--address","13","--output",tmp+"/new","--ts-fifo",tmp+"/ts.fifo",
                "--stop-file",tmp+"/stop"]),0)
            plan=json.loads(Path(tmp+"/new/plan.json").read_text())
            saved=json.loads(Path(tmp+"/new/result.json").read_text())
        sink_class.assert_called_once_with(Path(tmp+"/ts.fifo"))
        self.assertIsInstance(seen["owner"],long.LongOwner)
        self.assertEqual(seen["owner"].stop_file,Path(tmp+"/stop"))
        self.assertIs(seen["sessions"].owner,seen["owner"])
        self.assertEqual(seen["max_requests"],96)
        self.assertEqual((plan["media_seconds"],plan["cap_seconds"],plan["max_keepalives"],plan["outer_seconds"]),
                         (900,900,48,990))
        self.assertEqual(plan["diagnostic_wfd_profile"]["wfd_audio_codecs"],"AAC 00000001 00")
        self.assertEqual(plan["diagnostic_wfd_profile"]["wfd_uibc_capability"],"none")
        self.assertEqual(plan["client_profile"]["PcVer"],"2.0.0.23")
        self.assertTrue(saved["video_tested"])

    def test_launch_requires_fifo_new_stop_file_hashes_and_execs_long_probe(self):
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[SimpleNamespace(bus=3,address=13)]
        usb.core=core
        with tempfile.TemporaryDirectory() as tmp,patch.dict("sys.modules",{"usb":usb,"usb.core":core}),\
                patch.object(launch,"require_adb_server"),patch.object(launch.os,"execv") as execute,\
                contextlib.redirect_stdout(io.StringIO()):
            base=["--approved-phone-udp-long","--accept-persistent-state","--output",tmp+"/new"]
            regular=Path(tmp)/"regular";regular.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError,"not an existing FIFO"):
                launch.main(base+["--ts-fifo",str(regular),"--stop-file",tmp+"/stop"])
            fifo=Path(tmp)/"ts.fifo";os.mkfifo(fifo,0o600)
            with self.assertRaisesRegex(RuntimeError,"stop-file"):
                launch.main(base+["--ts-fifo",str(fifo),"--stop-file","/tmp/elsewhere-stop"])
            with self.assertRaisesRegex(RuntimeError,"stop-file"):
                launch.main(base+["--ts-fifo",str(fifo),"--stop-file",str(regular)])
            execute.assert_not_called()
            launch.main(base+["--ts-fifo",str(fifo),"--stop-file",tmp+"/stop"])
            args=execute.call_args.args[1]
        self.assertIn("research/native-usb/udp_long_probe.py",args)
        self.assertEqual(args[-4:],["--ts-fifo",str(fifo),"--stop-file",tmp+"/stop"])
        for name in ("rtsp_udp_long.py","udp_long_probe.py","rtsp_udp_live.py","live_sink.py",
                     "conn_transfer.py","duplex_link.py","rtsp_udp_play.py","rtsp_capabilities.py"):
            self.assertIn(name,launch.EXPECTED)
        self.assertNotIn("udp_live_probe.py",launch.EXPECTED)

if __name__=="__main__":unittest.main()
