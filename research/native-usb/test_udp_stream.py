"""Longer PLAY window limits, probe wiring and launcher pins; no actual USB/ADB."""
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

import conn_transfer
import duplex_link
import rtsp_udp_play as play
import rtsp_udp_stream as stream
import udp_stream_probe as probe
import udp_stream_launch as launch
from test_udp_play import PlayPhone,run,SECRET
from test_loopback_transfer import Device
from tunnel_probe import Link


class Tests(unittest.TestCase):
    def setUp(self):
        # Restores the pinned module's values after every test.
        patcher=patch.multiple(play,**stream.BASE)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_apply_sets_stream_limits_once_and_refuses_changed_base(self):
        stream.apply()
        self.assertEqual({name:getattr(play,name) for name in stream.STREAM},stream.STREAM)
        stream.apply()
        play.PLAY_ACKS=999
        with self.assertRaisesRegex(RuntimeError,"pinned base"):stream.apply()

    def test_longer_window_acks_exactly_the_cap_and_saves_no_payload(self):
        stream.apply()
        phone=PlayPhone(count=2100)
        result,session,events=run(phone)
        self.assertNotIn("error",result)
        self.assertTrue(result["rtp_media_verified"])
        self.assertEqual(len(phone.media_acks),2048)
        self.assertEqual(result["media_unacked_datagrams"],52)
        self.assertEqual(result["media_summary"]["rtp_datagrams"],2048)
        self.assertEqual(result["media_close_statuses"],{"1206":0,"1205":0})
        saved=json.dumps(dict(result=result,events=events))
        self.assertNotIn(SECRET.decode(),saved)
        self.assertNotIn(SECRET.hex(),saved)

    def test_session_installs_stream_budgets_before_io(self):
        stream.apply()
        phone=PlayPhone()
        link=Link(Device(phone),TimeoutError)
        play.PlaySession(link,1,65536,65536)
        self.assertEqual((link.acks_left,link.reads_left),(2304,12000))
        self.assertFalse(phone.inbound)

    def test_probe_applies_limits_before_plan_and_wires_duplex_owner(self):
        usb,core,util=ModuleType("usb"),ModuleType("usb.core"),ModuleType("usb.util")
        core.find=lambda **kw:[object()]
        core.USBTimeoutError=TimeoutError
        usb.core,usb.util=core,util
        def fake_probe(device,owner,timeout,out,result,**kwargs):
            self.assertIsInstance(owner,duplex_link.UsbOwner)
            sessions=kwargs["session_class"].__self__
            self.assertIsInstance(sessions,conn_transfer.TransferSessions)
            self.assertIs(sessions.owner,owner)
            self.assertEqual(kwargs["max_requests"],48)
            result.update(ui_tap_command_succeeded=True,wfd_startup_verified=True,rtp_media_verified=True)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
                {"DEX_AUTO_UI_DEADLINE":str(time.monotonic()+60)}),patch.dict("sys.modules",
                {"usb":usb,"usb.core":core,"usb.util":util}),patch.object(probe.auth_probe,
                "probe",side_effect=fake_probe),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(["--approved-phone-udp-stream","--accept-persistent-state",
                "--bus","3","--address","13","--output",tmp+"/new"]),0)
            plan=json.loads(Path(tmp+"/new/plan.json").read_text())
        self.assertTrue(plan["stream"] and plan["duplex_in"] and plan["transfer_pad_decoder"])
        self.assertEqual((plan["media_datagrams"],plan["media_seconds"],plan["media_bytes"],
                          plan["max_acks"],plan["max_reads"],plan["stage_seconds"]),
                         (2048,15,8<<20,2304,12000,26))
        self.assertEqual(plan["outer_seconds"],90)

    def test_launch_hashes_and_execs_only_stream_probe(self):
        usb,core=ModuleType("usb"),ModuleType("usb.core")
        core.find=lambda **kw:[SimpleNamespace(bus=3,address=13)]
        usb.core=core
        with tempfile.TemporaryDirectory() as tmp,patch.dict("sys.modules",{"usb":usb,"usb.core":core}):
            with patch.object(launch,"require_adb_server"),patch.object(launch.os,"execv") as execute,contextlib.redirect_stdout(io.StringIO()):
                launch.main(["--approved-phone-udp-stream","--accept-persistent-state","--output",tmp+"/new"])
            args=execute.call_args.args[1]
            self.assertIn("research/native-usb/udp_stream_probe.py",args)
            self.assertIn("--approved-phone-udp-stream",args)
        self.assertIn("rtsp_udp_stream.py",launch.EXPECTED)
        self.assertIn("duplex_link.py",launch.EXPECTED)
        self.assertIn("conn_transfer.py",launch.EXPECTED)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(launch.EXPECTED,{"rtsp_udp_stream.py":"0"*64},clear=True),self.assertRaisesRegex(RuntimeError,"source mismatch"):
            launch.main(["--approved-phone-udp-stream","--accept-persistent-state","--output",tmp+"/new"])

if __name__=="__main__":unittest.main()
