"""Targeted UI parsing, bounded child processes and native-pumped confirmation."""
import builtins
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import idc_handshake
import ui_confirm as ui
import wfd_startup as wfd
from conn_frames import Decoder
from test_idc_handshake import opened,KEY
from test_wfd_startup import WfdPhone

SERIAL=b"List of devices attached\nRFTEST device usb:3-1 product:y2s model:SM_G985F device:y2s transport_id:1\n"
FOCUS=b"  mCurrentFocus=Window{abc u0 com.sec.android.app.dexonpc/Dialog}\n"
XML=b'''<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<hierarchy rotation="0"><node package="com.sec.android.app.dexonpc" bounds="[0,0][1440,3200]">
<node package="com.sec.android.app.dexonpc" text="Start Samsung DeX on DeX-PC?" bounds="[100,1000][1340,1200]" />
<node package="com.sec.android.app.dexonpc" text="Start now" resource-id="android:id/button1"
class="android.widget.Button" enabled="true" clickable="true" bounds="[900,1600][1300,1700]" />
</node></hierarchy>UI hierchary dumped to: /proc/self/fd/1
'''


class AutoPhone(WfdPhone):
    def __init__(self):
        super().__init__()
        self.held_accept=b""
    def _handle(self,frame):
        super()._handle(frame)
        if frame.kind==1 and frame.command==5 and self.host_data[-1][0]==1203:
            self.held_accept=bytes(self.inbound[-44:])
            self.inbound[-44:]=b""
            assert Decoder(65536).feed(self.held_accept)[0].command==3
    def tap(self):
        assert self.held_accept
        self.inbound+=self.held_accept
        self.held_accept=b""


class FakeRunner:
    def __init__(self,phone=None,xml=XML,focus=FOCUS,stale=False):
        self.phone,self.xml,self.focus,self.stale=phone,xml,focus,stale
        self.commands=[]
    def __call__(self,argv,session,main,deadline,limit,log):
        self.commands.append(argv)
        if len(self.commands)==1:
            return SERIAL
        if "uiautomator" in argv:
            return self.xml
        if "dumpsys" in argv:
            assert argv[-3:]==["dumpsys","window","displays"]
            if self.stale:
                self.phone.now+=3
            return self.focus
        assert "input" in argv and argv[-4:-2]==["input","tap"]
        if self.phone:
            self.phone.tap()
        session.wait(.1,until=lambda:False)
        return b""


class Tests(unittest.TestCase):
    def test_device_is_one_authorized_matching_usb_model(self):
        self.assertEqual(ui.select_serial(SERIAL,3),"RFTEST")
        for data in (SERIAL.replace(b"usb:3-1",b"usb:4-1"),
                     SERIAL.replace(b"model:SM_G985F",b"model:other"),
                     SERIAL.replace(b" device ",b" unauthorized "),
                     SERIAL+b"other device usb:3-2 model:SM_G985F\n",
                     b"List of devices attached\n"):
            with self.subTest(data=data),self.assertRaises(ValueError):
                ui.select_serial(data,3)

    def test_exact_dialog_and_dynamic_bounds(self):
        xml,point=ui.dialog_button(XML)
        self.assertEqual(point,(1100,1650))
        self.assertTrue(xml.endswith(b"</hierarchy>"))
        self.assertEqual(ui.dialog_button(XML.replace(
            b"[900,1600][1300,1700]",b"[100,400][500,500]"))[1],(300,450))

    def test_wrong_hidden_disabled_ambiguous_or_malformed_dialog(self):
        for data in (XML.replace(b"Start now",b"Cancel"),
                     XML.replace(b'enabled="true"',b'enabled="false"'),
                     XML.replace(b'clickable="true"',b'clickable="false"'),
                     XML.replace(b"android:id/button1",b"android:id/button2"),
                     XML.replace(b"com.sec.android.app.dexonpc",b"com.android.systemui"),
                     XML.replace(b"on DeX-PC?",b"on other?"),
                     XML.replace(b"[900,1600][1300,1700]",b"[1400,1600][1600,1700]"),
                     XML.replace(b"[900,1600][1300,1700]",b"[1,1][1,1]"),
                     XML+b"<hierarchy></hierarchy>",
                     b"<!DOCTYPE hierarchy>"+XML,b"x"*262145,b"ERROR: null root"):
            with self.subTest(data=data[:80]),self.assertRaises(ValueError):
                ui.dialog_button(data)

    def test_focus_requires_exact_package_user_and_no_lock_flag(self):
        ui.validate_focus(FOCUS)
        for data in (FOCUS.replace(b"dexonpc/",b"dexonpc.evil/"),
                     FOCUS.replace(b"u0 ",b"u10 "),FOCUS+FOCUS,
                     FOCUS+b"mShowingLockscreen=true\n",b"mCurrentFocus=null\n"):
            with self.subTest(data=data),self.assertRaises(ValueError):
                ui.validate_focus(data)

    def test_full_callback_pumps_native_and_no_rtsp_sends(self):
        phone,result=AutoPhone(),{}
        session,main=opened(phone)
        runner=FakeRunner(phone)
        with tempfile.TemporaryDirectory() as tmp:
            def confirm(s,m,r,log,deadline):
                ui.confirm(s,m,r,log,deadline,tmp,3,runner=runner)
            idc_handshake.handshake(session,main,KEY,result,
                                   after_handshake=lambda *a:wfd.startup(*a,confirm=confirm))
            self.assertTrue((Path(tmp)/"ui-before.xml").exists())
        self.assertTrue(result["ui_tap_command_succeeded"])
        self.assertTrue(result["wfd_startup_verified"])
        self.assertEqual(len(runner.commands),4)
        self.assertEqual(runner.commands[-1][-4:],["input","tap","1100","1650"])
        self.assertEqual(len(phone.host_data),2)  # IDC+CONTROL; no RTSP send
        self.assertEqual(set(session.configs),{256})
        self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_wrong_prompt_focus_or_stale_tree_never_taps(self):
        for mode in ("wrong prompt","wrong focus","stale"):
            phone,result=AutoPhone(),{}
            session,main=opened(phone)
            runner=FakeRunner(phone,xml=XML.replace(b"Start now",b"Cancel") if mode=="wrong prompt" else XML,
                              focus=b"mCurrentFocus=null\n" if mode=="wrong focus" else FOCUS,
                              stale=mode=="stale")
            with tempfile.TemporaryDirectory() as tmp:
                def confirm(s,m,r,log,deadline):
                    ui.confirm(s,m,r,log,deadline,tmp,3,runner=runner)
                with self.assertRaises(Exception):
                    idc_handshake.handshake(session,main,KEY,result,
                        after_handshake=lambda *a:wfd.startup(*a,confirm=confirm))
            self.assertNotIn("ui_tap_attempted",result)
            self.assertFalse(any("input" in command for command in runner.commands))
            self.assertNotIn(1204,phone.cfgs)
            self.assertEqual(result["wfd_cleanup_errors"],[])

    def test_child_runner_real_pipes_bounds_and_native_pump(self):
        class Pump:
            clock=staticmethod(time.monotonic)
            calls=0
            def wait(self,seconds,until):
                self.calls+=1
                time.sleep(min(seconds,.005))
        session=Pump();main=SimpleNamespace(closed_by_phone=False)
        logs=[]
        logger=lambda **kw:logs.append(kw)
        out=ui.run_adb([sys.executable,"-c","import time;time.sleep(.02);print('ok')"],
                       session,main,time.monotonic()+2,128,logger)
        self.assertEqual(out,b"ok\n")
        self.assertGreater(session.calls,0)
        with self.assertRaisesRegex(ValueError,"output exceeds"):
            ui.run_adb([sys.executable,"-c","print('x'*10000)"],session,main,
                       time.monotonic()+2,128,logger)
        with self.assertRaisesRegex(Exception,"deadline"):
            ui.run_adb([sys.executable,"-c","import time;time.sleep(10)"],session,main,
                       time.monotonic()+.05,128,logger)
        self.assertTrue(any(e["event"]=="ui_command_error" for e in logs))

    def test_main_closure_cancels_and_reaps_ui_child(self):
        main=SimpleNamespace(closed_by_phone=False)
        class ClosingPump:
            clock=staticmethod(time.monotonic)
            def wait(self,seconds,until):
                time.sleep(.005)
                main.closed_by_phone=True
        with self.assertRaisesRegex(Exception,"main closure"):
            ui.run_adb([sys.executable,"-c","import time;time.sleep(10)"],
                       ClosingPump(),main,time.monotonic()+2,128,lambda **kw:None)
        with patch.object(ui.subprocess,"Popen",side_effect=AssertionError("must not spawn")):
            with self.assertRaisesRegex(Exception,"closure"):
                ui.run_adb(["unused"],ClosingPump(),main,time.monotonic()+2,128,
                           lambda **kw:None)






class SamsungReplayTests(unittest.TestCase):
    def test_saved_actual_samsung_dialog_matches_and_uses_measured_center(self):
        fixture=Path(__file__).parent/"fixtures"/"samsung-dex-confirm-20261102.xml"
        xml,point=ui.dialog_button(fixture.read_bytes())
        self.assertEqual(point,(746,2206))
        self.assertIn(b"Start Samsung DeX on DeX-PC?",xml)

    def test_window_listing_without_focus_field_is_refused(self):
        # The real windows query included this app window but no mCurrentFocus.
        with self.assertRaisesRegex(ValueError,"current focus"):
            ui.validate_focus(b"WINDOW MANAGER WINDOWS\n"
                              b"  Window #6 Window{33d3f84 u0 com.sec.android.app.dexonpc}:\n"
                              b"    mOwnerUid=1000 package=com.sec.android.app.dexonpc\n")
