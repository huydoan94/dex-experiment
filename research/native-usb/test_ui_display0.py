"""Only display-scoped focus parsing and guarded tap integration; synthetic/saved inputs."""
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

import ui_confirm_display0 as ui
from test_ui_confirm import FakeRunner,FOCUS,XML
from usb_tunnel import TunnelError

CAPTURE = Path(__file__).resolve().parent / "udp-play-after-relisten-20261102T212614+0000"
SAVED = CAPTURE.is_dir()

FOCUS_MULTI=b"  Display: mDisplayId=2 rootTasks=0\n  mCurrentFocus=null\n  Display: mDisplayId=0 rootTasks=3\n"+FOCUS

class DisplayRunner(FakeRunner):
    def __init__(self,phone=None,**kwargs):
        kwargs.setdefault("focus",FOCUS_MULTI)
        super().__init__(phone,**kwargs)
    def __call__(self,argv,session,main,deadline,limit,log):
        if "input" not in argv:
            return super().__call__(argv,session,main,deadline,limit,log)
        self.commands.append(argv)
        if argv[-6:-2]!=["input","-d","0","tap"]:
            raise AssertionError("tap did not explicitly select display0")
        if self.phone:
            self.phone.tap()
        session.wait(.1,until=lambda:False)
        return b""

class Tests(unittest.TestCase):
    @unittest.skipUnless(SAVED, "saved capture is kept outside the repository")
    def test_saved_multi_display_dump_selects_default(self):
        path=CAPTURE/"focus-saved.txt"
        self.assertIn("u0 com.sec.android.app.dexonpc",ui.validate_focus(path.read_bytes()))
        self.assertIn("u0",ui.validate_focus(FOCUS_MULTI))

    def test_wrong_or_ambiguous_default_focus_refused(self):
        for output in (
            FOCUS_MULTI.replace(b"u0 ",b"u10 "),
            FOCUS_MULTI.replace(b"com.sec.android.app.dexonpc",b"com.sec.android.app.dexonpc.evil"),
            FOCUS_MULTI+FOCUS,
            FOCUS_MULTI.replace(FOCUS,b"  mCurrentFocus=null\n"),
            FOCUS_MULTI.replace(b"mDisplayId=0",b"mDisplayId=1"),
            FOCUS_MULTI+FOCUS_MULTI,
            FOCUS+FOCUS_MULTI,
            FOCUS,
            FOCUS_MULTI.replace(b"rootTasks=3",b"unsupported"),
        ):
            with self.subTest(output=output),self.assertRaises(ValueError):
                ui.validate_focus(output)

    def test_lock_on_other_display_still_refused(self):
        for flag in (b"mShowingLockscreen=true",b"mDreamingLockscreen=true"):
            with self.assertRaises(ValueError):
                ui.validate_focus(FOCUS_MULTI.replace(b"mCurrentFocus=null",flag))

    def test_other_display_cannot_supply_dex_focus(self):
        output=FOCUS_MULTI.replace(b"mCurrentFocus=null",FOCUS.strip()).replace(
            b"rootTasks=3\n"+FOCUS,b"rootTasks=3\n  mCurrentFocus=null\n")
        with self.assertRaises(ValueError):
            ui.validate_focus(output)

    def test_confirm_taps_only_display0_after_four_commands(self):
        session=SimpleNamespace(clock=lambda:0,wait=lambda *a,**kw:None)
        runner=DisplayRunner()
        with tempfile.TemporaryDirectory() as tmp:
            result={}
            ui.confirm(session,SimpleNamespace(closed_by_phone=False),result,
                       lambda **kw:None,20,Path(tmp),3,runner=runner)
        self.assertTrue(result["ui_tap_command_succeeded"])
        self.assertEqual(len(runner.commands),4)
        self.assertEqual(runner.commands[-1][-6:-2],["input","-d","0","tap"])

    def test_stale_snapshot_still_stops_before_tap(self):
        phone=SimpleNamespace(now=0)
        session=SimpleNamespace(clock=lambda:phone.now,wait=lambda *a,**kw:None)
        runner=DisplayRunner(phone=phone,stale=True)
        with tempfile.TemporaryDirectory() as tmp,self.assertRaises(TunnelError):
            ui.confirm(session,SimpleNamespace(closed_by_phone=False),{},
                       lambda **kw:None,20,Path(tmp),3,runner=runner)
        self.assertEqual(len(runner.commands),3)

    def test_invalid_focus_stops_without_tap(self):
        session=SimpleNamespace(clock=lambda:0,wait=lambda *a,**kw:None)
        runner=DisplayRunner(focus=FOCUS_MULTI.replace(FOCUS,b"  mCurrentFocus=null\n"))
        with tempfile.TemporaryDirectory() as tmp,self.assertRaises(ValueError):
            ui.confirm(session,SimpleNamespace(closed_by_phone=False),{},
                       lambda **kw:None,20,Path(tmp),3,runner=runner)
        self.assertEqual(len(runner.commands),3)

if __name__=="__main__":
    unittest.main()
