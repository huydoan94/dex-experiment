"""Offline tests for the existing-manager notification precondition."""
import json
from pathlib import Path
import unittest

import app_bootstrap as b
import relisten_bootstrap as r

D = Path(__file__).resolve().parent / "bootstrap-20261102T055725Z-$"


def saved(name):
    return json.loads((D / (name + ".json")).read_text())["stdout"]


class Tests(unittest.TestCase):
    def setUp(self):
        self.service = saved("service-before")
        self.desktop = saved("desktop-before")

    def test_actual_23_57_state_accepted_by_wrapper_only(self):
        with self.assertRaisesRegex(ValueError, "main-server manager exists"):
            b.preflight(self.service, self.desktop)
        self.assertEqual(r.preflight_existing(self.service, self.desktop), 24144)

    def test_connected_or_busy_manager_refused(self):
        for old, new in (("mMainServer.isConnected=false", "mMainServer.isConnected=true"),
                         ("Current o state: no instance", "Current o state: READY"),
                         ("Current n state: no instance", "Current n state: x")):
            with self.subTest(new=new):
                with self.assertRaises(ValueError):
                    r.preflight_existing(self.service.replace(old, new), self.desktop)

    def test_baseline_and_desktop_checks_still_apply(self):
        with self.assertRaisesRegex(ValueError, "unsupported baseline"):
            r.preflight_existing(self.service.replace("gsSetMode=true", "gsSetMode=false"),
                                 self.desktop)
        with self.assertRaises(ValueError):
            r.preflight_existing(self.service, self.desktop.replace(
                "mDesktopDisplayId=-1", "mDesktopDisplayId=2"))

    def test_installed_wrapper_runs_through_app_bootstrap_name(self):
        # The approved run calls b.preflight after main() replaced it (00:02 recursion bug).
        original = b.preflight
        try:
            b.preflight = r.preflight_existing
            self.assertEqual(b.preflight(self.service, self.desktop), 24144)
            with self.assertRaisesRegex(ValueError, "main server connected"):
                b.preflight(self.service.replace("mMainServer.isConnected=false",
                                                 "mMainServer.isConnected=true"), self.desktop)
        finally:
            b.preflight = original

    def test_actual_post_play_idle_kms_manager(self):
        service=json.loads((D.parent/"post-relisten-state-20261102T212010+0000"/"dop-service.json").read_text())["stdout"]
        desktop=json.loads((D.parent/"post-relisten-state-20261102T212010+0000"/"desktopmode.json").read_text())["stdout"]
        self.assertEqual(r.preflight_existing(service,desktop),24144)
        for old,new in (
            ("mKMSService=null","mKMSService=active"),
            ("mKMSService.pinchOn=false","mKMSService.pinchOn=true"),
            ("mKMSServiceState=0","mKMSServiceState=1"),
            ("mKMSService=null","unknownField=null"),
            ("mKMSService.pinchOn=false","mKMSService.pinchOn=false\n      extra=unknown"),
            ("Current s state:","Current s state: no instance\n\n    Current s state:"),
        ):
            with self.subTest(new=new):
                with self.assertRaises(ValueError):
                    r.preflight_existing(service.replace(old,new),desktop)

    def test_actual_post_kms_idle_file_manager(self):
        source=D.parent/"relisten-20261103T083453Z-$"
        service=json.loads((source/"service-before.json").read_text())["stdout"]
        desktop=json.loads((source/"desktop-before.json").read_text())["stdout"]
        with self.assertRaisesRegex(ValueError,"main-server manager exists"):
            b.preflight(service,desktop)
        self.assertEqual(r.preflight_existing(service,desktop),24144)
        for old,new in (
            ("mReceiveStatus=0","mReceiveStatus=1"),
            ("mReceiveStatus=0","mReceiveStatus=2"),
            ("mReceiveStatus=0","mReceiveStatus=-1"),
            ("mReceiveStatus=0","unknownStatus=0"),
            ("mFinalFileURI=null","mFinalFileURI=null\n      extra=unknown"),
            ("mFinalFileURI=null","unknownField=null"),
            ("Current n state:","Current n state: no instance\n\n    Current n state:"),
            ("Current n state:","Current unknown state:"),
            ("mKMSService=null","mKMSService=active"),
            ("Current o state: no instance","Current o state: READY"),
            ("mMainServer.isConnected=false","mMainServer.isConnected=true"),
        ):
            with self.subTest(new=new),self.assertRaises(ValueError):
                r.preflight_existing(service.replace(old,new),desktop)
        for kms in ("mKMSService=active", "mKMSService=com.sec.android.app.dexonpc.kms.source.KMSService@zz",
                    "mKMSService=other.KMSService@1a2b"):
            with self.subTest(kms=kms), self.assertRaises(ValueError):
                r.preflight_existing(service.replace("mKMSService=null", kms), desktop)
        with self.assertRaises(ValueError):
            r.preflight_existing(service.replace("mKMSService=null", "mKMSService=com.sec.android.app.dexonpc.kms.source.KMSService@78bea54")
                                 .replace("mKMSServiceState=0", "mKMSServiceState=1"), desktop)
        # Idle after file transfer: the phone keeps its KMSService object and the last file's path.
        self.assertEqual(r.preflight_existing(service.replace("mKMSService=null", "mKMSService=com.sec.android.app.dexonpc.kms.source.KMSService@78bea54"), desktop), 24144)
        self.assertEqual(r.preflight_existing(service.replace("mFinalFileURI=null","mFinalFileURI=/storage/a/b.docx"),desktop),24144)

    def test_main_installs_wrapper_and_keeps_default_plan_only(self):
        original = b.preflight
        try:
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(r.main([]), 0)
            self.assertIn("PLAN_ONLY", out.getvalue())
            self.assertIs(b.preflight, r.preflight_existing)
        finally:
            b.preflight = original


if __name__ == "__main__":
    unittest.main()
