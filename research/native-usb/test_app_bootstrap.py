import builtins
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app_bootstrap as b
from test_version_query import Device as VersionDevice, Util

SAVED = (Path(__file__).resolve().parent / "app-state-20261101T195355Z").is_dir()

SERVICE = """SERVICE com.sec.android.app.dexonpc/.service.DOPService abc pid=123 user=0
  mPackageVersion = 2.5.00.16
  mDOPServiceRunning = true
  ConnectionUtil.isUsbConnected() = true
  dexonpc_connection_state = SETTING_SOURCE_CONNECT_USB(1)
  gsSWVersion=2.17.21.0
  gsSetMode=true
  Current g state: no instance
"""
AFTER = SERVICE.replace("Current g state: no instance",
                        "Current g state:\n  mMainServer.isConnected=false")
DESKTOP = """mDesktopDisplayId=-1
 mDualModeEnabled=false
 mStandaloneModeEnabled=false
 mIsWirelessDexEntered=false
 mDualModeEnabled=false
"""


class Device(VersionDevice):
    serial_number = "unit-device"

    def __init__(self, failure=None, **kwargs):
        super().__init__(**kwargs)
        self.failure = failure

    def write(self, endpoint, data, timeout):
        if (endpoint, timeout) != (3, 1000):
            raise AssertionError("wrong endpoint or timeout")
        if bytes(data) != (bytes.fromhex("434f4e4e0c0000001001000003000000") +
                           b"dop pc app start" + b"\0"*240):
            raise AssertionError("wrong notification bytes")
        self.calls.append("write")
        if self.failure:
            raise self.failure
        return 5 if self.partial else len(data)


class Tests(unittest.TestCase):
    def setUp(self):
        self.logging = patch.object(b, "emit")
        self.logging.start()
        self.addCleanup(self.logging.stop)

    def test_packet_exact_header_and_body(self):
        packet = b.payload()
        self.assertEqual(packet[:16].hex(), "434f4e4e0c0000001001000003000000")
        self.assertEqual(len(packet), 272)
        self.assertEqual(packet[16:32], b"dop pc app start")
        self.assertEqual(packet[32:], b"\0"*240)

    def test_default_guard_precedes_usb_import_and_adb(self):
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == "usb" or name.startswith("usb."):
                raise AssertionError("USB imported")
            return original(name, *args, **kwargs)
        with patch.object(b, "experiment", side_effect=AssertionError("phone accessed")), \
             patch("builtins.__import__", guarded):
            self.assertEqual(b.main([]), 0)

    def test_explicit_retention_required_before_phone_access(self):
        with patch.object(b, "experiment", side_effect=AssertionError("phone accessed")), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            b.main(["--phone-bootstrap-approved", "--output", "/unused"])

    def test_existing_output_refused_before_phone_access(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(b, "experiment", side_effect=AssertionError("phone accessed")), \
             self.assertRaises(FileExistsError):
            b.main(["--phone-bootstrap-approved", "--retain-started-service", "--output", folder])

    @unittest.skipUnless(SAVED, "saved capture is kept outside the repository")
    def test_actual_saved_baseline_parses_offline(self):
        root=Path(__file__).parent/"app-state-20261101T195355Z"
        service=json.loads((root/"dex-service.json").read_text())["stdout"]
        desktop=json.loads((root/"desktopmode.json").read_text())["stdout"]
        self.assertGreater(b.preflight(service, desktop), 0)

    def test_missing_conflicting_active_state_rejected(self):
        for desktop in (DESKTOP.replace("mDesktopDisplayId=-1", ""),
                        DESKTOP.replace("mDesktopDisplayId=-1", "mDesktopDisplayId=2"),
                        DESKTOP+"mDualModeEnabled=true\n"):
            with self.assertRaises(ValueError):
                b.preflight(SERVICE, desktop)

    def test_existing_manager_and_unsupported_app_rejected(self):
        for service in (AFTER, SERVICE.replace("2.5.00.16", "2.5.00.17"),
                        SERVICE.replace("gsSetMode=true", "gsSetMode=false"),
                        SERVICE.replace("user=0", "user=10")):
            with self.assertRaises(ValueError):
                b.preflight(service, DESKTOP)

    def test_observation_is_not_tcp_or_dex_success(self):
        result=b.observed(AFTER, DESKTOP, 123)
        self.assertTrue(result["main_server_manager_initialized"])
        self.assertFalse(result["tcp_listener_verified"])
        self.assertFalse(result["dex_activation_observed"])
        with self.assertRaises(ValueError):
            b.observed(AFTER.replace("pid=123", "pid=124"), DESKTOP, 123)
        with self.assertRaises(ValueError):
            b.observed(AFTER.replace("isConnected=false", "isConnected=true"), DESKTOP, 123)

    def notify(self, device, util=None):
        state={}
        try:
            b.notify(device, util or Util(device), "unit-device", state)
        finally:
            self.state=state
        return state

    def test_single_write_releases_and_closes(self):
        device=Device()
        state=self.notify(device)
        self.assertEqual(device.calls, ["config", "kernel", "claim", "write", "release", "dispose"])
        self.assertEqual(state["bytes_written"], 272)
        self.assertTrue(state["interface_released"])
        self.assertTrue(state["usb_handle_closed"])

    def test_serial_mismatch_stops_before_claim(self):
        device=Device()
        device.serial_number="other-device"
        with self.assertRaises(ValueError):
            self.notify(device)
        self.assertEqual(device.calls, ["dispose"])
        self.assertNotIn("write_attempted", self.state)

    def test_busy_or_changed_descriptor_stops_before_claim(self):
        for device in (Device(busy=True), Device()):
            if not device.busy:
                device.config[0][0].wMaxPacketSize=64
            with self.assertRaises(ValueError):
                self.notify(device)
            self.assertNotIn("claim",device.calls)
            self.assertEqual(device.calls[-1],"dispose")

    def test_partial_or_timeout_write_not_retried_and_marked_uncertain(self):
        for device in (Device(partial=True), Device(failure=TimeoutError("write timed out"))):
            with self.assertRaises((RuntimeError,TimeoutError)):
                self.notify(device)
            self.assertEqual(device.calls.count("write"),1)
            self.assertEqual(device.calls[-2:],["release","dispose"])
            self.assertTrue(self.state["write_attempted"])

    def test_release_failure_still_disposes(self):
        device=Device()
        with self.assertRaises(OSError):
            self.notify(device,Util(device,release_error=True))
        self.assertEqual(device.calls[-2:],["release","dispose"])
        self.assertTrue(self.state["usb_handle_closed"])

    def test_broken_cleanup_logging_still_releases_and_disposes(self):
        device=Device()
        def log(event,**fields):
            if event in ("usb_release","usb_dispose"):
                raise BrokenPipeError("log closed")
        with patch.object(b,"emit",log):
            state=self.notify(device)
        self.assertTrue(state["logging_errors"])
        self.assertEqual(device.calls[-2:],["release","dispose"])

    def exercise(self, device, before=SERVICE, after=AFTER, failed_read=None):
        calls=[]
        values={"devices":"List of devices attached\nunit-device\tdevice\n",
                "service-before":before, "desktop-before":DESKTOP,
                "service-after":after, "desktop-after":DESKTOP}
        def read(out,name,argv,seconds,**kwargs):
            calls.append((name,argv,seconds))
            if name==failed_read:
                raise RuntimeError("simulated "+name)
            return values[name]
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(b,"read_adb",side_effect=read), \
             patch.object(b,"find_usb",return_value=(device,Util(device))) as discovery, \
             patch.object(b.time,"sleep") as pause:
            rc=b.experiment(Path(folder),3,2)
            result=json.loads((Path(folder)/"result.json").read_text())
        return rc,result,calls,discovery.call_count,pause.call_count

    def test_experiment_success_has_exact_five_adb_commands(self):
        device=Device()
        rc,result,calls,discoveries,pauses=self.exercise(device)
        self.assertEqual(rc,0)
        self.assertTrue(result["bootstrap_observed"])
        self.assertFalse(result["phone_teardown_attempted"])
        self.assertEqual([x[0] for x in calls],
                         ["devices","service-before","desktop-before","service-after","desktop-after"])
        self.assertEqual([x[2] for x in calls],[5,15,15,15,15])
        self.assertEqual((discoveries,pauses),(1,1))

    def test_preflight_refusal_does_not_discover_usb(self):
        device=Device()
        rc,result,calls,discoveries,pauses=self.exercise(device,before=AFTER)
        self.assertEqual(rc,1)
        self.assertEqual((len(calls),discoveries,pauses),(3,0,0))
        self.assertEqual(device.calls,[])

    def test_read_error_before_write_prevents_usb(self):
        rc,result,calls,discoveries,pauses=self.exercise(Device(),failed_read="service-before")
        self.assertEqual(rc,1)
        self.assertEqual((len(calls),discoveries,pauses),(2,0,0))

    def test_failed_write_still_gets_both_after_snapshots(self):
        device=Device(partial=True)
        rc,result,calls,discoveries,pauses=self.exercise(device)
        self.assertEqual(rc,1)
        self.assertEqual(len(calls),5)
        self.assertEqual(device.calls.count("write"),1)
        self.assertTrue(result["phone_state_may_be_retained"])

    def test_persistent_log_failure_after_write_still_reads_and_saves_results(self):
        device=Device()
        original_write=device.write
        broken=[False]
        def write(*args,**kwargs):
            count=original_write(*args,**kwargs)
            broken[0]=True
            return count
        device.write=write
        def emit(event,**fields):
            if broken[0]:
                raise BrokenPipeError("persistent closed stdout")
        calls=[]
        values=["List of devices attached\nunit-device\tdevice\n",
                SERVICE,DESKTOP,AFTER,DESKTOP]
        def run(argv,timeout):
            calls.append((argv,timeout))
            return dict(returncode=0,timed_out=False,stdout=values[len(calls)-1],stderr="")
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(b,"emit",emit), \
             patch.object(b.dex_probe,"run",side_effect=run), \
             patch.object(b,"find_usb",return_value=(device,Util(device))), \
             patch.object(b.time,"sleep"):
            rc=b.experiment(Path(folder),3,2)
            result=json.loads((Path(folder)/"result.json").read_text())
            self.assertTrue((Path(folder)/"service-after.json").exists())
            self.assertTrue((Path(folder)/"desktop-after.json").exists())
        self.assertEqual(rc,1)  # Do not report complete success with a broken transcript.
        self.assertEqual(len(calls),5)
        self.assertEqual(device.calls[-2:],["release","dispose"])
        self.assertTrue(result["usb"]["logging_errors"])
        self.assertTrue(result["phone_state_may_be_retained"])

    def test_after_snapshot_failure_does_not_skip_other_snapshot(self):
        rc,result,calls,discoveries,pauses=self.exercise(Device(),failed_read="service-after")
        self.assertEqual(rc,1)
        self.assertEqual(len(calls),5)
        self.assertEqual(calls[-1][0],"desktop-after")


if __name__=="__main__":
    unittest.main()
