"""Default-off, one-shot DeX app notification; may leave the control server running."""
import argparse
import json
from pathlib import Path
import re
import shlex
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import dex_probe
from version_query import emit, validate_config

SERVICE = "com.sec.android.app.dexonpc/.service.DOPService"
SERVICE_COMMAND = ["dumpsys", "activity", "service", SERVICE]
DESKTOP_COMMAND = ["dumpsys", "desktopmode"]


def payload():
    text = b"dop pc app start"
    return struct.pack("<4sIII256s", b"CONN", 12, 272, 3, text)


def field(text, name, equals=r"\s*=\s*"):
    matches = re.findall(r"^\s*" + re.escape(name) + equals + r"([^\r\n]+?)\s*$",
                         text, re.MULTILINE)
    values = set(matches)
    if len(values) != 1:
        raise ValueError("missing/conflicting field: " + name)
    return values.pop()


def desktop_inactive(text):
    for name in ("mDualModeEnabled", "mStandaloneModeEnabled", "mIsWirelessDexEntered"):
        if field(text, name) != "false":
            raise ValueError("desktop mode already active or unknown: " + name)
    if field(text, "mDesktopDisplayId") != "-1":
        raise ValueError("desktop display already exists")


def service_pid(text):
    matches = re.findall(r"^SERVICE\s+" + re.escape(SERVICE) +
                         r"\s+\S+\s+pid=(\d+)\s+user=0\s*$", text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("expected exactly one primary-user DOPService instance")
    return int(matches[0])


def preflight(service, desktop):
    desktop_inactive(desktop)
    pid = service_pid(service)
    expected = {
        "mPackageVersion": "2.5.00.16",
        "mDOPServiceRunning": "true",
        "ConnectionUtil.isUsbConnected()": "true",
        "dexonpc_connection_state": "SETTING_SOURCE_CONNECT_USB(1)",
        "gsSWVersion": "2.17.21.0",
        "gsSetMode": "true",
    }
    for name, value in expected.items():
        if field(service, name) != value:
            raise ValueError("unsupported baseline: " + name)
    if field(service, "Current g state", equals=r":\s*") != "no instance":
        raise ValueError("main-server manager exists; refusing notification")
    return pid


def observed(service, desktop, baseline_pid):
    if service_pid(service) != baseline_pid:
        raise ValueError("DOPService process changed")
    desktop_inactive(desktop)
    # A manager/transport object is evidence of startup, not proof of LISTEN or DeX.
    if not re.search(r"^\s*Current g state:\s*$", service, re.MULTILINE):
        raise ValueError("main-server manager was not observed")
    if field(service, "mMainServer.isConnected", equals=r"\s*=\s*") != "false":
        raise ValueError("main server connected or unexpected; no teardown attempted")
    return {"main_server_manager_initialized": True, "tcp_listener_verified": False,
            "dex_activation_observed": False, "phone_app_state_retained": True}


def find_usb(bus, address):
    # No USB import/discovery before main's two explicit approval acknowledgments.
    import usb.core
    import usb.util
    emit("usb_find", vendor=1256, product=26720, bus=bus, address=address)
    devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                bus=bus, address=address))
    if len(devices) != 1:
        raise ValueError("expected one matching USB device; refusing alternatives")
    return devices[0], usb.util


def diagnostic_log(state, event, **fields):
    """A broken transcript must not prevent safe readback or resource cleanup."""
    try:
        emit(event, **fields)
    except (OSError, ValueError) as error:
        state.setdefault("logging_errors", []).append(event + ": " + str(error))


def notify(device, util, expected_serial, state):
    claimed = False
    try:
        emit("usb_read_serial_for_identity_match")
        if device.serial_number != expected_serial:
            raise ValueError("ADB and USB identities differ")
        emit("usb_get_active_configuration")
        validate_config(device.get_active_configuration())
        emit("usb_kernel_driver_check", interface=3)
        if device.is_kernel_driver_active(3):
            raise ValueError("interface3 has a kernel driver; refusing detach")
        emit("usb_claim", interface=3)
        util.claim_interface(device, 3)
        claimed = True
        packet = payload()
        emit("usb_bulk_write", endpoint=3, size_bytes=len(packet),
             timeout_ms=1000, bytes_hex=packet.hex())
        state["write_attempted"] = True  # Timeout/partial write can still have phone effects.
        count = device.write(3, packet, timeout=1000)
        state["bytes_written"] = int(count)
        diagnostic_log(state, "usb_bulk_write_result", size_bytes=int(count))
        if count != len(packet):
            raise RuntimeError("partial notification write; NEVER retry")
    finally:
        try:
            if claimed:
                try:
                    diagnostic_log(state, "usb_release", interface=3)
                finally:
                    util.release_interface(device, 3)
                state["interface_released"] = True
        finally:
            try:
                diagnostic_log(state, "usb_dispose")
            finally:
                util.dispose_resources(device)
            state["usb_handle_closed"] = True


def read_adb(out, name, argv, timeout_seconds, *, diagnostics_state=None):
    def log(event, **fields):
        if diagnostics_state is None:
            emit(event, **fields)  # Fail closed before any USB write.
        else:
            diagnostic_log(diagnostics_state, event, **fields)
    log("phone_read_command", name=name, argv=shlex.join(argv),
        timeout_seconds=timeout_seconds)
    result = dex_probe.run(argv, timeout=timeout_seconds)
    (out / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    log("phone_read_result", name=name, **result)
    if result["timed_out"] or result["returncode"] != 0:
        raise RuntimeError("failed phone command: " + name)
    return result["stdout"]


def experiment(out, bus, address):
    state = {"write_attempted": False, "bytes_written": None,
             "interface_released": False, "usb_handle_closed": False}
    errors = []
    after = {}
    baseline_pid = None
    serial = None
    try:
        listing = read_adb(out, "devices", ["adb", "devices"], 5)
        serial = dex_probe.select_device(dex_probe.devices_from_output(listing))
        service = read_adb(out, "service-before", ["adb", "-s", serial, "shell",
                           *SERVICE_COMMAND], 15)
        desktop = read_adb(out, "desktop-before", ["adb", "-s", serial, "shell",
                           *DESKTOP_COMMAND], 15)
        baseline_pid = preflight(service, desktop)
        (out / "notification.bin").write_bytes(payload())
        device, util = find_usb(bus, address)
        notify(device, util, serial, state)
    except Exception as error:
        errors.append(str(error))
        diagnostic_log(state, "experiment_error", error=str(error))
    finally:
        if state["write_attempted"]:
            # Also collect both readbacks after partial writes/errors. No payload retries.
            time.sleep(2)
            for name, command in (("service-after", SERVICE_COMMAND),
                                  ("desktop-after", DESKTOP_COMMAND)):
                try:
                    after[name] = read_adb(out, name, ["adb", "-s", serial, "shell",
                                          *command], 15, diagnostics_state=state)
                except Exception as error:
                    errors.append(str(error))
    result = {"bootstrap_observed": False, "errors": errors, "usb": state,
              "phone_state_may_be_retained": state["write_attempted"],
              "phone_teardown_attempted": False, "dex_activation_tested": False}
    if not errors:
        try:
            result.update(observed(after["service-after"], after["desktop-after"], baseline_pid))
            result["bootstrap_observed"] = True
        except Exception as error:
            errors.append(str(error))
    diagnostic_log(state, "experiment_result", **result)
    if state.get("logging_errors"):
        errors.append("transcript logging failed; inspect saved readback files")
        result["bootstrap_observed"] = False
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["bootstrap_observed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phone-bootstrap-approved", action="store_true")
    parser.add_argument("--retain-started-service", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bus", type=int, default=3)
    parser.add_argument("--address", type=int, default=2)
    args = parser.parse_args(argv)
    if not args.phone_bootstrap_approved:
        emit("PLAN_ONLY", phone_access=False, max_usb_writes=1,
             notification_bytes=272, max_adb_commands=5, outer_timeout_seconds=90,
             retained_state="New phone control server/listeners may keep running; no automatic teardown")
        return 0
    if not args.retain_started_service or args.output is None:
        parser.error("approval must explicitly cover retained phone service state; require --retain-started-service and fresh --output")
    if not 1 <= args.bus <= 255 or not 1 <= args.address <= 127:
        parser.error("invalid USB bus/address")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.output / "plan.json").write_text(json.dumps({
        "max_usb_writes": 1, "packet_bytes": 272, "max_adb_commands": 5,
        "bus": args.bus, "address": args.address, "outer_timeout_seconds": 90,
        "retain_started_service_explicitly_acknowledged": True,
        "host_attached": False, "tcp_connection_or_auth": False}, indent=2) + "\n")
    return experiment(args.output, args.bus, args.address)


if __name__ == "__main__":
    raise SystemExit(main())
