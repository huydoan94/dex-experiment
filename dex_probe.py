#!/usr/bin/env python3
"""Read-only USB/ADB reconnaissance for a Samsung DeX Linux prototype."""
import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import sys

VERSION = "0.1.0"
PROPERTIES = (
    "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.version.oneui", "ro.build.version.incremental",
)
PACKAGES = (
    "com.sec.android.app.dexonpc", "com.sec.android.desktopmode.uiservice",
    "com.sec.android.app.desktoplauncher",
)


def run(argv, timeout=15):
    """No host shell; a failed or hanging probe must not prevent other probes."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        return {"returncode": proc.returncode, "stdout": proc.stdout,
                "stderr": proc.stderr, "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "Probe timed out",
                "timed_out": True}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc),
                "timed_out": False}


def devices_from_output(output):
    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("List of devices", "*")):
            continue
        fields = line.split()
        if len(fields) >= 2:
            devices.append((fields[0], fields[1]))
    return devices


def select_device(devices, requested=None):
    if requested:
        matches = [d for d in devices if d[0] == requested]
        if not matches:
            raise ValueError("Requested device not found.")
        if matches[0][1] != "device":
            raise ValueError("Requested device is not authorized/online; unlock it and approve USB debugging.")
        return requested
    # Never choose silently when another attached device is present.
    if len(devices) != 1:
        raise ValueError("Connect exactly one phone, or use --serial SERIAL to select it.")
    if devices[0][1] != "device":
        raise ValueError("Phone is not authorized/online; unlock it and approve USB debugging.")
    return devices[0][0]


def samsung_usb(root=pathlib.Path("/sys/bus/usb/devices")):
    result = []
    def read(path):
        try:
            return path.read_text().strip()
        except OSError:
            return None
    for path in sorted(root.glob("*")):
        if read(path / "idVendor") != "04e8":
            continue
        item = {"port": path.name, "vendor_id": "04e8",
                "product_id": read(path / "idProduct"),
                "product": read(path / "product"), "speed_mbps": read(path / "speed"),
                "interfaces": []}
        for interface in sorted(root.glob(path.name + ":*")):
            item["interfaces"].append({
                "interface": interface.name,
                "class": read(interface / "bInterfaceClass"),
                "subclass": read(interface / "bInterfaceSubClass"),
                "protocol": read(interface / "bInterfaceProtocol"),
            })
        result.append(item)
    return result


def redact(value, identifiers):
    """Remove known device identifiers from serialized diagnostic text."""
    if isinstance(value, dict):
        return {k: redact(v, identifiers) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, identifiers) for v in value]
    if isinstance(value, str):
        for identifier in sorted(set(identifiers), key=len, reverse=True):
            if identifier:
                value = value.replace(identifier, "[device-id]")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="Select a particular ADB device; not saved in report")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("dex-report.json"))
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("Output already exists; choose a fresh --output path.")
    report = {"schema_version": 1, "probe_version": VERSION,
              "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "samsung_usb": samsung_usb(), "probes": {}}
    adb = shutil.which("adb")
    identifiers = []
    code = 0
    if not adb:
        report["error"] = "adb is not installed. Install the Debian adb package, then rerun."
        code = 2
    else:
        listing = run([adb, "devices"])
        devices = devices_from_output(listing["stdout"])
        identifiers = [d[0] for d in devices]
        report["device_states"] = [d[1] for d in devices]
        report["adb_listing"] = listing
        try:
            serial = select_device(devices, args.serial)
        except ValueError as exc:
            report["error"] = str(exc)
            code = 2
        else:
            def probe(name, command):
                print("Reading " + name + "...", flush=True)
                report["probes"][name] = run([adb, "-s", serial, "shell", *command])
            for prop in PROPERTIES:
                probe(prop, ["getprop", prop])
            for package in PACKAGES:
                probe("package_path:" + package, ["pm", "path", package])
            probe("services", ["dumpsys", "-l"])
            probe("desktopmode", ["dumpsys", "desktopmode"])
            probe("display", ["dumpsys", "display"])
            probe("desktopmode_help", ["cmd", "desktopmode", "help"])
            probe("display_help", ["cmd", "display", "help"])
            report["assessment"] = (
                "Collection completed; service errors and permission denials are retained. "
                "This does not demonstrate DeX activation or loopback support."
            )
    # ADB's known serial and USB serial attributes are omitted/redacted. Service
    # dumps can still contain app names, display names and network addresses.
    for usb in pathlib.Path("/sys/bus/usb/devices").glob("*/serial"):
        try:
            if (usb.parent / "idVendor").read_text().strip() == "04e8":
                identifiers.append(usb.read_text().strip())
        except OSError:
            pass
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(redact(report, identifiers), handle, indent=2)
        handle.write("\n")
    print("Saved " + str(args.output))
    if "error" in report:
        print(report["error"], file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
