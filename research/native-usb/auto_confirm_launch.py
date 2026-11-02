"""Validate approved automatic-confirmation snapshot and select USB identity inside outer timeout."""
import argparse
import hashlib
import os
import socket
from pathlib import Path
import sys
import time

EXPECTED = {
    'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
    'rtsp_hello.py': 'f3d487c194cb51d5041942ce3599928148d8b10cb6db88ea9cd71ea54a00db3b',
    'rtsp_capabilities.py': 'febeddd3205c547df005b32007d489df2d555343065c364f521e19ad6e090fdf',
    'auto_confirm_probe.py': '745c903a5b05fd69a13700f8fccd8188246899e5b58d826b6c3a8a457eab4a5e',
    'ui_confirm.py': 'dc065406b6ca0b94a236f67fb8ace558c3a1f6e250262475c08a26e3b6292de6',
    "wfd_startup.py": "150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df",
    "idc_handshake.py": "526474bb455280d931d78aef32c834485e656d781f71b8c3369f979d798c7036",
    "idc.py": "a36d6974c787944c093290a5e929a5ac9bdb39ee8f52030cbc05006389590557",
    "usb_tunnel.py": "c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b",
    "tcp_control.py": "5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1",
    "idc_capture.py": "0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647",
    "loopback_transfer.py": "a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6",
    "auth_probe.py": "3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6",
}



def require_adb_server():
    """Check only the backend machine TCP endpoint; do not send ADB/device commands."""
    try:
        with socket.create_connection(("127.0.0.1",5037),timeout=.5):
            pass
    except OSError as error:
        raise RuntimeError("container ADB server unavailable; prepare it under a fresh phone grant") from error


def main(argv=None):
    started_at = time.monotonic()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-auto-start-now", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--approved-udp-capabilities", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_auto_start_now:
        print("PLAN_ONLY: no phone access; run only through auto_confirm_once.sh", flush=True)
        return 0
    if not a.accept_persistent_state or a.output is None:
        p.error("requires persistent-state acceptance and new output")
    if a.output.exists():
        raise FileExistsError("output already exists")
    # Leave15s before the outer90s limit for remote timeout/cleanup.
    os.environ["DEX_AUTO_UI_DEADLINE"] = str(started_at + 75)
    root = Path("research/native-usb")
    for name, digest in EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("approved source mismatch: " + name)
    require_adb_server()
    import usb.core
    phones = list(usb.core.find(find_all=True, idVendor=0x0000, idProduct=0x0000))
    if len(phones) != 1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone = phones[0]
    print("SELECTED_USB bus=%03d address=%03d" % (phone.bus, phone.address), flush=True)
    print("AUTO_CONFIRM_OUTPUT_DIR=" + str(a.output), flush=True)
    stage_flags=["--approved-udp-capabilities"] if a.approved_udp_capabilities else []
    os.execv(sys.executable, [sys.executable, str(root/"auto_confirm_probe.py"),
        "--approved-phone-auto-start-now", "--accept-persistent-state",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output)]+stage_flags)


if __name__ == "__main__":
    raise SystemExit(main())
