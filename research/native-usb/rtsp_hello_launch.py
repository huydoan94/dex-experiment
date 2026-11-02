"""Validate approved RTSP hello snapshot and select USB identity inside outer timeout."""
import argparse
import hashlib
import os
from pathlib import Path
import sys

EXPECTED = {
    'rtsp_hello.py': 'f3d487c194cb51d5041942ce3599928148d8b10cb6db88ea9cd71ea54a00db3b',
    'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
    "wfd_startup.py": "150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df",
    "idc_handshake.py": "526474bb455280d931d78aef32c834485e656d781f71b8c3369f979d798c7036",
    "idc.py": "a36d6974c787944c093290a5e929a5ac9bdb39ee8f52030cbc05006389590557",
    "usb_tunnel.py": "c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b",
    "tcp_control.py": "5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1",
    "idc_capture.py": "0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647",
    "loopback_transfer.py": "a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6",
    "auth_probe.py": "3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6",
}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-hello", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--ready-for-start-now", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_rtsp_hello:
        print("PLAN_ONLY: no phone access; run only through rtsp_hello_once.sh", flush=True)
        return 0
    if not a.accept_persistent_state or not a.ready_for_start_now or a.output is None:
        p.error("requires persistent-state acceptance, manual readiness and new output")
    if a.output.exists():
        raise FileExistsError("output already exists")
    root = Path("research/native-usb")
    for name, digest in EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("approved source mismatch: " + name)
    import usb.core
    phones = list(usb.core.find(find_all=True, idVendor=0x0000, idProduct=0x0000))
    if len(phones) != 1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone = phones[0]
    print("SELECTED_USB bus=%03d address=%03d" % (phone.bus, phone.address), flush=True)
    print("RTSP_HELLO_OUTPUT_DIR=" + str(a.output), flush=True)
    os.execv(sys.executable, [sys.executable, str(root/"rtsp_hello.py"),
        "--approved-phone-rtsp-hello", "--accept-persistent-state", "--ready-for-start-now",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output)])


if __name__ == "__main__":
    raise SystemExit(main())
