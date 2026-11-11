"""Validate approved RTSP capabilities snapshot and select USB identity inside outer timeout."""
import argparse
import hashlib
import os
from pathlib import Path
import sys

EXPECTED = {
    "rtsp_capabilities.py": "751c6ecd628906a257e27680efc3737a46d32db37e3cdeac5d641edcc169a12d",
    'rtsp_hello.py': '0af2962ffdd5458ddf1121a74f70a47b44660c71b94325c3339f00b7a6ea63f8',
    'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
    "wfd_startup.py": "bb03b53d7761ff06ae1d3ebf475c2d10dabdc5a536500b414a89dc6614c2311c",
    "idc_handshake.py": "6560f0896ffd2e8f81c1a47f02623a67d7496846412aad24c0fd7e6c420c84db",
    "idc.py": "b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6",
    "usb_tunnel.py": "e4835e708921672a012be58e19a1fb276301c15a7a26c1e6715d76c108238133",
    "tcp_control.py": "5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1",
    "idc_capture.py": "b73f0438dfd4a88310dd1e122b4ba4f9584e085af9a71d878d5f37dc2676cfd8",
    "loopback_transfer.py": "a04144f328dc9a626bfa72af093de7105e261484d32a1270cb77a713a5d6ac2f",
    "auth_probe.py": "56b1d6a4c36a11a27db8469c14fcb02c5187bc151b2a1c6b3982cceae0783b8e",
}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-capabilities", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--ready-for-start-now", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_rtsp_capabilities:
        print("PLAN_ONLY: no phone access; run only through rtsp_capabilities_once.sh", flush=True)
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
    phones = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860))
    if len(phones) != 1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone = phones[0]
    print("SELECTED_USB bus=%03d address=%03d" % (phone.bus, phone.address), flush=True)
    print("RTSP_HELLO_OUTPUT_DIR=" + str(a.output), flush=True)
    os.execv(sys.executable, [sys.executable, str(root/"rtsp_capabilities.py"),
        "--approved-phone-rtsp-capabilities", "--accept-persistent-state", "--ready-for-start-now",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output)])


if __name__ == "__main__":
    raise SystemExit(main())
