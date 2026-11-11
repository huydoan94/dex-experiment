"""Validate approved RTSP SETUP snapshot and select USB identity inside outer timeout."""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import time

EXPECTED = {
    'auto_confirm_launch.py': 'd940b3ca589fe15983e2f39c54f1df2eebd7de908aea62fcec072a404d19778b',
    'ui_confirm.py': 'dcc55d9ab5866842370f6dd39f84f803a0ba0e3c1ae050be7d6edf48058c0394',
    "rtsp_setup.py": "9d2acc07e2ea07a039a2c1020ac3995227f3f77cb74f0f553d54c38bc4ebe238",
    "rtsp_capabilities.py": "0ea945fea841680ce14d58f435e5adcaa90e7100505e3ea4650b42e4a088a7d4",
    'rtsp_hello.py': 'f3d487c194cb51d5041942ce3599928148d8b10cb6db88ea9cd71ea54a00db3b',
    'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
    "wfd_startup.py": "150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df",
    "idc_handshake.py": "1826c43df350a83531547887444a88fc6aa91e9c36200c62e5758b3616514d6e",
    "idc.py": "b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6",
    "usb_tunnel.py": "c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b",
    "tcp_control.py": "5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1",
    "idc_capture.py": "0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647",
    "loopback_transfer.py": "a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6",
    "auth_probe.py": "3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6",
}


def main(argv=None):
    started_at=time.monotonic()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-setup", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    mode=p.add_mutually_exclusive_group()
    mode.add_argument("--ready-for-start-now", action="store_true")
    mode.add_argument("--approved-auto-start-now", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_rtsp_setup:
        print("PLAN_ONLY: no phone access; run only through rtsp_setup_once.sh", flush=True)
        return 0
    if (not a.accept_persistent_state
            or not (a.ready_for_start_now or a.approved_auto_start_now) or a.output is None):
        p.error("requires persistent-state acceptance, confirmation mode and new output")
    if a.output.exists():
        raise FileExistsError("output already exists")
    root = Path("research/native-usb")
    for name, digest in EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("approved source mismatch: " + name)
    raise RuntimeError("TCP-interleaved SETUP disabled: confirmed Samsung RTPSender abort")


if __name__ == "__main__":
    raise SystemExit(main())
