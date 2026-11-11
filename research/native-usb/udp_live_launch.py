"""Validate approved live PLAY snapshot and FIFO, then select USB identity inside outer timeout."""
import argparse
import hashlib
import os
import socket
import stat
from pathlib import Path
import sys
import time

EXPECTED = {'duplex_link.py': 'e9cc017b3d0b2106ddaacd7daa6d27cc3a4cbcfe57ae613203a1da9b237c46d0',
 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4',
 'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
 'rtsp_hello.py': 'f3d487c194cb51d5041942ce3599928148d8b10cb6db88ea9cd71ea54a00db3b',
 'rtsp_capabilities.py': '0ea945fea841680ce14d58f435e5adcaa90e7100505e3ea4650b42e4a088a7d4',
 'rtsp_setup.py': '9d2acc07e2ea07a039a2c1020ac3995227f3f77cb74f0f553d54c38bc4ebe238',
 'rtsp_udp_setup.py': 'e926b95bdfde5cb7fde209fa44d3db5986c6d0a67863b57e8b609cf786af83f1',
 'ui_confirm.py': 'dcc55d9ab5866842370f6dd39f84f803a0ba0e3c1ae050be7d6edf48058c0394',
 'wfd_startup.py': '150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df',
 'idc_handshake.py': '1826c43df350a83531547887444a88fc6aa91e9c36200c62e5758b3616514d6e',
 'idc.py': 'b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6',
 'usb_tunnel.py': 'e4835e708921672a012be58e19a1fb276301c15a7a26c1e6715d76c108238133',
 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1',
 'udp_tunnel.py': 'fa9a7ce9f0657279b05662335b0860f53a2125849b8bbf5a174a9d8833628d04',
 'idc_capture.py': '0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647',
 'loopback_transfer.py': 'a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6',
 'loopback_capture.py': 'ec5ffe6c70eca6e6c937e5b51cc17f27c4154b8072e9f4c0b92342a04fa0a267',
 'auth_probe.py': '3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6',
 'capabilities_probe.py': '368005a3113d4fcbf9eccaf3ffe176c8959072b93d61d57bfd2767d2ddaceba2',
 'pss_probe.py': '48874690a939687a193e78e81d56c7370c6fd15bec034e80d58c1896bd53c41b',
 'tunnel_probe.py': '824add622548ccae8f0fbc3633bd5dec5abad986c36b7f1323cb2eeb0ded1f14',
 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1',
 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a',
 'version_query.py': 'bf3b459d624655f6b37074c23876bab20f72275967a36752edf600e5a130a758',
 'rtsp_udp_play.py': '18ab29b2a6780dc803702268fa2b36557269f39a5758ef8d69a1d3db84ffa2a1',
 'conn_transfer.py': 'cc681c6ca5b7a0117d8f017e6538d511bc3f27bc6ad9049e4b52467f18f6d6cf',
 'rtsp_udp_live.py': 'a66248078833f8429042715e1980a9dc6f10f67e3cab47cc818e2840960d157f',
 'live_sink.py': 'ad6054c773fcfe1c63473757469bdf1ccc74eb1c965805d77e9f4617139b0a73',
 'udp_live_probe.py': '3b7d44bd61eb513f20a29a7095239e03d184a11d11ddb41029c42ba513cebc05'}



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
    p.add_argument("--approved-phone-udp-live", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--output", type=Path)
    p.add_argument("--ts-fifo", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_udp_live:
        print("PLAN_ONLY: no phone access; run only through udp_live_once.sh", flush=True)
        return 0
    if not a.accept_persistent_state or a.output is None or a.ts_fifo is None:
        p.error("requires persistent-state acceptance, new output and ts-fifo")
    # Media must only ever reach a pipe to the viewer, never a regular file.
    if not stat.S_ISFIFO(os.lstat(a.ts_fifo).st_mode):
        raise RuntimeError("ts-fifo is not an existing FIFO")
    if a.output.exists():
        raise FileExistsError("output already exists")
    # Leave15s before the outer90s limit for remote timeout/cleanup.
    os.environ["DEX_AUTO_UI_DEADLINE"] = str(started_at + 75)
    if not EXPECTED:
        raise RuntimeError("empty approved source manifest")
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
    print("UDP_LIVE_OUTPUT_DIR=" + str(a.output), flush=True)
    os.execv(sys.executable, [sys.executable, str(root/"udp_live_probe.py"),
        "--approved-phone-udp-live", "--accept-persistent-state",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output),
        "--ts-fifo", str(a.ts_fifo)])


if __name__ == "__main__":
    raise SystemExit(main())
