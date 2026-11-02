"""Validate approved UDP PLAY snapshot and select USB identity inside outer timeout."""
import argparse
import hashlib
import os
import socket
from pathlib import Path
import sys
import time

EXPECTED = {'duplex_link.py': 'e9cc017b3d0b2106ddaacd7daa6d27cc3a4cbcfe57ae613203a1da9b237c46d0',
 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4',
 'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0',
 'rtsp_hello.py': '0af2962ffdd5458ddf1121a74f70a47b44660c71b94325c3339f00b7a6ea63f8',
 'rtsp_capabilities.py': '7df72d5a5cd16a9f8e9995f38e5950bec934f4b62eeec3034760147d77521ebb',
 'rtsp_setup.py': '9d2acc07e2ea07a039a2c1020ac3995227f3f77cb74f0f553d54c38bc4ebe238',
 'rtsp_udp_setup.py': 'e926b95bdfde5cb7fde209fa44d3db5986c6d0a67863b57e8b609cf786af83f1',
 'ui_confirm.py': 'dc065406b6ca0b94a236f67fb8ace558c3a1f6e250262475c08a26e3b6292de6',
 'wfd_startup.py': 'bb03b53d7761ff06ae1d3ebf475c2d10dabdc5a536500b414a89dc6614c2311c',
 'idc_handshake.py': 'c188c4884e6a73428504a3b7045584aa04a2acef39158a0903343e40a573a5ca',
 'idc.py': 'a36d6974c787944c093290a5e929a5ac9bdb39ee8f52030cbc05006389590557',
 'usb_tunnel.py': 'c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b',
 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1',
 'udp_tunnel.py': 'fa9a7ce9f0657279b05662335b0860f53a2125849b8bbf5a174a9d8833628d04',
 'idc_capture.py': 'b73f0438dfd4a88310dd1e122b4ba4f9584e085af9a71d878d5f37dc2676cfd8',
 'loopback_transfer.py': 'a04144f328dc9a626bfa72af093de7105e261484d32a1270cb77a713a5d6ac2f',
 'loopback_capture.py': 'e29e9074eb3e6db1e91b0124303906d80fcb0a02d8ef8e84bad9ea79603908a4',
 'auth_probe.py': '56b1d6a4c36a11a27db8469c14fcb02c5187bc151b2a1c6b3982cceae0783b8e',
 'capabilities_probe.py': 'a4a8426b6be46632a21c8b7e8a8736d2a706d199eedd9a9fc881f0c04fcf7930',
 'pss_probe.py': 'b882fc41e06291b8b2f446d22d95878883a9b752459aa4a81eda24279702e356',
 'tunnel_probe.py': '3a55ae78816995aeb3113cc5158f9d598ee1a1cc943a696eb6b5efee3c884c7e',
 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1',
 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a',
 'version_query.py': '3a393f2c1e99761510f590a6da4790fe242be5a03b60024f15e9c03d0d4c15b8',
 'rtsp_udp_play.py': '18ab29b2a6780dc803702268fa2b36557269f39a5758ef8d69a1d3db84ffa2a1',
 'udp_duplex_probe.py': '14aad933c2a272d80c39bd2eb3191ea611117f28183012782a992caa541a469a'}



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
    p.add_argument("--approved-phone-udp-duplex", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_udp_duplex:
        print("PLAN_ONLY: no phone access; run only through udp_duplex_once.sh", flush=True)
        return 0
    if not a.accept_persistent_state or a.output is None:
        p.error("requires persistent-state acceptance and new output")
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
    phones = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860))
    if len(phones) != 1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone = phones[0]
    print("SELECTED_USB bus=%03d address=%03d" % (phone.bus, phone.address), flush=True)
    print("UDP_DUPLEX_OUTPUT_DIR=" + str(a.output), flush=True)
    os.execv(sys.executable, [sys.executable, str(root/"udp_duplex_probe.py"),
        "--approved-phone-udp-duplex", "--accept-persistent-state",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output)])


if __name__ == "__main__":
    raise SystemExit(main())
