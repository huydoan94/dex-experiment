"""Validate approved long live PLAY snapshot, FIFO and stop path, then select USB identity inside outer timeout."""
import argparse
import hashlib
import os
import socket
import stat
from pathlib import Path
import sys
import time

EXPECTED = {'duplex_link.py': 'e9cc017b3d0b2106ddaacd7daa6d27cc3a4cbcfe57ae613203a1da9b237c46d0', 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4', 'rtsp.py': 'b4ae5bb775b5aa908787ad0b8fef3ed35c6e7270c831872b1507a68972d830c0', 'rtsp_hello.py': '0af2962ffdd5458ddf1121a74f70a47b44660c71b94325c3339f00b7a6ea63f8', 'rtsp_capabilities.py': '751c6ecd628906a257e27680efc3737a46d32db37e3cdeac5d641edcc169a12d', 'rtsp_setup.py': '9d2acc07e2ea07a039a2c1020ac3995227f3f77cb74f0f553d54c38bc4ebe238', 'rtsp_udp_setup.py': 'e926b95bdfde5cb7fde209fa44d3db5986c6d0a67863b57e8b609cf786af83f1', 'ui_confirm.py': 'dcc55d9ab5866842370f6dd39f84f803a0ba0e3c1ae050be7d6edf48058c0394', 'wfd_startup.py': 'bb03b53d7761ff06ae1d3ebf475c2d10dabdc5a536500b414a89dc6614c2311c', 'idc_handshake.py': '6560f0896ffd2e8f81c1a47f02623a67d7496846412aad24c0fd7e6c420c84db', 'idc.py': 'b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6', 'usb_tunnel.py': 'c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b', 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1', 'udp_tunnel.py': 'fa9a7ce9f0657279b05662335b0860f53a2125849b8bbf5a174a9d8833628d04', 'idc_capture.py': 'b73f0438dfd4a88310dd1e122b4ba4f9584e085af9a71d878d5f37dc2676cfd8', 'loopback_transfer.py': 'a04144f328dc9a626bfa72af093de7105e261484d32a1270cb77a713a5d6ac2f', 'loopback_capture.py': 'e29e9074eb3e6db1e91b0124303906d80fcb0a02d8ef8e84bad9ea79603908a4', 'auth_probe.py': '56b1d6a4c36a11a27db8469c14fcb02c5187bc151b2a1c6b3982cceae0783b8e', 'capabilities_probe.py': 'f9a3ab2a8fa01d48c986e7a8d70fc9174470c0508637f55982e85bf599c0e5f6', 'pss_probe.py': 'b882fc41e06291b8b2f446d22d95878883a9b752459aa4a81eda24279702e356', 'tunnel_probe.py': '3a55ae78816995aeb3113cc5158f9d598ee1a1cc943a696eb6b5efee3c884c7e', 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1', 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a', 'version_query.py': '3a393f2c1e99761510f590a6da4790fe242be5a03b60024f15e9c03d0d4c15b8', 'rtsp_udp_play.py': '18ab29b2a6780dc803702268fa2b36557269f39a5758ef8d69a1d3db84ffa2a1', 'conn_transfer.py': 'cc681c6ca5b7a0117d8f017e6538d511bc3f27bc6ad9049e4b52467f18f6d6cf', 'rtsp_udp_live.py': 'a66248078833f8429042715e1980a9dc6f10f67e3cab47cc818e2840960d157f', 'live_sink.py': 'ad6054c773fcfe1c63473757469bdf1ccc74eb1c965805d77e9f4617139b0a73', 'rtsp_udp_long.py': 'efe5132db7bc8c82bafc1c81cbfd8eb1f5c4d51c512acc8b671ff73560c23dc3', 'kms_mouse_live.py': '5576f8d1261f388f941b6d7b5221728fc4626b96c5e30214322c1f18dc571cf9', 'kms_handshake.py': '47a530360a186008f313eaa68ff89ad151ad5ab8fd844d7dd1027d0340924ac2', 'sidesync_packets.py': 'a382472f8d5e6ff8c8901371efe946937137017bae27d2fe7058a5af24738ce9', 'kms_hover_live.py': '5096acb84dd28d7691d9a8fdc5eb1e5505160fd97ba2e0526d46feb4360bea09', 'kms_input_live.py': '9d560161d09a9094d4849f44fb0d436abb0abbc8ff407f50d6efdfb7acf553b1', 'kms_input_live_probe.py': '2d96674ae47fed5258079eda8876efc4fe2afcd2df247b97a83055ef11d617f2', 'kms_input_live_once.sh': '3644efdacc1c6f62121faa5e5f5e5fcb2f6996367a885ea93f2d12911bba4cc9'}


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
    p.add_argument("--approved-phone-kms-input-live", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--output", type=Path)
    p.add_argument("--ts-fifo", type=Path)
    p.add_argument("--stop-file", type=Path)
    p.add_argument("--input-fifo", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_kms_input_live:
        print("PLAN_ONLY: no phone access; run only through kms_input_live_once.sh", flush=True)
        return 0
    if (not a.accept_persistent_state or a.output is None or a.ts_fifo is None
            or a.stop_file is None or a.input_fifo is None):
        p.error("requires persistent-state acceptance, new output, ts-fifo, stop-file and input-fifo")
    # Media must only ever reach a pipe to the viewer, never a regular file.
    if not stat.S_ISFIFO(os.lstat(a.ts_fifo).st_mode):
        raise RuntimeError("ts-fifo is not an existing FIFO")
    # The stop path lives beside the FIFO and must not exist yet, or the run would end at once.
    if a.stop_file.parent != a.ts_fifo.parent or os.path.lexists(a.stop_file):
        raise RuntimeError("stop-file must be a new path in the FIFO directory")
    if a.input_fifo.parent != a.ts_fifo.parent or not stat.S_ISFIFO(os.lstat(a.input_fifo).st_mode):
        raise RuntimeError("input-fifo must be an existing FIFO in the FIFO directory")
    if a.output.exists():
        raise FileExistsError("output already exists")
    # Leave15s before the outer limit for remote timeout/cleanup.
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
    print("KMS_INPUT_LIVE_OUTPUT_DIR=" + str(a.output), flush=True)
    os.execv(sys.executable, [sys.executable, str(root/"kms_input_live_probe.py"),
        "--approved-phone-kms-input-live", "--accept-persistent-state",
        "--bus", str(phone.bus), "--address", str(phone.address), "--output", str(a.output),
        "--ts-fifo", str(a.ts_fifo), "--stop-file", str(a.stop_file),
        "--input-fifo", str(a.input_fifo)])


if __name__ == "__main__":
    raise SystemExit(main())
