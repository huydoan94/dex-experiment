"""Pin the KMS discovery snapshot before USB selection; default has no phone I/O."""
import argparse
import hashlib
import os
from pathlib import Path
import socket
import sys
import time

EXPECTED = {'auth_probe.py': '56b1d6a4c36a11a27db8469c14fcb02c5187bc151b2a1c6b3982cceae0783b8e', 'capabilities_probe.py': 'f9a3ab2a8fa01d48c986e7a8d70fc9174470c0508637f55982e85bf599c0e5f6', 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1', 'conn_transfer.py': 'cc681c6ca5b7a0117d8f017e6538d511bc3f27bc6ad9049e4b52467f18f6d6cf', 'idc.py': 'b42bc257c1f8045682636b731a990754048ea954225ccbbbe6dcd8d339e6c2d6', 'idc_capture.py': 'b73f0438dfd4a88310dd1e122b4ba4f9584e085af9a71d878d5f37dc2676cfd8', 'idc_handshake.py': '6560f0896ffd2e8f81c1a47f02623a67d7496846412aad24c0fd7e6c420c84db', 'kms_discovery.py': 'd0b16ae0fb5255d100b403d94117dccdb46231fc00fdcea9dd56a483eb62138c', 'kms_discovery_once.sh': 'e593d832c9e2358602a84f8ce738e8559d189a687c485099d056ddca01a249fa', 'kms_discovery_probe.py': '8b806820fb796b905c31e3737b5f5156fe291636420b1f23f3a95f527238d0f4', 'loopback_capture.py': 'e29e9074eb3e6db1e91b0124303906d80fcb0a02d8ef8e84bad9ea79603908a4', 'loopback_transfer.py': 'a04144f328dc9a626bfa72af093de7105e261484d32a1270cb77a713a5d6ac2f', 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a', 'pss_probe.py': 'b882fc41e06291b8b2f446d22d95878883a9b752459aa4a81eda24279702e356', 'sidesync_packets.py': 'a382472f8d5e6ff8c8901371efe946937137017bae27d2fe7058a5af24738ce9', 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1', 'tunnel_probe.py': '3a55ae78816995aeb3113cc5158f9d598ee1a1cc943a696eb6b5efee3c884c7e', 'ui_confirm.py': 'dcc55d9ab5866842370f6dd39f84f803a0ba0e3c1ae050be7d6edf48058c0394', 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4', 'usb_tunnel.py': 'c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b', 'version_query.py': '3a393f2c1e99761510f590a6da4790fe242be5a03b60024f15e9c03d0d4c15b8', 'wfd_startup.py': 'bb03b53d7761ff06ae1d3ebf475c2d10dabdc5a536500b414a89dc6614c2311c'}


def verify_sources(root):
    for name,digest in EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError("approved source mismatch: "+name)


def main(argv=None):
    started=time.monotonic()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-phone-kms-discovery",action="store_true")
    parser.add_argument("--accept-persistent-state",action="store_true")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args(argv)
    if not args.approved_phone_kms_discovery:
        print("PLAN_ONLY: no phone access; use kms_discovery_once.sh",flush=True)
        return 0
    if not args.accept_persistent_state or args.output is None:
        parser.error("requires persistent-state acceptance and output")
    if args.output.exists():
        raise FileExistsError("output already exists")
    root=Path("research/native-usb")
    verify_sources(root)
    # TCP endpoint check only; no ADB request and no server start/restart.
    with socket.create_connection(("127.0.0.1",5037),timeout=.5):
        pass
    os.environ["DEX_AUTO_UI_DEADLINE"]=str(started+75)
    import usb.core
    phones=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860))
    if len(phones)!=1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone=phones[0]
    print("SELECTED_USB bus=%03d address=%03d"%(phone.bus,phone.address),flush=True)
    os.execv(sys.executable,[sys.executable,str(root/"kms_discovery_probe.py"),
        "--approved-phone-kms-discovery","--accept-persistent-state",
        "--bus",str(phone.bus),"--address",str(phone.address),"--output",str(args.output)])


if __name__=="__main__":
    raise SystemExit(main())
