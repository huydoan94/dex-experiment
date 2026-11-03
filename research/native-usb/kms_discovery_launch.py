"""Pin the KMS discovery snapshot before USB selection; default has no phone I/O."""
import argparse
import hashlib
import os
from pathlib import Path
import socket
import sys
import time

EXPECTED = {'auth_probe.py': '3c3b7dfa734a851b4fb162da0cd83189d4575f67a9fc6d009fb3aae7c602acf6', 'capabilities_probe.py': 'a4a8426b6be46632a21c8b7e8a8736d2a706d199eedd9a9fc881f0c04fcf7930', 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1', 'conn_transfer.py': 'cc681c6ca5b7a0117d8f017e6538d511bc3f27bc6ad9049e4b52467f18f6d6cf', 'idc.py': 'a36d6974c787944c093290a5e929a5ac9bdb39ee8f52030cbc05006389590557', 'idc_capture.py': '0d5e64f98886b3680b940ab73bce6e759df701ea0723b6a5880e29fa0eb05647', 'idc_handshake.py': '526474bb455280d931d78aef32c834485e656d781f71b8c3369f979d798c7036', 'kms_discovery.py': 'd0b16ae0fb5255d100b403d94117dccdb46231fc00fdcea9dd56a483eb62138c', 'kms_discovery_once.sh': 'e593d832c9e2358602a84f8ce738e8559d189a687c485099d056ddca01a249fa', 'kms_discovery_probe.py': 'e40b26bfbe8493f328189643622899bb6db207d7419cc00a9ee9ceb6660e331d', 'loopback_capture.py': 'ec5ffe6c70eca6e6c937e5b51cc17f27c4154b8072e9f4c0b92342a04fa0a267', 'loopback_transfer.py': 'a3f36a210708a8f8158ee07594c9ed6ac84eaa4a8af51c8f2b9fca5e05e1c7f6', 'main_channel.py': 'dce673a0ee07298a208e15d6e789e4196d2723d72aafb4a24f3d1c7e82b5979a', 'pss_probe.py': '48874690a939687a193e78e81d56c7370c6fd15bec034e80d58c1896bd53c41b', 'sidesync_packets.py': 'a382472f8d5e6ff8c8901371efe946937137017bae27d2fe7058a5af24738ce9', 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1', 'tunnel_probe.py': '824add622548ccae8f0fbc3633bd5dec5abad986c36b7f1323cb2eeb0ded1f14', 'ui_confirm.py': 'dc065406b6ca0b94a236f67fb8ace558c3a1f6e250262475c08a26e3b6292de6', 'ui_confirm_display0.py': '8fcbca3a7cdd035dd2fa82af9c55eeaa45ec77af69e6ff2f7893e13076d891f4', 'usb_tunnel.py': 'c21fc066271ff90da51d710f0484136a8707be812f75c0f0f4244ef0d8a7367b', 'version_query.py': 'bf3b459d624655f6b37074c23876bab20f72275967a36752edf600e5a130a758', 'wfd_startup.py': '150277552e6c8d9bf5d97e8d65b1c72db64b10f9a0a0fe3156e83d4f7f3054df'}


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
    phones=list(usb.core.find(find_all=True,idVendor=0x0000,idProduct=0x0000))
    if len(phones)!=1:
        raise RuntimeError("expected exactly one Samsung phone; refusing alternatives")
    phone=phones[0]
    print("SELECTED_USB bus=%03d address=%03d"%(phone.bus,phone.address),flush=True)
    os.execv(sys.executable,[sys.executable,str(root/"kms_discovery_probe.py"),
        "--approved-phone-kms-discovery","--accept-persistent-state",
        "--bus",str(phone.bus),"--address",str(phone.address),"--output",str(args.output)])


if __name__=="__main__":
    raise SystemExit(main())
