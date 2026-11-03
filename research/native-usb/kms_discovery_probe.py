"""Approved WFD startup and passive KMS discovery, no RTSP replies/SETUP/PLAY/input."""
import argparse
from functools import partial
import json
import math
import os
from pathlib import Path
import signal
import time

import auth_probe
import capabilities_probe as cap
from conn_transfer import TransferDecoder
import idc_handshake
import kms_discovery
from loopback_transfer import TransferSession
import pss_probe
from tunnel_probe import emit
import ui_confirm_display0 as ui
import wfd_startup as wfd

MAX_REQUESTS = 40


class DiscoverySession(TransferSession):
    def __init__(self,link,*args,**kwargs):
        super().__init__(link,*args,**kwargs)
        # auth_probe keeps a plain raw recorder callable, not a decoder owner.
        self.decoder = TransferDecoder(self.decoder.max_frame_bytes)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-phone-kms-discovery",action="store_true")
    parser.add_argument("--accept-persistent-state",action="store_true")
    parser.add_argument("--bus",type=int)
    parser.add_argument("--address",type=int)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args(argv)
    if not args.approved_phone_kms_discovery:
        emit("PLAN_ONLY",phone_access=False,max_adb_commands=4,max_taps=1,
             kms_start=True,kms_port=30830,input=False,rtsp_sends=0,
             setup=False,play=False,max_requests=MAX_REQUESTS,outer_seconds=90)
        return 0
    if (not args.accept_persistent_state or args.output is None
            or args.bus is None or args.address is None):
        parser.error("requires acceptance, bus/address/output")
    if not 1<=args.bus<=255 or not 1<=args.address<=127:
        parser.error("invalid bus/address")
    try:
        ui_deadline=float(os.environ["DEX_AUTO_UI_DEADLINE"])
    except (KeyError,ValueError):
        parser.error("use kms_discovery_once.sh")
    now=time.monotonic()
    if not math.isfinite(ui_deadline) or not now<ui_deadline<=now+75:
        parser.error("invalid launcher deadline")
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    signal.signal(signal.SIGTERM,auth_probe._terminated)
    result=dict(transport_completed=False,kms_discovery_verified=False,
                input_sent=False,persistent_state_may_remain=True)
    (args.output/"plan.json").write_text(json.dumps(dict(
        client_profile=cap.PROFILE,max_requests=MAX_REQUESTS,max_acks=64,
        max_reads=2000,raw_in_limit_bytes=1024000,max_adb_commands=4,
        max_adb_output_bytes=811008,max_taps=1,kms_start=True,
        kms_port=30830,kms_capture_bytes=512,kms_seconds=4,
        rtsp_sends=0,setup=False,play=False,input=False,outer_seconds=90),indent=2)+"\n")

    def after_auth(session,connection,client,result,clock,log):
        cap.capabilities(session,connection,client,result,clock,log)
        pss_probe.pss_ready(session,connection,client,result,clock,log)
        def confirm(s,main,r,logger,deadline):
            ui.confirm(s,main,r,logger,min(deadline,ui_deadline),args.output,args.bus)
        after_rtsp=partial(kms_discovery.discover,client=client,latest=ui_deadline+8)
        idc_handshake.handshake(session,connection,client.codec()._key,result,log,
            after_handshake=partial(wfd.startup,confirm=confirm,after_rtsp=after_rtsp))

    try:
        import usb.core
        import usb.util
        devices=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860,
                                  bus=args.bus,address=args.address))
        if len(devices)!=1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0],usb.util,usb.core.USBTimeoutError,args.output,result,
                         after_auth=after_auth,max_requests=MAX_REQUESTS,
                         session_class=DiscoverySession)
        result["transport_completed"]=True
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        (args.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        emit("kms_discovery_result",**result)
    return 0 if result["transport_completed"] and result["kms_discovery_verified"] else 1


if __name__=="__main__":
    raise SystemExit(main())
