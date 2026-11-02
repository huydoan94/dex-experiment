"""One WFD startup with approved targeted ADB confirmation; no SETUP/media."""
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
import idc_handshake
import pss_probe
import rtsp_capabilities
import rtsp_hello
import ui_confirm
import wfd_startup as wfd
from loopback_transfer import TransferSession
from tunnel_probe import emit


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-auto-start-now",action="store_true")
    p.add_argument("--accept-persistent-state",action="store_true")
    p.add_argument("--approved-udp-capabilities",action="store_true")
    p.add_argument("--bus",type=int)
    p.add_argument("--address",type=int)
    p.add_argument("--output",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_auto_start_now:
        emit("PLAN_ONLY",phone_access=False,max_adb_commands=4,max_taps=1,
             setup=False,rtsp_sends=3 if a.approved_udp_capabilities else 0,outer_seconds=90)
        return 0
    if (not a.accept_persistent_state or a.output is None or a.bus is None
            or a.address is None):
        p.error("requires persistent-state acceptance, bus/address/output")
    if not 1<=a.bus<=255 or not 1<=a.address<=127:
        p.error("invalid bus/address")
    try:
        absolute_ui_deadline=float(os.environ["DEX_AUTO_UI_DEADLINE"])
    except (KeyError,ValueError):
        p.error("requires launcher UI deadline; use auto_confirm_once.sh")
    now=time.monotonic()
    if not math.isfinite(absolute_ui_deadline) or not now<absolute_ui_deadline<=now+75:
        p.error("invalid/expired launcher UI deadline")
    max_requests=40 if a.approved_udp_capabilities else 32
    rtsp_sends=3 if a.approved_udp_capabilities else 0
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    signal.signal(signal.SIGTERM,auth_probe._terminated)
    result=dict(transport_completed=False,auto_confirmation_verified=False,
                activation_tested=True,desktop_verified=False,video_tested=False,
                persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        client_profile=cap.PROFILE,enable_screen_share=True,
        auto_confirmation=True,max_adb_commands=4,max_taps=1,
        hierarchy_destination="/proc/self/fd/1",max_adb_output_bytes=811008,
        ui_acceptance_seconds=20,ui_snapshot_max_age_seconds=2,
        ui_driver_deadline_seconds_from_launcher=75,
        setup=False,rtsp_sends=rtsp_sends,max_requests=max_requests,max_acks=64,
        diagnostic_wfd_profile=rtsp_capabilities.UDP_PROFILE if a.approved_udp_capabilities else None,
        max_reads=2000,cleanup_reserved_reads=200,outer_seconds=90),indent=2)+"\n")
    def after_auth(session,connection,client,result,clock,log):
        cap.capabilities(session,connection,client,result,clock,log)
        pss_probe.pss_ready(session,connection,client,result,clock,log)
        def confirm(s,main,r,logger,deadline):
            ui_confirm.confirm(s,main,r,logger,min(deadline,absolute_ui_deadline),
                               a.output,a.bus)
        after_rtsp=None
        if a.approved_udp_capabilities:
            after_rtsp=partial(rtsp_hello.exchange,after_query=partial(
                rtsp_capabilities.exchange,profile=rtsp_capabilities.UDP_PROFILE))
        idc_handshake.handshake(session,connection,client.codec()._key,result,log,
                               after_handshake=partial(wfd.startup,confirm=confirm,
                                                       after_rtsp=after_rtsp))
    try:
        import usb.core
        import usb.util
        devices=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860,
                                  bus=a.bus,address=a.address))
        if len(devices)!=1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0],usb.util,usb.core.USBTimeoutError,a.output,result,
                         after_auth=after_auth,max_requests=max_requests,session_class=TransferSession)
        result["transport_completed"]=True
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        result["auto_confirmation_verified"]=bool(
            result.get("ui_tap_command_succeeded") and result.get("wfd_startup_verified"))
        (a.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        emit("auto_confirmation_result",**result)
    return 0 if (result["transport_completed"] and result["auto_confirmation_verified"]
                 and (not a.approved_udp_capabilities
                      or result.get("rtsp_capabilities_verified"))) else 1


if __name__=="__main__":
    raise SystemExit(main())
