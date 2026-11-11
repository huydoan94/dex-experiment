"""dexd's per-viewer live PLAY with KMS input (kms_daemon_live); TS to a detachable FIFO only.

Derived from kms_session_live_probe (unchanged): same startup chain, with the
daemon limits, the detachable sink, and SIGTERM ending the media window
(TEARDOWN, then every cleanup) instead of raising inside it.
"""
import argparse
from functools import partial
import json
import math
import os
from pathlib import Path
import resource
import signal
import sys
import time

import auth_probe
import capabilities_probe as cap
import conn_transfer
import idc_handshake
import pss_probe
import rtsp_capabilities
import rtsp_hello
import rtsp_udp_live
import rtsp_udp_long
import kms_hover_live
import kms_daemon_live as daemon
import ui_confirm_display0 as ui_confirm
import wfd_startup as wfd
from tunnel_probe import emit

STAGE_MARGIN_SECONDS = 8
# True: report the official PcVer (rtsp_udp_live.BASE_PC_VERSION), so the phone
# scrambles RTP with the AUTH session key and kms_daemon_live.Descrambler undoes it.
# False: the proven plain profile (PLAIN_PC_VERSION, one patch below the gate).
SCRAMBLED = True


def select_profile():
    """Pinned Windows TerminalInfo with the scrambling (base) or plain PcVer."""
    rtsp_udp_live.plain_profile(cap)  # also refuses any profile but the pinned base
    if SCRAMBLED:
        cap.PROFILE=dict(cap.PROFILE,PcVer=rtsp_udp_live.BASE_PC_VERSION)


def main(argv=None):
    daemon.configure()
    select_profile()
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-kms-daemon",action="store_true")
    p.add_argument("--accept-persistent-state",action="store_true")
    p.add_argument("--bus",type=int)
    p.add_argument("--address",type=int)
    p.add_argument("--output",type=Path)
    p.add_argument("--ts-fifo",type=Path)
    p.add_argument("--stop-file",type=Path)
    p.add_argument("--input-fifo",type=Path)
    p.add_argument("--event-log",type=Path)
    p.add_argument("--streaming-file",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_kms_daemon:
        emit("PLAN_ONLY",phone_access=False,max_adb_commands=4,max_taps=1,play=True,live_view=True,
             audio=rtsp_udp_long.AUDIO_CODECS,media_saved="headers_only",until="sigterm")
        return 0
    if (not a.accept_persistent_state or None in (a.output,a.bus,a.address,a.ts_fifo,a.stop_file,
                                                  a.input_fifo,a.event_log,a.streaming_file)):
        p.error("requires persistent-state acceptance and every path/bus/address argument")
    if not 1<=a.bus<=255 or not 1<=a.address<=127:
        p.error("invalid bus/address")
    try:
        absolute_ui_deadline=float(os.environ["DEX_AUTO_UI_DEADLINE"])
    except (KeyError,ValueError):
        p.error("requires dexd's UI deadline")
    now=time.monotonic()
    if not math.isfinite(absolute_ui_deadline) or not now<absolute_ui_deadline<=now+75:
        p.error("invalid/expired UI deadline")
    # Media passes through this process's memory: no core dump may persist it.
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    events=daemon.EventLog(a.event_log)
    owner=sessions=sink=None

    def terminated(signum,frame):
        # Inside the media window: stop it and let TEARDOWN and cleanup run. Before: unwind.
        if owner is None or not owner.terminate():
            auth_probe._terminated(signum,frame)
    signal.signal(signal.SIGTERM,terminated)

    def streaming():
        events("streaming")
        try:
            a.streaming_file.touch()
        except OSError:
            pass
    result=dict(transport_completed=False,auto_confirmation_verified=False,
                rtsp_play_verified=False,rtp_media_verified=False,activation_tested=True,
                desktop_verified=False,video_tested=False,input_sent=False,viewer_input=True,play=True,
                media_headers_only=True,live_view=True,duplex_in=True,daemon=True,
                persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        client_profile=cap.PROFILE,rtp_scrambling=SCRAMBLED,enable_screen_share=True,auto_confirmation=True,
        max_adb_commands=4,max_taps=1,ui_driver_deadline_seconds_from_launcher=75,
        diagnostic_wfd_profile=rtsp_udp_long.AUDIO_UDP_PROFILE,setup=True,setup_transport="udp",
        play=True,teardown=True,live_view=True,media_saved="headers_only",ts_fifo=str(a.ts_fifo),
        detachable_sink=True,stop_file=str(a.stop_file),stop_on=["sigterm","stop_file","sink_error","kms_closed","viewer_left"],
        viewer_grace_seconds=daemon.VIEWER_GRACE_SECONDS,
        input_fifo=str(a.input_fifo),keyboard=True,input_saved="counts_only",
        input_slice_seconds=daemon.base.SESSION_SLICE_SECONDS,limits=daemon.DAEMON,
        receive_bytes=daemon.DAEMON_RECEIVE_BYTES,full_log_seconds=daemon.FULL_LOG_SECONDS,
        quiet_events=sorted(daemon.QUIET_EVENTS)),indent=2)+"\n")
    latest_stage=absolute_ui_deadline+STAGE_MARGIN_SECONDS
    def after_auth(session,connection,client,result,clock,log):
        if SCRAMBLED:
            # Before any RTP: the phone keys scrambling with this AUTH session key.
            session.descrambler=daemon.Descrambler(client.codec()._key)
        cap.capabilities(session,connection,client,result,clock,log)
        pss_probe.pss_ready(session,connection,client,result,clock,log)
        # Clipboard (clipboard_bridge) sends and reads on the main channel later.
        session.main_connection,session.main_codec=connection,client.codec()
        def confirm(s,main,r,logger,deadline):
            ui_confirm.confirm(s,main,r,logger,min(deadline,absolute_ui_deadline),
                               a.output,a.bus)
        after_rtsp=partial(rtsp_hello.exchange,after_query=partial(
            rtsp_capabilities.exchange,profile=rtsp_udp_long.AUDIO_UDP_PROFILE,
            after_selection=partial(rtsp_udp_long.exchange,
                latest=latest_stage+daemon.FOREVER_SECONDS)))
        after_rtsp=partial(kms_hover_live.startup,client=client,latest=latest_stage,
                          after_kms=after_rtsp)
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
        sink=daemon.DetachableSink(a.ts_fifo,notify=events).start()
        owner=daemon.DaemonOwner(usb.util,result,sink,a.stop_file,a.input_fifo,on_streaming=streaming)
        sessions=conn_transfer.TransferSessions(owner)
        auth_probe.probe(devices[0],owner,usb.core.USBTimeoutError,a.output,result,
                         after_auth=after_auth,max_requests=daemon.UNLIMITED,
                         session_class=sessions.session)
        result["transport_completed"]=True
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        if sink is not None:
            sink.close()
            result.setdefault("live",{})["sink"]=sink.summary()
            result["video_tested"]=bool(result["live"]["sink"].get("forwarded_bytes"))
        if sessions is not None:
            result["transfer_pads_dropped"]=sessions.pads()
        result["input_sent"]=bool(result.get("live",{}).get("kms_input",{}).get("sends",0))
        result["auto_confirmation_verified"]=bool(
            result.get("ui_tap_command_succeeded") and result.get("wfd_startup_verified"))
        (a.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        events("ended stop_reason=%s error=%s"%(result.get("live",{}).get("stop_reason"),
                                                  result.get("error_type")))
    if owner is not None and owner.reader is not None and owner.reader.alive():
        # Interpreter teardown could free USB resources under the live read; libusb forbids it.
        sys.stdout.flush();sys.stderr.flush()
        os._exit(1)
    return 0 if (result["transport_completed"] and result["auto_confirmation_verified"]
                 and result.get("rtp_media_verified")
                 and result.get("live",{}).get("stop_reason") in ("sigterm","stop_file","viewer_left")) else 1


if __name__=="__main__":
    raise SystemExit(main())
