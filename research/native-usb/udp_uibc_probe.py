"""Run B: long live PLAY with audio plus WFD UIBC input from the viewer's FIFO; TS to FIFO only."""
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
import live_sink
import pss_probe
import rtsp_capabilities
import rtsp_hello
import rtsp_udp_play
import rtsp_udp_live
import rtsp_udp_long
import rtsp_udp_uibc
import ui_confirm_display0 as ui_confirm
import wfd_startup as wfd
from tunnel_probe import emit

# Bounded PLAY's 48 requests/8 RTSP sends, one per answered keep-alive or uibc setting,
# the UIBC open/connect/disconnect/close and one per input send.
RTSP_SENDS = 8 + rtsp_udp_long.LONG_KEEPALIVES + rtsp_udp_uibc.MAX_UIBC_SETTINGS
MAX_REQUESTS = 40 + RTSP_SENDS + 4 + rtsp_udp_uibc.MAX_INPUT_SENDS
# UI deadline is launcher start+75; the stage ends by +83+cap, leaving 7 s of the outer limit.
STAGE_MARGIN_SECONDS = 8
OUTER_SECONDS = 90 + rtsp_udp_long.CAP_SECONDS


def main(argv=None):
    rtsp_udp_uibc.apply()
    rtsp_udp_live.plain_profile(cap)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-udp-uibc",action="store_true")
    p.add_argument("--accept-persistent-state",action="store_true")
    p.add_argument("--bus",type=int)
    p.add_argument("--address",type=int)
    p.add_argument("--output",type=Path)
    p.add_argument("--ts-fifo",type=Path)
    p.add_argument("--stop-file",type=Path)
    p.add_argument("--input-fifo",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_udp_uibc:
        emit("PLAN_ONLY",phone_access=False,max_adb_commands=4,max_taps=1,setup=True,
             setup_transport="udp",play=True,live_view=True,audio=rtsp_udp_long.AUDIO_CODECS,uibc=rtsp_udp_uibc.UIBC_CAPABILITY,
             media_saved="headers_only",rtsp_sends=RTSP_SENDS,cap_seconds=rtsp_udp_long.CAP_SECONDS,
             outer_seconds=OUTER_SECONDS)
        return 0
    if (not a.accept_persistent_state or a.output is None or a.bus is None
            or a.address is None or a.ts_fifo is None or a.stop_file is None or a.input_fifo is None):
        p.error("requires persistent-state acceptance, bus/address/output/ts-fifo/stop-file/input-fifo")
    if not 1<=a.bus<=255 or not 1<=a.address<=127:
        p.error("invalid bus/address")
    try:
        absolute_ui_deadline=float(os.environ["DEX_AUTO_UI_DEADLINE"])
    except (KeyError,ValueError):
        p.error("requires launcher UI deadline; use udp_uibc_once.sh")
    now=time.monotonic()
    if not math.isfinite(absolute_ui_deadline) or not now<absolute_ui_deadline<=now+75:
        p.error("invalid/expired launcher UI deadline")
    # Media passes through this process's memory: no core dump may persist it.
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    signal.signal(signal.SIGTERM,auth_probe._terminated)
    result=dict(transport_completed=False,auto_confirmation_verified=False,
                rtsp_play_verified=False,rtp_media_verified=False,activation_tested=True,
                desktop_verified=False,video_tested=False,play=True,media_headers_only=True,live_view=True,duplex_in=True,persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        client_profile=cap.PROFILE,enable_screen_share=True,
        auto_confirmation=True,max_adb_commands=4,max_taps=1,
        hierarchy_destination="/proc/self/fd/1",max_adb_output_bytes=811008,
        ui_acceptance_seconds=20,ui_snapshot_max_age_seconds=2,
        ui_driver_deadline_seconds_from_launcher=75,
        diagnostic_wfd_profile=rtsp_udp_uibc.UIBC_PROFILE,
        rtp_config=rtsp_udp_play.RTP_CONFIG,rtp_port=rtsp_udp_play.RTP_PORT,
        rtcp_config=rtsp_udp_play.RTCP_CONFIG,rtcp_port=rtsp_udp_play.RTCP_PORT,
        setup=True,setup_transport="udp",play=True,teardown=True,rtsp_sends=RTSP_SENDS,
        live=True,live_view=True,media_saved="headers_only",ts_fifo=str(a.ts_fifo),
        stop_file=str(a.stop_file),input_fifo=str(a.input_fifo),uibc_config=rtsp_udp_uibc.UIBC_CONFIG,
        uibc_host_port=rtsp_udp_uibc.UIBC_HOST,max_input_sends=rtsp_udp_uibc.MAX_INPUT_SENDS,
        input_slice_seconds=rtsp_udp_uibc.UIBC_SLICE_SECONDS,input_saved="counts_only",stop_on=["stop_file","viewer_closed","cap"],
        cap_seconds=rtsp_udp_long.CAP_SECONDS,full_log_seconds=rtsp_udp_long.FULL_LOG_SECONDS,
        media_headers_kept=rtsp_udp_long.MEDIA_KEEP,receive_bytes=rtsp_udp_long.LONG_RECEIVE_BYTES,
        ts_queue_bytes=live_sink.QUEUE_BYTES,max_keepalives=rtsp_udp_live.MAX_KEEPALIVES,
        transfer_pad_decoder=True,duplex_in=True,duplex_queue_bytes=rtsp_udp_live.duplex_link.QUEUE_BYTES,
        duplex_read_timeout_ms=rtsp_udp_live.duplex_link.READ_TIMEOUT_MS,
        media_headers_only=True,media_datagrams=rtsp_udp_play.MEDIA_DATAGRAMS,
        media_seconds=rtsp_udp_play.MEDIA_SECONDS,media_bytes=rtsp_udp_play.MEDIA_BYTES,
        rtcp_datagrams=rtsp_udp_play.RTCP_DATAGRAMS,
        stage_seconds=rtsp_udp_play.STAGE_SECONDS,
        setup_latest_seconds_from_launcher=75+STAGE_MARGIN_SECONDS+rtsp_udp_long.CAP_SECONDS,
        max_requests=MAX_REQUESTS,max_acks=rtsp_udp_play.PLAY_ACKS,max_reads=rtsp_udp_play.PLAY_READS,
        cleanup_reserved_reads=200,outer_seconds=OUTER_SECONDS),indent=2)+"\n")
    def after_auth(session,connection,client,result,clock,log):
        cap.capabilities(session,connection,client,result,clock,log)
        pss_probe.pss_ready(session,connection,client,result,clock,log)
        def confirm(s,main,r,logger,deadline):
            ui_confirm.confirm(s,main,r,logger,min(deadline,absolute_ui_deadline),
                               a.output,a.bus)
        after_rtsp=partial(rtsp_hello.exchange,after_query=partial(
            rtsp_capabilities.exchange,profile=rtsp_udp_uibc.UIBC_PROFILE,
            after_selection=partial(rtsp_udp_uibc.exchange,
                latest=absolute_ui_deadline+STAGE_MARGIN_SECONDS+rtsp_udp_long.CAP_SECONDS)))
        idc_handshake.handshake(session,connection,client.codec()._key,result,log,
                               after_handshake=partial(wfd.startup,confirm=confirm,
                                                       after_rtsp=after_rtsp))
    owner=sessions=sink=None
    try:
        import usb.core
        import usb.util
        devices=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860,
                                  bus=a.bus,address=a.address))
        if len(devices)!=1:
            raise RuntimeError("expected exactly one selected phone")
        sink=live_sink.TsSink(a.ts_fifo).start()
        owner=rtsp_udp_uibc.UibcOwner(usb.util,result,sink,a.stop_file,a.input_fifo)
        sessions=conn_transfer.TransferSessions(owner)
        auth_probe.probe(devices[0],owner,usb.core.USBTimeoutError,a.output,result,
                         after_auth=after_auth,max_requests=MAX_REQUESTS,
                         session_class=sessions.session)
        result["transport_completed"]=True
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        if sink is not None:
            sink.close()
            result.setdefault("live",{})["sink"]=sink.summary()
            result["video_tested"]=bool(result["live"]["sink"].get("opened")
                                        and result["live"]["sink"].get("forwarded_bytes"))
        if sessions is not None:
            result["transfer_pads_dropped"]=sessions.pads()
        result["auto_confirmation_verified"]=bool(
            result.get("ui_tap_command_succeeded") and result.get("wfd_startup_verified"))
        (a.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        emit("udp_uibc_result",**result)
    if owner is not None and owner.reader is not None and owner.reader.alive():
        # Interpreter teardown could free USB resources under the live read; libusb forbids it.
        sys.stdout.flush();sys.stderr.flush()
        os._exit(1)
    return 0 if (result["transport_completed"] and result["auto_confirmation_verified"]
                 and result.get("rtp_media_verified")) else 1


if __name__=="__main__":
    raise SystemExit(main())
