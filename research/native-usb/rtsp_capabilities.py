"""One M3 capability response and passive M4 capture; no M4 ACK/SETUP/PLAY."""
from functools import partial
import argparse
import json
from pathlib import Path
import re
import signal

import auth_probe
import capabilities_probe as cap
import idc_handshake
import pss_probe
import rtsp
import rtsp_hello
import wfd_startup as wfd
from loopback_transfer import TransferSession
from tunnel_probe import emit
from usb_tunnel import TunnelError

# Declared diagnostic profile, not proof of a working media decoder.
PROFILE = {
    "wfd_video_formats": "38 00 02 04 00000081 00000000 00000000 00 0000 0000 00 none none",
    "wfd_audio_codecs": "none",
    "wfd_client_rtp_ports": "RTP/AVP/TCP;interleaved mode=play",
    "wfd_content_protection": "none",
    "wfd_uibc_capability": "none",
}
UDP_PROFILE = dict(PROFILE, wfd_client_rtp_ports="RTP/AVP/UDP;unicast 46002 0 mode=play")
CORE = {"wfd_video_formats", "wfd_audio_codecs", "wfd_client_rtp_ports"}
VENDOR = {"wfd_sec_screensharing", "wfd_sec_portrait_display", "wfd_sec_rotation",
          "wfd_sec_hw_rotation", "wfd_sec_framerate"}
CAP_SECONDS = 5


def capability_reply(cseq, names, profile=PROFILE):
    if not CORE.issubset(names) or not set(names).issubset(profile.keys() | VENDOR):
        raise ValueError("unexpected capability query schema")
    # Unknown Samsung extensions are deliberately omitted, not claimed supported.
    body = "".join(name + ": " + profile[name] + "\r\n"
                   for name in names if name in profile).encode("ascii")
    return ("RTSP/1.0 200 OK\r\nCSeq: %d\r\nContent-Type: text/parameters\r\n"
            "Content-Length: %d\r\n\r\n" % (cseq,len(body))).encode("ascii") + body


def selected_parameters(message):
    if (message["kind"] != "request" or message["method"] != "SET_PARAMETER"
            or not message["uri"].startswith("rtsp://")):
        raise ValueError("expected M4 SET_PARAMETER")
    if message["headers"].get("content-type","").lower() != "text/parameters":
        raise ValueError("unexpected M4 content type")
    text = message["body"].decode("ascii","strict")
    if not text.endswith("\r\n"):
        raise ValueError("incomplete parameter body")
    values = {}
    for line in text[:-2].split("\r\n"):
        name,sep,value = line.partition(":")
        name=name.lower()
        if (not sep or not rtsp.NAME.fullmatch(name) or name in values
                or not value.startswith(" ") or not value.strip()
                or any(ord(c)<32 or ord(c)>126 for c in value)):
            raise ValueError("invalid/duplicate selected parameter")
        values[name]=value.strip()
    if "wfd_trigger_method" in values or "wfd_video_formats" not in values:
        raise ValueError("expected selected capabilities, not an activation trigger")
    # Export only known non-key values. Raw USB evidence may contain other fields.
    safe = PROFILE.keys() | {"wfd_presentation_url"}
    if values.get("wfd_sec_scramble") in ("enable","disable"):
        safe |= {"wfd_sec_scramble"}
    return {name:value for name,value in values.items() if name in safe}, sorted(values)


def selection_compatible(values, profile=PROFILE):
    tokens=values["wfd_video_formats"].split()
    widths=(2,2,2,2,8,8,8,2,4,4,2)
    if (len(tokens)!=13 or any(not re.fullmatch("[0-9A-Fa-f]{%d}"%width,token)
            for width,token in zip(widths,tokens[:11]))
            or any(token!="none" for token in tokens[11:])):
        return False
    video_profile,level,cea,vesa,hh=(int(t,16) for t in tokens[2:7])
    presentation=values.get("wfd_presentation_url","").split()
    return (len(presentation)==2 and presentation[0].startswith("rtsp://")
            and presentation[1]=="none"
            and all(int(tokens[i],16)==0 for i in (1,7,8,9,10))
            and video_profile==2 and level==4 and cea in (1,128) and vesa==0 and hh==0
            and values.get("wfd_audio_codecs","none")=="none"
            and values.get("wfd_content_protection","none")=="none"
            and values.get("wfd_uibc_capability","none")=="none"
            and values.get("wfd_client_rtp_ports")==profile["wfd_client_rtp_ports"])


def exchange(session,main,connection,result,log,after_selection=None,profile=PROFILE):
    # Acceptance deadline; inherited in-flight write/ACK can overshoot.
    deadline=session.clock()+CAP_SECONDS
    offset=len(connection.received)

    def guard():
        if session.clock()>=deadline:
            raise TunnelError("RTSP capability acceptance deadline expired")
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel during capability exchange")
        if len(connection.received)>rtsp.STREAM_BYTES:
            raise TunnelError("RTSP capability stream exceeds limit")

    guard()
    payload=capability_reply(result["rtsp_query_cseq"],result["rtsp_parameter_names"],profile)
    result["rtsp_capability_reply_attempted"]=True
    session.send(connection,payload,timeout_s=min(2,deadline-session.clock()))
    while True:
        guard()
        parsed=rtsp.parse(bytes(connection.received[offset:]))
        if parsed is not None:
            message,size=parsed
            guard()
            if message["cseq"]<=result["rtsp_query_cseq"]:
                raise ValueError("unexpected M4 CSeq")
            values,names=selected_parameters(message)
            result["rtsp_selected_values"]=values
            result["rtsp_selected_names"]=names
            result["rtsp_selected_cseq"]=message["cseq"]
            result["rtsp_selection_compatible"]=selection_compatible(values,profile)
            if not result["rtsp_selection_compatible"]:
                raise ValueError("source selected parameters outside declared profile")
            if len(connection.received)!=offset+size:
                raise ValueError("unexpected trailing M4 data")
            guard()
            result["rtsp_capabilities_verified"]=True
            log(event="rtsp_capabilities_verified",selected_names=names,
                m4_reply_sent=False,setup=False,play=False,media=False)
            if after_selection is not None:
                guard()
                after_selection(session,main,connection,result,log)
            return
        seen=len(connection.received)
        session.wait(deadline-session.clock(),until=lambda:
                     len(connection.received)>seen or connection.closed_by_phone
                     or main.closed_by_phone)


def after_auth(session,connection,client,result,clock,log):
    cap.capabilities(session,connection,client,result,clock,log)
    pss_probe.pss_ready(session,connection,client,result,clock,log)
    hello=partial(rtsp_hello.exchange,after_query=exchange)
    idc_handshake.handshake(session,connection,client.codec()._key,result,log,
                            after_handshake=partial(wfd.startup,after_rtsp=hello))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-capabilities",action="store_true")
    p.add_argument("--accept-persistent-state",action="store_true")
    p.add_argument("--ready-for-start-now",action="store_true")
    p.add_argument("--bus",type=int)
    p.add_argument("--address",type=int)
    p.add_argument("--output",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_rtsp_capabilities:
        emit("PLAN_ONLY",phone_access=False,rtsp_sends=3,m4_reply=False,
             setup=False,play=False,media=False,outer_seconds=90)
        return 0
    if (not a.accept_persistent_state or not a.ready_for_start_now or a.output is None
            or a.bus is None or a.address is None):
        p.error("requires persistent-state acceptance, readiness, bus/address/output")
    if not 1<=a.bus<=255 or not 1<=a.address<=127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    signal.signal(signal.SIGTERM,auth_probe._terminated)
    result=dict(transport_completed=False,rtsp_capabilities_verified=False,
                activation_tested=True,desktop_verified=False,video_tested=False,
                persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        client_profile=cap.PROFILE,diagnostic_wfd_profile=PROFILE,
        enable_screen_share=True,manual_wait_seconds=30,rtsp_sends=3,
        m4_reply=False,setup=False,play=False,media=False,cap_seconds=CAP_SECONDS,
        max_requests=40,max_acks=64,max_reads=2000,cleanup_reserved_reads=200,
        rtsp_stream_bytes=16384,outer_seconds=90),indent=2)+"\n")
    try:
        import usb.core
        import usb.util
        devices=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860,
                                  bus=a.bus,address=a.address))
        if len(devices)!=1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0],usb.util,usb.core.USBTimeoutError,a.output,result,
                         after_auth=after_auth,max_requests=40,session_class=TransferSession)
        result["transport_completed"]=True
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        (a.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        emit("rtsp_capabilities_result",**result)
    return 0 if result["transport_completed"] and result["rtsp_capabilities_verified"] else 1


if __name__=="__main__":
    raise SystemExit(main())
