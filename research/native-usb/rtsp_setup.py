"""Acknowledge M4/M5 and make one RTSP SETUP; stop before PLAY/media."""
from functools import partial
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

import capabilities_probe as cap
import idc_handshake
import pss_probe
import rtsp
import rtsp_hello
import rtsp_capabilities as caps
import wfd_startup as wfd
from tunnel_probe import emit
from usb_tunnel import TunnelError

SETUP_SECONDS = 8


def response(cseq):
    return ("RTSP/1.0 200 OK\r\nCSeq: %d\r\n\r\n"%cseq).encode("ascii")


def presentation_uri(values):
    fields=values["wfd_presentation_url"].split()
    if len(fields)!=2 or fields[1]!="none":
        raise ValueError("invalid current presentation URL")
    uri=fields[0]
    if any(ord(c)<33 or ord(c)>126 for c in uri):
        raise ValueError("invalid presentation URL bytes")
    parsed=urlsplit(uri)
    if (parsed.scheme!="rtsp" or parsed.hostname!="127.0.0.1"
            or parsed.port not in (None,7236) or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path!="/wfd1.0/streamid=0"):
        raise ValueError("presentation URL outside current loopback stream")
    return uri


def setup_request(uri):
    return ("SETUP %s RTSP/1.0\r\nCSeq: 2\r\n"
            "Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n"%uri).encode("ascii")


def setup_response(message):
    if (message["kind"]!="response" or message["status"]!=200
            or message["cseq"]!=2 or message["body"]):
        raise ValueError("unexpected SETUP response")
    session=message["headers"].get("session","").split(";")
    if not 1<=len(session[0])<=128 or not rtsp.TOKEN.fullmatch(session[0]):
        raise ValueError("missing/invalid SETUP Session")
    timeout=None
    if len(session)>2:
        raise ValueError("unexpected Session attributes")
    if len(session)==2:
        name,sep,value=session[1].strip().partition("=")
        if (name.lower()!="timeout" or not sep or not value.isascii()
                or not value.isdecimal() or not 1<=int(value)<=86400):
            raise ValueError("invalid Session timeout")
        timeout=int(value)
    transport=message["headers"].get("transport","")
    parts=transport.split(";")
    if parts[0]!="RTP/AVP/TCP" or "," in transport:
        raise ValueError("SETUP did not select single TCP transport")
    attributes={}
    for part in parts[1:]:
        if not part.strip():
            continue
        name,sep,value=part.strip().partition("=")
        name=name.lower()
        if not rtsp.TOKEN.fullmatch(name) or name in attributes:
            raise ValueError("duplicate/invalid Transport attribute")
        attributes[name]=value if sep else None
    if attributes.get("interleaved")!="0-1":
        raise ValueError("SETUP did not select channels0-1")
    return dict(session_id=session[0],timeout_seconds=timeout,transport=transport)


def exchange(session,main,connection,result,log):
    deadline=session.clock()+SETUP_SECONDS
    offset=len(connection.received)
    uri=presentation_uri(result["rtsp_selected_values"])

    def guard():
        if session.clock()>=deadline:
            raise TunnelError("RTSP SETUP acceptance deadline expired")
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel during SETUP stage")
        if len(connection.received)>rtsp.STREAM_BYTES:
            raise TunnelError("RTSP SETUP stream exceeds limit")

    def send(payload):
        guard()
        session.send(connection,payload,timeout_s=min(2,deadline-session.clock()))
        guard()

    def receive():
        nonlocal offset
        while True:
            guard()
            parsed=rtsp.parse(bytes(connection.received[offset:]))
            if parsed is not None:
                message,size=parsed
                offset+=size
                guard()
                return message
            seen=len(connection.received)
            session.wait(deadline-session.clock(),until=lambda:
                         len(connection.received)>seen or main.closed_by_phone
                         or connection.closed_by_phone)

    result["rtsp_m4_reply_attempted"]=True
    send(response(result["rtsp_selected_cseq"]))
    trigger=receive()
    if (trigger["kind"]!="request" or trigger["method"]!="SET_PARAMETER"
            or not trigger["uri"].startswith("rtsp://")
            or trigger["cseq"]<=result["rtsp_selected_cseq"]
            or trigger["headers"].get("content-type","").lower()!="text/parameters"
            or trigger["body"]!=b"wfd_trigger_method: SETUP\r\n"):
        raise ValueError("expected exact M5 SETUP trigger")
    result["rtsp_m5_trigger_verified"]=True
    result["rtsp_m5_cseq"]=trigger["cseq"]
    result["rtsp_m5_reply_attempted"]=True
    send(response(trigger["cseq"]))
    result["rtsp_setup_attempted"]=True
    send(setup_request(uri))
    reply=receive()
    result["rtsp_setup"]=setup_response(reply)
    if len(connection.received)!=offset:
        raise ValueError("unexpected trailing data before PLAY")
    guard()
    result["rtsp_setup_verified"]=True
    log(event="rtsp_setup_verified",play=False,media=False)


def after_auth(session,connection,client,result,clock,log,confirm=None):
    cap.capabilities(session,connection,client,result,clock,log)
    pss_probe.pss_ready(session,connection,client,result,clock,log)
    capability=partial(caps.exchange,after_selection=exchange)
    hello=partial(rtsp_hello.exchange,after_query=capability)
    idc_handshake.handshake(session,connection,client.codec()._key,result,log,
                            after_handshake=partial(wfd.startup,after_rtsp=hello,confirm=confirm))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-setup",action="store_true")
    p.add_argument("--accept-persistent-state",action="store_true")
    mode=p.add_mutually_exclusive_group()
    mode.add_argument("--ready-for-start-now",action="store_true")
    mode.add_argument("--approved-auto-start-now",action="store_true")
    p.add_argument("--bus",type=int)
    p.add_argument("--address",type=int)
    p.add_argument("--output",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_rtsp_setup:
        emit("PLAN_ONLY",phone_access=False,rtsp_sends=6,setup=True,
             play=False,intentional_media=False,disabled=True,outer_seconds=90)
        return 0
    p.error("TCP-interleaved SETUP disabled: confirmed Samsung RTPSender abort")


if __name__=="__main__":
    raise SystemExit(main())
