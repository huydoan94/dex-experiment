"""Bind the daemon RTP socket, acknowledge M4/M5 and make one UDP SETUP; no PLAY.

Runs as rtsp_capabilities.exchange(after_selection=...) after a verified UDP
M4. Opens a native UDP op1 config on the advertised RTP port BEFORE SETUP so
the phone's RTP sender has a daemon socket to reach; stops after the SETUP
reply plus a short observation. Datagrams arriving before PLAY are counted,
acknowledged and summarized by their 12-byte RTP header only.
The TCP-interleaved SETUP (rtsp_setup.py) stays disabled: Samsung RTPSender
aborts on it (SETUP_RETAINED_LOGS_RESULT.md).
"""
from udp_tunnel import UdpSession
from usb_tunnel import TunnelError
import rtsp
import rtsp_capabilities as caps
import rtsp_setup
from tunnel_probe import SERVICE_UID

RTP_CONFIG = 1205               # host-chosen, clear of the main's random 1..999
RTP_PORT = 46002
SETUP_SECONDS = 8
OBSERVE_SECONDS = 1
assert caps.UDP_PROFILE["wfd_client_rtp_ports"] == "RTP/AVP/UDP;unicast %d 0 mode=play" % RTP_PORT


class WfdUdpSession(UdpSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, accept_inbound=True)


def setup_request(uri):
    # RTCP port0 was declared, so only the RTP client port is offered.
    return ("SETUP %s RTSP/1.0\r\nCSeq: 2\r\n"
            "Transport: RTP/AVP/UDP;unicast;client_port=%d\r\n\r\n" % (uri, RTP_PORT)).encode("ascii")


def _port_range(value):
    low, sep, high = value.partition("-")
    ports = [low] + ([high] if sep else [])
    if not all(p.isascii() and p.isdecimal() and 1 <= int(p) <= 65535 for p in ports):
        raise ValueError("invalid Transport port")
    ports = [int(p) for p in ports]
    if ports != sorted(ports):
        raise ValueError("reversed Transport port range")
    return ports


def setup_response(message):
    if (message["kind"] != "response" or message["status"] != 200
            or message["cseq"] != 2 or message["body"]):
        raise ValueError("unexpected SETUP response")
    # Same Session rules as the reviewed TCP helper (rtsp_setup.setup_response).
    session = message["headers"].get("session", "").split(";")
    if not 1 <= len(session[0]) <= 128 or not rtsp.TOKEN.fullmatch(session[0]):
        raise ValueError("missing/invalid SETUP Session")
    if len(session) > 2:
        raise ValueError("unexpected Session attributes")
    timeout = None
    if len(session) == 2:
        name, sep, value = session[1].strip().partition("=")
        if (name.lower() != "timeout" or not sep or not value.isascii()
                or not value.isdecimal() or not 1 <= int(value) <= 86400):
            raise ValueError("invalid Session timeout")
        timeout = int(value)
    transport = message["headers"].get("transport", "")
    parts = transport.split(";")
    if parts[0] != "RTP/AVP/UDP" or "," in transport:
        raise ValueError("SETUP did not select single UDP transport")
    attributes = {}
    for part in parts[1:]:
        if not part.strip():
            continue
        name, sep, value = part.strip().partition("=")
        name = name.lower()
        if not rtsp.TOKEN.fullmatch(name) or name in attributes:
            raise ValueError("duplicate/invalid Transport attribute")
        attributes[name] = value if sep else None
    # A destination or interleaving would send media somewhere else.
    if set(attributes) - {"unicast", "client_port", "server_port", "source", "mode", "ssrc"}:
        raise ValueError("unexpected Transport attribute")
    if "unicast" not in attributes or attributes["unicast"] is not None:
        raise ValueError("SETUP did not select unicast")
    if _port_range(attributes.get("client_port") or "")[0] != RTP_PORT:
        raise ValueError("SETUP did not keep the RTP client port")
    if "mode" in attributes and (attributes["mode"] or "").strip('"').lower() != "play":
        raise ValueError("unexpected Transport mode")
    server = None
    if "server_port" in attributes:
        server = _port_range(attributes["server_port"] or "")
    return dict(session_id=session[0], timeout_seconds=timeout, transport=transport,
                server_ports=server)


def rtp_header(payload):
    """Version/marker/type/sequence/timestamp/SSRC only; never payload bytes."""
    if len(payload) < 12:
        return dict(size_bytes=len(payload), rtp=False)
    return dict(size_bytes=len(payload), rtp=payload[0] >> 6 == 2,
                payload_type=payload[1] & 0x7f, sequence=int.from_bytes(payload[2:4], "big"),
                timestamp=int.from_bytes(payload[4:8], "big"),
                ssrc=int.from_bytes(payload[8:12], "big"))


def exchange(session, main, connection, result, log, latest=None):
    # latest: absolute session-clock limit so the stage cannot push teardown
    # past the outer process bound (probe passes launcher deadline + margin).
    deadline = session.clock() + SETUP_SECONDS
    if latest is not None:
        deadline = min(deadline, latest)
    offset = len(connection.received)
    uri = rtsp_setup.presentation_uri(result["rtsp_selected_values"])
    first_error = None

    def guard():
        if session.clock() >= deadline:
            raise TunnelError("RTSP UDP SETUP acceptance deadline expired")
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel during UDP SETUP stage")
        if len(connection.received) > rtsp.STREAM_BYTES:
            raise TunnelError("RTSP UDP SETUP stream exceeds limit")

    def send(payload):
        guard()
        session.send(connection, payload, timeout_s=min(2, deadline - session.clock()))
        guard()

    def receive():
        nonlocal offset
        while True:
            guard()
            parsed = rtsp.parse(bytes(connection.received[offset:]))
            if parsed is not None:
                message, size = parsed
                offset += size
                guard()
                return message
            seen = len(connection.received)
            session.wait(deadline - session.clock(), until=lambda:
                         len(connection.received) > seen or main.closed_by_phone
                         or connection.closed_by_phone)

    try:
        guard()
        opened = session.open_udp(RTP_CONFIG, SERVICE_UID, RTP_PORT, operation=1,
                                  timeout_s=min(2, deadline - session.clock()))
        result["rtp_open"] = opened
        if (opened["port"], opened["client_port"]) != (RTP_PORT, 0):
            raise TunnelError("RTP UDP config did not bind the advertised port")
        result["rtsp_m4_reply_attempted"] = True
        send(rtsp_setup.response(result["rtsp_selected_cseq"]))
        trigger = receive()
        if (trigger["kind"] != "request" or trigger["method"] != "SET_PARAMETER"
                or not trigger["uri"].startswith("rtsp://")
                or trigger["cseq"] <= result["rtsp_selected_cseq"]
                or trigger["headers"].get("content-type", "").lower() != "text/parameters"
                or trigger["body"] != b"wfd_trigger_method: SETUP\r\n"):
            raise ValueError("expected exact M5 SETUP trigger")
        result["rtsp_m5_trigger_verified"] = True
        result["rtsp_m5_cseq"] = trigger["cseq"]
        result["rtsp_m5_reply_attempted"] = True
        send(rtsp_setup.response(trigger["cseq"]))
        result["rtsp_udp_setup_attempted"] = True
        send(setup_request(uri))
        reply = receive()
        result["rtsp_udp_setup_status"] = reply.get("status")
        result["rtsp_udp_setup_raw_transport"] = reply["headers"].get("transport")
        result["rtsp_udp_setup"] = setup_response(reply)
        if len(connection.received) != offset:
            raise ValueError("unexpected trailing data before PLAY")
        guard()
        result["rtsp_udp_setup_verified"] = True
        log(event="rtsp_udp_setup_verified", play=False)
        # The source should not stream before PLAY; observe briefly, no requests.
        session.wait(max(0, min(OBSERVE_SECONDS, deadline - session.clock())),
                     until=lambda: False)
        result["rtsp_bytes_after_setup"] = len(connection.received) - offset
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel after UDP SETUP")
        result["rtp_observation_completed"] = True
    except Exception as error:
        first_error = error
        result["rtp_first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        # Only closes/disconnects follow this stage. Entering cleanup now opens
        # the reserved reads and suppresses ACKs past budget, so a pre-PLAY RTP
        # burst cannot desynchronize the close replies (independent review M1).
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["rtp_cleanup_errors"] = []
        if RTP_CONFIG in session.configs:
            try:
                result["rtp_close_status"] = session.close_config(SERVICE_UID, config_id=RTP_CONFIG)
            except Exception as error:
                result["rtp_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        rtp = [d for d in session.datagrams + session.dropped_datagrams
               if d.config_id == RTP_CONFIG]
        result["rtp_datagrams_before_play"] = len(rtp)
        result["rtp_headers_before_play"] = [dict(rtp_header(d.payload), source_port=d.source_port)
                                             for d in rtp[:16]]
    if first_error is not None:
        raise first_error
