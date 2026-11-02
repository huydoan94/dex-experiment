"""One RTSP M1/M2 OPTIONS exchange; capture M3 without responding."""
from functools import partial
import argparse
import json
from pathlib import Path
import signal

import auth_probe
import capabilities_probe as cap
import idc_handshake
import pss_probe
import rtsp
import wfd_startup as wfd
from loopback_transfer import TransferSession
from tunnel_probe import emit
from usb_tunnel import TunnelError

# Acceptance deadline, not a hard per-phase wall-clock bound: an in-flight
# inherited USB write/ACK may finish after it. Late completion is rejected;
# the outer process timeout remains the hard run bound.
HELLO_SECONDS = 5


def exchange(session, main, connection, result, log, after_query=None):
    deadline = session.clock() + HELLO_SECONDS
    offset = 0

    def guard():
        if session.clock() >= deadline:
            raise TunnelError("RTSP hello deadline expired")
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel during RTSP hello")
        if len(connection.received) > rtsp.STREAM_BYTES:
            raise TunnelError("RTSP hello stream exceeds limit")

    def receive():
        nonlocal offset
        while True:
            guard()
            message = rtsp.parse(bytes(connection.received[offset:]))
            if message is not None:
                item, size = message
                offset += size
                guard()
                return item
            seen = len(connection.received)
            session.wait(deadline - session.clock(), until=lambda:
                         len(connection.received) > seen or connection.closed_by_phone
                         or main.closed_by_phone)

    first = receive()
    rtsp.initial_options(first)
    guard()
    result["rtsp_m1_reply_attempted"] = True
    session.send(connection, rtsp.options_reply(first["cseq"]),
                 timeout_s=min(2, deadline-session.clock()))
    guard()
    result["rtsp_m2_attempted"] = True
    session.send(connection, rtsp.options_request(),
                 timeout_s=min(2, deadline-session.clock()))
    guard()
    response, query = None, None
    # Exactly two messages, in either order; no auto-response to anything.
    for _ in range(2):
        message = receive()
        if message["kind"] == "response":
            if response is not None or message["cseq"] != 1 or message["status"] != 200:
                raise ValueError("unexpected OPTIONS response")
            if message["body"]:
                raise ValueError("unexpected OPTIONS response body")
            public = {s.strip() for s in message["headers"].get("public", "").split(",")}
            if "org.wfa.wfd1.0" not in public or "GET_PARAMETER" not in public:
                raise ValueError("OPTIONS response lacks required methods")
            response = message
        else:
            if query is not None or message["cseq"] <= first["cseq"]:
                raise ValueError("unexpected capability sequence")
            query = rtsp.query_names(message)
            result["rtsp_query_cseq"] = message["cseq"]
    guard()
    if response is None or query is None:
        raise ValueError("missing OPTIONS response or capability query")
    if len(connection.received) != offset:
        raise ValueError("unexpected trailing RTSP data")
    result["rtsp_parameter_names"] = query
    result["rtsp_hello_received_bytes"] = offset
    result["rtsp_hello_verified"] = True
    log(event="rtsp_hello_verified", parameter_names=query,
        capability_reply_sent=False, media=False)
    if after_query is not None:
        guard()
        after_query(session, main, connection, result, log)


def after_auth(session, connection, client, result, clock, log):
    cap.capabilities(session, connection, client, result, clock, log)
    pss_probe.pss_ready(session, connection, client, result, clock, log)
    idc_handshake.handshake(session, connection, client.codec()._key, result, log,
                            after_handshake=partial(wfd.startup, after_rtsp=exchange))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-hello", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--ready-for-start-now", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_rtsp_hello:
        emit("PLAN_ONLY", phone_access=False, rtsp_sends=2, capability_reply=False,
             video=False, outer_seconds=90)
        return 0
    if (not a.accept_persistent_state or not a.ready_for_start_now or a.output is None
            or a.bus is None or a.address is None):
        p.error("requires persistent-state acceptance, readiness, bus/address/output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(transport_completed=False, rtsp_hello_verified=False,
                  activation_tested=True, desktop_verified=False, video_tested=False,
                  persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        profile=cap.PROFILE, enable_screen_share=True, manual_wait_seconds=30,
        rtsp_sends=2, capability_reply=False, hello_seconds=HELLO_SECONDS,
        header_bytes=rtsp.HEADER_BYTES, body_bytes=rtsp.BODY_BYTES,
        rtsp_stream_bytes=rtsp.STREAM_BYTES, max_requests=36, max_acks=64,
        max_reads=2000, cleanup_reserved_reads=200, outer_seconds=90), indent=2)+"\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=after_auth, max_requests=36, session_class=TransferSession)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output/"result.json").write_text(json.dumps(result, indent=2)+"\n")
        emit("rtsp_hello_result", **result)
    return 0 if result["transport_completed"] and result["rtsp_hello_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
