"""One WFD startup + first RTSP-header capture; no RTSP replies/media/input.

Manual Start now required. Default PLAN_ONLY. Specific grant and readiness
flags required. WFD/global preferences may remain after cleanup.
"""
import argparse
import json
from pathlib import Path
import signal
import struct

import auth_probe
import capabilities_probe as cap
import idc
import idc_handshake as handshake
import pss_probe as pss
from loopback_transfer import TransferSession
from tunnel_probe import SERVICE_UID, emit
from usb_tunnel import TunnelError

CONTROL_CONFIG = 1203
RTSP_CONFIG = 1204
CONTROL_HOST = 50003
RTSP_HOST = 50004
USER_SECONDS = 30
RTSP_SECONDS = 3


def collect_events(session, key, offsets, observed, result):
    for connection in list(session.connections.values()):
        if not connection.inbound or connection.config_id != handshake.LISTENER_CONFIG:
            continue
        data = bytes(connection.received)
        observed[connection.host_port] = len(data)
        offset = offsets.get(connection.host_port, 0)
        while len(data) - offset >= 2:
            length = struct.unpack_from(">H", data, offset)[0]
            end = offset + 2 + length
            if end > len(data):
                break
            try:
                message = idc.encrypted_message(key, data[offset:end])
                if (message["main"], message["sub"], message["type"]) == (
                        "SCR_SHR", "SCR_SHR_ENABLED", "EVENT"):
                    parts = message["info"].split(idc.SEP)
                    if len(parts) != 2:
                        raise ValueError("bad SCR_SHR_ENABLED info")
                    status, state = map(int, parts)
                    result["wfd_enable_event"] = dict(result=status, previous_state=state)
                else:
                    result["other_idc_events"] = result.get("other_idc_events", 0) + 1
            except ValueError:
                result["idc_event_errors"] = result.get("idc_event_errors", 0) + 1
            offset = end
        offsets[connection.host_port] = offset


def first_rtsp_header(data):
    end = data.find(b"\r\n\r\n")
    if end < 0 or end + 4 > 8192:
        raise ValueError("missing/oversized RTSP header")
    text = data[:end + 4].decode("ascii", "strict")
    line = text.split("\r\n", 1)[0]
    fields = line.split(" ")
    if (len(fields) != 3 or fields[2] != "RTSP/1.0"
            or not fields[0].isalpha() or not fields[0].isupper()):
        raise ValueError("unexpected initial RTSP request line")
    return dict(request_line=line, header_bytes=end + 4)


def startup(session, main_connection, key, result, log, after_rtsp=None, confirm=None):
    first_error = None
    result["wfd_startup_verified"] = False
    try:
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel before WFD setup")
        port = result["idc_response"]["control_port"]
        session.open_config(CONTROL_CONFIG, SERVICE_UID, port)
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel before CONTROL Connect")
        control = session.connect(CONTROL_HOST, config_id=CONTROL_CONFIG, timeout_s=2)
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel before enable send")
        payload = idc.encode(key, idc.command_text(
            "SCR_SHR", "ENABLE_SCR_SHR", "REQUEST", "null", seq=2))
        result["screen_share_request_attempted"] = True
        session.send(control, payload, timeout_s=2)
        log(event="ACTION_REQUIRED" if confirm is None else "AUTO_CONFIRMATION",
            instruction="Tap Start now on the phone" if confirm is None else
                        "Waiting for approved automatic DeX confirmation",
            wait_seconds=USER_SECONDS)
        deadline = session.clock() + USER_SECONDS
        if confirm is not None:
            confirm(session, main_connection, result, log, deadline)
        offsets, observed = {}, {}
        while session.clock() < deadline:
            collect_events(session, key, offsets, observed, result)
            if main_connection.closed_by_phone:
                raise TunnelError("phone closed main channel during WFD request")
            event = result.get("wfd_enable_event")
            if event is not None:
                if session.clock() >= deadline:
                    raise TunnelError("WFD event/manual confirmation deadline expired")
                if event["result"] != 1:
                    raise TunnelError("phone did not accept WFD enable")
                break
            remaining = deadline - session.clock()
            session.wait(min(1, remaining), until=lambda: any(
                c.inbound and c.config_id == handshake.LISTENER_CONFIG
                and len(c.received) > observed.get(c.host_port, 0)
                for c in session.connections.values()))
        else:
            raise TunnelError("WFD event/manual confirmation deadline expired")
        # The app reports request-complete 500ms after calling the framework.
        # Give its listener one further second; then ONE Connect, no retry.
        session.wait(1, until=lambda: False)
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel before RTSP setup")
        session.open_config(RTSP_CONFIG, SERVICE_UID, 7236)
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel before RTSP Connect")
        rtsp = session.connect(RTSP_HOST, config_id=RTSP_CONFIG, timeout_s=2)
        rtsp_deadline = session.clock() + RTSP_SECONDS
        session.wait(RTSP_SECONDS, until=lambda: b"\r\n\r\n" in rtsp.received or rtsp.closed_by_phone)
        if session.clock() >= rtsp_deadline:
            raise TunnelError("initial RTSP header deadline expired")
        if main_connection.closed_by_phone:
            raise TunnelError("phone closed main channel during RTSP capture")
        if len(rtsp.received) > 8192:
            raise TunnelError("initial RTSP data exceeds exported-header cap")
        result["rtsp_received_bytes"] = len(rtsp.received)
        result["rtsp_initial"] = first_rtsp_header(bytes(rtsp.received))
        result["rtsp_initial_hex"] = bytes(
            rtsp.received[:result["rtsp_initial"]["header_bytes"]]).hex()
        result["wfd_startup_verified"] = True
        if after_rtsp is not None:
            after_rtsp(session, main_connection, rtsp, result, log)
    except Exception as error:
        first_error = error
        result["wfd_first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["wfd_disconnect_statuses"] = {}
        result["wfd_close_statuses"] = {}
        result["wfd_cleanup_errors"] = []
        for connection in list(session.connections.values()):
            if connection.config_id not in (CONTROL_CONFIG, RTSP_CONFIG):
                continue
            try:
                status = session.disconnect(connection)
                result["wfd_disconnect_statuses"][str(connection.host_port)] = status
                if status != 0:
                    raise TunnelError("WFD socket disconnect status %d" % status)
            except Exception as error:
                result["wfd_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        for config in (RTSP_CONFIG, CONTROL_CONFIG):
            if config not in session.configs:
                continue
            try:
                result["wfd_close_statuses"][str(config)] = session.close_config(
                    SERVICE_UID, config_id=config)
            except Exception as error:
                result["wfd_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
    if first_error is not None:
        raise first_error


def after_auth(session, connection, client, result, clock, log):
    cap.capabilities(session, connection, client, result, clock, log)
    pss.pss_ready(session, connection, client, result, clock, log)
    handshake.handshake(session, connection, client.codec()._key, result, log,
                        after_handshake=startup)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-wfd-startup", action="store_true")
    p.add_argument("--accept-persistent-state", action="store_true")
    p.add_argument("--ready-for-start-now", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_wfd_startup:
        emit("PLAN_ONLY", phone_access=False, manual_start_now=True,
             persistent_state=True, video=False, rtsp_responses=False, outer_seconds=90)
        return 0
    if (not a.accept_persistent_state or not a.ready_for_start_now or a.bus is None
            or a.address is None or a.output is None):
        p.error("requires persistent-state acceptance, manual readiness and bus/address/output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(transport_completed=False, wfd_startup_verified=False,
                  activation_tested=True, desktop_verified=False, video_tested=False,
                  persistent_state_may_remain=True)
    (a.output/"plan.json").write_text(json.dumps(dict(
        profile=cap.PROFILE, change_pss_state=pss.change_pss()["PARAM"],
        enable_screen_share=True, manual_wait_seconds=USER_SECONDS,
        rtsp_port=7236, rtsp_header_limit=8192, rtsp_responses=False,
        max_requests=32, max_acks=64, max_reads=2000,
        cleanup_reserved_reads=200, outer_seconds=90), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=after_auth, max_requests=32, session_class=TransferSession)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output/"result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("wfd_startup_result", **result)
    return 0 if result["transport_completed"] and result["wfd_startup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
