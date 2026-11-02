"""One validated IDC SIDESYNC_CONN handshake; no CONTROL or screen sharing.

Uses live-proven inbound USB handling, and decodes the encrypted reply while
the key is in memory. Default PLAN_ONLY. Needs a fresh specific phone grant.
"""
import argparse
import json
from pathlib import Path
import signal
import struct

import auth_probe
import capabilities_probe as cap
import pss_probe as pss
import idc
from idc_capture import observe_replies
from loopback_transfer import TransferSession
from tunnel_probe import SERVICE_UID, emit

LISTENER_CONFIG = 1201
CONNECT_CONFIG = 1202
LISTENER_PORT = 46001
HOST_PORT = 50002


def complete_reply(connection):
    data = connection.received
    return len(data) >= 2 and len(data) >= 2 + struct.unpack_from(">H", data)[0]


def handshake(session, main_connection, key, result, log=lambda **fields: None,
              after_handshake=None):
    result["idc_handshake_verified"] = False
    result["idc_request_attempted"] = False
    connection = None
    first_error = None
    try:
        listener = session.open_config(LISTENER_CONFIG, SERVICE_UID, LISTENER_PORT, operation=1)
        port = listener["port"]
        if not 1 <= port <= 65535:
            raise ValueError("invalid listener port")
        result["listener_port"] = port
        session.open_config(CONNECT_CONFIG, SERVICE_UID, 7246)
        connection = session.connect(HOST_PORT, config_id=CONNECT_CONFIG, timeout_s=2)
        payload = idc.sidesync_conn_request(key, port)
        result["idc_request_attempted"] = True
        log(event="idc_handshake_send", size_bytes=len(payload))
        session.send(connection, payload, timeout_s=2)
        session.wait(3, until=lambda: complete_reply(connection) or connection.closed_by_phone)
        reply = idc.sidesync_conn_response(key, bytes(connection.received))
        result["idc_response"] = reply
        if not reply["accepted"]:
            raise ValueError("IDC request rejected: " + reply["reason"])
        result["idc_handshake_verified"] = True
        # Observe the queued main state notice / first phone outbound command
        # for at most one second. Never send a CONTROL or accepted-app reply.
        session.wait(1, until=lambda: main_connection.closed_by_phone)
        if after_handshake is not None:
            if main_connection.closed_by_phone:
                raise ValueError("phone closed main channel before continuation")
            after_handshake(session, main_connection, key, result, log)
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["idc_disconnect_statuses"] = {}
        result["idc_close_statuses"] = {}
        result["idc_cleanup_errors"] = []
        owned = [c for c in session.connections.values()
                 if c.config_id in (LISTENER_CONFIG, CONNECT_CONFIG)]
        result["accepted_connections"] = [
            dict(key=c.key, host_port=c.host_port, config_id=c.config_id,
                 received_bytes=len(c.received), received_hex=bytes(c.received).hex())
            for c in owned if c.inbound]
        for c in sorted(owned, key=lambda item: not item.inbound):
            if session.connections.get(c.host_port) is not c:
                continue
            try:
                status = session.disconnect(c)
                result["idc_disconnect_statuses"][str(c.host_port)] = status
                if status != 0:
                    raise ValueError("IDC disconnect status %d" % status)
            except Exception as error:
                result["idc_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        for config_id in (CONNECT_CONFIG, LISTENER_CONFIG):
            if config_id not in session.configs:
                continue
            try:
                result["idc_close_statuses"][str(config_id)] = session.close_config(
                    SERVICE_UID, config_id=config_id)
            except Exception as error:
                result["idc_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        response = bytes(connection.received) if connection else b""
        result["connection_response_hex"] = response.hex()
        observe_replies(bytes(main_connection.received), response, key, result)
    if first_error is not None:
        raise first_error


def after_auth(session, connection, client, result, clock, log):
    cap.capabilities(session, connection, client, result, clock, log)
    pss.pss_ready(session, connection, client, result, clock, log)
    handshake(session, connection, client.codec()._key, result, log)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-idc-handshake", action="store_true")
    p.add_argument("--accept-persistent-preferences", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_idc_handshake:
        emit("PLAN_ONLY", phone_access=False, auth=True, terminal_info=True,
             pss_ready=True, idc_requests=1, control=False, activation=False,
             max_requests=20, max_acks=64, max_reads=2000, outer_seconds=60)
        return 0
    if not a.accept_persistent_preferences or a.bus is None or a.address is None or a.output is None:
        p.error("approved run needs persistent-preferences acceptance, bus/address/output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(authentication_verified=False, capabilities_verified=False,
                  pss_ready_confirmed=False, idc_handshake_verified=False,
                  transport_completed=False, activation_tested=False,
                  persistent_preferences_may_change=True)
    (a.output / "plan.json").write_text(json.dumps(dict(
        profile=cap.PROFILE, change_pss_state=pss.change_pss()["PARAM"],
        idc_requests=1, control=False, max_requests=20, max_acks=64,
        max_reads=2000, cleanup_reserved_reads=200, outer_seconds=60), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=after_auth, max_requests=20, session_class=TransferSession)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("idc_handshake_result", **result)
    return 0 if result["transport_completed"] and result["idc_handshake_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
