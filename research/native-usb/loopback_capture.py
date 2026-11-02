"""One-shot native USB loopback accept capture; default PLAN_ONLY.

Op1 listener + Op2 Connect to the same phone-local port. No AUTH, TerminalInfo,
PSS, application data or IDC. Capture unknown frames without guessing a reply.
"""
import argparse
import json
from pathlib import Path
import signal
import time

from idc_capture import CaptureSession
from tunnel_probe import Link, SERVICE_UID, emit, _terminated
from version_query import validate_config

LISTENER_CONFIG = 601
CONNECT_CONFIG = 602
LISTENER_PORT = 46001
HOST_PORT = 50002
CAPTURE_SECONDS = 3
MAX_REQUESTS = 8
MAX_READS = 256
CLEANUP_READS = 32


def exchange(session, result):
    first_error = None
    try:
        result["daemon_version"] = session.get_version()
        result["exchange"] = session.exchange(0, tcp_send_buffer_bytes=0)
        opened = session.open_config(
            LISTENER_CONFIG, SERVICE_UID, LISTENER_PORT, operation=1)
        port = opened["port"]
        if not 1 <= port <= 65535:
            raise ValueError("listener did not return a valid bound port")
        result["listener_port"] = port
        session.open_config(CONNECT_CONFIG, SERVICE_UID, port)
        conn = session.connect(HOST_PORT, config_id=CONNECT_CONFIG)
        result["outbound_connection_key"] = conn.key
        # Do not stop on the first unknown frame: it may precede the accept.
        session.wait(CAPTURE_SECONDS, until=lambda: False)
        result["capture_window_completed"] = True
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["cleanup_errors"] = []
        for conn in list(session.connections.values()):
            try:
                status = session.disconnect(conn)
                result["disconnect_status"] = status
                if status != 0:
                    raise ValueError("loopback disconnect status %d" % status)
            except Exception as error:
                result["cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        result["close_statuses"] = {}
        for config_id in reversed(list(session.configs)):
            try:
                result["close_statuses"][str(config_id)] = session.close_config(
                    SERVICE_UID, config_id=config_id)
            except Exception as error:
                result["cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        # Includes unknown frames that arrived during teardown; cannot yet prove
        # which is an accept. Raw logs also preserve recognized traffic.
        result["captured"] = list(session.captured)
        result["unknown_frames"] = len(session.captured)
        result["inbound_layout_verified"] = False
    if first_error is not None:
        raise first_error


def probe(device, util, timeout_error, output, result, clock=time.monotonic,
          session_class=CaptureSession, exchange_fn=exchange, max_requests=MAX_REQUESTS):
    claimed = False
    with (output / "events.jsonl").open("x") as events:
        def log(event, **fields):
            events.write(json.dumps(dict(event=event, **fields), sort_keys=True) + "\n")
            events.flush()
            emit(event, **fields)
        try:
            log("usb_get_active_configuration")
            validate_config(device.get_active_configuration())
            log("usb_kernel_driver_check", interface=3)
            if device.is_kernel_driver_active(3):
                raise RuntimeError("kernel driver active; refusing detach")
            log("usb_claim", interface=3)
            util.claim_interface(device, 3)
            claimed = True
            link = Link(device, timeout_error, max_requests=max_requests,
                        max_acks=16, max_reads=MAX_READS, cleanup_reads=CLEANUP_READS,
                        record=lambda direction, data: log(
                            "usb_raw", direction=direction, bytes_hex=data.hex()))
            session = session_class(link, 1, 65536, 65536, log=log, clock=clock)
            exchange_fn(session, result)
        finally:
            try:
                if claimed:
                    try:
                        log("usb_release", interface=3)
                    finally:
                        util.release_interface(device, 3)
                    result["usb_released"] = True
            finally:
                try:
                    log("usb_dispose")
                finally:
                    util.dispose_resources(device)
                result["usb_disposed"] = True


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-loopback-capture", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_loopback_capture:
        emit("PLAN_ONLY", phone_access=False, auth=False, terminal_info=False,
             pss=False, application_data=False, outer_timeout_seconds=30,
             max_requests=MAX_REQUESTS, max_acks=16, max_reads=MAX_READS)
        return 0
    if a.output is None or a.bus is None or a.address is None:
        p.error("approved run requires --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(transport_completed=False, inbound_layout_verified=False,
                  auth=False, pss=False, application_data_sent=False)
    (a.output / "plan.json").write_text(json.dumps(dict(
        listener_config=LISTENER_CONFIG, connect_config=CONNECT_CONFIG,
        listener_port=LISTENER_PORT, capture_seconds=CAPTURE_SECONDS,
        max_requests=MAX_REQUESTS, max_acks=16, max_reads=MAX_READS,
        cleanup_reads=CLEANUP_READS, outer_seconds=30), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("loopback_capture_result", **result)
    return 0 if result["transport_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
