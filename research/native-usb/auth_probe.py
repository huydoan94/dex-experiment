"""Bounded DeX USB AUTH SEQ1..3 test; default PLAN_ONLY, no ADB or activation."""
import argparse
import json
from pathlib import Path
import secrets
import signal
import time

from main_channel import AuthClient, AUTH_LIMIT, FrameDecoder, ProtocolError, encode_frame
from usb_tunnel import Session, TunnelError
from tunnel_probe import (Link, SERVICE_UID, MAX_FRAME_BYTES, MAX_RECEIVE_BYTES,
                          emit, _teardown, _terminated)
from version_query import validate_config

MAC = "02:00:00:00:00:01"  # Synthetic locally administered client identity.
AUTH_SECONDS = 12
ROUND_SECONDS = 3
MAX_REQUESTS = 9  # version, exchange, open, connect, three Data, disconnect, close.
MAX_ACKS = 64
MAX_READS = 2000
CLEANUP_READS = 200
OUTER_SECONDS = 45


def authenticate(session, connection, client, clock=time.monotonic, log=lambda **fields: None):
    """One attempt, at most three sends. No resend on timeout or malformed input."""
    decoder = FrameDecoder(AUTH_LIMIT)
    deadline = clock() + AUTH_SECONDS
    outgoing = client.start(1)
    for step in (1, 2, 3):
        remaining = deadline - clock()
        if remaining <= 0:
            raise ProtocolError("AUTH deadline expired")
        payload = encode_frame(outgoing, AUTH_LIMIT)
        # This keeps each AUTH frame in one native Data request at buffer>=1024.
        if len(payload) > 512:
            raise ProtocolError("unexpected outgoing AUTH size")
        log(event="auth_send", step=step, sid=outgoing.sid, size_bytes=len(payload))
        session.send(connection, payload, timeout_s=min(2, remaining))
        round_deadline = min(deadline, clock() + ROUND_SECONDS)
        frames = []
        while not frames:
            if connection.closed_by_phone:
                raise ProtocolError("phone closed AUTH connection")
            if connection.received:
                chunk = bytes(connection.received)
                connection.received.clear()
                frames = decoder.feed(chunk)
                if len(frames) > 1:
                    raise ProtocolError("unexpected additional AUTH frame")
                if frames:
                    break
            remaining = round_deadline - clock()
            if remaining <= 0:
                raise ProtocolError("AUTH reply deadline expired")
            if not session.wait(remaining, until=lambda: bool(connection.received)
                                or connection.closed_by_phone):
                raise ProtocolError("AUTH reply deadline expired")
        # Even a queued response is not accepted after the shared deadline.
        if clock() >= deadline or clock() >= round_deadline:
            raise ProtocolError("AUTH reply deadline expired")
        log(event="auth_reply", step=step, sid=frames[0].sid,
            size_bytes=len(frames[0].payload))
        outgoing = client.receive(frames[0], step + 1 if step < 3 else None)
    decoder.finish()
    if outgoing is not None or client.state != "AUTHENTICATED":
        raise ProtocolError("AUTH did not complete")
    log(event="auth_verified", verified=True)


def exchange(session, config_id, host_port, result, begin_cleanup=lambda: None,
             clock=time.monotonic, log=lambda **fields: None, after_auth=None):
    """Always attempt Disconnect with the learned key, then close config."""
    first_error = None
    client = None
    try:
        result["daemon_version"] = session.get_version()
        fields = session.exchange(0, tcp_send_buffer_bytes=0)
        result["exchange"] = fields
        if fields["usb_buffer_bytes"] < 1024:
            raise ProtocolError("negotiated buffer too small for bounded AUTH writes")
        result["open"] = session.open_config(config_id, SERVICE_UID, 15000)
        connection = session.connect(host_port)
        result["connection_key"] = connection.key
        result["authentication_verified"] = False
        client = AuthClient(MAC)
        authenticate(session, connection, client, clock, log)
        result["authentication_verified"] = True
        if after_auth is not None:
            after_auth(session, connection, client, result, clock, log)
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        if client is not None:
            result["authentication_verified"] = client.state == "AUTHENTICATED"
        session.begin_cleanup()
        begin_cleanup()
        errors = _teardown(session, result)
        if first_error is None:
            if errors:
                first_error = errors[0]
            elif result.get("disconnect_status") != 0 or result.get("close_status") != 0:
                first_error = TunnelError("cleanup was not confirmed")
    if first_error is not None:
        raise first_error


def probe(device, util, timeout_error, output, result, clock=time.monotonic,
          after_auth=None, max_requests=MAX_REQUESTS, session_class=Session):
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
                raise RuntimeError("interface has kernel driver; refusing detach")
            log("usb_claim", interface=3)
            util.claim_interface(device, 3)
            claimed = True
            link = Link(device, timeout_error, max_requests=max_requests, max_acks=MAX_ACKS,
                        max_reads=MAX_READS, cleanup_reads=CLEANUP_READS,
                        record=lambda direction, data: log("usb_raw", direction=direction,
                                                           bytes_hex=data.hex()))
            session = session_class(link, secrets.randbelow(0xffffffff) + 1,
                              MAX_FRAME_BYTES, MAX_RECEIVE_BYTES, clock=clock, log=log)
            config_id = secrets.randbelow(999) + 1
            host_port = 40000 + secrets.randbelow(10000)
            log("transport_identity", config_id=config_id, host_port=host_port,
                client_mac=MAC)
            exchange(session, config_id, host_port, result, link.begin_cleanup, clock=clock, log=log,
                     after_auth=after_auth)
        finally:
            try:
                if claimed:
                    # Cleanup must still happen if any event write fails.
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
    p.add_argument("--approved-phone-auth-test", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_auth_test:
        emit("PLAN_ONLY", phone_access=False, max_usb_requests=MAX_REQUESTS,
             max_usb_acks=MAX_ACKS, max_usb_reads=MAX_READS,
             auth_seconds=AUTH_SECONDS, outer_timeout_seconds=OUTER_SECONDS,
             adb=False, activation=False, terminal_info=False)
        return 0
    if a.output is None or a.bus is None or a.address is None:
        p.error("approved run requires --output, --bus, --address")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid USB bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(authentication_verified=False, activation_tested=False)
    # USB imports and selection occur only after the explicit guard and new output.
    try:
        import usb.core
        import usb.util
        emit("usb_find", bus=a.bus, address=a.address, vendor=0x04e8, product=0x6860)
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone; refusing alternatives")
        probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result)
        result["success"] = True
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("auth_test_result", **result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

