"""One native daemon loopback transfer in each direction; no app protocol.

Default PLAN_ONLY. Requires a fresh phone grant. Reuses the reviewed loopback
resource acquisition/budgets and the opt-in inbound Connect handler.
"""
import argparse
import json
from pathlib import Path
import signal

import loopback_capture as base
from tunnel_probe import SERVICE_UID, emit, _terminated
from usb_tunnel import Session, TunnelError

FORWARD = b"dex-loop-forward-v1"
REVERSE = b"dex-loop-reverse-v1"
MAX_REQUESTS = 11


class TransferSession(Session):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, accept_inbound=True)


def transfer(session, result):
    result["bidirectional_verified"] = False
    first_error = None
    try:
        result["daemon_version"] = session.get_version()
        result["exchange"] = session.exchange(0, tcp_send_buffer_bytes=0)
        opened = session.open_config(601, SERVICE_UID, base.LISTENER_PORT, operation=1)
        port = opened["port"]
        if not 1 <= port <= 65535:
            raise TunnelError("listener did not return a valid bound port")
        result["listener_port"] = port
        session.open_config(602, SERVICE_UID, port)
        outbound = session.connect(base.HOST_PORT, config_id=602, timeout_s=2)
        accepted = lambda: [c for c in session.connections.values()
                           if c.inbound and c.config_id == 601]
        if not session.wait(3, until=lambda: bool(accepted())) or len(accepted()) != 1:
            raise TunnelError("expected one accepted loopback connection")
        inbound = accepted()[0]
        result["outbound_key"] = outbound.key
        result["accepted_key"] = inbound.key
        result["accepted_host_port"] = inbound.host_port
        session.send(outbound, FORWARD, timeout_s=2)
        session.wait(3, until=lambda: len(inbound.received) >= len(FORWARD)
                     or inbound.closed_by_phone)
        if bytes(inbound.received) != FORWARD:
            raise TunnelError("forward payload not confirmed")
        result["forward_verified"] = True
        session.send(inbound, REVERSE, timeout_s=2)
        session.wait(3, until=lambda: len(outbound.received) >= len(REVERSE)
                     or outbound.closed_by_phone)
        if bytes(outbound.received) != REVERSE:
            raise TunnelError("reverse payload not confirmed")
        if len(accepted()) != 1:
            raise TunnelError("unexpected additional inbound connection")
        result["reverse_verified"] = True
        result["bidirectional_verified"] = True
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["disconnect_statuses"] = {}
        result["close_statuses"] = {}
        result["cleanup_errors"] = []
        # Disconnect accepted side first, then its outbound peer, then both
        # configs. Every key stays tracked even if sending its ACK failed.
        connections = sorted(list(session.connections.values()), key=lambda c: not c.inbound)
        for connection in connections:
            if session.connections.get(connection.host_port) is not connection:
                continue
            try:
                status = session.disconnect(connection)
                result["disconnect_statuses"][str(connection.host_port)] = status
                if status != 0:
                    raise TunnelError("disconnect status %d" % status)
            except Exception as error:
                result["cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        for config_id in reversed(list(session.configs)):
            try:
                result["close_statuses"][str(config_id)] = session.close_config(
                    SERVICE_UID, config_id=config_id)
            except Exception as error:
                result["cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
    if first_error is not None:
        raise first_error


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-loopback-transfer", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_loopback_transfer:
        emit("PLAN_ONLY", phone_access=False, auth=False, pss=False,
             payload_bytes_each_direction=len(FORWARD), outer_seconds=45,
             max_requests=MAX_REQUESTS, max_acks=16, max_reads=256)
        return 0
    if a.bus is None or a.address is None or a.output is None:
        p.error("approved run requires --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(transport_completed=False, bidirectional_verified=False)
    (a.output / "plan.json").write_text(json.dumps(dict(
        listener_port=base.LISTENER_PORT, config_ids=[601, 602],
        forward_hex=FORWARD.hex(), reverse_hex=REVERSE.hex(),
        max_requests=MAX_REQUESTS, max_acks=16, max_reads=256,
        cleanup_reserved_reads=32, outer_seconds=45,
        auth=False, pss=False, adb=False), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        base.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                   session_class=TransferSession, exchange_fn=transfer,
                   max_requests=MAX_REQUESTS)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("loopback_transfer_result", **result)
    return 0 if result["transport_completed"] and result["bidirectional_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
