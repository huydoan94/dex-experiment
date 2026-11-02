"""One native daemon UDP loopback datagram in each direction; no app protocol.

Default PLAN_ONLY. Requires a fresh phone grant. Op1 UDP config binds
BOUND_PORT; op2 UDP config gets a daemon-created ephemeral socket named by
SOCKET_KEY on first send. No AUTH, TerminalInfo, PSS, IDC, WFD, RTSP or ADB.
Layouts: UDP_TRANSPORT_MAP.md (static A54 reference, not S20+ proof).
"""
import argparse
import json
from pathlib import Path
import signal

import loopback_capture as base
from tunnel_probe import SERVICE_UID, emit, _terminated
from udp_tunnel import UdpSession
from usb_tunnel import TunnelError

BOUND_CONFIG = 611
EPHEMERAL_CONFIG = 612
BOUND_PORT = 46003
# Names the op2 socket; must differ from every op1 port (global lookup 0001ea1c).
SOCKET_KEY = 50003
FORWARD = b"dex-udp-forward-v1"
REVERSE = b"dex-udp-reverse-v1"
MAX_REQUESTS = 8
OUTER_SECONDS = 45


def _one(session, config_id):
    found = [d for d in session.datagrams if d.config_id == config_id]
    return found[0] if len(found) == 1 else None


def transfer(session, result):
    result["bidirectional_verified"] = False
    first_error = None
    try:
        result["daemon_version"] = session.get_version()
        result["exchange"] = session.exchange(0, tcp_send_buffer_bytes=0)
        opened = session.open_udp(BOUND_CONFIG, SERVICE_UID, BOUND_PORT, operation=1)
        result["bound_open"] = opened
        if (opened["port"], opened["client_port"]) != (BOUND_PORT, 0):
            raise TunnelError("UDP op1 did not report the requested bound port")
        opened = session.open_udp(EPHEMERAL_CONFIG, SERVICE_UID, 0)
        result["ephemeral_open"] = opened
        if (opened["port"], opened["client_port"]) != (0, 0):
            raise TunnelError("UDP op2 reported an unexpected port")
        session.send_datagram(EPHEMERAL_CONFIG, SOCKET_KEY, BOUND_PORT, FORWARD, timeout_s=2)
        session.wait(3, until=lambda: bool(session.datagrams))
        # Gating checks are only what routing needs; the remaining mapped
        # predictions are recorded separately so a mismatch keeps the evidence.
        forward = _one(session, BOUND_CONFIG)
        if (len(session.datagrams) != 1 or forward is None or forward.payload != FORWARD
                or forward.socket_port != BOUND_PORT or forward.source_port == BOUND_PORT):
            raise TunnelError("forward datagram not confirmed")
        ephemeral_port = forward.source_port
        result["ephemeral_source_port"] = ephemeral_port
        result["forward_verified"] = True
        session.send_datagram(BOUND_CONFIG, BOUND_PORT, ephemeral_port, REVERSE, timeout_s=2)
        session.wait(3, until=lambda: len(session.datagrams) >= 2)
        reverse = _one(session, EPHEMERAL_CONFIG)
        if (len(session.datagrams) != 2 or reverse is None or reverse.payload != REVERSE
                or reverse.socket_port != SOCKET_KEY):
            raise TunnelError("reverse datagram not confirmed")
        result["reverse_verified"] = True
        result["bidirectional_verified"] = True
        result["map_predictions_matched"] = (
            (forward.config_port, forward.bound_port) == (BOUND_PORT, BOUND_PORT)
            and (reverse.source_port, reverse.config_port, reverse.bound_port)
            == (BOUND_PORT, 0, 0))
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["close_statuses"] = {}
        result["cleanup_errors"] = []
        # No UDP socket Disconnect is mapped; config close is the only teardown.
        for config_id in reversed(list(session.configs)):
            try:
                result["close_statuses"][str(config_id)] = session.close_config(
                    SERVICE_UID, config_id=config_id)
            except Exception as error:
                result["cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        # After the closes, so datagrams that arrive during teardown are kept.
        result["datagrams"] = [dict(config_id=d.config_id, socket_port=d.socket_port,
                                    source_port=d.source_port, config_port=d.config_port,
                                    bound_port=d.bound_port, payload_hex=d.payload.hex())
                               for d in session.datagrams]
        result["dropped_datagrams"] = [dict(config_id=d.config_id, socket_port=d.socket_port,
                                            source_port=d.source_port,
                                            payload_hex=d.payload.hex())
                                       for d in session.dropped_datagrams]
    if first_error is not None:
        raise first_error


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-udp-loopback", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_udp_loopback:
        emit("PLAN_ONLY", phone_access=False, auth=False, pss=False,
             payload_bytes_each_direction=len(FORWARD), outer_seconds=OUTER_SECONDS,
             max_requests=MAX_REQUESTS, max_acks=16, max_reads=base.MAX_READS)
        return 0
    if a.bus is None or a.address is None or a.output is None:
        p.error("approved run requires --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(transport_completed=False, bidirectional_verified=False)
    (a.output / "plan.json").write_text(json.dumps(dict(
        config_ids=[BOUND_CONFIG, EPHEMERAL_CONFIG], bound_port=BOUND_PORT,
        socket_key=SOCKET_KEY, forward_hex=FORWARD.hex(), reverse_hex=REVERSE.hex(),
        max_requests=MAX_REQUESTS, max_acks=16, max_reads=base.MAX_READS,
        cleanup_reserved_reads=base.CLEANUP_READS, outer_seconds=OUTER_SECONDS,
        auth=False, pss=False, adb=False), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8,
                                    idProduct=0x6860, bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        base.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                   session_class=UdpSession, exchange_fn=transfer,
                   max_requests=MAX_REQUESTS)
        result["transport_completed"] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("udp_loopback_result", **result)
    return 0 if result["transport_completed"] and result["bidirectional_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
