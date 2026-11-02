"""TerminalInfo, then ONE ChangePSSState READY request. Default performs no phone access."""
import argparse
import json
from pathlib import Path
import signal
import time

import auth_probe
import capabilities_probe as cap
from main_channel import Frame, FrameDecoder, ProtocolError, encode_frame

MAX_REQUESTS = 11  # capability batch (10) plus one ChangePSSState Data.
REPLY_SECONDS = 3
MAX_PSS_BYTES = 1024
PSS_SID = 5  # Host SID counter: AUTH 1..3, TerminalInfo 4.


def change_pss():
    # l2/g.p -> l2/f.b: PSS_STATE1/PSS_MODE0 is the only value that starts Wimp.
    return {"TYPE": "REQ", "MSG": "ChangePSSState", "PARAM": {"PSS_STATE": 1, "PSS_MODE": 0}}


def pss_ready(session, connection, client, result, clock=time.monotonic,
              log=lambda **fields: None):
    """Send once; accept only RESP ChangePSSState RESULT=true (sent after Wimp READY)."""
    result["pss_attempted"] = False
    result["pss_ready_confirmed"] = False
    codec = client.codec()
    wire = encode_frame(Frame(PSS_SID, codec.encrypt(change_pss())))
    if len(wire) > min(2048, session.usb_buffer_bytes - 56):
        raise ProtocolError("ChangePSSState does not fit one bounded Data request")
    log(event="pss_send", sid=PSS_SID, size_bytes=len(wire), pss_state=1, pss_mode=0)
    # Mark attempted before sending; a lost ack does not prove the phone ignored it.
    result["pss_attempted"] = True
    session.send(connection, wire, timeout_s=2)
    decoder = FrameDecoder(MAX_PSS_BYTES)
    deadline = clock() + REPLY_SECONDS
    frames = []
    while not frames:
        if connection.closed_by_phone:
            raise ProtocolError("phone closed connection before PSS reply")
        if connection.received:
            chunk = bytes(connection.received)
            connection.received.clear()
            frames = decoder.feed(chunk)
            if len(frames) > 1:
                raise ProtocolError("unexpected additional PSS frame")
            if frames:
                break
        remaining = deadline - clock()
        if remaining <= 0 or not session.wait(
                remaining, until=lambda: bool(connection.received) or connection.closed_by_phone):
            raise ProtocolError("PSS reply deadline expired")
    if clock() >= deadline:
        raise ProtocolError("PSS reply deadline expired")
    obj = codec.decrypt(frames[0].payload)  # No plaintext fallback.
    result["pss_reply"] = obj
    if obj.get("TYPE") != "RESP" or obj.get("MSG") != "ChangePSSState":
        raise ProtocolError("unexpected encrypted PSS message")
    if obj.get("RESULT") is not True or obj.get("REASON") is not None:
        raise ProtocolError("phone did not confirm PSS READY")
    result["pss_ready_confirmed"] = True
    decoder.finish()
    log(event="pss_ready_confirmed")


def after_auth(session, connection, client, result, clock, log):
    cap.capabilities(session, connection, client, result, clock, log)
    pss_ready(session, connection, client, result, clock, log)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-pss-ready-test", action="store_true")
    p.add_argument("--accept-persistent-preferences", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_pss_ready_test:
        auth_probe.emit("PLAN_ONLY", phone_access=False, max_usb_requests=MAX_REQUESTS,
                        terminal_info=True, change_pss_state=change_pss()["PARAM"],
                        idc=False, wfd=False, activation=False, outer_timeout_seconds=45)
        return 0
    if (not a.accept_persistent_preferences or a.output is None
            or a.bus is None or a.address is None):
        p.error("approved run needs --accept-persistent-preferences, --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid USB bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(authentication_verified=False, terminal_info_attempted=False,
                  capabilities_verified=False, pss_attempted=False,
                  pss_ready_confirmed=False, activation_tested=False,
                  persistent_preferences_may_change=True)
    (a.output / "plan.json").write_text(json.dumps(dict(
        profile=cap.PROFILE, change_pss_state=change_pss()["PARAM"],
        max_native_requests=MAX_REQUESTS, max_native_acks=64, max_usb_reads=2000,
        cleanup_read_reserve=200, outer_seconds=45, auth_seconds=12,
        capability_reply_seconds=cap.REPLY_SECONDS, pss_reply_seconds=REPLY_SECONDS,
        idc=False, wfd=False), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        auth_probe.emit("usb_find", bus=a.bus, address=a.address, vendor=0x04e8, product=0x6860)
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone; refusing alternatives")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=after_auth, max_requests=MAX_REQUESTS)
        result["success"] = True
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        auth_probe.emit("pss_test_result", **result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
