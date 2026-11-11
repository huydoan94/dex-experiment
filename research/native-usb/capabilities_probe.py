"""One encrypted TerminalInfo exchange after AUTH. Default performs no phone access."""
import argparse
import json
from pathlib import Path
import signal
import time

import auth_probe
import site_env
from main_channel import Frame, FrameDecoder, ProtocolError, encode_frame

MAX_REQUESTS = 10
REPLY_SECONDS = 3
MAX_CAPABILITY_BYTES = 8192

# Windows-compatible DeX protocol profile; the implementation runs on Linux.
PROFILE = {
    "SinkMAC": "02:00:00:00:00:01",
    "SinkName": site_env.sink_name(),
    "SinkIP": "127.0.0.1",
    "KmsVer": "",
    "SinkType": "Windows",
    "PcVer": "2.4.1.27",
    "SinkApkVersion": "",
    "ConnectedSourceIP": "127.0.0.1",
    "SinkIDCConnectBeforehand": False,
    "SinkAutoStartStatus": False,
    "SinkNotificationStatus": False,
    "SinkCmdAsCtrlStatus": False,
    "SinkOSVersion": "10.0",
    "SinkUIRatio": "100",
    "SinkSilentInstallCount": 0,
    "WifiConnectivity": "None",
}


def terminal_info():
    return {"TYPE": "REQ", "MSG": "TerminalInfo", "PARAM": dict(PROFILE)}


def _redact_reply(obj):
    saved = dict(obj)
    saved["PARAM"] = dict(obj.get("PARAM", {}))
    for field in ("SerialNumber", "Wifi_MACAddress"):
        if field in saved["PARAM"]:
            saved["PARAM"][field] = "[device-id]"
    return saved


def capabilities(session, connection, client, result, clock=time.monotonic,
                 log=lambda **fields: None):
    """Send once, receive once, never activate PSS or issue extra commands."""
    result["terminal_info_attempted"] = False
    result["terminal_info_accepted"] = False
    result["capabilities_verified"] = False
    codec = client.codec()
    payload = codec.encrypt(terminal_info())
    wire = encode_frame(Frame(4, payload))
    # Bound this phase to ONE native host Data request.
    if len(wire) > min(2048, session.usb_buffer_bytes - 56):
        raise ProtocolError("TerminalInfo does not fit one bounded Data request")
    log(event="terminal_info_send", sid=4, size_bytes=len(wire), profile=PROFILE)
    # Mark attempted before sending; a lost ack does not prove no phone write.
    result["terminal_info_attempted"] = True
    session.send(connection, wire, timeout_s=2)
    decoder = FrameDecoder(MAX_CAPABILITY_BYTES)
    deadline = clock() + REPLY_SECONDS
    frames = []
    while not frames:
        if connection.closed_by_phone:
            raise ProtocolError("phone closed capability connection")
        if connection.received:
            chunk = bytes(connection.received)
            connection.received.clear()
            frames = decoder.feed(chunk)
            if len(frames) > 1:
                raise ProtocolError("unexpected additional capability frame")
            if frames:
                break
        remaining = deadline - clock()
        if remaining <= 0 or not session.wait(
                remaining, until=lambda: bool(connection.received) or connection.closed_by_phone):
            raise ProtocolError("capability reply deadline expired")
    if clock() >= deadline:
        raise ProtocolError("capability reply deadline expired")
    obj = codec.decrypt(frames[0].payload)  # No plaintext fallback.
    if obj["TYPE"] != "RESP" or obj["MSG"] != "TerminalInfo":
        raise ProtocolError("unexpected encrypted capability message")
    result["terminal_info_accepted"] = obj.get("RESULT") is True
    if not isinstance(obj.get("PARAM"), dict):
        raise ProtocolError("missing capability parameters")
    result["capabilities"] = _redact_reply(obj)
    if not result["terminal_info_accepted"] or obj.get("REASON") is not None:
        raise ProtocolError("phone rejected TerminalInfo")
    param = obj["PARAM"]
    expected = {"ModelName": "SM-G985F", "Platform": "Android", "SourceSDKInt": 33,
                "ApkVersion": "2.5.00.16", "SourceEncryptVersion": 2}
    if any(param.get(key) != value for key, value in expected.items()):
        raise ProtocolError("unsupported source capability identity")
    resolution = param.get("Resolution")
    if (param.get("SrcWfdSupport") is not True or not isinstance(resolution, dict)
            or any(type(resolution.get(key)) is not int or not 1 <= resolution[key] <= 8192
                   for key in ("Width", "Height"))):
        raise ProtocolError("unsupported display capabilities")
    result["capabilities_verified"] = True
    decoder.finish()
    log(event="capabilities_verified", model=param["ModelName"],
        source_sdk=param["SourceSDKInt"], encryption_version=param["SourceEncryptVersion"],
        wfd_supported=True, resolution=resolution)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-capabilities-test", action="store_true")
    p.add_argument("--accept-persistent-preferences", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_capabilities_test:
        auth_probe.emit("PLAN_ONLY", phone_access=False, max_usb_requests=MAX_REQUESTS,
                        terminal_info=True, persistent_preferences=True,
                        activation=False, outer_timeout_seconds=45, profile=PROFILE)
        return 0
    if (not a.accept_persistent_preferences or a.output is None
            or a.bus is None or a.address is None):
        p.error("approved run needs --accept-persistent-preferences, --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid USB bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(authentication_verified=False, terminal_info_attempted=False,
                  terminal_info_accepted=False, capabilities_verified=False,
                  activation_tested=False, persistent_preferences_may_change=True)
    (a.output / "plan.json").write_text(json.dumps(dict(
        profile=PROFILE, max_native_requests=MAX_REQUESTS, max_native_acks=64,
        max_usb_reads=2000, cleanup_read_reserve=200, outer_seconds=45,
        auth_seconds=12, capability_reply_seconds=REPLY_SECONDS,
        terminal_info_count=1, pss_activation=False), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        auth_probe.emit("usb_find", bus=a.bus, address=a.address, vendor=0x04e8, product=0x6860)
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone; refusing alternatives")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=capabilities, max_requests=MAX_REQUESTS)
        result["success"] = True
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        auth_probe.emit("capability_test_result", **result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

