"""Capture the phone's connect-back frame on a host Operation1 listener.

Drives AUTH -> TerminalInfo -> ChangePSSState(READY), opens an Operation1
listener L (bound port P) and an Operation2 connection C to the phone's IDC
CONNECTION server (7246), sends ONE encrypted SIDESYNC_CONN REQUEST advertising
P, then passively RECORDS whatever the phone sends on L when its IDC sender
dials back — a frame whose layout is not yet mapped (IDC_ACCEPTOR.md). Nothing
is sent on CONTROL and no ENABLE_SCR_SHR, so no "Start now" dialog / WFD / video.
Default performs no phone access. See IDC_CAPTURE_DESIGN.md.
"""
import argparse
import json
from pathlib import Path
import signal
import time

import auth_probe
import capabilities_probe as cap
from conn_frames import encode
import idc
import pss_probe as pss
from main_channel import ControlCodec, FrameDecoder
from tunnel_probe import SERVICE_UID
from usb_tunnel import Session, TunnelError

CONNECTION_PORT = 7246          # phone IDC CONNECTION server (o2/o.V, i2/i.e)
LISTENER_CONFIG = 1201          # host-chosen config ids, clear of the main's random 1..999
CONNECT_CONFIG = 1202
LISTENER_PORT = 46001           # host-chosen phone-side listener port to request
C_HOST_PORT = 50002             # host Connect port, clear of the main's 40000..49999
CAPTURE_SECONDS = 8
MAX_CAPTURED = 32
REPLY_SECONDS = 3


class CaptureSession(Session):
    """Like Session, but records an unexpected phone frame instead of raising.

    Only Data(5)/Disconnect(4) on KNOWN connections are handled normally. Any
    other phone frame (the unmapped connect-back notify, a Data on the listener
    from an unknown key, a notification) is logged raw and capture continues.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured = []

    def _record_unknown(self, frame):
        if len(self.captured) >= MAX_CAPTURED:
            return
        raw = encode(frame)
        entry = dict(command=frame.command, kind=frame.kind,
                     transaction=frame.transaction, size_bytes=len(raw),
                     bytes_hex=raw.hex())
        self.captured.append(entry)
        self.log('idc_inbound_captured', **{k: entry[k] for k in
                 ('command', 'kind', 'transaction', 'size_bytes')})

    def _handle_unsolicited(self, frame):
        if frame.kind == 1 and frame.command in (4, 5):
            try:
                self._phone_request(frame)
                return
            except TunnelError:
                pass
        self._record_unknown(frame)



def observe_replies(main_data, idc_data, session_key, result):
    """Offline decoding only: called while the key exists; never stores the key.

    Diagnostics must not prevent cleanup or mask the original transport error.
    Missing/truncated/rejected IDC responses are explicit, never called accepted.
    Main notice bodies are reduced to protocol names, booleans and PSS integers.
    """
    result["idc_response_verified"] = False
    try:
        reply = idc.sidesync_conn_response(session_key, idc_data)
        result["idc_response"] = reply
        result["idc_response_verified"] = reply["accepted"]
    except ValueError:
        result["idc_response_error"] = "missing, malformed or undecryptable IDC reply"
    result["main_notifications"] = []
    decoder = FrameDecoder(65536)
    codec = ControlCodec(session_key)
    try:
        for frame in decoder.feed(main_data):
            obj = codec.decrypt(frame.payload)
            notice = dict(sid=frame.sid)
            for key in ("TYPE", "MSG"):
                value = obj.get(key)
                if isinstance(value, str) and len(value) <= 64 and value.isascii() and value.replace("_", "").isalnum():
                    notice[key.lower()] = value
            if type(obj.get("RESULT")) is bool:
                notice["result"] = obj["RESULT"]
            params = obj.get("PARAM")
            if isinstance(params, dict):
                for key in ("PSS_STATE", "PSS_MODE"):
                    if type(params.get(key)) is int:
                        notice[key.lower()] = params[key]
            result["main_notifications"].append(notice)
        decoder.finish()
    except ValueError:
        result["main_notification_error"] = "malformed, truncated or undecryptable main notice"


def idc_probe(session, main_connection, session_key, result, clock=time.monotonic,
              log=lambda **f: None):
    """Open L + C, send one SIDESYNC_CONN(field0=P), capture the connect-back.

    main_connection (the 15000 channel) and its config stay open for the caller's
    teardown; this closes only C and L.
    """
    result["listener_opened"] = False
    result["idc_request_sent"] = False
    result["inbound_frames"] = 0
    cconn = None
    first_error = None
    try:
        listener = session.open_config(LISTENER_CONFIG, SERVICE_UID, LISTENER_PORT, operation=1)
        bound_port = listener["port"] or LISTENER_PORT
        result["listener_opened"] = True
        result["listener_port"] = bound_port
        log(event="idc_listener_open", config_id=LISTENER_CONFIG, bound_port=bound_port)
        session.open_config(CONNECT_CONFIG, SERVICE_UID, CONNECTION_PORT)
        cconn = session.connect(C_HOST_PORT, config_id=CONNECT_CONFIG)
        frame = idc.sidesync_conn_request(session_key, bound_port)
        log(event="idc_request_send", size_bytes=len(frame), listener_port=bound_port)
        session.send(cconn, frame)
        result["idc_request_sent"] = True
        # Capture window: wait for the first frame on the listener, then drain briefly.
        deadline = clock() + CAPTURE_SECONDS
        session.wait(CAPTURE_SECONDS, until=lambda: bool(session.captured)
                     or main_connection.closed_by_phone)
        session.wait(min(1.0, max(0.0, deadline - clock())), until=lambda: False)
    except Exception as error:
        first_error = error
        result["first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        result["inbound_frames"] = len(session.captured)
        result["captured"] = list(session.captured)
        response = bytes(cconn.received) if cconn else b""
        result["connection_response_hex"] = response.hex()
        observe_replies(bytes(main_connection.received), response, session_key, result)
        # Unknown frames can be unrelated notifications; never call them a
        # verified connection-back before their native layout is mapped.
        result["capture_goal_met"] = False
        result["unknown_frame_candidate_present"] = bool(session.captured)
        # No further protocol work follows: unlock the read reserve before IDC
        # teardown, not only later when auth_probe tears down the main channel.
        session.begin_cleanup()
        session.link.begin_cleanup()
        errors = []
        result["idc_cleanup_errors"] = []
        if cconn is not None and session.connections.get(cconn.host_port) is cconn:
            try:
                status = session.disconnect(cconn)
                result["idc_disconnect_status"] = status
                if status != 0:
                    raise TunnelError("IDC disconnect status %d" % status)
            except Exception as error:
                errors.append(error)
        for config_id in (CONNECT_CONFIG, LISTENER_CONFIG):
            if config_id in session.configs:
                try:
                    session.close_config(SERVICE_UID, config_id=config_id)
                except Exception as error:
                    errors.append(error)
        result["idc_cleanup_errors"] = [
            type(error).__name__ + ": " + str(error) for error in errors
        ]
        if first_error is None and errors:
            first_error = errors[0]
    if first_error is not None:
        raise first_error


def after_auth(session, connection, client, result, clock, log):
    cap.capabilities(session, connection, client, result, clock, log)
    pss.pss_ready(session, connection, client, result, clock, log)
    # Session key is the authenticated AES-CBC key behind client.codec().
    idc_probe(session, connection, client.codec()._key, result, clock, log)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-idc-capture", action="store_true")
    p.add_argument("--accept-persistent-preferences", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_idc_capture:
        auth_probe.emit("PLAN_ONLY", phone_access=False, terminal_info=True,
                        change_pss_state=True, idc_request="CONNECT/SIDESYNC_CONN",
                        control_channel=False, screen_share=False, activation=False,
                        listener_config=LISTENER_CONFIG, connect_config=CONNECT_CONFIG,
                        outer_timeout_seconds=90)
        return 0
    if (not a.accept_persistent_preferences or a.output is None
            or a.bus is None or a.address is None):
        p.error("approved run needs --accept-persistent-preferences, --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid USB bus/address")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, auth_probe._terminated)
    result = dict(authentication_verified=False, capabilities_verified=False,
                  pss_ready_confirmed=False, listener_opened=False,
                  idc_request_sent=False, inbound_frames=0, activation_tested=False,
                  persistent_preferences_may_change=True)
    (a.output / "plan.json").write_text(json.dumps(dict(
        listener_config=LISTENER_CONFIG, connect_config=CONNECT_CONFIG,
        listener_port=LISTENER_PORT, connection_port=CONNECTION_PORT,
        capture_seconds=CAPTURE_SECONDS, control_channel=False, screen_share=False,
        outer_seconds=90), indent=2) + "\n")
    try:
        import usb.core
        import usb.util
        auth_probe.emit("usb_find", bus=a.bus, address=a.address, vendor=0x04e8, product=0x6860)
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone; refusing alternatives")
        auth_probe.probe(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result,
                         after_auth=after_auth, max_requests=20, session_class=CaptureSession)
        result["transport_completed"] = True
        result["success"] = result.get("capture_goal_met", False)
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        auth_probe.emit("idc_capture_result", **{k: v for k, v in result.items()
                                                 if k != "captured"})
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
