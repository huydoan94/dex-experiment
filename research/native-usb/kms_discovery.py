"""One KMS start request and passive SideSync event-socket discovery; no input."""
from main_channel import Frame, encode_frame
import sidesync_packets as packets
from tunnel_probe import SERVICE_UID
from usb_tunnel import TunnelError

CONFIG = 1208
HOST_PORT = 50008
SID = 6  # AUTH 1..3, TerminalInfo 4, ChangePSSState 5.
MAX_EVENT_BYTES = 512


def discover(session, main, rtsp, result, log, *, client, latest):
    first_error = None
    result["kms_discovery_verified"] = False
    result["kms_cleanup_errors"] = []
    deadline = min(latest, session.clock() + 4)

    def guard():
        if session.clock() >= deadline or main.closed_by_phone or rtsp.closed_by_phone:
            raise TunnelError("KMS discovery deadline/channel closure")

    try:
        guard()
        wire = encode_frame(Frame(SID, client.codec().encrypt(
            {"TYPE": "REQ", "MSG": "ChangeKMSState", "PARAM": {"KMS_STATE": 1}})))
        if len(wire) > min(512, session.usb_buffer_bytes - 56):
            raise TunnelError("KMS request does not fit one bounded native Data")
        result["kms_start_attempted"] = True
        session.send(main, wire, timeout_s=min(2, deadline-session.clock()))
        guard()
        # KMS handles its bind asynchronously. One fixed wait, then one Connect.
        session.wait(.5, until=lambda: main.closed_by_phone or rtsp.closed_by_phone)
        guard()
        session.open_config(CONFIG, SERVICE_UID, packets.EVENT_PORT,
                            timeout_s=min(1, deadline-session.clock()))
        guard()
        connection = session.connect(HOST_PORT, config_id=CONFIG,
                                     timeout_s=min(1, deadline-session.clock()))
        result["kms_connection_established"] = True
        guard()

        def complete():
            data = connection.received
            if len(data) > MAX_EVENT_BYTES:
                return True
            return (len(data) >= 4 and
                    len(data) >= int.from_bytes(data[2:4], "big"))

        session.wait(min(1, deadline-session.clock()), until=lambda:
                     complete() or connection.closed_by_phone or main.closed_by_phone
                     or rtsp.closed_by_phone)
        guard()
        data = bytes(connection.received)
        if not 4 <= len(data) <= MAX_EVENT_BYTES:
            raise TunnelError("missing/oversized KMS event packet")
        # Exactly one frame, with no echo, heartbeat response or other app sends.
        packet = packets.parse(data)
        result["kms_first_packet"] = dict(kind=packet.kind, bytes=len(data),
                                         packet_hex=data.hex())
        if data != packets.connect_confirmed():
            raise TunnelError("unexpected initial SideSync event packet")
        result["kms_discovery_verified"] = True
        log(event="kms_discovery_verified",port=packets.EVENT_PORT,
            kind=packet.kind,bytes=len(data),input_sent=False)
    except Exception as error:
        first_error = error
    finally:
        session.begin_cleanup()
        session.link.begin_cleanup()
        # Include an unconfirmed Connect retained by the native session on timeout.
        for connection in list(session.connections.values()):
            if connection.config_id != CONFIG:
                continue
            try:
                status = session.disconnect(connection)
                result["kms_disconnect_status"] = status
                if status != 0:
                    raise TunnelError("KMS disconnect was not confirmed")
            except Exception as error:
                result["kms_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        if CONFIG in session.configs:
            try:
                status = session.close_config(SERVICE_UID,config_id=CONFIG)
                result["kms_close_status"] = status
                if status != 0:
                    raise TunnelError("KMS config close was not confirmed")
            except Exception as error:
                result["kms_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
    if first_error is not None:
        raise first_error
