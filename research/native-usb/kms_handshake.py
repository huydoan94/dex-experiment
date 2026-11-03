"""One KMS start, one connection confirmation and one heartbeat; no input."""
from main_channel import Frame, encode_frame
import sidesync_packets as packets
from tunnel_probe import SERVICE_UID
from usb_tunnel import TunnelError

CONFIG = 1208
HOST_PORT = 50008
SID = 6  # AUTH 1..3, TerminalInfo 4, ChangePSSState 5.
MAX_EVENT_BYTES = 512


def handshake(session, main, rtsp, result, log, *, client, latest, after_verified=None):
    first_error = None
    result["kms_handshake_verified"] = False
    result["kms_cleanup_errors"] = []
    deadline = min(latest, session.clock() + 4)

    def guard():
        if session.clock() >= deadline or main.closed_by_phone or rtsp.closed_by_phone:
            raise TunnelError("KMS handshake deadline/channel closure")

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

        offset = 0
        received_packets = []
        heartbeat_seen = False

        def complete():
            nonlocal offset, heartbeat_seen
            data = connection.received
            if len(data) > MAX_EVENT_BYTES:
                raise TunnelError("KMS received-byte cap exceeded")
            while len(data)-offset >= 4:
                size = int.from_bytes(data[offset+2:offset+4], "big")
                if not 4 <= size <= MAX_EVENT_BYTES:
                    raise TunnelError("invalid KMS packet length")
                if len(data)-offset < size:
                    return False
                wire = bytes(data[offset:offset+size])
                packet = packets.parse(wire)
                received_packets.append(dict(kind=packet.kind, bytes=size))
                if len(received_packets)>16:
                    raise TunnelError("KMS packet-count cap exceeded")
                if packet.kind == 5:
                    if wire != packets.heartbeat_response():
                        raise TunnelError("unexpected KMS heartbeat response")
                    heartbeat_seen = True
                offset += size
            # Require no incomplete trailing packet in the accepted capture.
            return heartbeat_seen and offset == len(data)

        # USB server accept does not send first. Each application packet is sent once.
        for wire in (packets.connect_confirmed(), packets.heartbeat_request()):
            guard()
            complete()  # Refuse another application write after invalid received data.
            session.send(connection, wire, timeout_s=min(1, deadline-session.clock()))
            result["kms_application_packets_sent"] = result.get("kms_application_packets_sent", 0)+1
        guard()
        complete()

        session.wait(min(1, deadline-session.clock()), until=lambda:
                     complete() or connection.closed_by_phone or main.closed_by_phone
                     or rtsp.closed_by_phone)
        guard()
        if connection.closed_by_phone:
            raise TunnelError("KMS closed before handshake acceptance")
        if not complete():
            raise TunnelError("missing/incomplete KMS heartbeat response")
        result["kms_received_packets"] = received_packets
        result["kms_capture_bytes"] = len(connection.received)
        result["kms_handshake_verified"] = True
        log(event="kms_handshake_verified",port=packets.EVENT_PORT,
            packets=received_packets,input_sent=False)
        if after_verified is not None:
            after_verified(session,main,rtsp,connection,result,log)
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
