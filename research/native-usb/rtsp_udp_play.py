"""Bind RTP/RTCP, SETUP, PLAY a bounded RTP sample, TEARDOWN; media headers only.

Runs as rtsp_capabilities.exchange(after_selection=...) after a verified UDP
M4 (UDP_PLAY.md). User decision (2026-11-02): RTP payload bytes are never
stored. PlaySession replaces the Link's raw recorder: OUT chunks stay raw (the
host sends no media); IN frame bodies are hashed, never logged raw. Valid media
Data additionally records its native header and parsed RTP/RTCP header fields. After MEDIA_DATAGRAMS RTP datagrams the host stops ACKing
RTP, so the daemon's flow control (0001deac) pauses that socket.
"""
import hashlib

from conn_frames import Decoder, encode
import rtsp
import rtsp_setup
import rtsp_udp_setup as udp_setup
import tcp_control as tcp
import udp_tunnel
from tunnel_probe import SERVICE_UID
from usb_tunnel import TunnelError

RTP_CONFIG, RTP_PORT = udp_setup.RTP_CONFIG, udp_setup.RTP_PORT
RTCP_CONFIG, RTCP_PORT = 1206, 46003   # phone widened client_port to 46002-46003
MEDIA_CONFIGS = frozenset((RTP_CONFIG, RTCP_CONFIG))
MEDIA_DATAGRAMS = 64
RTCP_DATAGRAMS = 32
MEDIA_SECONDS = 3
TEARDOWN_SECONDS = 2
STAGE_SECONDS = 16
MEDIA_BYTES = 2 << 20
PLAY_ACKS = 160
PLAY_READS = 6000      # <=512 B each: room for the daemon backlog after ACKs stop


def media_header(payload, config_id=RTP_CONFIG):
    if config_id == RTCP_CONFIG:
        return dict(size_bytes=len(payload), rtcp=len(payload)>=4 and payload[0]>>6==2,
                    packet_type=payload[1] if len(payload)>1 else None)
    summary=udp_setup.rtp_header(payload)
    if summary.get("rtp"):
        header_bytes=12+4*(payload[0]&15)
        if len(payload)<header_bytes:
            summary["rtp"]=False
        elif payload[0]&16:
            if len(payload)<header_bytes+4:
                summary["rtp"]=False
            else:
                words=int.from_bytes(payload[header_bytes+2:header_bytes+4],"big")
                summary["rtp"]=len(payload)>=header_bytes+4+words*4
        summary["marker"]=bool(payload[1]&128)
    return summary


class RedactingRecorder:
    """Data bodies never fall back to raw, including malformed/unknown Data."""
    def __init__(self, log, max_frame_bytes):
        self.log=log
        self.decoder=Decoder(max_frame_bytes)
        self.failed=False

    def __call__(self,direction,data):
        if direction!="in":
            self.log("usb_raw",direction=direction,bytes_hex=data.hex())
            return
        if self.failed:
            self.log("usb_in_unparsed",size_bytes=len(data),
                     sha256=hashlib.sha256(data).hexdigest())
            return
        self.log("usb_in_chunk",size_bytes=len(data))
        try:
            frames=self.decoder.feed(data)
        except ValueError:
            self.failed=True
            self.log("usb_in_unparsed",size_bytes=len(data),
                     sha256=hashlib.sha256(data).hexdigest())
            return
        for frame in frames:
            raw=encode(frame)
            if (frame.command,frame.kind)==(5,1):
                # Only the CONN prefix is raw unless a complete UDP envelope validates.
                fields=dict(header_hex=raw[:20].hex(),body_bytes=len(frame.body),
                            body_sha256=hashlib.sha256(frame.body).hexdigest())
                try:
                    message=udp_tunnel.datagram_message(frame,MEDIA_CONFIGS)
                except ValueError:
                    pass
                else:
                    fields.update(header_hex=raw[:56].hex(),
                        payload_bytes=len(message.payload),
                        payload_sha256=hashlib.sha256(message.payload).hexdigest(),
                        media_header=media_header(message.payload,message.config_id))
                self.log("usb_frame_in_data",**fields)
            else:
                self.log("usb_frame_in",header_hex=raw[:16 if frame.kind==3 else 20].hex(),
                         body_bytes=len(frame.body),
                         body_sha256=hashlib.sha256(frame.body).hexdigest())


class PlaySession(udp_setup.WfdUdpSession):
    def __init__(self,link,*args,**kwargs):
        super().__init__(link,*args,**kwargs)
        link.record=RedactingRecorder(self.log,self.max_frame_bytes)
        link.acks_left=PLAY_ACKS
        link.reads_left=PLAY_READS
        self.media=[]
        self.media_bytes=0
        self.media_unacked=0
        self.media_after_cleanup=0
        self.media_before_play=0
        self.media_before_play_rtp=0
        self.media_counts={config:0 for config in MEDIA_CONFIGS}
        self.collect_media=False
        self.media_server_ports={}
        self.media_unexpected_source=0

    def _phone_datagram(self,frame):
        if int.from_bytes(frame.body[4:8],"little") not in MEDIA_CONFIGS:
            # No other UDP config is part of this test; never retain its body.
            raise TunnelError("unexpected UDP config during PLAY")
        message=udp_tunnel.datagram_message(frame,self.udp_configs.keys()|self.retired_udp)
        expected=self.media_server_ports.get(message.config_id)
        if expected is not None and message.source_port!=expected:
            self.media_unexpected_source+=1
            if not self.cleanup:
                raise TunnelError("media source port differs from SETUP")
            return
        self.media_bytes+=len(message.payload)
        if self.media_bytes>MEDIA_BYTES and not self.cleanup:
            raise TunnelError("media byte limit exceeded")
        self.media_counts[message.config_id]+=1
        limit=MEDIA_DATAGRAMS if message.config_id==RTP_CONFIG else RTCP_DATAGRAMS
        accepted=(self.media_counts[message.config_id]<=limit and self.media_bytes<=MEDIA_BYTES)
        if self.cleanup or message.config_id in self.retired_udp:
            self.media_after_cleanup+=1
        elif not self.collect_media:
            self.media_before_play+=1
            if message.config_id==RTP_CONFIG:
                self.media_before_play_rtp+=1
        elif accepted:
            self.media.append(dict(media_header(message.payload,message.config_id),
                config_id=message.config_id,source_port=message.source_port,at=self.clock()))
        if accepted:
            self._send(tcp.data_ack(frame.transaction,20+len(frame.body)))
        else:
            # This remains withheld during cleanup, so a paused socket cannot resume.
            self.media_unacked+=1


def play_request(uri, session_id):
    return ("PLAY %s RTSP/1.0\r\nCSeq: 3\r\nSession: %s\r\n\r\n" % (uri, session_id)).encode("ascii")


def teardown_request(uri, session_id):
    return ("TEARDOWN %s RTSP/1.0\r\nCSeq: 4\r\nSession: %s\r\n\r\n" % (uri, session_id)).encode("ascii")


def play_response(message, cseq, session_id):
    if (message["kind"] != "response" or message["status"] != 200
            or message["cseq"] != cseq or message["body"]):
        raise ValueError("unexpected PLAY/TEARDOWN response")
    echoed = message["headers"].get("session")
    if echoed is not None and echoed.split(";")[0] != session_id:
        raise ValueError("response for another Session")
    return message["headers"].get("rtp-info")


def media_summary(media, started):
    rtp = [m for m in media if m["config_id"] == RTP_CONFIG and m.get("rtp")]
    summary = dict(rtp_datagrams=len(rtp), rtcp_datagrams=sum(
        m["config_id"] == RTCP_CONFIG for m in media), payload_bytes=sum(
        m["size_bytes"] for m in media if m["config_id"] == RTP_CONFIG))
    if rtp:
        summary.update(
            ssrcs=sorted({m["ssrc"] for m in rtp}),
            payload_types=sorted({m["payload_type"] for m in rtp}),
            markers=sum(m["marker"] for m in rtp),
            first_sequence=rtp[0]["sequence"], last_sequence=rtp[-1]["sequence"],
            timestamp_span_ticks=((rtp[-1]["timestamp"] - rtp[0]["timestamp"]) % (1 << 32)
                                  if len({m["ssrc"] for m in rtp})==1 else None),
            source_ports=sorted({m["source_port"] for m in rtp}),
            first_after_play_seconds=round(rtp[0]["at"] - started, 3),
            receive_span_seconds=round(rtp[-1]["at"] - rtp[0]["at"], 3))
    return summary


def exchange(session, main, connection, result, log, latest=None):
    deadline = session.clock() + STAGE_SECONDS
    if latest is not None:
        deadline = min(deadline, latest)
    offset = len(connection.received)
    uri = rtsp_setup.presentation_uri(result["rtsp_selected_values"])
    first_error = None
    played = None

    def guard():
        if session.clock() >= deadline:
            raise TunnelError("RTSP UDP PLAY stage deadline expired")
        if main.closed_by_phone or connection.closed_by_phone:
            raise TunnelError("phone closed channel during UDP PLAY stage")
        if len(connection.received) > rtsp.STREAM_BYTES:
            raise TunnelError("RTSP UDP PLAY stream exceeds limit")

    def send(payload):
        guard()
        session.send(connection, payload, timeout_s=min(2, deadline - session.clock()))
        guard()

    def receive(until_deadline=None):
        nonlocal offset
        limit = deadline if until_deadline is None else min(deadline, until_deadline)
        while True:
            guard()
            if session.clock()>=limit:
                raise TunnelError("RTSP response wait expired")
            parsed = rtsp.parse(bytes(connection.received[offset:]))
            if parsed is not None:
                message, size = parsed
                offset += size
                guard()
                if session.clock()>=limit:
                    raise TunnelError("RTSP response completed late")
                return message
            if session.clock() >= limit:
                raise TunnelError("RTSP response wait expired")
            seen = len(connection.received)
            session.wait(limit - session.clock(), until=lambda:
                         len(connection.received) > seen or main.closed_by_phone
                         or connection.closed_by_phone)

    try:
        guard()
        for config_id, port in ((RTP_CONFIG, RTP_PORT), (RTCP_CONFIG, RTCP_PORT)):
            opened = session.open_udp(config_id, SERVICE_UID, port, operation=1,
                                      timeout_s=min(2, deadline - session.clock()))
            result["media_open_%d" % config_id] = opened
            if (opened["port"], opened["client_port"]) != (port, 0):
                raise TunnelError("media UDP config did not bind the advertised port")
        result["rtsp_m4_reply_attempted"] = True
        send(rtsp_setup.response(result["rtsp_selected_cseq"]))
        trigger = receive()
        if (trigger["kind"] != "request" or trigger["method"] != "SET_PARAMETER"
                or not trigger["uri"].startswith("rtsp://")
                or trigger["cseq"] <= result["rtsp_selected_cseq"]
                or trigger["headers"].get("content-type", "").lower() != "text/parameters"
                or trigger["body"] != b"wfd_trigger_method: SETUP\r\n"):
            raise ValueError("expected exact M5 SETUP trigger")
        result["rtsp_m5_trigger_verified"] = True
        result["rtsp_m5_reply_attempted"] = True
        send(rtsp_setup.response(trigger["cseq"]))
        result["rtsp_udp_setup_attempted"] = True
        send(udp_setup.setup_request(uri))
        reply = receive()
        result["rtsp_udp_setup_raw_transport"] = reply["headers"].get("transport")
        setup = udp_setup.setup_response(reply)
        client_ports=next(part.partition("=")[2] for part in setup["transport"].split(";")
                          if part.partition("=")[0].strip().lower()=="client_port")
        if udp_setup._port_range(client_ports) not in ([RTP_PORT],[RTP_PORT,RTCP_PORT]):
            raise ValueError("SETUP client ports exceed bound media sockets")
        if not setup["server_ports"]:
            raise ValueError("SETUP omitted media source ports")
        session.media_server_ports[RTP_CONFIG]=setup["server_ports"][0]
        if len(setup["server_ports"])==2:
            session.media_server_ports[RTCP_CONFIG]=setup["server_ports"][1]
        result["rtsp_udp_setup"] = setup
        if len(connection.received) != offset:
            raise ValueError("unexpected trailing data before PLAY")
        result["rtsp_udp_setup_verified"] = True
        # Drain a bounded pre-PLAY interval so queued SETUP-era RTP cannot
        # masquerade as the requested PLAY sample. No extra RTSP send.
        session.wait(min(.1,max(0,deadline-session.clock())),until=lambda:
                     session.media_before_play_rtp>0 or main.closed_by_phone
                     or connection.closed_by_phone)
        guard()
        if session.media_before_play_rtp:
            raise TunnelError("RTP arrived before PLAY")
        session.collect_media = True
        result["rtsp_play_attempted"] = True
        played = session.clock()
        send(play_request(uri, setup["session_id"]))
        result["rtsp_play_rtp_info"] = play_response(receive(), 3, setup["session_id"])
        result["rtsp_play_verified"] = True
        log(event="rtsp_play_verified", media_headers_only=True)
        session.wait(max(0, min(MEDIA_SECONDS, deadline - session.clock())), until=lambda:
                     sum(m["config_id"] == RTP_CONFIG for m in session.media) >= MEDIA_DATAGRAMS
                     or main.closed_by_phone or connection.closed_by_phone)
        guard()
        # RTSP the phone sent during media (e.g. keep-alive) is recorded, not answered.
        requests = []
        while True:
            parsed = rtsp.parse(bytes(connection.received[offset:]))
            if parsed is None:
                break
            message, size = parsed
            offset += size
            requests.append(dict(kind=message["kind"], method=message.get("method"),
                                 cseq=message.get("cseq")))
        result["rtsp_during_media"] = requests
        if not any(m["config_id"] == RTP_CONFIG and m.get("rtp") for m in session.media):
            raise TunnelError("no RTP datagram received after PLAY")
        result["rtp_media_verified"] = True
    except Exception as error:
        first_error = error
        result["play_first_error"] = type(error).__name__ + ": " + str(error)
    finally:
        if result.get("rtsp_play_verified"):
            result["rtsp_teardown_attempted"] = True
            try:
                send(teardown_request(uri, setup["session_id"]))
                message = receive(session.clock() + TEARDOWN_SECONDS)
                play_response(message, 4, setup["session_id"])
                result["rtsp_teardown_status"] = message["status"]
            except Exception as error:
                # Recorded, not gating: cleanup below closes every socket anyway.
                result["rtsp_teardown_error"] = type(error).__name__ + ": " + str(error)
        session.begin_cleanup()
        session.link.begin_cleanup()
        result["media_close_statuses"] = {}
        result["media_cleanup_errors"] = []
        for config_id in (RTCP_CONFIG, RTP_CONFIG):
            if config_id not in session.configs:
                continue
            try:
                result["media_close_statuses"][str(config_id)] = session.close_config(
                    SERVICE_UID, config_id=config_id)
            except Exception as error:
                result["media_cleanup_errors"].append(type(error).__name__ + ": " + str(error))
                if first_error is None:
                    first_error = error
        result["media_summary"] = media_summary(session.media, played if played is not None else session.clock())
        result["media_headers"] = [{k: v for k, v in m.items() if k != "at"}
                                   for m in session.media[:16]]
        result["media_unexpected_source_datagrams"] = session.media_unexpected_source
        result["media_bytes_seen"] = session.media_bytes
        result["media_before_play_datagrams"] = session.media_before_play
        result["media_unacked_datagrams"] = session.media_unacked
        result["media_after_cleanup_datagrams"] = session.media_after_cleanup
    if first_error is not None:
        raise first_error
