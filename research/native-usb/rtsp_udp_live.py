"""60 s live PLAY: unchanged rtsp_udp_play exchange, RTSP keep-alive replies and MPEG-TS forwarding.

Payload goes from RAM to the sink only; nothing here persists it. Saved results
stay headers, digests and counts.
"""
import duplex_link
import rtsp
import rtsp_setup
import rtsp_udp_play as play
import udp_tunnel

BASE=dict(MEDIA_DATAGRAMS=64,MEDIA_SECONDS=3,MEDIA_BYTES=2<<20,PLAY_ACKS=160,
          PLAY_READS=6000,STAGE_SECONDS=16,RTCP_DATAGRAMS=32)
# Burst seen ~405-485 RTP/s; 60 s at 485/s is ~29000. Caps leave headroom; the
# window normally ends on time. Reads keep the base slack: 6000+3*(40000-64).
# The phone's keep-alive (~24 s after PLAY) is answered, so 60 s may pass it.
LIVE=dict(MEDIA_DATAGRAMS=40000,MEDIA_SECONDS=60,MEDIA_BYTES=64<<20,PLAY_ACKS=42000,
          PLAY_READS=126000,STAGE_SECONDS=70,RTCP_DATAGRAMS=512)
TS_PACKET=188
KEEPALIVE_SLICE_SECONDS=.2
MAX_KEEPALIVES=8
# The window ends this long before the stage deadline, leaving TEARDOWN its 2 s and slack.
DEADLINE_MARGIN_SECONDS=5


# DeX app 2.5.00.16 (jadx r2/r.B, o2/i.A): a Windows sink reporting PcVer >= 2.0.0.24
# gets SECURED_CONNECTION, i.e. scramble_support = the AUTH ECDH session key, and the
# phone then negotiates wfd_sec_scramble: enable. One patch below asks for a plain stream.
BASE_PC_VERSION="2.4.1.27"
PLAIN_PC_VERSION="2.0.0.23"


def plain_profile(cap):
    """Swap the pinned TerminalInfo profile's PcVer; refuse any other base profile."""
    version=cap.PROFILE.get("PcVer")
    if version==PLAIN_PC_VERSION:
        return
    if version!=BASE_PC_VERSION or cap.PROFILE.get("SinkType")!="Windows":
        raise RuntimeError("TerminalInfo profile differs from the pinned base")
    cap.PROFILE=dict(cap.PROFILE,PcVer=PLAIN_PC_VERSION)


def apply():
    current={name:getattr(play,name) for name in BASE}
    if current==LIVE:
        return
    if current!=BASE:
        raise RuntimeError("rtsp_udp_play limits differ from the pinned base")
    for name,value in LIVE.items():
        setattr(play,name,value)


def ts_payload(packet):
    """MPEG-TS bytes of one RTP packet, or None if the RTP header is invalid."""
    if len(packet)<12 or packet[0]>>6!=2:
        return None
    offset=12+4*(packet[0]&15)
    if packet[0]&16:
        if len(packet)<offset+4:
            return None
        offset+=4+4*int.from_bytes(packet[offset+2:offset+4],"big")
    end=len(packet)
    if packet[0]&32:
        # RTP padding: the last byte counts the padding bytes, itself included.
        if not packet[-1] or end-packet[-1]<offset:
            return None
        end-=packet[-1]
    if end<offset:
        return None
    return packet[offset:end]


class LiveSession(play.PlaySession):
    def __init__(self,link,*args,sink,**kwargs):
        super().__init__(link,*args,**kwargs)
        self.sink=sink
        self.rtsp_connection=None
        self.stage_latest=None
        self.window_seconds=None
        self.keepalive_offset=None
        self.keepalives=0
        self.rtsp_seen=[]
        self.ts=dict(packets=0,sync_ok=0,sync_bad=0,unaligned=0,invalid_rtp=0)
        self.last_sequence=None
        self.sequence_gaps=0

    @property
    def collect_media(self):
        return self._collect_media

    @collect_media.setter
    def collect_media(self,value):
        # exchange() enables collection just before PLAY, after checking no RTSP is pending.
        connection=getattr(self,"rtsp_connection",None)
        if value and connection is not None and getattr(self,"keepalive_offset",None) is None:
            self.keepalive_offset=len(connection.received)
            # The pinned exchange reads MEDIA_SECONDS after PLAY; end it before its stage deadline.
            self.window_seconds=max(1,min(LIVE["MEDIA_SECONDS"],
                                          self.stage_latest-DEADLINE_MARGIN_SECONDS-self.clock()))
            play.MEDIA_SECONDS=self.window_seconds
        self._collect_media=value

    def _phone_datagram(self,frame):
        before=len(self.media)
        super()._phone_datagram(frame)
        if len(self.media)==before or self.media[-1]["config_id"]!=play.RTP_CONFIG:
            return
        packet=udp_tunnel.datagram_message(frame,self.udp_configs.keys()|self.retired_udp).payload
        sequence=int.from_bytes(packet[2:4],"big") if len(packet)>=4 else None
        if self.last_sequence is not None and sequence!=(self.last_sequence+1)&0xffff:
            self.sequence_gaps+=1
        self.last_sequence=sequence
        ts=ts_payload(packet)
        if ts is None:
            self.ts["invalid_rtp"]+=1
            return
        if len(ts)%TS_PACKET:
            self.ts["unaligned"]+=1
        for offset in range(0,len(ts)-TS_PACKET+1,TS_PACKET):
            self.ts["packets"]+=1
            self.ts["sync_ok" if ts[offset]==0x47 else "sync_bad"]+=1
        self.sink.put(ts)

    def wait(self,seconds,until=lambda: False):
        if not self.collect_media or self.cleanup or self.keepalive_offset is None:
            return super().wait(seconds,until)
        deadline=self.clock()+seconds
        while True:
            # The caller's check counts all media; evaluate it per slice, not per frame.
            # It goes first so a completed PLAY/TEARDOWN response is returned before
            # a phone request in the same slice is judged.
            if until():
                return True
            self._answer_keepalives()
            remaining=deadline-self.clock()
            if remaining<=0:
                return False
            super().wait(min(KEEPALIVE_SLICE_SECONDS,remaining))

    def _answer_keepalives(self):
        while True:
            parsed=rtsp.parse(bytes(self.rtsp_connection.received[self.keepalive_offset:]))
            if parsed is None:
                return
            message,size=parsed
            self.keepalive_offset+=size
            self.rtsp_seen.append(dict(kind=message["kind"],method=message.get("method"),
                                       cseq=message.get("cseq")))
            if message["kind"]!="request":
                continue
            if message["method"]!="GET_PARAMETER" or message["body"]:
                raise play.TunnelError("unexpected RTSP request during live media")
            if self.keepalives>=MAX_KEEPALIVES:
                raise play.TunnelError("RTSP keep-alive count exceeded")
            self.keepalives+=1
            self.log("rtsp_keepalive_reply",cseq=message["cseq"])
            self.send(self.rtsp_connection,rtsp_setup.response(message["cseq"]),timeout_s=2)

    def summary(self):
        return dict(window_seconds=self.window_seconds,keepalives_answered=self.keepalives,
                    rtsp_seen=self.rtsp_seen,
                    rtp_sequence_gaps=self.sequence_gaps,ts=dict(self.ts),sink=self.sink.summary())


def exchange(session,main,connection,result,log,latest=None):
    # Same deadline as play.exchange: stage start + STAGE_SECONDS, capped by latest.
    session.stage_latest=session.clock()+play.STAGE_SECONDS
    if latest is not None:
        session.stage_latest=min(session.stage_latest,latest)
    session.rtsp_connection=connection
    try:
        return play.exchange(session,main,connection,result,log,latest=latest)
    finally:
        result["live"]=session.summary()


class LiveOwner(duplex_link.UsbOwner):
    """UsbOwner whose session is LiveSession; the reader lifetime rules are inherited."""
    def __init__(self,util,result,sink):
        super().__init__(util,result)
        self.sink=sink

    def session(self,link,*args,**kwargs):
        session=LiveSession(link,*args,sink=self.sink,**kwargs)
        self.reader=duplex_link.ReadPump(link,session.log)
        return session
