"""Long live PLAY (user decision 2026-11-03): until the user stops, capped at 15 min, audio advertised.

Builds on the unchanged rtsp_udp_play exchange and rtsp_udp_live.LiveSession.
The small backend cannot keep one header dict per datagram for 15 min, nor
log every media frame, so this keeps the first headers plus running totals, and
after FULL_LOG_SECONDS logs only non-routine frames (routine ones are counted).
Payload still goes from RAM to the FIFO sink only.
"""
from collections import Counter
import os

import rtsp_capabilities as caps
import rtsp_udp_live as live
import rtsp_udp_play as play
from tunnel_probe import MAX_RECEIVE_BYTES

CAP_SECONDS=900
# ~390-485 RTP/s seen, plus audio. Datagram/ACK caps leave room for ~880/s; the
# read cap keeps the live ratio (~3 reads per datagram) plus the base slack.
LONG=dict(MEDIA_DATAGRAMS=800000,MEDIA_SECONDS=CAP_SECONDS,MEDIA_BYTES=1536<<20,
          PLAY_ACKS=850000,PLAY_READS=2600000,STAGE_SECONDS=CAP_SECONDS+30,RTCP_DATAGRAMS=2048)
# SETUP gave timeout=30; the phone sends M16 every ~25 s, i.e. 36 in 15 min.
BASE_KEEPALIVES,LONG_KEEPALIVES=8,48
# Session-wide TCP receive cap (main-channel notifications accumulate for 15 min).
LONG_RECEIVE_BYTES=1<<20
FULL_LOG_SECONDS=60
MEDIA_KEEP=256

# Advertised as SamsungDeX.exe's AAC entry narrowed to mode bit 0 (AAC-LC 2ch
# 48 kHz), which ffplay decodes from the TS. LPCM is not offered (TS stream type
# 0x83 decoding is unverified).
AUDIO_CODECS="AAC 00000001 00"
AUDIO_UDP_PROFILE=dict(caps.UDP_PROFILE,wfd_audio_codecs=AUDIO_CODECS)
_PINNED_SELECTION=caps.selection_compatible


def audio_selection(value):
    """The phone's audio choice: "none" or one AAC entry within the advertised modes."""
    if value in (None,"none"):
        return None
    parts=value.split()
    if (len(parts)!=3 or parts[0]!="AAC" or len(parts[1])!=8 or len(parts[2])!=2
            or any(c not in "0123456789abcdefABCDEF" for c in parts[1]+parts[2])):
        return False
    modes=int(parts[1],16)
    return dict(codec="AAC",modes=modes,latency=int(parts[2],16)) if modes and not modes&~1 else False


def selection_compatible(values,profile=caps.PROFILE):
    """Pinned check with the audio entry validated here; the rest is unchanged."""
    if profile is AUDIO_UDP_PROFILE:
        if audio_selection(values.get("wfd_audio_codecs")) is False:
            return False
        return _PINNED_SELECTION(dict(values,wfd_audio_codecs="none"),caps.UDP_PROFILE)
    return _PINNED_SELECTION(values,profile)


def apply():
    current={name:getattr(play,name) for name in live.BASE}
    if current!=LONG:
        if current!=live.BASE:
            raise RuntimeError("rtsp_udp_play limits differ from the pinned base")
        for name,value in LONG.items():
            setattr(play,name,value)
    if live.MAX_KEEPALIVES not in (BASE_KEEPALIVES,LONG_KEEPALIVES):
        raise RuntimeError("keep-alive limit differs from the pinned base")
    live.MAX_KEEPALIVES=LONG_KEEPALIVES
    if caps.selection_compatible not in (_PINNED_SELECTION,selection_compatible):
        raise RuntimeError("capability selection check differs from the pinned base")
    caps.selection_compatible=selection_compatible


class BoundedMedia(list):
    """Keeps the first MEDIA_KEEP headers; totals cover every accepted datagram."""
    def __init__(self):
        super().__init__()
        self.rtp=self.rtcp=self.payload_bytes=self.markers=0
        self.ssrcs,self.payload_types,self.source_ports=set(),set(),set()
        self.first=self.last=None
        self.accepted=0
        self.last_config=None

    def append(self,item):
        self.accepted+=1
        self.last_config=item["config_id"]
        if item["config_id"]==play.RTP_CONFIG:
            self.payload_bytes+=item["size_bytes"]
            if item.get("rtp"):
                self.rtp+=1
                self.ssrcs.add(item["ssrc"])
                self.payload_types.add(item["payload_type"])
                self.source_ports.add(item["source_port"])
                self.markers+=item["marker"]
                self.first=self.first or item
                self.last=item
        elif item["config_id"]==play.RTCP_CONFIG:
            self.rtcp+=1
        if len(self)<MEDIA_KEEP:
            super().append(item)

    def summary(self,pinned):
        """play.media_summary over all datagrams; first_* come from the retained head."""
        summary=dict(pinned,rtp_datagrams=self.rtp,rtcp_datagrams=self.rtcp,
                     payload_bytes=self.payload_bytes)
        if self.rtp:
            summary.update(ssrcs=sorted(self.ssrcs),payload_types=sorted(self.payload_types),
                markers=self.markers,last_sequence=self.last["sequence"],
                timestamp_span_ticks=((self.last["timestamp"]-self.first["timestamp"])%(1<<32)
                                      if len(self.ssrcs)==1 else None),
                source_ports=sorted(self.source_ports),
                receive_span_seconds=round(self.last["at"]-self.first["at"],3))
        return summary


# Per-frame events that carry no protocol decision once media flows.
ROUTINE=frozenset(("usb_in_chunk","usb_read","usb_write","duplex_write_completed"))
DATA_ACK_PREFIX="434f4e4e050000002000000002000000"   # CONN cmd 5, 32 bytes, kind 2


class QuietLog:
    """While quiet, routine media events are counted instead of written."""
    def __init__(self,log):
        self.log=log
        self.quiet=False
        self.suppressed=Counter()

    def __call__(self,event,**fields):
        if self.quiet and self.routine(event,fields):
            self.suppressed[event]+=1
            return
        self.log(event,**fields)

    @staticmethod
    def routine(event,fields):
        if event in ROUTINE:
            return True
        if event=="usb_frame_in_data":
            return "media_header" in fields
        return (event=="usb_raw" and fields.get("direction")=="out"
                and fields.get("bytes_hex","").startswith(DATA_ACK_PREFIX))


class LongSession(live.LiveSession):
    def __init__(self,link,*args,stop_file,**kwargs):
        super().__init__(link,*args,**kwargs)
        self.media=BoundedMedia()
        self.stop_file=stop_file
        self.stop_reason=None
        self.window_armed=False
        self.window_started=None

    @property
    def collect_media(self):
        return self._collect_media

    @collect_media.setter
    def collect_media(self,value):
        connection=getattr(self,"rtsp_connection",None)
        if value and connection is not None and getattr(self,"keepalive_offset",None) is None:
            self.keepalive_offset=len(connection.received)
            self.window_seconds=max(1,min(CAP_SECONDS,
                                          self.stage_latest-live.DEADLINE_MARGIN_SECONDS-self.clock()))
            play.MEDIA_SECONDS=self.window_seconds
        self._collect_media=value

    def _phone_datagram(self,frame):
        # LiveSession detects acceptance by media list growth, which stops once
        # BoundedMedia is full; same forwarding, keyed on the acceptance count.
        before=self.media.accepted
        play.PlaySession._phone_datagram(self,frame)
        if self.media.accepted==before or self.media.last_config!=play.RTP_CONFIG:
            return
        packet=live.udp_tunnel.datagram_message(frame,self.udp_configs.keys()|self.retired_udp).payload
        sequence=int.from_bytes(packet[2:4],"big") if len(packet)>=4 else None
        if self.last_sequence is not None and sequence!=(self.last_sequence+1)&0xffff:
            self.sequence_gaps+=1
        self.last_sequence=sequence
        ts=live.ts_payload(packet)
        if ts is None:
            self.ts["invalid_rtp"]+=1
            return
        if len(ts)%live.TS_PACKET:
            self.ts["unaligned"]+=1
        for offset in range(0,len(ts)-live.TS_PACKET+1,live.TS_PACKET):
            self.ts["packets"]+=1
            self.ts["sync_ok" if ts[offset]==0x47 else "sync_bad"]+=1
        self.sink.put(ts)

    def stop_requested(self):
        if self.window_started is not None and self.clock()-self.window_started>=FULL_LOG_SECONDS:
            self.log.quiet=True
        if os.path.lexists(self.stop_file):
            self.stop_reason="stop_file"
        elif self.sink.error is not None:
            # The viewer went away (ffplay closed, ssh ended): the FIFO write failed.
            self.stop_reason="viewer_closed"
        return self.stop_reason is not None

    def wait(self,seconds,until=lambda: False):
        if not self.window_armed:
            return super().wait(seconds,until)
        # The first wait after PLAY verified is the pinned exchange's media window.
        self.window_armed=False
        self.window_started=self.clock()
        try:
            ended=super().wait(seconds,lambda: until() or self.stop_requested())
        finally:
            self.log.quiet=False
        if not ended:
            self.stop_reason="cap"
        elif self.stop_reason is None:
            # The pinned exchange's own condition: phone close or datagram cap.
            self.stop_reason="exchange_condition"
        return ended

    def summary(self):
        return dict(super().summary(),stop_reason=self.stop_reason,
                    cap_seconds=CAP_SECONDS,suppressed_events=dict(self.log.suppressed))


def exchange(session,main,connection,result,log,latest=None):
    def watched(event,**fields):
        if event=="rtsp_play_verified":
            session.window_armed=True
        log(event=event,**fields)
    try:
        return live.exchange(session,main,connection,result,watched,latest=latest)
    finally:
        if "media_summary" in result:
            result["media_summary"]=session.media.summary(result["media_summary"])
            result["media_summary_aggregated"]=True
        result["audio_selection"]=audio_selection(
            result.get("rtsp_selected_values",{}).get("wfd_audio_codecs"))


class LongOwner(live.LiveOwner):
    def __init__(self,util,result,sink,stop_file):
        super().__init__(util,result,sink)
        self.stop_file=stop_file

    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=LongSession(link,first_transaction,max_frame_bytes,LONG_RECEIVE_BYTES,
                            sink=self.sink,stop_file=self.stop_file,log=QuietLog(log),**kwargs)
        self.reader=live.duplex_link.ReadPump(link,session.log)
        return session
