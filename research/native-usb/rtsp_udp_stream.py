"""Longer bounded PLAY window: unchanged rtsp_udp_play session/exchange with explicit raised limits."""
import rtsp_udp_play as play

# Single-sample values of the pinned module; apply() refuses any other base.
BASE=dict(MEDIA_DATAGRAMS=64,MEDIA_SECONDS=3,MEDIA_BYTES=2<<20,PLAY_ACKS=160,
          PLAY_READS=6000,STAGE_SECONDS=16)
# Rates seen: ~54 RTP/s averaged at 22:30, a ~485/s burst at 22:40, so the
# 2048 cap may end the sample before 15 s. 15 s stays below the phone's first
# RTSP keep-alive (~24 s after PLAY), which is not answered.
# Reads (<=512 B, ~3 per 1384 B frame) keep the base slack for setup and the
# post-ACK backlog: 6000+3*(2048-64). Media bytes also count unacked backlog.
STREAM=dict(MEDIA_DATAGRAMS=2048,MEDIA_SECONDS=15,MEDIA_BYTES=8<<20,PLAY_ACKS=2304,
            PLAY_READS=12000,STAGE_SECONDS=26)


def apply():
    current={name:getattr(play,name) for name in BASE}
    if current==STREAM:
        return
    if current!=BASE:
        raise RuntimeError("rtsp_udp_play limits differ from the pinned base")
    for name,value in STREAM.items():
        setattr(play,name,value)
