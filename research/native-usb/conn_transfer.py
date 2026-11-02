"""CONN decoding that also drops the daemon's per-transfer pad byte.

Live 22:40 stream: under load the daemon batches several frames into one USB
write and pads that write (not each frame) when its total length is a multiple
of 64, e.g. 1384+1008+1384=3776 arrived as a 3777-byte transfer. The pinned
base Decoder only knows the single-frame case. Each feed() must be exactly one
USB read; a read that is not a whole number of packets ends the transfer.
"""
from conn_frames import Decoder,PAD_BYTE,PAD_BOUNDARY

PACKET_BYTES=512


class TransferDecoder(Decoder):
    def __init__(self,max_frame_bytes):
        super().__init__(max_frame_bytes)
        self.transfer_bytes=0
        self.transfer_pads=0

    def feed(self,data):
        self.transfer_bytes+=len(data)
        if len(data)%PACKET_BYTES==0:
            return super().feed(data)
        length,self.transfer_bytes=self.transfer_bytes,0
        if not (data and data[-1]==PAD_BYTE and (length-1)%PAD_BOUNDARY==0):
            return super().feed(data)
        frames=super().feed(data[:-1])
        if self._pad_pending or self._expected is not None or self._buffer:
            # Not between frames (or the base rule owns this pad): ordinary data.
            return frames+super().feed(data[-1:])
        self.transfer_pads+=1
        return frames


class TransferSessions:
    """Session factory installing TransferDecoder for protocol and recorder before any I/O."""
    def __init__(self,owner):
        self.owner=owner
        self.decoders=[]

    def session(self,link,*args,**kwargs):
        session=self.owner.session(link,*args,**kwargs)
        for holder in (session,link.record):
            holder.decoder=TransferDecoder(holder.decoder.max_frame_bytes)
            self.decoders.append(holder.decoder)
        return session

    def pads(self):
        return [decoder.transfer_pads for decoder in self.decoders]
