"""Two scripted mouse moves during an existing live-video session; no clicks/keys."""
import kms_handshake
import rtsp_udp_long as long
import rtsp_udp_live as live
import rtsp_udp_play as play
import sidesync_packets
from usb_tunnel import TunnelError

CAP_SECONDS=30
MOVES=((3,480,540),(6,1440,540))
LIVE_PACKET_SUMMARY=64


def configure():
    long.CAP_SECONDS=CAP_SECONDS
    long.LONG.update(MEDIA_DATAGRAMS=30000,MEDIA_SECONDS=CAP_SECONDS,
        MEDIA_BYTES=64<<20,PLAY_ACKS=35000,PLAY_READS=110000,
        STAGE_SECONDS=CAP_SECONDS+30)
    long.LONG_KEEPALIVES=4


def received_summary(data,offset):
    """Kinds and sizes of KMS frames after the handshake; metadata only, never raises."""
    frames,error,total=[],None,len(data)-offset
    while len(data)-offset>=4 and len(frames)<LIVE_PACKET_SUMMARY:
        size=int.from_bytes(data[offset+2:offset+4],"big")
        if data[offset]!=sidesync_packets.VERSION or size<4:
            error="invalid frame header"
            break
        if len(data)-offset<size:
            break
        frames.append(dict(kind=data[offset+1],bytes=size))
        offset+=size
    return dict(bytes=total,packets=frames,unparsed_bytes=len(data)-offset,error=error)


def startup(session,main,rtsp,result,log,*,client,latest,after_kms):
    def verified(s,m,r,connection,res,logger):
        s.kms_connection=connection
        handshake_bytes=len(connection.received)
        try:
            return after_kms(s,m,r,res,logger)
        finally:
            res["kms_live_received"]=received_summary(connection.received,handshake_bytes)
    return kms_handshake.handshake(session,main,rtsp,result,log,
        client=client,latest=latest,after_verified=verified)


class MouseSession(long.LongSession):
    def wait(self,seconds,until=lambda:False):
        if not self.window_armed:
            return super().wait(seconds,until)
        started=self.clock()
        self.mouse_attempted=0
        self.mouse_sent=0
        def watched():
            if until() or self.stop_requested():
                return True
            connection=self.kms_connection
            if connection.closed_by_phone:
                raise TunnelError("KMS closed during live mouse test")
            if self.clock()>=self.stage_latest-live.DEADLINE_MARGIN_SECONDS:
                self.stop_reason="stage_deadline"
                return True
            if self.mouse_attempted<len(MOVES):
                at,x,y=MOVES[self.mouse_attempted]
                if self.clock()-started>=at:
                    # Advance before nested transport waits; never retry this event.
                    self.mouse_attempted+=1
                    self.send(connection,sidesync_packets.mouse_event(0,x,y),
                        timeout_s=min(1,self.stage_latest-self.clock()))
                    self.mouse_sent+=1
                    self.log(event="scripted_kms_mouse_move",index=self.mouse_sent,x=x,y=y)
            return False
        return super().wait(seconds,watched)

    def summary(self):
        return dict(super().summary(),mouse_moves_attempted=getattr(self,"mouse_attempted",0),
                    mouse_moves_sent=getattr(self,"mouse_sent",0))


class MouseOwner(long.LongOwner):
    def session(self,link,first_transaction,max_frame_bytes,max_receive_bytes,*,log,**kwargs):
        if max_receive_bytes!=long.MAX_RECEIVE_BYTES:
            raise RuntimeError("session receive limit differs from the pinned base")
        session=MouseSession(link,first_transaction,max_frame_bytes,long.LONG_RECEIVE_BYTES,
            sink=self.sink,stop_file=self.stop_file,log=long.QuietLog(log),**kwargs)
        self.reader=live.duplex_link.ReadPump(link,session.log)
        return session
