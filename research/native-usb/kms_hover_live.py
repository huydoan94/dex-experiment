"""Slow scripted hover path over the DeX taskbar and desktop icons during live video; no clicks/keys."""
import json
import kms_mouse_live as mouse
import sidesync_packets

# DeX desktop is 1920x1080 raw pixels: e2/p injects HOVER_MOVE without scaling.
TASKBAR_Y=1055
FIRST_SECONDS=3
STEP_SECONDS=.4  # two 0.2 s live-wait slices per point
POINTS=tuple([(x,TASKBAR_Y) for x in range(20,1901,80)]
             +[(60,y) for y in range(80,801,80)]+[(960,540)])
MOVES=tuple((FIRST_SECONDS+i*STEP_SECONDS,x,y) for i,(x,y) in enumerate(POINTS))
NOTICE_LIMIT=64
CURSOR_MSG="MOUSE_CURSOR_CHANGE"
# commonMessageStart/Buffer/End; request form 0x64-0x66, response form 0x67-0x69.
START,BODY,END=(0x64,0x67),(0x65,0x68),(0x66,0x69)


def configure():
    mouse.configure()
    # MouseSession schedules from this module global.
    mouse.MOVES=MOVES


def notice(raw,response):
    """TYPE and MSG of one JSON common message; PARAM only for cursor changes."""
    try:
        message=json.loads(raw.decode("utf-8"))
    except ValueError:
        message=None
    if not isinstance(message,dict):
        return dict(bytes=len(raw),response=response,decoded=False)
    kept=dict(bytes=len(raw),response=response,decoded=True,
              TYPE=message.get("TYPE"),MSG=message.get("MSG"))
    if message.get("MSG")==CURSOR_MSG:
        kept["PARAM"]=message.get("PARAM")
    return kept


def notices(data,offset):
    """Common messages the phone sent on KMS after offset; never raises."""
    found,body,error=[],None,None
    while len(data)-offset>=4 and len(found)<NOTICE_LIMIT:
        kind=data[offset+1]
        size=int.from_bytes(data[offset+2:offset+4],"big")
        if data[offset]!=sidesync_packets.VERSION or size<4:
            error="invalid frame header"
            break
        if len(data)-offset<size:
            break
        if kind in START:
            body=bytearray()
        elif kind in BODY and body is not None:
            body+=data[offset+4:offset+size]
        elif kind in END and body is not None:
            found.append(notice(bytes(body),kind==END[1]))
            body=None
        offset+=size
    return dict(notices=found,error=error)


def startup(session,main,rtsp,result,log,*,client,latest,after_kms):
    def recorded(s,m,r,res,logger):
        connection=s.kms_connection
        start=len(connection.received)
        try:
            return after_kms(s,m,r,res,logger)
        finally:
            res["kms_live_notices"]=notices(connection.received,start)
    return mouse.startup(session,main,rtsp,result,log,client=client,latest=latest,
                         after_kms=recorded)
