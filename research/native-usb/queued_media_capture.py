"""Default-off receive-only queued USB evidence; every IN body hashed, no bulk OUT."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import time

from rtsp_udp_play import RedactingRecorder
from tunnel_probe import _terminated,emit,READ_ENDPOINT
from version_query import validate_config
import udp_play_launch

MAX_READS=32
MAX_BYTES=16384
WINDOW_SECONDS=2


def capture(device,util,timeout_error,out,result,clock=time.monotonic):
    claimed=False
    result.update(read_calls=0,raw_in_bytes=0,complete_frames=0,quiet_observed=False)
    with (out/"events.jsonl").open("x") as stream:
        def log(event,**fields):
            if event.startswith("usb_frame_in"):
                result["complete_frames"]+=1
            line=json.dumps(dict(event=event,**fields),sort_keys=True)
            stream.write(line+"\n");stream.flush()
            print(line,flush=True)
        recorder=RedactingRecorder(log,65536)
        try:
            validate_config(device.get_active_configuration())
            if device.is_kernel_driver_active(3):
                raise RuntimeError("interface3 has kernel driver; no detach")
            util.claim_interface(device,3)
            claimed=True
            deadline=clock()+WINDOW_SECONDS
            while result["read_calls"]<MAX_READS and clock()<deadline:
                result["read_calls"]+=1
                try:
                    data=bytes(device.read(READ_ENDPOINT,512,timeout=max(1,min(200,int((deadline-clock())*1000)))))
                except timeout_error:
                    result["quiet_observed"]=True
                    break
                if len(data)>512:
                    raise ValueError("USB read exceeds requested limit")
                result["raw_in_bytes"]+=len(data)
                recorder("in",data)
                if result["complete_frames"] or recorder.failed:
                    result["decode_failed"]=recorder.failed
                    break
            result["capture_completed"]=True
        finally:
            try:
                if claimed:
                    util.release_interface(device,3)
                    result["usb_released"]=True
            finally:
                util.dispose_resources(device)
                result["usb_disposed"]=True


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-queued-media-capture",action="store_true")
    p.add_argument("--output",type=Path)
    a=p.parse_args(argv)
    if not a.approved_phone_queued_media_capture:
        emit("PLAN_ONLY",phone_access=False,max_reads=MAX_READS,max_bytes=MAX_BYTES,
             bulk_out=False,acks=False,payload_persistence=False)
        return 0
    if a.output is None:
        p.error("requires fresh output")
    if a.output.exists():
        raise FileExistsError("output already exists")
    root=Path(__file__).resolve().parent
    if not udp_play_launch.EXPECTED:
        raise RuntimeError("empty source manifest")
    for name,digest in udp_play_launch.EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError("source mismatch: "+name)
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    signal.signal(signal.SIGTERM,_terminated)
    result=dict(capture_completed=False,bulk_out=False,acks=False,payload_persistence=False)
    try:
        import usb.core
        import usb.util
        phones=list(usb.core.find(find_all=True,idVendor=0x04e8,idProduct=0x6860))
        if len(phones)!=1:
            raise RuntimeError("expected exactly one Samsung phone")
        device=phones[0]
        result["selected_usb"]=dict(bus=device.bus,address=device.address)
        capture(device,usb.util,usb.core.USBTimeoutError,a.output,result)
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error))
    finally:
        (a.output/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        emit("queued_media_capture_result",**result)
    return 0 if result["capture_completed"] and "error" not in result else 1


if __name__=="__main__":
    raise SystemExit(main())
