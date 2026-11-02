"""Targeted DeX dialog confirmation via bounded ADB, while pumping native USB."""
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

from usb_tunnel import TunnelError

PACKAGE="com.sec.android.app.dexonpc"
TITLE="Start Samsung DeX on <lab>?"
MAX_XML_BYTES=262144
ADB=["/usr/bin/adb","-H","127.0.0.1","-P","5037"]


def select_serial(output,bus):
    lines=output.decode("utf-8","strict").splitlines()
    header=lines.index("List of devices attached")
    rows=[line.split() for line in lines[header+1:] if line.strip()]
    if len(rows)!=1 or len(rows[0])<3 or rows[0][1]!="device":
        raise ValueError("expected exactly one authorized ADB device")
    serial=rows[0][0]
    fields=rows[0][2:]
    if (not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",serial)
            or "model:SM_G985F" not in fields
            or not any(re.fullmatch(r"usb:"+str(bus)+r"-[0-9]+(?:\.[0-9]+)*",f)
                       for f in fields)):
        raise ValueError("ADB identity does not match selected S20+ USB bus")
    return serial


def dialog_button(output):
    if len(output)>MAX_XML_BYTES:
        raise ValueError("UI hierarchy exceeds limit")
    if b"<!DOCTYPE" in output.upper() or b"<!ENTITY" in output.upper():
        raise ValueError("UI XML declarations forbidden")
    start=output.find(b"<?xml")
    end=output.find(b"</hierarchy>",start)
    if start<0 or end<0 or output.count(b"<hierarchy")!=1:
        raise ValueError("missing/ambiguous UI hierarchy")
    xml=output[start:end+len(b"</hierarchy>")]
    root=ET.fromstring(xml)
    if root.tag!="hierarchy":
        raise ValueError("unexpected UI root")
    nodes=list(root.iter("node"))
    if not 1<=len(nodes)<=1000:
        raise ValueError("UI node count outside limit")
    if any(n.get("package")!=PACKAGE for n in nodes):
        raise ValueError("active UI is not exclusively DeX")
    titles=[n for n in nodes if n.get("text")==TITLE]
    candidates=[n for n in nodes if n.get("text","").casefold()=="start now"
                and n.get("resource-id")=="android:id/button1"
                and n.get("class")=="android.widget.Button"
                and n.get("enabled")=="true" and n.get("clickable")=="true"]
    if len(titles)!=1 or len(candidates)!=1:
        raise ValueError("expected unique DeX title and enabled Start now button")
    def bounds(node):
        match=re.fullmatch(r"\[([0-9]{1,4}),([0-9]{1,4})\]\[([0-9]{1,4}),([0-9]{1,4})\]",
                           node.get("bounds",""))
        if not match:
            raise ValueError("invalid UI bounds")
        x1,y1,x2,y2=map(int,match.groups())
        if not 0<=x1<x2<=4096 or not 0<=y1<y2<=8192:
            raise ValueError("UI bounds outside supported display")
        return x1,y1,x2,y2
    outer=bounds(nodes[0]); button=bounds(candidates[0])
    if not (outer[0]<=button[0]<button[2]<=outer[2]
            and outer[1]<=button[1]<button[3]<=outer[3]):
        raise ValueError("button outside active window")
    return xml,((button[0]+button[2])//2,(button[1]+button[3])//2)


def validate_focus(output):
    text=output.decode("utf-8","strict")
    matches=re.findall(r"^\s*mCurrentFocus=(.*)$",text,re.MULTILINE)
    if len(matches)!=1 or not re.search(r"\bu0\s+"+re.escape(PACKAGE)+r"(?=/|\s|\})",matches[0]):
        raise ValueError("current focus is not the DeX dialog")
    if any(re.search(pattern,text) for pattern in (
            r"\bmShowingLockscreen=true\b",r"\bmDreamingLockscreen=true\b")):
        raise ValueError("lock screen reported")
    return matches[0]


def run_adb(argv,session,main,deadline,limit,log):
    """One bounded child. Main thread services native frames; no worker tap race."""
    if session.clock()>=deadline or main.closed_by_phone:
        raise TunnelError("UI operation canceled by deadline/main closure")
    # Independent timer remains even if the Python driver is forcibly killed.
    bounded_argv=["/usr/bin/timeout","--signal=KILL",
                  "%.6fs"%max(.001,deadline-session.clock())]+argv
    log(event="ui_command",argv=bounded_argv,output_limit_bytes=limit)
    output=bytearray()
    child=subprocess.Popen(bounded_argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,start_new_session=True)
    try:
        os.set_blocking(child.stdout.fileno(),False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            eof=False
            while not eof or child.poll() is None:
                if session.clock()>=deadline or main.closed_by_phone:
                    raise TunnelError("UI command deadline/main closure")
                if not eof and selector.select(timeout=0):
                    chunk=os.read(child.stdout.fileno(),min(8192,limit+1-len(output)))
                    if not chunk:
                        eof=True
                        selector.unregister(child.stdout)
                    else:
                        output+=chunk
                        if len(output)>limit:
                            raise ValueError("ADB output exceeds limit")
                if eof and child.poll() is not None:
                    break
                session.wait(min(.1,max(0,deadline-session.clock())),until=lambda:False)
        if session.clock()>=deadline or main.closed_by_phone:
            raise TunnelError("UI command completed late/after main closure")
        log(event="ui_command_result",returncode=child.returncode,
            output=bytes(output).decode("utf-8","backslashreplace"))
        if child.returncode!=0:
            raise RuntimeError("ADB command failed with status%d"%child.returncode)
        return bytes(output)
    except Exception as error:
        log(event="ui_command_error",error=type(error).__name__+": "+str(error),
            output=bytes(output).decode("utf-8","backslashreplace"))
        raise
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait(timeout=2)
        child.stdout.close()


def confirm(session,main,result,log,deadline,output,bus,runner=run_adb):
    """At most4 ADB calls, one hierarchy, one focus check and one tap."""
    ui_deadline=min(deadline,session.clock()+20)
    result["ui_confirmation_attempted"]=True
    devices=runner(ADB+["devices","-l"],session,main,
                   min(ui_deadline,session.clock()+3),16384,log)
    serial=select_serial(devices,bus)
    base=ADB+["-s",serial,"exec-out","timeout","-s","KILL"]
    hierarchy=runner(base+["12","uiautomator","dump","--compressed","/proc/self/fd/1"],
                     session,main,min(ui_deadline,session.clock()+13),MAX_XML_BYTES,log)
    xml,point=dialog_button(hierarchy)
    (Path(output)/"ui-before.xml").write_bytes(xml)
    captured_at=session.clock()
    focus=runner(base+["2","dumpsys","window","displays"],session,main,
                 min(ui_deadline,session.clock()+3),524288,log)
    validate_focus(focus)
    if (session.clock()-captured_at>=2 or session.clock()>=ui_deadline
            or main.closed_by_phone):
        raise TunnelError("UI snapshot stale/deadline/main closure before tap")
    result["ui_tap_attempted"]=True
    result["ui_tap_point"]=list(point)
    runner(base+["2","input","tap",str(point[0]),str(point[1])],session,main,
           min(ui_deadline,session.clock()+3),8192,log)
    result["ui_tap_command_succeeded"]=True
    log(event="ui_confirmation_command_completed",point=list(point),
        confirmation_requires_wfd_event=True)
