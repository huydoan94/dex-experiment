"""Guard automatic DeX confirmation on explicit display0; original helpers unchanged."""
from pathlib import Path
import re

import ui_confirm as ui
from usb_tunnel import TunnelError


def validate_focus(output):
    text=output.decode("utf-8","strict")
    markers=list(re.finditer(r"^  Display: mDisplayId=([0-9]+) rootTasks=[0-9]+[ \t]*$",text,re.MULTILINE))
    if not markers or len(re.findall(r"^  Display:",text,re.MULTILINE))!=len(markers):
        raise ValueError("missing/unsupported display sections")
    ids=[int(m[1]) for m in markers]
    if len(set(ids))!=len(ids) or ids.count(0)!=1:
        raise ValueError("missing/duplicate default display")
    if re.search(r"^\s*mCurrentFocus=",text[:markers[0].start()],re.MULTILINE):
        raise ValueError("unscoped current focus")
    if any(re.search(p,text) for p in (
            r"\bmShowingLockscreen=true\b",r"\bmDreamingLockscreen=true\b")):
        raise ValueError("lock screen reported")
    index=ids.index(0)
    end=markers[index+1].start() if index+1<len(markers) else len(text)
    section=text[markers[index].start():end]
    return ui.validate_focus(section.encode("utf-8"))


def confirm(session,main,result,log,deadline,output,bus,runner=ui.run_adb):
    """At most4 ui.ADB calls, one hierarchy, one focus check and one tap."""
    ui_deadline=min(deadline,session.clock()+20)
    result["ui_confirmation_attempted"]=True
    devices=runner(ui.ADB+["devices","-l"],session,main,
                   min(ui_deadline,session.clock()+3),16384,log)
    serial=ui.select_serial(devices,bus)
    base=ui.ADB+["-s",serial,"exec-out","timeout","-s","KILL"]
    hierarchy=runner(base+["12","uiautomator","dump","--compressed","/proc/self/fd/1"],
                     session,main,min(ui_deadline,session.clock()+13),ui.MAX_XML_BYTES,log)
    xml,point=ui.dialog_button(hierarchy)
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
    runner(base+["2","input","-d","0","tap",str(point[0]),str(point[1])],session,main,
           min(ui_deadline,session.clock()+3),8192,log)
    result["ui_tap_command_succeeded"]=True
    log(event="ui_confirmation_command_completed",point=list(point),
        confirmation_requires_wfd_event=True)
