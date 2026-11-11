"""Site choices that dexd reads from its local settings and hands to the session.

dexd passes them as environment variables; without them the session uses the
defaults below (the profile every earlier run used, apart from the sink name).
The phone, not the PC, picks the video format from what is offered; select()
records its pick so viewer input is scaled to the DeX desktop it really built.
"""
import os
import re

DEFAULT_SINK_NAME = "DeX-PC"
# The name the phone shows ("Start Samsung DeX on NAME?"); the IDC text is
# space-tokenised, so no spaces.
SINK_NAME = re.compile(r"[A-Za-z0-9._-]{1,32}")

# WFD resolution tables (bit -> width, height, frames per second; "i" = interlaced).
CEA = [(640, 480, 60), (720, 480, 60), (720, 480, "60i"), (720, 576, 50), (720, 576, "50i"),
       (1280, 720, 30), (1280, 720, 60), (1920, 1080, 30), (1920, 1080, 60), (1920, 1080, "60i"),
       (1280, 720, 25), (1280, 720, 50), (1920, 1080, 25), (1920, 1080, 50), (1920, 1080, "50i"),
       (1280, 720, 24), (1920, 1080, 24)]
VESA = [(w, h, f) for w, h in ((800, 600), (1024, 768), (1152, 864), (1280, 768), (1280, 800),
                               (1360, 768), (1366, 768), (1280, 1024), (1400, 1050), (1440, 900),
                               (1600, 900), (1600, 1200), (1680, 1024), (1680, 1050), (1920, 1200))
        for f in (30, 60)]
HH = [(w, h, f) for w, h in ((800, 480), (854, 480), (864, 480), (640, 360), (960, 540), (848, 480))
      for f in (30, 60)]
TABLES = (("CEA", CEA), ("VESA", VESA), ("HH", HH))

# Video mode -> (native byte, CEA mask, VESA mask, HH mask).
# 1080p30: what every earlier run offered. all: SamsungDeX.exe's own offer
# (wfd_video_formats "02 00 02 04 0001DEFF 157C7FFF 00000FFF ..."); the phone picks.
# 1080p60: 1080p30 and 1080p60 (SamsungDeX.exe never offers 1080p60); the phone picks.
# 60fps: only SamsungDeX.exe's 60 fps entries from 720p up (CEA 720p60; VESA 800x600 to
# 1600x900 at 60) plus the mandatory 640x480p60; native = VESA 1600x900p60.
MODES = {"1080p30": (0x38, 0x81, 0, 0), "all": (0x02, 0x0001DEFF, 0x157C7FFF, 0x00000FFF),
         "1080p60": (0x40, 0x181, 0, 0), "60fps": (0xA9, 0x41, 0x00282AAA, 0)}
DEFAULT_MODE = "1080p30"
# Viewer input lines use this coordinate space whatever the phone picks.
INPUT_WIDTH, INPUT_HEIGHT = 1920, 1080
_selected = None  # (width, height) of the format the phone picked in M4


def sink_name():
    value = os.environ.get("DEX_SINK_NAME", "")
    return value if SINK_NAME.fullmatch(value) else DEFAULT_SINK_NAME


def video_mode():
    value = os.environ.get("DEX_VIDEO_MODE", "")
    return value if value in MODES else DEFAULT_MODE


def video_formats():
    """wfd_video_formats offered in M3 (H.264 CBP, level 4.2)."""
    native, cea, vesa, hh = MODES[video_mode()]
    return "%02X 00 02 04 %08X %08X %08X 00 0000 0000 00 none none" % (native, cea, vesa, hh)


def picked(cea, vesa, hh):
    """The phone's pick as (table, width, height, fps), or None unless exactly one offered entry."""
    _, offered_cea, offered_vesa, offered_hh = MODES[video_mode()]
    bits = [(name, table, mask) for (name, table), mask in zip(TABLES, (cea, vesa, hh)) if mask]
    if len(bits) != 1:
        return None
    name, table, mask = bits[0]
    offered = dict(CEA=offered_cea, VESA=offered_vesa, HH=offered_hh)[name]
    if mask & (mask - 1) or mask & ~offered or mask.bit_length() > len(table):
        return None
    return (name, *table[mask.bit_length() - 1])


def select(width, height):
    global _selected
    _selected = (width, height)


def desktop_size():
    return _selected or (INPUT_WIDTH, INPUT_HEIGHT)


def to_desktop(x, y):
    """Viewer input space (1920x1080) -> DeX desktop pixels of the format the phone picked."""
    width, height = desktop_size()
    return x * width // INPUT_WIDTH, y * height // INPUT_HEIGHT
