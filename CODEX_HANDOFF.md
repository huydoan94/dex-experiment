# Handoff: 2026-11-11

## Status

Project wrapped up 2026-11-11 at the user's request: everything requested is
delivered and accepted, and no further steps are planned. The Open items below
stay as known limits, not as pending work. To resume, start with
AGENTS.md, docs/agents/SESSION_START.md and `python3 scripts/session-preflight.py`.
This repository is the research project. Data is saved in another container.

## Running now

- **Backend machine** runs the runtime subset of research/native-usb plus
  `dex_probe.py`, the black-screen script and APK, and dexd state. Pins: dexd 187f3e5b, kms_daemon_live b0804406, kms_daemon_probe 76da72e6, kms_session_live 94d8e954, direct_gateway 2451bdeb, clipboard_bridge 4471c768, file_bridge 8571a4bc, site_env 4787c7ff,
  blackscreen.sh 42f65682, tcp_control 5b7b82c3 (full list:
  research/native-usb/MANIFEST.sha256). Rollbacks are kept there as
  `before-*-2026111x`. Time zone, phone serial and sink name come from a local
  config file read by dexd; without it, logs are UTC and the single attached
  phone is used.
- **Client**: 1.0.1 packaged
  (build from `windows/`; earlier test builds were 0.0.x and are only in git).
- **Behaviour**: async USB in/out, scrambled RTP with descrambling, pause on
  disconnect / resume on connect (10 s reply / 30 s video timeouts fall back to
  TEARDOWN + replug), replug after a session ends, pointer shapes, input wake,
  client low-latency video and adaptive audio, system keys (Windows key,
  Alt+Tab, Alt+Esc, Ctrl+Esc), text clipboard both ways, files PC to phone by
  copy-paste and drag and drop with delivery progress (docs/FILE_TRANSFER.md).
  What each fixed: docs/FIXES.md. Numbers: evidence/results.json.

## Changing the backend

Edit research/native-usb and update the pin in dexd.py. Test here, one module
per process, memory-capped: test_daemon_recorder, test_dexd,
test_kms_daemon_live (19 older modules need capture fixtures that are not in
this repository). Copy only changed runtime files to the backend machine as a
candidate, check its pins, and swap with a `before-*` backup, either during a
stream or while idle followed by a backend restart before the next connect
(the running dexd checks new files against its old pins). The new code loads
at the backend machine restart. Then update
evidence/results.json, evidence/checks.log, docs/FIXES.md and MANIFEST.sha256.

## Open

- Long pause (minutes/hours) not yet observed.
- Phone connect refusal (status 4, error 111): one cause found 2026-11-11, the
  relisten guard refusing the idle state file transfer leaves (fixed, FIXES.md).
- No physical/optical latency or listening measurement; user feel is the test.
- Files phone to PC: drag out works live with client 1.0.1 (1-byte placeholder
  finds the drop folder; files are fetched into it; the phone pointer goes one
  step off-screen while the drag is outside). The placeholder can stay visible
  during a large copy. A virtual-file drag did not work and was reverted. Copying
  files on the phone to paste on the PC is not supported by the phone app. See docs/FILE_TRANSFER.md.
- Cleanup 2026-11-11 (PLAN-cleanup.md, untracked): experiments, the Python viewer
  and dead tests removed; kms_daemon_live and MainWindow.Live split. Step H measured:
  streaming costs ~16% of the backend machine's CPU; no efficiency change needed.
- Resolution: the phone picks; it gives DeX on PC only 1080p30 (720p60 and
  1080p60 refused, 2026-11-10).

## Environment

SSH helpers in the private lab tools read their settings from the untracked
the private settings. Append backend
commands to a private command log. Backend machine: small,
Python 3.13. Workspace: ~3.9 GB RAM, so tests run one module per process.
