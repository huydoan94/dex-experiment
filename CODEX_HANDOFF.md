# Handoff: 2026-11-07

## Status

Everything requested is delivered and accepted; no task is open. Start with
AGENTS.md, docs/agents/SESSION_START.md and `python3 scripts/session-preflight.py`.
This repository is the research project. Data is saved in another container.

## Running now

- **Backend machine** runs the runtime subset of research/native-usb plus
  `dex_probe.py`, the black-screen script and APK, and dexd state. Pins: dexd 82cba96c, kms_daemon_live b0804406, kms_daemon_probe 76da72e6, kms_session_live 94d8e954, direct_gateway 2451bdeb, clipboard_bridge 4471c768, file_bridge 1afc3615, site_env 4787c7ff,
  blackscreen.sh 42f65682, tcp_control 5b7b82c3 (full list:
  research/native-usb/MANIFEST.sha256). Rollbacks are kept there as
  `before-*-2026111x`. Time zone, phone serial and sink name come from a local
  config file read by dexd; without it, logs are UTC and the single attached
  phone is used.
- **Client**: v15 test package packaged (build from
  `windows/`).
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
- Phone connect refusal (status 4, error 111) is avoided by replugging; cause
  unknown.
- No physical/optical latency or listening measurement; user feel is the test.
- Files phone to PC (drag out of the DeX window, phone copy then PC paste) not
  built; protocol mapped in docs/FILE_TRANSFER.md. With it: usb_tunnel's
  arbitrary cap of 16 phone-initiated connections per session (sessions use 1
  today) would end a session after ~15 drag-outs; count open ones instead.
- Resolution: the phone picks; it gives DeX on PC only 1080p30 (720p60 and
  1080p60 refused, 2026-11-10).

## Environment

SSH helpers in the private lab tools read their settings from the untracked
the private settings. Append backend
commands to a private command log. Backend machine: small,
Python 3.13. Workspace: ~3.9 GB RAM, so tests run one module per process.
