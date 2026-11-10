# Handoff: 2026-11-07

## Status

Everything requested is delivered and accepted; no task is open. Start with
AGENTS.md, docs/agents/SESSION_START.md and `python3 scripts/session-preflight.py`.
This repository is the research project. Data is saved in another container.

## Running now

- **Backend machine** runs the runtime subset of research/native-usb plus
  `dex_probe.py`, the black-screen script and APK, and dexd state. Pins: dexd
  5bd8d746, kms_daemon_live e061b6af, kms_daemon_probe 810bc806, direct_gateway
  99d3cc48, blackscreen.sh 42f65682, tcp_control 5b7b82c3 (full list:
  research/native-usb/MANIFEST.sha256). The previous two versions are kept there
  as `before-*` rollbacks. Time zone and phone serial come from a local config file read
  by dexd; without it, logs are UTC and the single attached phone is used.
- **Client**: v7 package; v8 test = v7 + system keys (build from `windows/`).
- **Behaviour**: async USB in/out, scrambled RTP with descrambling, pause on
  disconnect / resume on connect (10 s reply / 30 s video timeouts fall back to
  TEARDOWN + replug), replug after a session ends, pointer shapes, input wake,
  client low-latency video and adaptive audio. What each fixed: docs/FIXES.md.
  Numbers: evidence/results.json.

## Changing the backend

Edit research/native-usb and update the pin in dexd.py. Test here, one module
per process, memory-capped: test_daemon_recorder, test_dexd,
test_kms_daemon_live (19 older modules need capture fixtures that are not in
this repository). Copy only changed runtime files to the backend machine as a
candidate, check pins there while no viewer is attached, swap during a streaming
session with a `before-*` backup; the new code loads at the next dexd restart
(a backend restart, since sessions now pause instead of ending). Then update
evidence/results.json, evidence/checks.log, docs/FIXES.md and MANIFEST.sha256.

## Open

- Long pause (minutes/hours) not yet observed.
- Phone connect refusal (status 4, error 111) is avoided by replugging; cause
  unknown.
- No physical/optical latency or listening measurement; user feel is the test.
- Client features still to do: clipboard sync, resolution choice / 720p60,
  file drag and drop. System keys done (v8 test, accepted 2026-11-10).

## Environment

SSH helpers in the private lab tools read their settings from the untracked
the private settings. Append backend
commands to a private command log. Backend machine: small,
Python 3.13. Workspace: ~3.9 GB RAM, so tests run one module per process.
