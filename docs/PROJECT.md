# Project guide

## Architecture (locked 2026-11-07)

Phone (DeX) --USB--> the backend machine Python backend --TLS 7443--> Windows WinUI app.

**Backend (`research/native-usb/` here; its runtime subset runs on the backend machine).** `dexd.py` (systemd `dexd.service`, user dex) runs
one session per backend run:

1. On backend start: find the one phone, check source pins (`EXPECTED` in
   `dexd.py`, SHA256 per file), run `reconnect_relisten.sh` (reopens the phone's
   one-shot listener), create FIFOs, start the TLS gateway (`direct_gateway.py`)
   and keep the black-screen app running.
2. A viewer connects: one session, `kms_daemon_probe.py` ->
   `kms_daemon_live.DaemonSession` -> `kms_session_live` -> `kms_input_live` ->
   `rtsp_udp_long`/`rtsp_udp_live`/`rtsp_udp_play` -> `duplex_link` ->
   `conn_transfer.TransferDecoder` (keep the whole chain; the base Decoder alone
   is not the reference).
3. Viewer leaves: TEARDOWN, cleanup, then dexd asks the host to **replug** the
   phone (also restarts the backend machine); ready again in ~20 s.

Key behaviour in `kms_daemon_live.py`:

- USB: eight 16 KB async IN transfers (split into 512-byte pieces for
  TransferDecoder) and up to eight in-order async OUT transfers (`AsyncOut`,
  one transfer per frame, ZLP its own). USB is never released while a transfer
  may be in flight.
- RTP scrambling: PcVer 2.4.1.27 makes the phone scramble; `Descrambler` XORs
  byte i>=12 with the uppercase-hex AUTH session key `[i % 64]` (latches on the
  first TS sync byte; plain streams still play). Switch: `SCRAMBLED` in
  `kms_daemon_probe.py`.
- Input: FIFO worker wakes the media slice when viewer input is queued.
- Cursor shapes: phone `MOUSE_CURSOR_CHANGE` -> `cursor.fifo` -> gateway ->
  client (opt-in line `X cursor`, sent at first picture).
- Results (`dexd/session-*/result.json`): counts and timings only, never media.
  Sink drops are split into `overflow_dropped_*` (real loss) and
  `detach_dropped_*` (queued data discarded when the viewer left).

**Client (`windows/`, WinUI 2.6.5, .NET 10, x64).** FFmpeg H264/AAC. Video
rendering (Telemetry panel, per user in `%LOCALAPPDATA%\DexClient\settings.json`,
from the next connection): Hardware (default) shares one D3D11 device between
FFmpeg D3D11VA decoding and the presenter's video processor, so frames stay on
the GPU, and falls back to the CPU when the GPU cannot; Software decodes and
converts on the CPU. Either way D3D presents (WARP without a GPU). WASAPI 20 ms with an adaptive audio buffer (starts 40 ms, grows on
underrun up to 160 ms, shrinks after quiet stretches). "Low latency" (default on)
shows the newest picture at once. While a session shows a picture the client keeps the
PC awake (SetThreadExecutionState), released when it ends or is minimized. Input: ordered bounded queue, hover coalescing,
release on focus loss. Gateway marks client traffic DSCP 41.

## Machines and access

| Where | What | Rules |
| --- | --- | --- |
| WSL (this project) | docs, evidence, backend source + tests, client source, exports, research tools | 3.9 GB RAM |
| the backend machine `<backend-host>` `<backend-project>` | running backend only (runtime files, deps `tools/crypto-root`, `tools/usb-root`, dexd state) | small |
| Windows build machine (Windows 10 x64) | client build/test workspace in the the build folder folder (the build folder) | all build machine files there |

Admin access only through the private lab tools
(pinned SSH; every backend command is appended to a private command log). Run
the private lab tools after a backend batch. SSH settings live in the untracked
the private settings; never print or commit them.
Physical Windows and the virtualization host hosts are off limits.

## Changing the backend

1. Edit in `research/native-usb/` here, update the pin in `dexd.py`.
2. Test here, **one module per process**, memory-capped (see LESSONS): the daemon
   suites are `test_daemon_recorder`, `test_dexd`, `test_kms_daemon_live`.
   the backend machine has no tests any more (runtime only).
3. Copy the changed runtime files to backend `efficiency-20261106/candidate-*` and run
   `dexd.check_pins()` against them there (light; only while no viewer).
4. Swap during a streaming session (the running session keeps the old code; the
   next cycle loads the new pins), keeping a `before-*` backup. Swap only runtime
   files; tests stay here.
5. Verify the next session's `result.json`, then record it in
   `evidence/results.json`, `evidence/checks.log`, and a line in `docs/FIXES.md`.

## Client build and package

Build on the Windows build machine in the build folder, package with
the private packaging scripts (update the expected hashes there). the lab runner maps the
folder for each SSH session and sets `the build folder`; the scripts refuse to run without
it. The folder is a share that maps the DOS Archive attribute to the execute bit;
files written by MSBuild lack it and fail with "Access is denied". After a
build, set Archive on the outputs (`$_.Attributes = $_.Attributes -bor 'Archive'`). The standalone ZIP
bundles the runtime, `backend.json` and the token (`gateway-token`).
Keep the launcher `DexClient.App.exe` unchanged between releases (copy only the
app DLLs, `.pri` and `.xbf`): it is unsigned and runs from a network share, so
every new exe build makes SmartScreen ask again. The version lives in the app
DLL (`<Version>` in DexClient.App.csproj); the launcher's own file version stays 1.0.0.0.
Local gateway regression: `python3 scripts/gateway/test_direct_gateway.py`.
Docs check: `python3 scripts/session-preflight.py`.
Pins: after editing a pinned backend file, `python3 scripts/pins.py` refreshes
every pin (dexd.EXPECTED, the reconnect scripts) and MANIFEST.sha256.

## Known limits

No physical/optical latency or listening measurement. Async OUT shown at light
load only (p99 8.4 ms vs 22-38 ms sync); heavy-load sessions not yet measured.
Phone connect refusal (status 4) after restart-only cycles is avoided by
replug-first; watched, not closed. See the handoff for the current list.
