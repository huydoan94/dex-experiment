# Fixed problems

What went wrong, why, how it was fixed and what it gave. Newest first within
each area. Raw measurements are kept outside this repository.

## USB transport (backend, `kms_daemon_live.py`)

- **Input lag behind acknowledgements** (2026-11-07). One thread wrote every USB
  OUT frame synchronously; ~150k per-packet ACKs per 2 min kept it 30% busy, and
  viewer input queued behind them (queued-to-done p99 96 ms, max 258 ms, 376
  waiting). *Fix:* `AsyncOut` keeps up to 8 libusb OUT transfers in flight,
  strictly in queue order (same transfers, same order, ZLP kept); USB is never
  released while one may be in flight. *Result:* p99 7.5 ms / max 38 ms at
  3,166 writes/s; user: "input feel very snappy".
- **Periodic video/audio gaps on keyframes** (2026-11-06). One-at-a-time 512-byte
  synchronous reads capped USB at ~3 MB/s and blocking ACK writes added ~40 ms.
  *Fix:* 8×16 KB async IN transfers (split into 512-byte pieces so the transfer
  decoder sees identical input) plus a pipelined single writer. *Result:*
  keyframe span 93 → 44 ms, video gaps >100 ms 52 → 1-3 per minute.
- **Batched-transfer padding** (2026-11-04). The phone pads whole batched
  transfers with 0x5a; decoders that ignored transfer boundaries broke frames.
  *Fix:* `conn_transfer.TransferDecoder` keeps read boundaries. Rule: always
  test through the full chain, not the base decoder.
- **Full-packet OUT writes stalled.** *Fix:* a zero-length packet after any OUT
  transfer that is an exact multiple of 512 bytes.

## Media

- **Stream had to travel unscrambled** (2026-11-06). Reporting the official PC
  version (2.4.1.27) makes the phone XOR-scramble RTP. *Fix:* `Descrambler`
  XORs byte i ≥ 12 with the uppercase-hex AUTH session key `[i % 64]` (as in
  SamsungDeX.exe), latching on the first TS sync byte. *Result:* 151,146 packets
  descrambled, TS sync 100%, 0 gaps.
- **TCP media aborted the phone's RTP sender.** *Fix:* UDP RTP/RTCP only.
- **"Sink drops" looked like media loss** (2026-11-06). They were only chunks
  queued when the viewer disconnected (queue peak ≤165 KB vs 8 MB limit).
  *Fix:* counters split into `overflow_dropped_*` (real loss) and
  `detach_dropped_*`.

## Session lifecycle (dexd)

- **Every reconnect cost a ~20 s backend cycle** (2026-11-07). A departed
  viewer ended the session (TEARDOWN + replug). *Fix:* `PauseControl` sends
  RTSP PAUSE 5 s after the viewer leaves and PLAY when one attaches (the same
  requests the official app uses); 10 s reply / 30 s video timeouts fall back to
  the old path. *Result:* video 42-58 ms after PLAY; user: "very snappy".
- **Phone refused the next connection** (status 4, error 111) after 7 of 30
  restart-only cycles. *Fix:* dexd always asks the host for a USB replug after a
  session (0/8 refusals since; ready in ~20 s instead of 12). Root cause unknown.
- **Pinned files swapped while idle were refused.** dexd checks in-memory pins
  at each session start. *Fix:* swap during a streaming session; the next cycle
  loads the new dexd.
- **Viewer startup leaked ownership** (old dd/flock path). *Fix:* the TLS
  gateway pairs media and input sockets before taking locks, with busy and
  partial-pair handling.

## Input

- **~10 ms polling delay on input** (2026-11-06). *Fix:* the input FIFO worker
  sleeps in poll() and ends the media slice early when input is queued.
- **Early input closed sessions** (0.0.7 cursor opt-in sent at connect). The daemon
  only reads input once streaming starts. *Fix:* the client sends nothing on the
  input socket before its first picture.
- **Pointer shape never changed on Windows** (2026-11-06). *Fix:* the phone's
  `MOUSE_CURSOR_CHANGE` (Android PointerIcon id) is relayed via cursor.fifo and
  the gateway (opt-in `X cursor`); the client sets the Windows cursor.

## Windows client (`windows/`)

- **~150 ms input lag** (0.0.4). Video waited for the audio clock (queue + WASAPI).
  *Fix (0.0.5):* "Low latency" (default on) shows the newest picture at once.
- **Audio crackle/stutter** (0.0.1-0.0.3). Playback started with no buffer, so bursts
  underran then overflowed. *Fix:* jitter buffer, then (0.0.6) WASAPI 20 ms and an
  adaptive target (40 → 160 ms on underruns, shrinks when quiet; settles ~80 ms).
  *Result:* audio drops 646,144 → 0 bytes.
- **Glyph corruption on resize.** *Fix:* WinUI 2.6.5 (keep pinned).
- **Standalone exe could not find its runtime.** *Fix:* take the apphost from
  `dotnet publish` (AppHostRelativeDotNet) and include .xbf/.pri files.
- Tried and rejected: decoder LOW_DELAY (broke B-frame EOF/pixel parity), a
  fixed 40 ms audio target (11-14 rebuffers per 30 s).

## Clipboard and files (2026-11-10/11)

- **Clipboard did nothing.** The request went on the IDC handshake connection;
  the phone takes each IDC command on a fresh connection to its control port.
  *Fix:* clipboard_bridge opens one per request (host ports 50100+).
- **Copied files never offered.** The WinRT clipboard gave this unpackaged app no
  file list. *Fix:* read CF_HDROP; offer per clipboard change counter, so the
  same file copied again is offered again.
- **Phone ignored file transfer.** It asks `REQ FeatureList` at KMS start.
  *Fix:* answer `FeatureList "KMS_FT_SUPPORTED"` as the PC app does; resend an
  unanswered FILE clip (3 s, 5 tries).
- **Paste did nothing.** My Files sends `/Document` from a category view, not a
  folder. *Fix:* paste inside a real folder (documented).
- **Drag landed after release / landed after leaving.** *Fix:* drive the phone's
  drag with mouse events 13/9/10 while hovering; on leaving, empty its file list
  so the drop becomes a cancel.

## Operations incidents

- **2026-11-07 02:19 stream drop** — the phone rebooted for an OMC software
  update (`reboot,omcupdate`); the backend recovered by itself in ~3.5 min.
- **2026-11-07 00:08 broken stream** — an agent ran ~50 test modules on the backend machine during a live session; later the same on WSL ran out of memory.
  *Rule:* tests one module per process, memory-capped, never on the backend machine while a
  viewer is attached (the backend machine now has no tests at all).
- **2026-11-11 "Media decode error" on connect** — after file transfer worked, the
  phone keeps an idle FileReceiveManager with the last file path and its KMSService
  object (connection state 0). The relisten guard took both for activity, so a closed
  phone listener was never reopened and every connection was refused (network error
  111). The guard now accepts exactly those idle shapes; any active state still refuses.
- **2026-11-11 phone files arrived empty** — the cursor relay wrote each line with one
  non-blocking `os.write` and dropped what the FIFO did not take; a 64 KiB `FB` line
  was cut, so the gateway rejected it. A partly written line now finishes first, and
  no other line goes inside it.
- **2026-11-11 PC-to-phone drag sometimes did nothing** — the phone's DeX app keeps
  drag operations by TransferID in a static map plus a 25-entry history; evicting an
  old entry removes its ID from the map. Our TransferIDs restarted at 1 every
  session, so a reused ID was removed together with its old twin and the drop failed
  ("FILE OPERATION ID DOESN'T EXIST" in the phone log). IDs now continue across
  sessions (`dexd/file-transfer-id`).
- **2026-11-11 SmartScreen "Windows protected your PC" on client 1.1.0** — from
  1.0.0 the packages shipped a newly built launcher exe (its version resource
  changed); unsigned and started from a share, each new exe was unknown to
  SmartScreen. 1.1.0 ships the launcher every earlier package used, and packages
  keep it from now on.
