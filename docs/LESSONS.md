# Lessons: rules not to repeat

Short rules learned the hard way. The stories behind them are in
[FIXES.md](FIXES.md); requirement statuses are in
[agents/migration.json](agents/migration.json).

## Backend and phone

- Test and reason through the whole working chain (dexd → kms_daemon_probe →
  DaemonSession → … → duplex → `TransferDecoder`), never the base decoder alone:
  transfer boundaries, 0x5a pads and partial frames matter.
- Keep UDP media, async USB IN/OUT in queue order, and the ZLP after full-packet
  OUT transfers.
- The phone's DeX listener is one-shot: relisten, black screen, automatic Start
  and exactly one USB owner are session preconditions.
- dexd checks its pins at every session start: swap pinned files during a
  streaming session, or while idle followed by a backend restart before the next
  connection. Only runtime files go to the backend machine, and they must match
  the repository.
- `dex_probe.py` at the project root is runtime (imported by `app_bootstrap.py`);
  import scans of `research/native-usb` alone miss it. Before removing anything
  from the backend machine, check scripts, data files and parent-folder imports too.
- Phone connect refusal (status 4, error 111) is a phone-side fault seen after
  restart-only cycles; do not blame the build under test.
- Before blaming the backend for a dropped stream, check the phone's boot reason
  (`getprop sys.boot.reason`; a software update reboots it).

## Client

- Never send anything on the input socket before the first picture.
- Keep WinUI 2.6.5, the published apphost and the .xbf/.pri files.
- Do not reapply decoder LOW_DELAY or a fixed small audio buffer.
- Never ship a rebuilt launcher exe: SmartScreen knows only the existing one.
- Input changes are checked by what the backend would receive (synthetic stream,
  `--record-input`, real desktop input); a phone adds nothing to that question.

## Gateway

- Limits before authentication need one total deadline, not a per-read timeout,
  and a per-address cap; otherwise slow clients hold every slot.

## Working safely

- The backend machine is small: never run heavy work there while a viewer is
  attached. Tests run in the workspace, one module per process, memory-capped
  (`ulimit -v`, `timeout`); a 50-module run broke a stream on the backend and ran
  the workspace out of memory.
- Verify by hash before deleting or moving, and keep the original until the copy
  is checked.
- Choose log tags, time window and encoding deliberately; empty filtered output
  does not prove there was no error.
- Treat everything tracked as public, logs and commit messages included.
- Report results honestly; a clean later run does not prove an older failure
  was fixed.
- Phone logs at debug level are invisible; add backend log lines for each
  protocol step before the next live attempt instead of guessing.
