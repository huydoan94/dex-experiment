# Python backend (source and tests; runtime subset on the backend machine)

Complete backend folder. the backend machine (`<backend-project>/research/native-usb`) runs
only the Runtime group below (plus dexd state). Locked 2026-11-07 after the user accepted async OUT ("input feel very snappy").
`MANIFEST.sha256` lists every file here; the backend machine's runtime files match their lines. The runtime pins are `EXPECTED` in `dexd.py`.

| Group | Files |
| --- | --- |
| Runtime (46) | `dexd.py`, `dexd.service`, the 43 pinned files in `dexd.EXPECTED` (incl. `reconnect_relisten.sh`, `blackscreen/blackscreen.sh`), plus `app_bootstrap.py`, `relisten_bootstrap.py`, `reconnect_bootstrap.sh` started by the relisten script, and `dex_probe.py` in the project root (imported by `app_bootstrap.py`) |
| Tests (59 `test_*.py`) | every test that imports a runtime file, and what those tests import |
| Test helpers | older probe/launch scripts, `*_once.sh` wrappers and vectors those tests use; not run in production |
| Data | `fixtures/`, `*-vectors.json` |

Main files: `dexd.py` (lifecycle, pins, replug request), `kms_daemon_probe.py`
(session entry, `SCRAMBLED` switch), `kms_daemon_live.py` (DaemonSession,
Descrambler, AsyncIn/AsyncOut USB, sink, cursor relay, input wake),
`direct_gateway.py` (TLS 7443, DSCP 41, cursor relay), `threaded_input.py`.

Tests: run **one module per process**, memory-capped (docs/LESSONS.md), never on
the backend machine while a session streams. 19 older modules fail identically on WSL and backend
because their capture folders were archived on 2026-11-06 (e.g.
`query-20261101T171251Z/`); the daemon suites `test_daemon_recorder`,
`test_dexd`, `test_kms_daemon_live` all pass.

