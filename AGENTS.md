# Instructions for every session

This project extends `~/ai-working-definitions/` (read its README and
session-start files); project rules and explicit user instructions take
precedence. Work alone. Report self-review honestly. Git commits, branch,
remote, history changes and publication only when the user asks.

This repository is the research project. Data is saved in another container.

## Startup

Python is the backend; the C# Windows client is the viewer. See the
[project guide](docs/PROJECT.md) and [delivery contract](docs/agents/EXECUTION_CONTRACT.md).
Before implementation, diagnosis or proposing live work:

1. Read [CODEX_HANDOFF.md](CODEX_HANDOFF.md) and
   [SESSION_START.md](docs/agents/SESSION_START.md).
2. Run `python3 scripts/session-preflight.py`. Read affected
   [migration.json](docs/agents/migration.json) rows, [evidence](evidence/README.md)
   and relevant [lessons](docs/LESSONS.md).
3. Identify the working entry point and the complete adapter chain, including
   TransferDecoder; base Decoder parity does not prove pipeline parity.
4. State the task, reused evidence, remaining gap and next action briefly.

## Access and ownership

- Never print or commit credentials or personal details; use placeholders such
  as `<backend-host>` in tracked files.
- Run tests here, one module per process, memory-capped; never run heavy work on
  the backend machine while a viewer is attached.
- Ask before reaching the phone outside the normal session lifecycle. Explain
  each live action's purpose, limits and cleanup in chat.
- Exactly one USB owner. Preserve the running daemon files, pins and service.
  Never stop the black-screen app in software. Documentation work implies no
  deployment or live access.
- Cleanup must not restart services or change phone state.

## Working style (user rules)

- Every tracked file, log, fixture and commit message is public; machine
  details, access and site values never go in it.
- Commits use the noreply identity and UTC dates, with no AI attribution trailer.
- After offering options, wait for the user's choice before building any of them.
- Client features are always on; add no toolbar toggles unless asked.
- Call the study of the phone apps "inside research".
- Judge input and UI behaviour by what the backend receives: the synthetic stream
  with `--record-input` and `--loop` plus real desktop input on Windows; no phone
  needed for that.
- The local repository is the source of truth: every tracked file on the backend
  machine or in a remote build folder must match it by hash, unpinned ones too.
  Change files only here, then copy and verify; compare before and after remote
  work and report any difference (copy the repository version, or let the user
  decide when it may be intended). Purely local work skips this.
- Deploy: check no viewer, verify the live files are the previous versions, stage,
  check pins, back up, swap, record each hash; the user restarts the backend, then
  verify.
- Fix automated security-review findings (with a test that fails on the old
  code) or say why they do not apply.
- The user's own PC is off limits.

## Lifecycle and established fixes

A live request covers listener relisten, idle owner, automatic Start, black
screen, exclusive USB ownership, bounded attempt, cleanup and resume. Prefer one
changed component per change; record each deployed hash. Before readiness
claims run `preflight --scope SCOPE --require-ready`; never change a status just
to pass. Keep unresolved faults visible even after a successful run.
[LESSONS.md](docs/LESSONS.md) holds the rules; [FIXES.md](docs/FIXES.md) how each
problem was fixed.

## Keep documentation small

Current results belong in evidence/results.json, evidence/checks.log and
evidence/README.md; fixed problems get a short entry in docs/FIXES.md. Do not
create a file per command; temporary work belongs in /tmp. At stops update
CODEX_HANDOFF.md (max 8192 bytes) and affected ledger rows.
