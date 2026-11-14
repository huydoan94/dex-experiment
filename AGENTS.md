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

- The lab machines, how they are reached, their limits and the lab tools are in a
  private lab guide kept outside this repository. Never add any of that here:
  no hosts, addresses, accounts, paths, access methods, tool locations or
  machine details, and no tooling that reveals what is secret.
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
