# Session start

1. Read AGENTS.md, CODEX_HANDOFF.md and EXECUTION_CONTRACT.md; run
   `python3 scripts/session-preflight.py` locally. It makes no remote/device calls.
2. Read the relevant migration.json rows, [current evidence](../../evidence/README.md)
   and [lessons](../LESSONS.md). Do not reload the whole archive.
3. Identify the full working entry point/adapter chain, saved fix to reuse, actual
   remaining outcome and next authorized action. The backend includes TransferDecoder.
   Work alone. Reuse unchanged passing checks and established permissions.

Before any live action, explain one complete lifecycle: listener relisten, idle
owner, automatic Start, black screen, exclusive USB owner, bounded activity/log
window, cleanup and supervisor resume. State attempts, question and stop rule.
Do not split an ordinary session into approval fragments or pin its grant to one
binary. The existing broad remaining-work grant persists; no new session is pending.
For changed scopes, run preflight --scope SCOPE --require-ready before a diagnostic
proposal and explain remaining limits; this check grants no phone access.

At a stop update the short handoff and affected ledger rows without changing
statuses just to pass checks. Use the existing current evidence files rather than
new dated directories and per-command copies. Original historical records are in
the history archive (kept outside this repository). Keep named
regressions and unresolved faults; archived instructions are historical.
