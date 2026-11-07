#!/usr/bin/env python3
"""Local documentation/readiness check. No remote access or test execution."""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/agents/migration.json"
SCOPES = ("transport", "startup", "media", "windows", "input", "diagnostics", "performance")
STATUSES = {"verified", "gap", "limited", "unverified", "deferred"}
# These historical failures must not disappear to make a readiness check pass.
REQUIRED_IDS = {"usb-transfer-padding", "cleanup-correlation", "diagnostic-collection"}
FIELDS = {"id", "scope", "requirement", "baseline", "status", "candidate", "acceptance", "next_action"}


def local_file(root, relative):
    """Reject broken references and paths outside the project, including symlinks."""
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"invalid project reference: {relative!r}")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"missing or external project reference: {relative}")
    return path


def load_rows(root, ledger):
    data = json.loads(ledger.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("updated"), str):
        raise ValueError("ledger needs schema_version1 and an updated date")
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("ledger rows must be a nonempty list")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each ledger row must be an object")
        for field in FIELDS:
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ValueError(f"row {row.get('id', '?')}: missing {field}")
        if row["id"] in seen:
            raise ValueError(f"duplicate requirement: {row['id']}")
        seen.add(row["id"])
        if row["scope"] not in SCOPES or row["status"] not in STATUSES:
            raise ValueError(f"row {row['id']}: invalid scope or status")
        refs = row.get("evidence")
        if not isinstance(refs, list) or not refs:
            raise ValueError(f"row {row['id']}: evidence is required")
        for ref in refs:
            local_file(root, ref)
    missing = REQUIRED_IDS - seen
    if missing:
        raise ValueError("required historical cases missing: " + ", ".join(sorted(missing)))
    return rows


def check_startup(root):
    for relative, limit in (("AGENTS.md", 8192), ("CODEX_HANDOFF.md", 8192)):
        if local_file(root, relative).stat().st_size > limit:
            raise ValueError(f"{relative} exceeds {limit}bytes")
    local_file(root, "docs/agents/SESSION_START.md")


def load_delivery(root, ledger):
    delivery = json.loads(ledger.read_text(encoding="utf-8")).get("delivery")
    if not isinstance(delivery, dict):
        raise ValueError("delivery objective/state missing; technical rows alone are insufficient")
    if not isinstance(delivery.get("objective"), str) or not delivery["objective"].strip():
        raise ValueError("delivery objective is required")
    local_file(root, delivery.get("contract"))
    if type(delivery.get("accepted")) is not bool:
        raise ValueError("delivery accepted must be an explicit boolean")
    for field in ("required_scopes", "completion_criteria", "remaining_work",
                  "independent_authorized_work", "follow_on_project_work", "acceptance_evidence"):
        values = delivery.get(field)
        if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
            raise ValueError("invalid delivery field: " + field)
    if not {"transport", "startup", "media", "input", "diagnostics"}.issubset(delivery["required_scopes"]) or set(delivery["required_scopes"]) - set(SCOPES):
        raise ValueError("delivery must retain all required pipeline scopes")
    if not delivery["completion_criteria"]:
        raise ValueError("delivery completion criteria are required")
    status = delivery.get("phone_request_status")
    if status not in {"none", "pending", "approved", "consumed", "withdrawn"}:
        raise ValueError("invalid delivery phone request status")
    request = delivery.get("pending_phone_request")
    if request is not None:
        local_file(root, request)
    if status in {"pending", "approved"} and request is None:
        raise ValueError("delivery phone scope reference is required")
    for reference in delivery["acceptance_evidence"]:
        local_file(root, reference)
    if delivery["accepted"] and (not delivery["acceptance_evidence"] or delivery["remaining_work"]):
        raise ValueError("accepted delivery requires live acceptance evidence and no remaining delivery work")
    return delivery


def show_delivery(delivery):
    print("DELIVERY OBJECTIVE: " + delivery["objective"])
    print("Delivery accepted: " + str(delivery["accepted"]) + "; phone request: " + delivery["phone_request_status"])
    for item in delivery["remaining_work"]:
        print("  Remaining outcome: " + item)
    for item in delivery["independent_authorized_work"]:
        print("  Independent authorized work: " + item)
    print("Offline test counts do not establish usable end-to-end delivery.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", action="append", choices=SCOPES,
                        help="select affected scope; repeat for multiple scopes; default all")
    parser.add_argument("--ledger", type=Path, default=LEDGER,
                        help="alternative local ledger for offline validation")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="validate structure/references only")
    mode.add_argument("--require-ready", action="store_true",
                      help="fail if any selected requirement is not declared verified")
    mode.add_argument("--require-complete", action="store_true",
                      help="fail unless the current delivery is accepted with evidence and required scopes")
    args = parser.parse_args(argv)
    try:
        check_startup(ROOT)
        rows = load_rows(ROOT, args.ledger)
        delivery = load_delivery(ROOT, args.ledger)
    except (OSError, ValueError, TypeError) as error:
        print(f"PREFLIGHT INVALID: {error}", file=sys.stderr)
        return 2
    if args.require_complete:
        show_delivery(delivery)
        unresolved = [row for row in rows if row["scope"] in delivery["required_scopes"] and row["status"] != "verified"]
        if not delivery["accepted"] or unresolved:
            print("NOT DELIVERED: complete live acceptance remains unfinished; a passing offline/scoped gate is insufficient.")
            return 1
        print("Declared current delivery has evidence; inspect it against the criteria. This grants no access or deployment permission.")
        return 0
    selected = [row for row in rows if not args.scope or row["scope"] in args.scope]
    if args.scope and set(args.scope) - {row["scope"] for row in selected}:
        print("PREFLIGHT INVALID: selected scope has no requirements", file=sys.stderr)
        return 2
    if args.check:
        print(f"PASS: {len(rows)} requirement rows, local references and startup size limits.")
        print("Structure only; no readiness, comprehension, runtime or approval claim.")
        return 0
    show_delivery(delivery)
    print("Read AGENTS.md, CODEX_HANDOFF.md, docs/agents/SESSION_START.md and docs/agents/EXECUTION_CONTRACT.md.")
    print("Then read the selected evidence and inspect the working adapter chain:")
    for row in selected:
        print(f"  {row['scope']}/{row['id']}: {row['status']}")
        if not args.require_ready or row["status"] != "verified":
            print("    " + row["next_action"])
            print("    Read: " + ", ".join(row["evidence"]))
    unresolved = [row for row in selected if row["status"] != "verified"]
    if args.require_ready and unresolved:
        print(f"NOT READY: {len(unresolved)} selected requirements remain unresolved.")
        print("Continue authorized offline work. Do not erase gaps or infer phone approval.")
        return 1
    if args.require_ready:
        print("Declared evidence covers selected rows only; verify source identities and tests.")
    else:
        print("Readiness not requested; unresolved rows remain visible above.")
    print("No remote access performed. This output grants no phone/deployment permission.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
