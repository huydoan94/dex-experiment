#!/usr/bin/env python3
"""Refresh the backend's pinned hashes after editing pinned files.

Pins live in dexd.EXPECTED (checked at every session start) and in the
`<sha256>  research/native-usb/<file>` lines of the reconnect scripts. Each stale
pin's old hash is replaced by the file's current hash in every tracked text file
under research/ and scripts/, repeated until nothing changes (a pinned file may
itself hold pins). MANIFEST.sha256 is then rewritten for the files it lists that
still exist. Run from the project root; prints the stale count per round.
"""
import ast
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "research/native-usb"
SCRIPT_PIN = re.compile(r"([0-9a-f]{64})  research/native-usb/([\w./-]+)")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tracked_text():
    names = subprocess.run(["git", "ls-files", "research", "scripts"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / n for n in names
            if n.endswith((".py", ".sh", ".json", ".md", ".txt")) and not n.endswith("MANIFEST.sha256")
            and (ROOT / n).is_file()]   # deleted but not yet committed


def pins():
    """{path: pinned hash} from dexd.EXPECTED and the shell scripts' sha256 lines."""
    text = (RESEARCH / "dexd.py").read_text()
    start = text.index("EXPECTED=")
    found = {RESEARCH / name: pinned
             for name, pinned in ast.literal_eval(text[start + 9:text.index("\n", start)]).items()}
    for script in RESEARCH.glob("*.sh"):
        for pinned, name in SCRIPT_PIN.findall(script.read_text()):
            found[RESEARCH / name] = pinned
    return found


def main():
    files = tracked_text()
    for round_number in range(8):
        stale = {pinned: digest(path) for path, pinned in pins().items() if digest(path) != pinned}
        if not stale:
            break
        changed = 0
        for path in files:
            text = path.read_text()
            updated = text
            for old, new in stale.items():
                updated = updated.replace(old, new)
            if updated != text:
                path.write_text(updated)
                changed += 1
        print(f"round {round_number}: {len(stale)} stale pins, {changed} files rewritten")
    manifest = RESEARCH / "MANIFEST.sha256"
    names = [line[66:] for line in manifest.read_text().splitlines() if line]
    manifest.write_text("".join(f"{digest(RESEARCH / n)}  {n}\n" for n in sorted(names) if (RESEARCH / n).is_file()))
    bad = [str(p.relative_to(RESEARCH)) for p, pinned in pins().items() if digest(p) != pinned]
    print(f"pins {len(pins())} mismatched {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
