#!/bin/bash
# One-command live session: start checks the newest relisten result, creates the
# FIFO directory and starts ONE kms_session run detached, printing FIFO_DIR= and
# OUTPUT=. The viewer then reads FIFO_DIR/ts.fifo and writes FIFO_DIR/input.fifo.
# stop FIFO_DIR touches its stop file. Each relisten result serves one session;
# a lock allows one session at a time. Starting a session is a phone action:
# the user runs it (from the viewer), or an agent with an explicit grant.
set -euo pipefail
root=${DEX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
research=$root/research/native-usb
fifo_base=${DEX_FIFO_BASE:-/tmp}
max_age=${DEX_RELISTEN_MAX_AGE:-300}
once=${DEX_SESSION_ONCE:-$research/kms_session_live_once.sh}
lock=$research/.kms-session.lock
consumed=$research/kms-session-consumed-relistens.txt

fail() { echo "ERROR: $*" >&2; exit 2; }

start() {
    exec 9>"$lock"
    flock -n 9 || fail "a session is already running"
    local latest
    latest=$(find "$research" -maxdepth 1 -type d -name 'relisten-*Z-*' | sort | tail -1)
    [ -n "$latest" ] && [ -s "$latest/result.json" ] || fail "no relisten result; run dex-phone-replug.sh --relisten first"
    local age=$(( $(date +%s) - $(stat -c %Y "$latest/result.json") ))
    (( age <= max_age )) || fail "newest relisten is older than ${max_age} s; run dex-phone-replug.sh --relisten again"
    if [ -f "$consumed" ] && grep -qxF "$latest" "$consumed"; then
        fail "newest relisten was already used by a session; run dex-phone-replug.sh --relisten again"
    fi
    python3 - "$latest/result.json" <<'PY' || fail "newest relisten was not successful"
import json,sys
r=json.load(open(sys.argv[1]))
sys.exit(0 if r.get("bootstrap_observed") is True and r.get("errors")==[] else 1)
PY
    local ts dir out
    ts=$(date +%Y%m%dT%H%M%S%z)
    dir=$fifo_base/dex-live-$ts
    out=$research/kms-session-$ts
    [ ! -e "$dir" ] && [ ! -e "$out" ] || fail "session paths already exist"
    mkdir -m 700 "$dir"
    mkfifo -m 600 "$dir/ts.fifo" "$dir/input.fifo" || { rm -rf "$dir"; fail "cannot create the FIFOs"; }
    echo "$latest" >> "$consumed"
    # The detached runner inherits the lock and holds it until the run ends. It then removes
    # the FIFOs while holding each open read-write (never blocks): a viewer cat still blocked
    # in open() is released and sees EOF, and nothing new can open them. A plain group
    # redirection, unlike exec, cannot abort the runner if a FIFO is already gone.
    setsid nohup bash -c 'bash "$1" --approved-phone-kms-session-live --accept-persistent-state --output "$2" \
        --ts-fifo "$3/ts.fifo" --stop-file "$3/stop" --input-fifo "$3/input.fifo"
        rc=$?
        { rm -rf "$3"; sleep 1; } 2>/dev/null 3<>"$3/ts.fifo" 4<>"$3/input.fifo"
        rm -rf "$3"; echo "SESSION_EXIT=$rc"' _ "$once" "$out" "$dir" \
        > "$out.run.log" 2>&1 < /dev/null &
    echo "FIFO_DIR=$dir"
    echo "OUTPUT=$out"
}

stop() {
    local dir=${1:-} name
    name=${dir#"$fifo_base"/}
    [ "$dir" = "$fifo_base/$name" ] && [[ $name =~ ^dex-live-[0-9]{8}T[0-9]{6}+0000$ ]] \
        || fail "not a session FIFO directory: $dir"
    [ -d "$dir" ] && [ ! -L "$dir" ] || fail "no such session: $dir"
    touch "$dir/stop"
}

case "${1:-}" in
    start) start ;;
    stop) stop "${2:-}" ;;
    *) echo "usage: $0 start | stop FIFO_DIR" >&2; exit 64 ;;
esac
