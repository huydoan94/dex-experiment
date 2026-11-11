#!/bin/bash
# User invokes as dex after a manually coordinated USB reconnect.
# Same as reconnect_bootstrap.sh, but runs relisten_bootstrap.py (existing idle
# manager allowed) inside ConnDaemonInit's 60 s indication window (MAIN_LISTENER.md).
set -euo pipefail
cd /home/dex/dex-experiment
if [ "$#" -ne 3 ] || [[ ! $1 =~ ^[0-9]{1,3}$ || ! $2 =~ ^[0-9]{1,3}$ || ! $3 =~ ^[0-9]{10}$ ]]; then
    echo 'Usage: reconnect_bootstrap.sh BUS ADDRESS STARTED_EPOCH' >&2
    exit 64
fi
if [ "$(id -u)" -ne 1000 ]; then
    echo 'STOP: must run as dex UID1000.' >&2
    exit 1
fi
dex_bus=$1
dex_address=$2
dex_started_epoch=$3
dex_now_epoch=$(date +%s)
dex_age_seconds=$((dex_now_epoch - 10#$dex_started_epoch))
if (( dex_age_seconds < 0 || dex_age_seconds > 45 )); then
    echo "STOP: reconnect marker age $dex_age_seconds seconds exceeds the allowed window." >&2
    exit 1
fi
printf '%s\n' 'ac9a2b515d899a9de9ed2bd405b70374d9d0cd7068e3f55443573fee85d72e7a  research/native-usb/app_bootstrap.py' \
    'cd046e4f554cbca5e46682e3a3c7b2d00dddf08ad0451539d924607f24aab254  research/native-usb/relisten_bootstrap.py' | sha256sum -c -
dex_marker=research/native-usb/reconnect-$dex_started_epoch.used
if ! (set -o noclobber; printf '%s\n' "$dex_now_epoch" > "$dex_marker") 2>/dev/null; then
    echo 'STOP: this reconnect marker has already been consumed.' >&2
    exit 1
fi
dex_stamp=$(date -u +%Y%m%dT%H%M%SZ)-$
dex_output=research/native-usb/relisten-$dex_stamp
dex_log=research/native-usb/reconnect-launch-$dex_stamp.log
set -o noclobber
exec 3>"$dex_log"
set +o noclobber
set +e
(
    set -euxo pipefail
    date -u
    printf 'RECONNECT_LAUNCH bus=%s address=%s marker_age_seconds=%s\n' "$dex_bus" "$dex_address" "$dex_age_seconds"
    PYTHONPATH="$PWD/tools/usb-root/usr/lib/python3/dist-packages" timeout -k 2 90 python3 -u research/native-usb/relisten_bootstrap.py --phone-bootstrap-approved --retain-started-service --bus "$dex_bus" --address "$dex_address" --output "$dex_output"
) 2>&1 | tee -a /dev/fd/3
dex_pipe_status=("${PIPESTATUS[@]}")
dex_rc=${dex_pipe_status[0]}
if (( dex_rc == 0 && dex_pipe_status[1] != 0 )); then
    dex_rc=${dex_pipe_status[1]}
fi
printf 'RECONNECT_FINISHED exit=%s output=%s transcript=%s\n' "$dex_rc" "$dex_output" "$dex_log" | tee -a /dev/fd/3
dex_summary_rc=$?
if (( dex_rc == 0 && dex_summary_rc != 0 )); then
    dex_rc=$dex_summary_rc
fi
exec 3>&-
exit "$dex_rc"
