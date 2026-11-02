#!/bin/bash
# Selection, hash checks and phone runner share one bounded process lifetime (90 s + 15 min cap).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PYTHONPATH="$PWD/tools/crypto-root/usr/lib/python3/dist-packages:$PWD/tools/usb-root/usr/lib/python3/dist-packages"
exec timeout -k 2 990 python3 research/native-usb/udp_uibc_launch.py "$@"
