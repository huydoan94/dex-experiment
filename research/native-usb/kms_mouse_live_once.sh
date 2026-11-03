#!/bin/bash
# Selection, hash checks and phone runner share one bounded process lifetime (90 s + 30 s media cap).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PYTHONPATH="$PWD/tools/crypto-root/usr/lib/python3/dist-packages:$PWD/tools/usb-root/usr/lib/python3/dist-packages"
exec timeout -k 2 120 python3 research/native-usb/kms_mouse_live_launch.py "$@"
