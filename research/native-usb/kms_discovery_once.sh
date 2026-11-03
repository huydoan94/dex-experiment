#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PYTHONPATH="$PWD/tools/crypto-root/usr/lib/python3/dist-packages:$PWD/tools/usb-root/usr/lib/python3/dist-packages"
exec timeout -k 2 90 python3 research/native-usb/kms_discovery_launch.py "$@"
