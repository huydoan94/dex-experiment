#!/bin/bash
# Phone black-screen cover (app.blackscreen). Every subcommand except "plan" is a phone
# action and needs an explicit grant. Each runs exactly the ADB calls listed, with stdin closed.
#   install    adb install <pinned APK>; appops set SYSTEM_ALERT_WINDOW allow     (2 calls)
#   start      am start-foreground-service; am start --display 0 BlackActivity     (2 calls)
#   stop       am force-stop (removes the overlay and the immersive activity)      (1 call)
#   status     dumpsys window windows, filtered to DexBlackScreen                  (1 call)
#   running    pidof; exit 0 only if the app runs (dexd, standing approval)        (1 call)
#   uninstall  pm uninstall                                                        (1 call)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
apk=$here/blackscreen.apk
pinned=7b99d724d6c046d392889d595f92cf00cf2365db0f89e258c27ea6d31fe68621
pkg=app.blackscreen
# DEX_PHONE_SERIAL comes from dexd's private site settings; without it adb uses the
# single attached phone (dexd only runs with exactly one).
serial=${DEX_PHONE_SERIAL:-}
adb=(/usr/bin/adb -H 127.0.0.1 -P 5037 ${serial:+-s "$serial"})
call() { echo "+ adb $*"; timeout -k 2 30 "${adb[@]}" "$@" < /dev/null; }
case "${1:-plan}" in
    install)
        [ "$(sha256sum "$apk" | cut -d' ' -f1)" = "$pinned" ] || { echo "APK hash mismatch" >&2; exit 2; }
        call install -r "$apk"
        call shell appops set "$pkg" SYSTEM_ALERT_WINDOW allow ;;
    start)
        call shell am start-foreground-service -n "$pkg/.BlackScreenService"
        call shell am start --display 0 -n "$pkg/.BlackActivity" ;;
    stop) call shell am force-stop "$pkg" ;;
    running) call shell pidof "$pkg" ;;
    status) call shell dumpsys window windows | grep -E 'DexBlackScreen|BlackActivity|mCurrentFocus|mFocusedApp|mTopFocusedDisplayId' | head -12 ;;
    uninstall) call uninstall "$pkg" ;;
    plan) sed -n '2,10p' "$0" ;;
    *) echo "usage: $0 plan|install|start|stop|status|running|uninstall" >&2; exit 64 ;;
esac
