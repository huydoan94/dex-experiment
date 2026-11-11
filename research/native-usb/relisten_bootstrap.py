"""app_bootstrap's one notification for an EXISTING, idle main-server manager.

Used when MainServer.D() lost its restart race (MAIN_LISTENER.md): the app-start
notification reaches DOPService.A(1) -> C(true) -> MainServer.D(), reopening TCP15000.
Every app_bootstrap check, bound and cleanup is reused unchanged; only the
"no manager" precondition is replaced by "manager idle, nothing else running"."""
import re
import sys

import app_bootstrap as b

EXISTING = "main-server manager exists; refusing notification"
KMS_IDLE = re.compile(r"mKMSService=(null|com\.sec\.android\.app\.dexonpc\.kms\.source\.KMSService@[0-9a-f]{1,8})")
_ORIGINAL_PREFLIGHT = b.preflight  # main() replaces b.preflight; never call through it.


def _state_lines(service, name):
    sections = re.findall(
        r"^[ \t]*Current " + re.escape(name) +
        r" state:([^\n]*)([\s\S]*?)(?=^[ \t]*Current [^\n]+ state:|\Z)",
        service, re.MULTILINE)
    if len(sections) != 1:
        raise ValueError("missing/duplicate " + name + " manager state")
    return [line.strip() for line in "\n".join(sections[0]).splitlines() if line.strip()]


def preflight_existing(service, desktop):
    try:
        return _ORIGINAL_PREFLIGHT(service, desktop)  # Fresh service: original path.
    except ValueError as error:
        if str(error) != EXISTING:
            raise
    # app_bootstrap.preflight checked desktop, PID and every baseline field first.
    pid = b.service_pid(service)
    if b.field(service, "mMainServer.isConnected") != "false":
        raise ValueError("main server connected; refusing notification")
    if b.field(service, "Current o state", equals=r":\s*") != "no instance":
        raise ValueError("Wimp/PSS helper exists; refusing notification: Current o state")
    # e2.n is FileReceiveManager, constructed by KMS and retained after teardown.
    # Accept only absent or idle (status 0); after a finished PC-to-phone copy the
    # idle manager keeps the last file's path, so mFinalFileURI may hold any value.
    lines = _state_lines(service, "n")
    if lines != ["no instance"] and not (len(lines) == 2 and lines[0] == "mReceiveStatus=0"
                                         and lines[1].startswith("mFinalFileURI=")):
        raise ValueError("file receive manager active or unknown; refusing notification")
    # e2.s is a persistent KMS manager; its existence alone is not an active service.
    # Accept only an absent manager or the exact inactive dump shape, never unknown fields.
    # Once file transfer is offered the phone keeps its KMSService object between
    # sessions; with the connection state 0 (checked below) that is still idle.
    lines = _state_lines(service, "s")
    if lines != ["no instance"]:
        if (len(lines) != 2 or lines[1] != "mKMSService.pinchOn=false"
                or not KMS_IDLE.fullmatch(lines[0])):
            raise ValueError("KMS service active or unknown; refusing notification")
        if b.field(service, "mKMSServiceState") != "0":
            raise ValueError("KMS connection active; refusing notification")
    if not re.search(r"^\s*Current g state:\s*$", service, re.MULTILINE):
        raise ValueError("unexpected main-server manager state")
    return pid


def main(argv=None):
    b.preflight = preflight_existing
    return b.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
