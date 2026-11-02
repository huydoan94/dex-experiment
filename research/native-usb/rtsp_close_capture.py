"""One receive-only check for the RTSP run's outstanding main close reply."""
import argparse
import hashlib
import json
from pathlib import Path
import signal

import queued_close_probe as queued
from tunnel_probe import _terminated, emit

EXPECTED_TRANSACTION = 801837119
EXPECTED = {'queued_close_probe.py': '2b895e1ecea821adc7c0152d0597e26436eb4443c547cea11944c7fb20cab3aa', 'conn_frames.py': '7ead84c77f09d946885c5c3326810e8c3bfe8cad8340338a338f963b24f560e1', 'tcp_control.py': '5b7b82c364fc620a1f937c8c377a12191388649ff52c4359efb77b8fce0080e1', 'version_query.py': '3a393f2c1e99761510f590a6da4790fe242be5a03b60024f15e9c03d0d4c15b8', 'tunnel_probe.py': '3a55ae78816995aeb3113cc5158f9d598ee1a1cc943a696eb6b5efee3c884c7e'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-rtsp-close-capture", action="store_true")
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_rtsp_close_capture:
        emit("PLAN_ONLY", phone_access=False, bulk_out=False,
             expected_transaction=EXPECTED_TRANSACTION, max_reads=16, outer_seconds=15)
        return 0
    if a.output is None:
        p.error("requires new --output")
    if a.output.exists():
        raise FileExistsError("output already exists")
    root = Path(__file__).resolve().parent
    for name, digest in EXPECTED.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("approved source mismatch: " + name)
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(old_close_confirmed=False, quiet_observed=False,
                  expected_transaction=EXPECTED_TRANSACTION, native_bulk_out=False)
    try:
        import usb.core
        import usb.util
        phones = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860))
        if len(phones) != 1:
            raise RuntimeError("expected exactly one Samsung phone")
        phone = phones[0]
        emit("selected_usb", bus=phone.bus, address=phone.address)
        result["selected_usb"] = dict(bus=phone.bus, address=phone.address)
        queued.capture(phone, usb.util, usb.core.USBTimeoutError, a.output, result,
                       expected_close_transaction=EXPECTED_TRANSACTION, allow_old_data=False)
        result["success"] = True
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output/"result.json").write_text(json.dumps(result, indent=2)+"\n")
        emit("rtsp_close_capture_result", **result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
