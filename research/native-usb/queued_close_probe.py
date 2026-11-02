"""Capture only known pending replies from the failed batch; no bulk OUT."""
import argparse
import json
import math
from pathlib import Path
import signal
import struct
import time

from conn_frames import Decoder
import tcp_control as tcp
from tunnel_probe import _terminated, emit
from version_query import validate_config

OLD_CLOSE_TRANSACTION = 2655014204
OLD_CONFIG = 193
OLD_KEY = 1002
OLD_HOST_PORT = 48989
MAX_READS = 16
MAX_OLD_DATA = 4


def capture(device, util, timeout_error, output, result, clock=time.monotonic,
            expected_close_transaction=OLD_CLOSE_TRANSACTION, allow_old_data=True):
    claimed = False
    with (output / "events.jsonl").open("x") as events:
        def log(event, **fields):
            events.write(json.dumps(dict(event=event, **fields), sort_keys=True) + "\n")
            events.flush()
            emit(event, **fields)
        try:
            log("usb_get_active_configuration")
            validate_config(device.get_active_configuration())
            log("usb_kernel_driver_check", interface=3)
            if device.is_kernel_driver_active(3):
                raise RuntimeError("kernel driver active; refusing detach")
            log("usb_claim", interface=3)
            util.claim_interface(device, 3)
            claimed = True
            # Direct IN reads distinguish a successful ZLP from USB timeout.
            decoder = Decoder(4095)
            deadline = clock() + 2
            quiet_deadline = None
            close_seen = False
            data_count = 0
            seen_data = set()
            for ordinal in range(1, MAX_READS + 1):
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                wait = min(.5, remaining)
                if quiet_deadline is not None:
                    wait = min(wait, max(.001, quiet_deadline - clock()))
                timeout_ms = max(1, math.ceil(wait * 1000))
                log("usb_in_read", ordinal=ordinal, timeout_ms=timeout_ms)
                try:
                    chunk = bytes(device.read(133, 512, timeout=timeout_ms))
                except timeout_error:
                    now = clock()
                    log("usb_in_timeout", ordinal=ordinal)
                    if (quiet_deadline is not None and now >= quiet_deadline
                            and now <= deadline):
                        decoder.finish()
                        result["quiet_observed"] = True
                        return
                    continue
                log("usb_raw", direction="in", bytes_hex=chunk.hex())
                # A successful empty USB packet is activity, not proof of quiet.
                packet_time = clock()
                for frame in decoder.feed(chunk):
                    if frame.kind == 2 and frame.command == 21:
                        if close_seen:
                            raise ValueError("duplicate old close reply")
                        status = tcp.close_reply(frame, expected_close_transaction)
                        result["old_close_status"] = status
                        if status != 0:
                            raise ValueError("old close status was not zero")
                        close_seen = True
                        result["old_close_confirmed"] = True
                        log("old_close_confirmed", transaction=frame.transaction, status=status)
                    elif allow_old_data and frame.kind == 1 and frame.command == 5:
                        message = tcp.data_message(frame, OLD_CONFIG)
                        if (message.connection_key != OLD_KEY or message.host_port != OLD_HOST_PORT
                                or struct.unpack_from("<I", frame.body, 20)[0] != 15000):
                            raise ValueError("data is not from the old selected connection")
                        if frame.transaction in seen_data:
                            raise ValueError("duplicate old data transaction")
                        seen_data.add(frame.transaction)
                        data_count += 1
                        if data_count > MAX_OLD_DATA:
                            raise ValueError("old data capture limit")
                        result["old_data_frames"] = data_count
                        log("old_encrypted_data_captured", size_bytes=len(message.payload),
                            acknowledged=False)
                    else:
                        raise ValueError("unexpected queued native frame")
                if close_seen:
                    quiet_deadline = packet_time + .2
            raise TimeoutError("old close reply/quiet window not established within capture budget")
        finally:
            try:
                if claimed:
                    try:
                        log("usb_release", interface=3)
                    finally:
                        util.release_interface(device, 3)
                    result["usb_released"] = True
            finally:
                try:
                    log("usb_dispose")
                finally:
                    util.dispose_resources(device)
                result["usb_disposed"] = True


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-phone-old-close-capture", action="store_true")
    p.add_argument("--bus", type=int)
    p.add_argument("--address", type=int)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    if not a.approved_phone_old_close_capture:
        emit("PLAN_ONLY", phone_access=False, max_native_in_reads=MAX_READS,
             native_bulk_out=False, max_old_data=MAX_OLD_DATA,
             expected_close_transaction=OLD_CLOSE_TRANSACTION, outer_seconds=15)
        return 0
    if a.output is None or a.bus is None or a.address is None:
        p.error("approved capture needs --bus, --address, --output")
    if not 1 <= a.bus <= 255 or not 1 <= a.address <= 127:
        p.error("invalid USB target")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    result = dict(old_close_confirmed=False, quiet_observed=False, old_data_frames=0)
    try:
        import usb.core
        import usb.util
        emit("usb_find", vendor=0x04e8, product=0x6860, bus=a.bus, address=a.address)
        devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=a.bus, address=a.address))
        if len(devices) != 1:
            raise RuntimeError("expected exactly one selected phone")
        capture(devices[0], usb.util, usb.core.USBTimeoutError, a.output, result)
        result["success"] = True
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__, error=str(error))
    finally:
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("old_close_capture_result", **result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

