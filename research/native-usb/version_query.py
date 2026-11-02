"""One candidate USB version query. Default mode performs no USB operations."""
import argparse
import json
from pathlib import Path
import secrets
import struct
import time

HEADER = struct.Struct("<4sIIII")
LIMIT_BYTES = 4096


def request(transaction):
    if not 1 <= transaction <= 0xffffffff:
        raise ValueError("transaction must be a nonzero uint32")
    return HEADER.pack(b"CONN", 2, 20, 1, transaction)


def version_response(data, transaction):
    """Return None for incomplete data; reject malformed/unrelated responses."""
    if len(data) > LIMIT_BYTES:
        raise ValueError("response exceeds byte limit")
    if len(data) < HEADER.size:
        return None
    magic, command, size, kind, correlation = HEADER.unpack_from(data)
    if (magic, command, size, kind, correlation) != (b"CONN", 2, 96, 2, transaction):
        raise ValueError("unexpected version-response header")
    if len(data) < size:
        return None
    if len(data) != size:
        raise ValueError("unexpected trailing USB data")
    status, major, minor = struct.unpack_from("<III", data, 20)
    if status != 0:
        raise ValueError("daemon rejected request: status " + str(status))
    return dict(major=major, minor=minor,
                description=data[32:96].split(b"\0", 1)[0].decode("utf-8", errors="replace"))


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


def validate_config(config):
    if config.bConfigurationValue != 1:
        raise ValueError("active USB configuration changed")
    interfaces = [i for i in config if i.bInterfaceNumber == 3]
    if len(interfaces) != 1:
        raise ValueError("unexpected interface count/alternate settings")
    interface = interfaces[0]
    if (interface.bAlternateSetting, interface.bInterfaceClass,
        interface.bInterfaceSubClass, interface.bInterfaceProtocol) != (0, 255, 64, 2):
        raise ValueError("conn_gadget interface signature changed")
    endpoints = sorted((e.bEndpointAddress, e.bmAttributes, e.wMaxPacketSize)
                       for e in interface)
    if endpoints != [(3, 2, 512), (133, 2, 512)]:
        raise ValueError("conn_gadget endpoints changed")


def query(device, util, output, transaction, clock=time.monotonic):
    """Caller must already have explicit approval. Never retries a write."""
    claimed = False
    deadline = clock() + 8
    data = b""
    result = None
    try:
        emit("usb_get_active_configuration")
        config = device.get_active_configuration()
        validate_config(config)
        emit("usb_configuration_valid", configuration=1, interface=3)
        emit("usb_kernel_driver_check", interface=3)
        if device.is_kernel_driver_active(3):
            raise RuntimeError("interface has kernel driver; refusing detach")
        emit("usb_claim", interface=3)
        util.claim_interface(device, 3)
        claimed = True
        payload = request(transaction)
        (output / "request.bin").write_bytes(payload)
        emit("usb_bulk_write", endpoint=3, timeout_ms=1000, bytes_hex=payload.hex())
        written = device.write(3, payload, timeout=1000)
        emit("usb_bulk_write_result", size_bytes=written)
        if written != len(payload):
            raise RuntimeError("partial write; no retry permitted")
        for _ in range(8):
            remaining_ms = int((deadline - clock()) * 1000)
            if remaining_ms <= 0:
                raise TimeoutError("version-query deadline expired")
            timeout_ms = min(1000, remaining_ms)
            emit("usb_bulk_read", endpoint=133, limit_bytes=512, timeout_ms=timeout_ms)
            chunk = bytes(device.read(133, 512, timeout=timeout_ms))
            emit("usb_bulk_read_result", bytes_hex=chunk.hex(), size_bytes=len(chunk))
            data += chunk
            (output / "response.bin").write_bytes(data)
            result = version_response(data, transaction)
            if result is not None:
                emit("version_response", **result)
                break
        if result is None:
            raise TimeoutError("no complete version response within read limit")
        return result
    finally:
        try:
            if claimed:
                try:
                    emit("usb_release", interface=3)
                finally:
                    util.release_interface(device, 3)
                emit("usb_release_ok", interface=3)
        finally:
            try:
                emit("usb_dispose")
            finally:
                util.dispose_resources(device)
            emit("usb_dispose_ok")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-phone-version-query", action="store_true")
    parser.add_argument("--bus", type=int, default=3)
    parser.add_argument("--address", type=int, default=2)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.approved_phone_version_query:
        emit("PLAN_ONLY", usb_access=False,
             plan="Read USB descriptors/configuration; claim interface3; one20-byte version query; bounded reply read; release. No ADB.")
        return 0
    if args.output is None or not 1 <= args.bus <= 255 or not 1 <= args.address <= 127:
        parser.error("approved run needs --output and valid bus/address")
    args.output.mkdir(parents=True, exist_ok=False)
    # Import/USB discovery is strictly behind the explicit approval guard.
    import usb.core
    import usb.util
    emit("usb_find", vendor=1256, product=26720, bus=args.bus, address=args.address)
    devices = list(usb.core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                bus=args.bus, address=args.address))
    if len(devices) != 1:
        raise RuntimeError("expected exactly one matching phone; refusing alternatives")
    transaction = secrets.randbelow(0xffffffff) + 1
    (args.output / "plan.json").write_text(json.dumps(dict(
        reference="A54 Android13; unverified on S20+",
        bus=args.bus, address=args.address, transaction=transaction,
        interface=3, write_endpoint=3, read_endpoint=133,
        max_writes=1, max_reads=8, max_read_bytes=4096), indent=2) + "\n")
    try:
        result = query(devices[0], usb.util, args.output, transaction)
    except Exception as error:
        emit("QUERY_FAILED", error=str(error), error_type=type(error).__name__)
        (args.output / "result.json").write_text(json.dumps(
            dict(success=False, error=str(error)), indent=2) + "\n")
        return 1
    (args.output / "result.json").write_text(json.dumps(
        dict(success=True, version=result, dex_activation_tested=False), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
