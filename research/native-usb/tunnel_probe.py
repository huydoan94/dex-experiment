"""One bounded TCP15000 tunnel probe (step 2). Default mode performs no USB operations.

Approved run: GetVersion, ExchangeConfiguration, open one Operation2 TCP config
for port 15000, Connect, listen passively (no payload is sent), then Disconnect
and close the config. Phone Data/Disconnect requests are acknowledged. Cleanup
is attempted once per step; nothing is retried. No ADB, no HostAttached, no
reset/detach/set_configuration.
"""
import argparse
import json
from pathlib import Path
import secrets
import signal
import struct
import time

from usb_tunnel import Session, TunnelError
from version_query import validate_config

INTERFACE = 3
WRITE_ENDPOINT = 3
READ_ENDPOINT = 133
# One max-size packet per read: PyUSB drops data already received when a larger
# read times out, which would lose a frame ending on a packet boundary.
READ_BYTES = 512
DEX_PORT = 15000
SERVICE_UID = b'dex-linux-lab'.ljust(64, b'\0')
# Daemon-allocated config IDs and connection keys start at 1000; stay below.
CONFIG_ID_RANGE = (1, 999)
HOST_PORT_RANGE = (40000, 49999)
MAX_FRAME_BYTES = 1 << 18
MAX_RECEIVE_BYTES = 1 << 16
# Host requests: version, exchange, open, connect, disconnect, close (+2 spare).
MAX_REQUESTS = 8
MAX_ACKS = 64
MAX_READS = 2000
# Reads kept back for teardown so a busy listen cannot starve it.
CLEANUP_READS = 200
LISTEN_SECONDS = 5
OUTER_TIMEOUT_SECONDS = 60


class Link:
    """PyUSB endpoints as the Session link, with hard request/ack/read counts.

    Requests (kind1) and acks (kind2) have separate budgets so phone traffic
    cannot use up the writes teardown needs. After begin_cleanup() the read
    reserve opens and acks beyond the budget are suppressed (logged, not sent):
    a paused phone read does not matter once the host is tearing down.
    """

    def __init__(self, device, timeout_error, max_requests=MAX_REQUESTS, max_acks=MAX_ACKS,
                 max_reads=MAX_READS, cleanup_reads=CLEANUP_READS,
                 record=lambda direction, data: None):
        self.device = device
        self.timeout_error = timeout_error
        self.requests_left = max_requests
        self.acks_left = max_acks
        self.reads_left = max_reads
        self.cleanup_reads = cleanup_reads
        self.cleanup = False
        self.record = record

    def begin_cleanup(self):
        self.cleanup = True

    def write(self, data, timeout_ms):
        if struct.unpack_from('<I', data, 12)[0] == 2:
            if self.acks_left <= 0:
                if self.cleanup:
                    self.record('ack_suppressed', data)
                    return len(data)
                raise TunnelError('USB ack budget exhausted')
            self.acks_left -= 1
        else:
            if self.requests_left <= 0:
                raise TunnelError('USB request budget exhausted')
            self.requests_left -= 1
        self.record('out', data)
        written = self.device.write(WRITE_ENDPOINT, data, timeout=timeout_ms)
        if written == len(data) and len(data) % READ_BYTES == 0:
            # End a full-packet OUT transfer without adding protocol bytes.
            self.record('out_zlp', b'')
            if self.device.write(WRITE_ENDPOINT, b'', timeout=timeout_ms) != 0:
                raise TunnelError('unexpected zero-length transfer result')
        return written

    def read(self, size, timeout_ms):
        if self.reads_left <= (0 if self.cleanup else self.cleanup_reads):
            raise TunnelError('USB read budget exhausted')
        self.reads_left -= 1
        try:
            data = bytes(self.device.read(READ_ENDPOINT, min(size, READ_BYTES),
                                          timeout=timeout_ms))
        except self.timeout_error:
            return b''
        self.record('in', data)
        return data


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


def _error_text(error):
    return '%s: %s' % (type(error).__name__, error)


def _teardown(session, result):
    """Disconnect every recorded connection, then close the config; one try each."""
    errors = []
    for connection in list(session.connections.values()):
        try:
            emit('tcp_disconnect', host_port=connection.host_port)
            result['disconnect_status'] = session.disconnect(connection)
        except Exception as error:
            result['disconnect_error'] = _error_text(error)
            errors.append(error)
    if session.config_id is not None:
        try:
            emit('config_close', config_id=session.config_id)
            result['close_status'] = session.close_config(SERVICE_UID)
        except Exception as error:
            result['close_error'] = _error_text(error)
            errors.append(error)
    return errors


def tunnel(session, config_id, host_port, listen_s, result, begin_cleanup=lambda: None,
           clock=time.monotonic):
    """Fill result step by step; always tries to undo what it set up."""
    connection = None
    started = None
    failed = True
    try:
        result['daemon_version'] = session.get_version()
        result['exchange'] = session.exchange(0, tcp_send_buffer_bytes=0)
        result['open'] = session.open_config(config_id, SERVICE_UID, DEX_PORT)
        connection = session.connect(host_port)
        result['connection_key'] = connection.key
        emit('tcp_connected', connection_key=connection.key, host_port=host_port)
        started = clock()
        session.wait(listen_s, until=lambda: connection.closed_by_phone)
        failed = False
    except Exception as error:
        # A teardown failure below would otherwise hide the first error.
        result['first_error'] = _error_text(error)
        raise
    finally:
        if started is not None:
            result['listened_seconds'] = round(clock() - started, 3)
        if connection is not None:
            result['closed_by_phone'] = connection.closed_by_phone
            result['received_hex'] = bytes(connection.received).hex()
        session.begin_cleanup()
        begin_cleanup()
        errors = _teardown(session, result)
        if errors and not failed:
            raise errors[0]


def probe(device, util, timeout_error, output, transaction, config_id, host_port, result,
          listen_s=LISTEN_SECONDS, clock=time.monotonic):
    """Caller must already have explicit approval. Never retries a write."""
    claimed = False
    events = (output / 'events.jsonl').open('a')

    def log(event, **fields):
        events.write(json.dumps(dict(event=event, **fields), sort_keys=True) + '\n')
        events.flush()

    try:
        emit('usb_get_active_configuration')
        validate_config(device.get_active_configuration())
        emit('usb_kernel_driver_check', interface=INTERFACE)
        if device.is_kernel_driver_active(INTERFACE):
            raise RuntimeError('interface has kernel driver; refusing detach')
        emit('usb_claim', interface=INTERFACE)
        util.claim_interface(device, INTERFACE)
        claimed = True
        link = Link(device, timeout_error,
                    record=lambda direction, data: log('usb_raw', direction=direction,
                                                       bytes_hex=data.hex()))
        session = Session(link, transaction, MAX_FRAME_BYTES,
                          MAX_RECEIVE_BYTES, clock=clock, log=log)
        tunnel(session, config_id, host_port, listen_s, result, link.begin_cleanup, clock)
    finally:
        try:
            if claimed:
                try:
                    emit('usb_release', interface=INTERFACE)
                finally:
                    util.release_interface(device, INTERFACE)
                emit('usb_release_ok', interface=INTERFACE)
        finally:
            try:
                emit('usb_dispose')
            finally:
                try:
                    util.dispose_resources(device)
                finally:
                    events.close()
            emit('usb_dispose_ok')


class Terminated(Exception):
    """Outer timeout's SIGTERM; not a TimeoutError, which wait() treats as a normal end."""


def _terminated(signum, frame):
    # Turns the SIGTERM into an exception so teardown and release run.
    raise Terminated('terminated by signal %d' % signum)


def run(output, bus, address, usb_core, usb_util, clock=time.monotonic):
    """Approved path after argument checks; returns the exit status."""
    result = {}
    try:
        emit('usb_find', vendor=0x04e8, product=0x6860, bus=bus, address=address)
        devices = list(usb_core.find(find_all=True, idVendor=0x04e8, idProduct=0x6860,
                                     bus=bus, address=address))
        if len(devices) != 1:
            raise RuntimeError('expected exactly one matching phone; refusing alternatives')
        transaction = secrets.randbelow(0xffffffff) + 1
        config_id = CONFIG_ID_RANGE[0] + secrets.randbelow(CONFIG_ID_RANGE[1])
        host_port = HOST_PORT_RANGE[0] + secrets.randbelow(
            HOST_PORT_RANGE[1] - HOST_PORT_RANGE[0] + 1)
        (output / 'plan.json').write_text(json.dumps(dict(
            reference='A54 Android13 + official PC client; unverified on S20+ beyond GetVersion',
            bus=bus, address=address, transaction=transaction, config_id=config_id,
            host_port=host_port, port=DEX_PORT, operation=2, interface=INTERFACE,
            max_requests=MAX_REQUESTS, max_acks=MAX_ACKS, max_reads=MAX_READS,
            read_bytes=READ_BYTES, listen_seconds=LISTEN_SECONDS,
            payload_sent=False, host_attached=False), indent=2) + '\n')
        probe(devices[0], usb_util, usb_core.USBTimeoutError, output,
              transaction, config_id, host_port, result, clock=clock)
    except Exception as error:
        emit('PROBE_FAILED', error=str(error), error_type=type(error).__name__)
        # Partial steps are kept: they are the evidence of how far the phone went.
        (output / 'result.json').write_text(json.dumps(
            dict(success=False, error=str(error), error_type=type(error).__name__,
                 dex_activation_tested=False, **result), indent=2) + '\n')
        return 1
    (output / 'result.json').write_text(json.dumps(
        dict(success=True, dex_activation_tested=False, **result), indent=2) + '\n')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approved-phone-tunnel-probe', action='store_true')
    parser.add_argument('--bus', type=int)
    parser.add_argument('--address', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if not args.approved_phone_tunnel_probe:
        emit('PLAN_ONLY', usb_access=False, max_usb_requests=MAX_REQUESTS,
             max_usb_acks=MAX_ACKS, max_usb_reads=MAX_READS, listen_seconds=LISTEN_SECONDS,
             port=DEX_PORT, outer_timeout_seconds=OUTER_TIMEOUT_SECONDS,
             plan='Validate descriptors; claim interface3; GetVersion; Exchange (zero sizes); '
                  'open Operation2 TCP config port15000; Connect; listen passively, acking phone '
                  'Data; Disconnect; close config; release. No payload sent, no ADB.')
        return 0
    if args.output is None or args.bus is None or args.address is None:
        parser.error('approved run needs --output, --bus and --address')
    if not 1 <= args.bus <= 255 or not 1 <= args.address <= 127:
        parser.error('invalid USB bus/address')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, _terminated)
    # Import/USB discovery is strictly behind the explicit approval guard.
    import usb.core
    import usb.util
    return run(args.output, args.bus, args.address, usb.core, usb.util)


if __name__ == '__main__':
    raise SystemExit(main())
