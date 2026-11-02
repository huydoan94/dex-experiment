"""Pure codecs reconstructed from saved A54 reference; not S20+ live proof.

No I/O. Connect/disconnect endpoint fields describe wire metadata; routing must
be confirmed from configuration/socket setup, not inferred from this field name.
Host policy excludes transaction0 and auto-allocated/reserved config identifiers.
"""
from dataclasses import dataclass
from ipaddress import IPv4Address
import struct

from conn_frames import Frame

_ENDPOINT = struct.Struct('<I16sI')
_CONNECT_REPLY = struct.Struct('<III16sI')
_OPEN_REPLY = struct.Struct('<IIII')
_STATUS = struct.Struct('<I')
_CONFIG_OPEN = struct.Struct('<I64sBBH6I')
_CONFIG_CLOSE = struct.Struct('<64sI')


def _uint(value, maximum, name):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(name + ' outside host policy range')
    return value


def _config_id(value):
    return _uint(value, 65529, 'config_id')


def _port(value):
    if type(value) is not int or not 0 <= value <= 65535:
        raise ValueError('invalid port')
    return value


def _address(value):
    if not isinstance(value, str):
        raise ValueError('IPv4 address must be text')
    return str(IPv4Address(value)).encode('ascii')


def _config_match(actual, config_id):
    # config_id is a single id (equality, range-checked) or a collection to test membership.
    valid = config_id if isinstance(config_id, (set, frozenset, dict)) else {_config_id(config_id)}
    return actual in valid


def _endpoint_request(command, transaction, config_id, address, port):
    _uint(transaction, 0xffffffff, 'transaction')
    body = _ENDPOINT.pack(_config_id(config_id), _address(address), _port(port))
    return Frame(command, 1, transaction, body)


def connect_request(transaction, config_id, address, port):
    # Ref00048d64: total44bytes, cfg20, address24..39, port40.
    return _endpoint_request(3, transaction, config_id, address, port)


def disconnect_request(transaction, config_id, address, connection_key):
    # Ref00048fe4: same layout, command4. Handler 0003fc78 looks up the config
    # (uint16 at20), then the connection by the uint16 at40 via 0001d4e0, which
    # matches the connection KEY, not the host's Connect port; no match -> status1
    # (seen live 2026-11-01T22:10:27Z with the host port). Address is logged only.
    _uint(connection_key, 65535, 'connection_key')
    return _endpoint_request(4, transaction, config_id, address, connection_key)



def _service_uid(value):
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError('service_uid must be exactly64bytes')
    return value


def configuration_request(transaction, config_id, service_uid, port, operation=2):
    # Layout matches official PC builder 1001fc50 (116 bytes, params copied
    # verbatim at 88). PC sends cfg 0 (daemon allocates from 1000 but echoes 0);
    # ref 0001fba8 uses a nonzero cfg as given, so the host chooses it.
    # Daemon dispatches on Protocol at 100; neither handler reads the UID.
    # Operation 2: no phone-side acceptor (operation 1 would create one).
    _uint(transaction, 0xffffffff, 'transaction')
    if operation not in (1, 2):
        raise ValueError('operation must be 1 (listener) or 2 (connect)')
    body = _CONFIG_OPEN.pack(_config_id(config_id), _service_uid(service_uid),
                             1, 1, 28, operation, 2, 6, _uint(port, 65535, 'port'), 0, 0)
    return Frame(20, 1, transaction, body)


def configuration_close_request(transaction, config_id, service_uid):
    # PC builder 10009cf0 (88 bytes); ref 000403fc looks up uint16 at 84,
    # TCP configs first, then UDP.
    _uint(transaction, 0xffffffff, 'transaction')
    return Frame(21, 1, transaction,
                 _CONFIG_CLOSE.pack(_service_uid(service_uid), _config_id(config_id)))


_DATA = struct.Struct('<9I')
_DATA_REPLY = struct.Struct('<III')
_DATA_HEADER_BYTES = 56


def data_request(transaction, config_id, host_port, connection_key, port, payload,
                 max_frame_bytes):
    # Ref builder 00049388: 56-byte header, payload at56; 32 = sender's port,
    # 36 = receiver's (TCP read path 00022ca0). Ref 0003ed98 reads protocol20,
    # cfg24 and the uint16 key36, then 0003ec24 copies the whole message into a
    # UsbBufferSize allocation and 00021c64 writes offset48/len52 unchecked:
    # max_frame_bytes must be the negotiated UsbBufferSize. 28/32/40/44 are
    # logged only; host_port is the port this host gave in its Connect.
    _uint(transaction, 0xffffffff, 'transaction')
    if not isinstance(payload, bytes) or not payload:
        raise ValueError('payload must be non-empty bytes')
    if _DATA_HEADER_BYTES + len(payload) > _uint(max_frame_bytes, 0xffffffff, 'max_frame_bytes'):
        raise ValueError('data frame exceeds negotiated buffer')
    body = _DATA.pack(6, _config_id(config_id), 2, _uint(host_port, 65535, 'host_port'),
                      _uint(connection_key, 65535, 'key'),
                      _uint(port, 65535, 'port'), 0, _DATA_HEADER_BYTES, len(payload))
    return Frame(5, 1, transaction, body + payload)


@dataclass(frozen=True)
class DataMessage:
    transaction: int
    config_id: int
    family: int
    connection_key: int
    host_port: int
    port: int
    value44: int
    payload: bytes


def data_message(frame, config_id):
    # Phone-to-host TCP data, ref 00022ca0 -> 00049388: 32 = connection key,
    # 36 = host's Connect port; payload may be empty.
    if (frame.command, frame.kind) != (5, 1) or frame.transaction is None:
        raise ValueError('not a data request')
    if len(frame.body) < _DATA.size:
        raise ValueError('truncated data header')
    (protocol, actual, family, key, host_port, port, value44, offset,
     length) = _DATA.unpack_from(frame.body)
    if protocol != 6 or not _config_match(actual, config_id):
        raise ValueError('unexpected data protocol or config identifier')
    if offset != _DATA_HEADER_BYTES or length != len(frame.body) - _DATA.size:
        raise ValueError('inconsistent data offset or length')
    if not 1 <= key <= 65535 or host_port > 65535 or port > 65535:
        raise ValueError('invalid data connection key or port')
    return DataMessage(frame.transaction, actual, family, key, host_port, port, value44,
                       frame.body[_DATA.size:])


def data_reply(frame, transaction, frame_bytes):
    # Ref 00049418 via write completion 00021e4c: one 32-byte reply per data
    # request after the socket write; status20 (0 ok, 1 native error, 9 other),
    # echoed request size24, native error28.
    _reply(frame, 5, transaction, _DATA_REPLY.size)
    status, size, error = _DATA_REPLY.unpack(frame.body)
    if size != frame_bytes:
        raise ValueError('data reply size mismatch')
    return status, error


def data_ack(transaction, frame_bytes):
    # Host reply to phone-to-host data, mirroring the phone's own 00049418.
    # Ref 0001deac: the phone pauses reading once unacknowledged bytes exceed a
    # negotiated limit, so every phone data request needs one of these.
    _uint(transaction, 0xffffffff, 'transaction')
    return Frame(5, 2, transaction,
                 _DATA_REPLY.pack(0, _uint(frame_bytes, 0xffffffff, 'frame_bytes'), 0))


@dataclass(frozen=True)
class Disconnect:
    transaction: int
    config_id: int
    address: str
    port: int


def disconnect_message(frame, config_id):
    # Phone-initiated close, ref 000231e0 -> 00048fe4: carries the cfg and the
    # host's own Connect address/port metadata, not the connection key, so the
    # host must keep that metadata unique per connection.
    if (frame.command, frame.kind) != (4, 1) or len(frame.body) != _ENDPOINT.size:
        raise ValueError('not a disconnect request')
    actual, address, port = _ENDPOINT.unpack(frame.body)
    if not _config_match(actual, config_id):
        raise ValueError('config identifier mismatch')
    return Disconnect(frame.transaction, actual, _wire_address(address), _port(port))


def disconnect_ack(transaction):
    # Ref 00049120: 24-byte reply, status20.
    _uint(transaction, 0xffffffff, 'transaction')
    return Frame(4, 2, transaction, _STATUS.pack(0))


EXCHANGE_FIELDS = (
    'keep_alive_timeout_ms', 'usb_buffer_bytes', 'socket_buffer_bytes', 'usb_write_queue',
    'usb_read_queue', 'tcp_send_buffer_bytes', 'tcp_recv_buffer_bytes',
    'udp_send_buffer_bytes', 'udp_recv_buffer_bytes', 'usb_tcp_sending_high_bytes',
    'usb_tcp_sending_low_bytes', 'usb_udp_sending_high_bytes', 'usb_udp_sending_low_bytes')
_EXCHANGE = struct.Struct('<H13I')
_VERSION_REPLY = struct.Struct('<III64s')


def version_request(transaction):
    # PC 10012ad0 / ref 0003f83c: header-only command2.
    _uint(transaction, 0xffffffff, 'transaction')
    return Frame(2, 1, transaction, b'')


def version_reply(frame, transaction):
    # Ref 00048d14: 96 bytes; PC 10012ad0 accepts only protocol 2.0.
    _reply(frame, 2, transaction, _VERSION_REPLY.size)
    status, major, minor, text = _VERSION_REPLY.unpack(frame.body)
    return status, major, minor, text.split(b'\0', 1)[0].decode('ascii', 'replace')


def exchange_request(transaction, os_type, **values):
    # Ref handler 00040700: packed, unaligned u16 + 13 u32 (74 bytes). Helper
    # 00042614 stores os_type, takes UsbBufferSize from the daemon default and
    # derives watermarks from the two send-buffer fields (0 = keep current).
    _uint(transaction, 0xffffffff, 'transaction')
    if type(os_type) is not int or not 0 <= os_type <= 0xffff:
        raise ValueError('invalid os_type')
    if set(values) - set(EXCHANGE_FIELDS):
        raise ValueError('unknown exchange field')
    fields = [values.get(name, 0) for name in EXCHANGE_FIELDS]
    for value in fields:
        if type(value) is not int or not 0 <= value <= 0x7fffffff:
            raise ValueError('invalid exchange value')
    return Frame(0x16, 1, transaction, _EXCHANGE.pack(os_type, *fields))


def exchange_reply(frame, transaction):
    # Ref builder 000496d0: status20, then the same packed fields (78 bytes).
    _reply(frame, 0x16, transaction, _STATUS.size + _EXCHANGE.size)
    status, = _STATUS.unpack_from(frame.body)
    os_type, *fields = _EXCHANGE.unpack_from(frame.body, _STATUS.size)
    return status, os_type, dict(zip(EXCHANGE_FIELDS, fields))


def disconnect_reply(frame, transaction):
    # Ref 00049120: 24 bytes, command4/status20.
    _reply(frame, 4, transaction, _STATUS.size)
    return _STATUS.unpack(frame.body)[0]


def _reply(frame, command, transaction, body_size):
    _uint(transaction, 0xffffffff, 'transaction')
    if (frame.command, frame.kind, frame.transaction) != (command, 2, transaction):
        raise ValueError('unexpected response identity')
    if len(frame.body) != body_size:
        raise ValueError('unexpected response length')


def _wire_address(raw):
    head, separator, padding = raw.partition(b'\0')
    if not separator or any(padding):
        raise ValueError('address is not a zero-padded16-byte string')
    try:
        return str(IPv4Address(head.decode('ascii')))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError('invalid response IPv4 address') from exc


@dataclass(frozen=True)
class ConnectReply:
    status: int
    network_error: int
    config_id: int
    address: str | None
    port: int


def connect_reply(frame, transaction, config_id):
    # Ref00048ea0 +00041768: total52bytes; network error at24, cfg at28.
    # Ref 0003f8cc: address is the daemon-global IP and port48 is the
    # daemon-assigned connection key (0001ce98) used at data offset36.
    _reply(frame, 3, transaction, _CONNECT_REPLY.size)
    expected = _config_id(config_id)
    status, network_error, actual, address, port = _CONNECT_REPLY.unpack(frame.body)
    if actual != expected:
        raise ValueError('config identifier mismatch')
    _port(port)
    # Failed native replies may legitimately have an empty endpoint.
    decoded = _wire_address(address) if status == 0 else None
    return ConnectReply(status, network_error, actual, decoded, port)


def open_reply(frame, transaction, config_id):
    # Ref000494d0: total36bytes, status20,cfg24,ports28/32.
    _reply(frame, 20, transaction, _OPEN_REPLY.size)
    status, actual, port, client_port = _OPEN_REPLY.unpack(frame.body)
    if actual != _config_id(config_id):
        raise ValueError('config identifier mismatch')
    return {'status': status, 'config_id': actual,
            'port': _port(port), 'client_port': _port(client_port)}


def close_reply(frame, transaction):
    # Ref00049604: total24bytes, command21/status20.
    _reply(frame, 21, transaction, _STATUS.size)
    return _STATUS.unpack(frame.body)[0]


@dataclass(frozen=True)
class InboundConnect:
    transaction: int
    config_id: int
    connection_key: int


def inbound_connect_message(frame, listener_configs):
    """Observed S20+ accept announcement; parse only, no guessed acknowledgment.

    Live 2026-11-02 11:41: total44, kind1/command3, config at20,
    sixteen ZERO metadata bytes at24..39, accepted key at40. Only the observed
    zero-metadata variant is supported; a nonzero address remains unmapped.
    This does not define host-port assignment, replies, or first Data routing.
    """
    if (frame.command, frame.kind) != (3, 1) or len(frame.body) != _ENDPOINT.size:
        raise ValueError("not an inbound Connect announcement")
    _uint(frame.transaction, 0xffffffff, "transaction")
    actual, metadata, key = _ENDPOINT.unpack(frame.body)
    if not _config_match(actual, listener_configs):
        raise ValueError("unknown listener config")
    if metadata != bytes(16):
        raise ValueError("unmapped inbound endpoint metadata")
    _uint(key, 65529, "connection_key")
    return InboundConnect(frame.transaction, actual, key)


def inbound_connect_ack(transaction, config_id, host_port):
    """52B Connect success reply; saved callback22924 reads addr32/host-id48.

    The accepted phone key remains separate from the host-chosen identifier.
    Host metadata is loopback by policy; no accepted remote-IP claim is made.
    """
    _uint(transaction, 0xffffffff, "transaction")
    return Frame(3, 2, transaction, _CONNECT_REPLY.pack(
        0, 0, _config_id(config_id), _address("127.0.0.1"),
        _uint(host_port, 65535, "host_port")))


def inbound_connect_reject(transaction, config_id):
    """52B failure response: callback22924 maps status1 to -1 and closes socket."""
    _uint(transaction, 0xffffffff, "transaction")
    return Frame(3, 2, transaction, _CONNECT_REPLY.pack(
        1, 0, _config_id(config_id), _address("127.0.0.1"), 0))
