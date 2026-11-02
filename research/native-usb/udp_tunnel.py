"""Native UDP (protocol17) codecs and a Session subclass; no I/O of its own.

Layouts from the saved A54 reference (UDP_TRANSPORT_MAP.md), not S20+ proof.
Kept separate from tcp_control/usb_tunnel so their source-pinned launchers stay
unchanged. A UDP config carries whole datagrams: send_datagram() sends one,
phone datagrams are acknowledged and recorded in datagrams. UDP sockets have
no host-visible keys and no mapped Disconnect; config close is the teardown.
"""
from dataclasses import dataclass

from conn_frames import Frame
import tcp_control as tcp
from usb_tunnel import Config, Session, TunnelError, _guarded

UDP = 17


def configuration_request(transaction, config_id, service_uid, port, operation):
    # Same 116-byte open as tcp_control, protocol100 = 17 (ref 000421e8).
    # Params at88 are copied to config+0x10: op1 binds port104 and replies the
    # bound port; op2 binds nothing until host Data names a socket. Port104
    # is still compared by the global lookup 0001ea1c and echoed at wire40,
    # so op2 sends 0 to never match a socket key.
    tcp._uint(transaction, 0xffffffff, 'transaction')
    if operation == 1:
        tcp._uint(port, 65535, 'port')
    elif operation != 2 or type(port) is not int or port != 0:
        raise ValueError('UDP open is op1 with a port or op2 with port 0')
    body = tcp._CONFIG_OPEN.pack(tcp._config_id(config_id), tcp._service_uid(service_uid),
                                 1, 1, 28, operation, 2, UDP, port, 0, 0)
    return Frame(20, 1, transaction, body)


def data_protocol(frame):
    # Ref 0003ec24 dispatches every Data request on protocol at 20.
    if len(frame.body) < tcp._STATUS.size:
        raise ValueError('truncated data header')
    return tcp._STATUS.unpack_from(frame.body)[0]


def datagram_request(transaction, config_id, socket_port, peer_port, payload,
                     max_frame_bytes):
    # Ref 0003ef84: cfg24; 36 names the sending socket by its port (an op1
    # config's bound port, else a socket the daemon creates in this config on
    # first use); 00023c04 sends ONE datagram to the daemon-global address :
    # port32, payload offset48/len52.
    tcp._uint(transaction, 0xffffffff, 'transaction')
    if not isinstance(payload, bytes) or not payload:
        raise ValueError('payload must be non-empty bytes')
    if (tcp._DATA_HEADER_BYTES + len(payload)
            > tcp._uint(max_frame_bytes, 0xffffffff, 'max_frame_bytes')):
        raise ValueError('datagram exceeds negotiated buffer')
    body = tcp._DATA.pack(UDP, tcp._config_id(config_id), 2,
                          tcp._uint(peer_port, 65535, 'peer_port'),
                          tcp._uint(socket_port, 65535, 'socket_port'), 0, 0,
                          tcp._DATA_HEADER_BYTES, len(payload))
    return Frame(5, 1, transaction, body + payload)


@dataclass(frozen=True)
class Datagram:
    transaction: int
    config_id: int
    socket_port: int
    source_port: int
    config_port: int
    bound_port: int
    payload: bytes


def datagram_message(frame, config_ids):
    # Phone-to-host, receive completion 0001deac -> 00049388: one datagram per
    # message; 32 = receiving socket's port, 36 = datagram source port,
    # 40 = config port104, 44 = op1 bound port. Source address is not sent and
    # zero-length datagrams are never forwarded by the reference.
    if (frame.command, frame.kind) != (5, 1) or frame.transaction is None:
        raise ValueError('not a data request')
    if len(frame.body) < tcp._DATA.size:
        raise ValueError('truncated data header')
    (protocol, actual, _, socket_port, source_port, config_port, bound_port, offset,
     length) = tcp._DATA.unpack_from(frame.body)
    if protocol != UDP or actual not in config_ids:
        raise ValueError('unexpected datagram protocol or config identifier')
    if (offset != tcp._DATA_HEADER_BYTES or not length
            or length != len(frame.body) - tcp._DATA.size):
        raise ValueError('inconsistent datagram offset or length')
    if not (1 <= socket_port <= 65535 and 1 <= source_port <= 65535
            and config_port <= 65535 and bound_port <= 65535):
        raise ValueError('invalid datagram port')
    return Datagram(frame.transaction, actual, socket_port, source_port, config_port,
                    bound_port, frame.body[tcp._DATA.size:])


class UdpSession(Session):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_configs = {}       # config_id -> (operation, port104)
        self.retired_udp = set()
        self.datagrams = []
        # Arrived during cleanup or for a closed config: acked, kept apart.
        self.dropped_datagrams = []

    def _phone_request(self, frame):
        if frame.command == 5 and self.configs and data_protocol(frame) == UDP:
            self._phone_datagram(frame)
        elif (frame.command == 3 and len(frame.body) >= 4 and
              tcp._STATUS.unpack_from(frame.body)[0] in self.udp_configs.keys() | self.retired_udp):
            raise TunnelError('TCP accept on a UDP config')
        else:
            super()._phone_request(frame)

    def _phone_datagram(self, frame):
        message = datagram_message(frame, self.udp_configs.keys() | self.retired_udp)
        if self.cleanup or message.config_id in self.retired_udp:
            self.log('datagram_dropped', config_id=message.config_id,
                     size_bytes=len(message.payload))
            self.dropped_datagrams.append(message)
        else:
            self.received_bytes += len(message.payload)
            if self.received_bytes > self.max_receive_bytes:
                raise TunnelError('receive limit exceeded')
            self.datagrams.append(message)
        # Ref 0001deac pauses the socket's receive once unacknowledged bytes
        # pass the limit; acknowledge the exact message size as for TCP.
        self._send(tcp.data_ack(frame.transaction, 20 + len(frame.body)))

    @_guarded
    def open_udp(self, config_id, service_uid, port, operation=2, timeout_s=2):
        if self.usb_buffer_bytes is None:
            raise TunnelError('open requires one prior exchange')
        if config_id in self.configs or config_id in self.retired_udp:
            raise TunnelError('config already used')
        if operation == 1 and any(port == p for _, p in self.udp_configs.values()):
            raise TunnelError('UDP port already bound in this session')
        transaction = self._next_transaction()
        frame = configuration_request(transaction, config_id, service_uid, port, operation)
        # Recorded before the reply, as in Session.open_config. Operation 2 is
        # stored so Session's TCP listener logic never treats it as one.
        self.configs[config_id] = Config(config_id, port, 2)
        self.udp_configs[config_id] = (operation, port)
        reply = tcp.open_reply(self._request(frame, timeout_s), transaction, config_id)
        if reply['status'] != 0:
            del self.configs[config_id]
            del self.udp_configs[config_id]
            raise TunnelError('open status %d' % reply['status'])
        return reply

    def open_config(self, config_id, *args, **kwargs):
        if config_id in self.udp_configs or config_id in self.retired_udp:
            raise TunnelError('config already used')
        return super().open_config(config_id, *args, **kwargs)

    def connect(self, host_port, config_id=None, timeout_s=5):
        if (self.config_id if config_id is None else config_id) in self.udp_configs:
            raise TunnelError('connect on a UDP config')
        return super().connect(host_port, config_id=config_id, timeout_s=timeout_s)

    @_guarded
    def send_datagram(self, config_id, socket_port, peer_port, payload, timeout_s=5):
        self._require_config()
        if config_id not in self.udp_configs:
            raise TunnelError('datagram on unknown UDP config')
        operation, port = self.udp_configs[config_id]
        # Any other key would make the daemon bind a new phone port (0001d8cc).
        if operation == 1 and socket_port != port:
            raise TunnelError('op1 datagram must use the bound socket port')
        if any(o == 1 and p == socket_port for o, p in self.udp_configs.values()) and (
                operation, port) != (1, socket_port):
            raise TunnelError('socket key would select another config socket')
        transaction = self._next_transaction()
        frame = datagram_request(transaction, config_id, socket_port, peer_port,
                                 bytes(payload), self.usb_buffer_bytes)
        status, error = tcp.data_reply(self._request(frame, timeout_s), transaction,
                                       20 + len(frame.body))
        if status != 0:
            raise TunnelError('datagram status %d native error %d' % (status, error))

    def close_config(self, service_uid, config_id=None, timeout_s=2):
        config_id = self.config_id if config_id is None else config_id
        status = super().close_config(service_uid, config_id=config_id, timeout_s=timeout_s)
        if config_id in self.udp_configs:
            del self.udp_configs[config_id]
            self.retired_udp.add(config_id)
        return status

