"""Host side of the conn_gadget TCP tunnel (step 2): session logic only.

The caller injects a link with write(data, timeout_ms) -> bytes written and
read(size, timeout_ms) -> bytes (b'' on timeout). No USB import, no retries.
One host request is outstanding at a time. Decoded frames are queued and
handled in arrival order; a request stops at its matching response, so frames
behind it wait until the host has recorded the result. Phone Data and
Disconnect requests are answered; opt-in inbound Connect handling acknowledges
observed listener accepts. Other phone requests/notifications stop the session. Session failures surface as TunnelError (link exceptions
such as USB errors propagate unchanged); the caller then tears down every entry
left in connections and an open config_id, and stops. A config or connection
whose reply failed after the request was sent stays recorded, so teardown
covers state the phone may have created.
Layouts and reference addresses: tcp_control.py and TRANSPORT.md.
"""
from collections import deque
from dataclasses import dataclass, field
import functools
import time

from conn_frames import Decoder, encode
import tcp_control as tcp

READ_CHUNK_BYTES = 16384
WRITE_TIMEOUT_MS = 1000
LOOPBACK = '127.0.0.1'
# Reference daemon connection keys come from a counter that wraps before 0xfffa.
MAX_CONNECTION_KEY = 0xfff9


class TunnelError(Exception):
    """The session cannot continue; the caller tears down and stops."""


def _guarded(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except TunnelError:
            raise
        except (ValueError, TypeError, KeyError, TimeoutError) as error:
            raise TunnelError('%s: %s' % (type(error).__name__, error)) from error
    return wrapper


@dataclass
class Config:
    config_id: int
    port: int
    operation: int


@dataclass
class Connection:
    key: int
    host_port: int
    config_id: int | None = None
    received: bytearray = field(default_factory=bytearray)
    closed_by_phone: bool = False
    closing: bool = False
    inbound: bool = False


class Session:
    def __init__(self, link, first_transaction, max_frame_bytes, max_receive_bytes,
                 clock=time.monotonic, log=None, accept_inbound=False):
        if type(first_transaction) is not int or not 1 <= first_transaction <= 0xffffffff:
            raise ValueError('first_transaction must be a nonzero uint32')
        self.link = link
        self.clock = clock
        self.log = log or (lambda event, **fields: None)
        self.decoder = Decoder(max_frame_bytes)
        self.inbox = deque()
        self.max_frame_bytes = max_frame_bytes
        self.max_receive_bytes = max_receive_bytes
        self.received_bytes = 0
        self.transaction = first_transaction
        self.usb_buffer_bytes = None
        self.configs = {}
        self.connections = {}
        # host_port -> key of connections the host closed; late data is acked and dropped.
        self.retired = {}
        self.cleanup = False
        self.accept_inbound = accept_inbound
        self.inbound_count = 0
        self.rejected_inbound_keys = set()
        self.retired_listeners = set()
        # Only failed host Data requests are eligible for late-ACK cleanup.
        self.late_data = {}

    @property
    def config_id(self):
        # Primary (first-opened) config: for single-config callers and teardown.
        return next(iter(self.configs), None)

    @property
    def config_port(self):
        primary = next(iter(self.configs.values()), None)
        return primary.port if primary else None

    def _next_transaction(self):
        transaction = self.transaction
        self.transaction = transaction % 0xffffffff + 1
        return transaction

    def _send(self, frame):
        raw = encode(frame)
        self.log('usb_write', command=frame.command, kind=frame.kind,
                 transaction=frame.transaction, size_bytes=len(raw))
        if self.link.write(raw, WRITE_TIMEOUT_MS) != len(raw):
            raise TunnelError('partial or failed USB write; no retry')

    def _next_frame(self, deadline):
        """Next queued frame; the deadline is checked before every frame."""
        while True:
            remaining_ms = int((deadline - self.clock()) * 1000)
            if remaining_ms <= 0:
                raise TimeoutError('USB deadline expired')
            if self.inbox:
                frame = self.inbox.popleft()
                header_bytes = 16 if frame.kind == 3 else 20
                self.log('usb_read', command=frame.command, kind=frame.kind,
                         transaction=frame.transaction,
                         size_bytes=header_bytes + len(frame.body))
                return frame
            chunk = self.link.read(READ_CHUNK_BYTES, min(remaining_ms, 1000))
            self.inbox.extend(self.decoder.feed(chunk))

    def _handle_unsolicited(self, frame):
        if frame.kind == 1:
            self._phone_request(frame)
        elif frame.kind == 2:
            raise TunnelError('unsolicited response command %d' % frame.command)
        else:
            # Kind3 includes the device-attached indication sent after a reset.
            raise TunnelError('unexpected notification command %d' % frame.command)

    def begin_cleanup(self):
        self.cleanup = True

    def _request(self, frame, timeout_s):
        if self.cleanup and frame.command not in (4, 0x15):
            raise TunnelError('only disconnect/close requests allowed during cleanup')
        try:
            self._send(frame)
            deadline = self.clock() + timeout_s
            while True:
                response = self._next_frame(deadline)
                if response.kind != 2:
                    self._handle_unsolicited(response)
                    continue
                if (response.command, response.transaction) != (frame.command, frame.transaction):
                    expected_size = self.late_data.get(response.transaction)
                    if self.cleanup and response.command == 5 and expected_size is not None:
                        status, error = tcp.data_reply(response, response.transaction, expected_size)
                        del self.late_data[response.transaction]
                        self.log('late_data_reply', transaction=response.transaction,
                                 status=status, native_error=error)
                        continue
                    raise TunnelError('unsolicited response command %d' % response.command)
                return response
        except Exception:
            if frame.command == 5:
                self.late_data[frame.transaction] = 20 + len(frame.body)
            raise

    def _phone_request(self, frame):
        if not self.configs:
            raise TunnelError('phone request without an open configuration')
        if frame.command == 3:
            if not self.accept_inbound:
                raise TunnelError("inbound Connect not enabled during this phase")
            listeners = {cfg.config_id for cfg in self.configs.values() if cfg.operation == 1}
            if self.cleanup:
                listeners |= self.retired_listeners
            message = tcp.inbound_connect_message(frame, listeners)
            if self.inbound_count >= 16:
                raise TunnelError("inbound connection count exceeded")
            if (any(c.key == message.connection_key for c in self.connections.values())
                    or message.connection_key in self.retired.values()
                    or message.connection_key in self.rejected_inbound_keys):
                raise TunnelError("inbound connection key already used")
            if self.cleanup:
                # The listener may already have accepted before shutdown.
                # Refuse without allocating a host ID or starting application IO.
                # Saved callback22924 maps status1 to -1 and tears the socket down.
                self.inbound_count += 1
                self.rejected_inbound_keys.add(message.connection_key)
                self.log("inbound_reject_attempt", config_id=message.config_id,
                         connection_key=message.connection_key)
                self._send(tcp.inbound_connect_reject(message.transaction, message.config_id))
                self.log("inbound_rejected_cleanup", config_id=message.config_id,
                         connection_key=message.connection_key)
                return
            host_port = next((port for port in range(65535, 59999, -1)
                              if port not in self.connections and port not in self.retired), None)
            if host_port is None:
                raise TunnelError("inbound host identifiers exhausted")
            connection = Connection(message.connection_key, host_port,
                                    config_id=message.config_id, inbound=True)
            # Record BEFORE ack: a partial/failed write may still change the
            # phone, and cleanup must retain the learned key.
            self.connections[host_port] = connection
            self.inbound_count += 1
            self._send(tcp.inbound_connect_ack(message.transaction, message.config_id, host_port))
            self.log("inbound_connected", config_id=message.config_id,
                     connection_key=message.connection_key, host_port=host_port)
        elif frame.command == 5:
            message = tcp.data_message(frame, set(self.configs))
            connection = self.connections.get(message.host_port)
            if connection is None:
                # A retired unconfirmed connection (key None) never learnt its key.
                if (message.host_port not in self.retired or
                        self.retired[message.host_port] not in (None, message.connection_key)):
                    raise TunnelError('data for unknown connection')
            elif connection.config_id != message.config_id:
                raise TunnelError('data for unknown connection')
            elif connection.key is not None and connection.key != message.connection_key:
                raise TunnelError('data for unknown connection')
            elif connection.key is None:
                # Arrived before the Connect reply was processed; raw bytes stay in the USB log.
                self.log('data_dropped_unconfirmed', host_port=message.host_port,
                         size_bytes=len(message.payload))
            elif not connection.closing:
                self.received_bytes += len(message.payload)
                if self.received_bytes > self.max_receive_bytes:
                    raise TunnelError('receive limit exceeded')
                connection.received += message.payload
            # The phone reduces its unacknowledged count by this exact size.
            self._send(tcp.data_ack(frame.transaction, 20 + len(frame.body)))
        elif frame.command == 4:
            message = tcp.disconnect_message(frame, set(self.configs))
            connection = self.connections.get(message.port)
            if message.address != LOOPBACK or (connection is None
                                               and message.port not in self.retired):
                raise TunnelError('disconnect for unknown connection')
            if connection is not None:
                if connection.config_id != message.config_id:
                    raise TunnelError('disconnect for unknown connection')
                connection.closed_by_phone = True
            self._send(tcp.disconnect_ack(frame.transaction))
        else:
            raise TunnelError('unhandled phone request command %d' % frame.command)

    def _require_config(self):
        if not self.configs or self.usb_buffer_bytes is None:
            raise TunnelError('no open configuration')

    def _retire(self, connection):
        self.connections.pop(connection.host_port, None)
        self.retired[connection.host_port] = connection.key

    @_guarded
    def get_version(self, timeout_s=2):
        transaction = self._next_transaction()
        reply = self._request(tcp.version_request(transaction), timeout_s)
        status, major, minor, text = tcp.version_reply(reply, transaction)
        if (status, major, minor) != (0, 2, 0):
            raise TunnelError('unsupported version reply')
        return text

    @_guarded
    def exchange(self, os_type, tcp_send_buffer_bytes, timeout_s=2):
        if self.configs:
            raise TunnelError('exchange must precede open')
        transaction = self._next_transaction()
        frame = tcp.exchange_request(transaction, os_type,
                                     tcp_send_buffer_bytes=tcp_send_buffer_bytes)
        status, _, fields = tcp.exchange_reply(self._request(frame, timeout_s), transaction)
        if status != 0:
            raise TunnelError('exchange status %d' % status)
        usb_buffer_bytes = fields['usb_buffer_bytes']
        # Data frames from the phone are at most UsbBufferSize bytes (0003f8cc).
        if not 56 < usb_buffer_bytes <= self.max_frame_bytes:
            raise TunnelError('negotiated USB buffer outside host limit')
        self.usb_buffer_bytes = usb_buffer_bytes
        return fields

    @_guarded
    def open_config(self, config_id, service_uid, port, timeout_s=2, operation=2):
        if self.usb_buffer_bytes is None:
            raise TunnelError('open requires one prior exchange')
        if config_id in self.configs:
            raise TunnelError('config already open')
        transaction = self._next_transaction()
        frame = tcp.configuration_request(transaction, config_id, service_uid, port, operation)
        # Recorded before the reply: a lost or malformed reply may follow an
        # applied config, which the caller must still close.
        self.configs[config_id] = Config(config_id, port, operation)
        reply = tcp.open_reply(self._request(frame, timeout_s), transaction, config_id)
        if reply['status'] != 0:
            del self.configs[config_id]
            raise TunnelError('open status %d' % reply['status'])
        return reply

    @_guarded
    def connect(self, host_port, config_id=None, timeout_s=5):
        self._require_config()
        if config_id is None:
            config_id = self.config_id
        if config_id not in self.configs:
            raise TunnelError('connect on unknown config')
        if host_port in self.connections or host_port in self.retired:
            raise TunnelError('host port already used in this session')
        transaction = self._next_transaction()
        frame = tcp.connect_request(transaction, config_id, LOOPBACK, host_port)
        # Unconfirmed (key None) until a valid reply: the phone may already hold
        # the connection, and Disconnect needs only the host port.
        connection = Connection(None, host_port, config_id=config_id)
        self.connections[host_port] = connection
        reply = tcp.connect_reply(self._request(frame, timeout_s), transaction, config_id)
        if reply.status != 0:
            del self.connections[host_port]
            raise TunnelError('connect status %d network error %d'
                              % (reply.status, reply.network_error))
        if not 1 <= reply.port <= MAX_CONNECTION_KEY:
            raise TunnelError('invalid connection key')
        connection.key = reply.port
        return connection

    @_guarded
    def send(self, connection, payload, timeout_s=5):
        self._require_config()
        payload = bytes(payload)
        chunk_bytes = self.usb_buffer_bytes - 56
        for offset in range(0, len(payload), chunk_bytes):
            if self.connections.get(connection.host_port) is not connection or connection.closing:
                raise TunnelError('connection is not open')
            if connection.closed_by_phone:
                raise TunnelError('connection closed by phone')
            transaction = self._next_transaction()
            frame = tcp.data_request(transaction, connection.config_id, connection.host_port,
                                     connection.key, self.configs[connection.config_id].port,
                                     payload[offset:offset + chunk_bytes], self.usb_buffer_bytes)
            status, error = tcp.data_reply(self._request(frame, timeout_s), transaction,
                                           20 + len(frame.body))
            if status != 0:
                raise TunnelError('data status %d native error %d' % (status, error))

    @_guarded
    def wait(self, seconds, until=lambda: False):
        """Serve phone requests for at most seconds; True once until() holds."""
        deadline = self.clock() + seconds
        while not until():
            try:
                frame = self._next_frame(deadline)
            except TimeoutError:
                return False
            self._handle_unsolicited(frame)
        return True

    @_guarded
    def disconnect(self, connection, timeout_s=2):
        if self.connections.get(connection.host_port) is not connection:
            raise TunnelError('connection is not open')
        if connection.closed_by_phone:
            self._retire(connection)
            return 0
        if connection.key is None:
            # The phone's Disconnect lookup needs the key; this one never got it.
            self._retire(connection)
            raise TunnelError('cannot disconnect a connection without a key')
        connection.closing = True
        try:
            transaction = self._next_transaction()
            frame = tcp.disconnect_request(transaction, connection.config_id, LOOPBACK,
                                           connection.key)
            status = tcp.disconnect_reply(self._request(frame, timeout_s), transaction)
            self.log("disconnect_reply", host_port=connection.host_port,
                     connection_key=connection.key, status=status,
                     closed_by_phone=connection.closed_by_phone)
            # Reference3fc78 returns1 after the peer has removed this key.
            # Only a matching, successfully processed phone Disconnect observed
            # during this request corroborates that benign close race.
            if status == 1 and connection.closed_by_phone:
                self.log("disconnect_peer_close_race", host_port=connection.host_port,
                         native_status=status)
                return 0
            return status
        finally:
            self._retire(connection)

    @_guarded
    def close_config(self, service_uid, config_id=None, timeout_s=2):
        if config_id is None:
            config_id = self.config_id
        if config_id is None or config_id not in self.configs:
            raise TunnelError('no open configuration')
        transaction = self._next_transaction()
        frame = tcp.configuration_close_request(transaction, config_id, service_uid)
        status = tcp.close_reply(self._request(frame, timeout_s), transaction)
        if status != 0:
            raise TunnelError('close status %d' % status)
        for connection in [c for c in self.connections.values() if c.config_id == config_id]:
            self._retire(connection)
        if self.configs[config_id].operation == 1:
            self.retired_listeners.add(config_id)
        del self.configs[config_id]
        return status
