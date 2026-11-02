"""Fake-device tests for tunnel_probe: guard, step order, cleanup and budgets.

The phone is test_usb_tunnel.FakePhone behind a PyUSB-shaped device, so the
reply shapes stay independent of the codec. Not proof of S20+ behaviour.
"""
import builtins
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS

import tunnel_probe as p
from conn_frames import Frame, encode
from test_usb_tunnel import FakePhone, _connect
from test_version_query import Config, Interface
from usb_tunnel import TunnelError


class FakeTimeout(Exception):
    pass


class Phone(FakePhone):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.commands = []
        self.connect_status = 0
        self.on_connect = None
        self.silent = set()

    def _handle(self, frame):
        if frame.kind == 1:
            self.commands.append(frame.command)
            if frame.command in self.silent:
                if frame.command == 0x14:
                    self.config_id = struct.unpack_from('<I', frame.body, 0)[0]
                return
        if frame.kind == 1 and frame.command == 3:
            cfg = struct.unpack_from('<I', frame.body, 0)[0]
            self.host_port = struct.unpack_from('<I', frame.body, 20)[0]  # wire offset 40
            self._reply(3, frame.transaction, _connect(cfg, self.key, status=self.connect_status,
                                                       net_error=111 if self.connect_status else 0))
            if self.on_connect:
                self.on_connect(self)
            return
        super()._handle(frame)


class Device:
    def __init__(self, phone, busy=False):
        self.phone = phone
        self.busy = busy
        self.read_error = None
        self.calls = []
        self.config = Config([Interface([
            NS(bEndpointAddress=3, bmAttributes=2, wMaxPacketSize=512),
            NS(bEndpointAddress=133, bmAttributes=2, wMaxPacketSize=512)])])

    def get_active_configuration(self):
        self.calls.append('config')
        return self.config

    def is_kernel_driver_active(self, interface):
        assert interface == 3
        self.calls.append('kernel')
        return self.busy

    def write(self, endpoint, data, timeout):
        assert endpoint == 3 and 0 < timeout <= 1000
        self.calls.append('write')
        return self.phone.write(bytes(data), timeout)

    def read(self, endpoint, size, timeout):
        assert endpoint == 133 and 0 < timeout <= 1000
        assert size == 512
        self.calls.append('read')
        # Fires on the first read after the Connect reply was consumed (the listen).
        if (self.read_error is not None and self.phone.commands[-1:] == [3]
                and not self.phone.inbound):
            error, self.read_error = self.read_error, None
            raise error
        chunk = self.phone.read(size, timeout)
        if not chunk:
            raise FakeTimeout()
        return chunk


class Util:
    def claim_interface(self, device, interface):
        assert interface == 3
        device.calls.append('claim')

    def release_interface(self, device, interface):
        assert interface == 3
        device.calls.append('release')

    def dispose_resources(self, device):
        device.calls.append('dispose')


class Tests(unittest.TestCase):
    def run_probe(self, phone, device=None, listen_s=1):
        device = device or Device(phone)
        result = self.result = {}
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                p.probe(device, Util(), FakeTimeout, Path(directory), 7, 123, 41000, result,
                        listen_s=listen_s, clock=phone.clock)
            finally:
                records = [json.loads(line) for line in
                           (Path(directory) / 'events.jsonl').read_text().splitlines()]
                self.events = [r['event'] for r in records]
                self.raw_reads = sum(1 for r in records if r.get('direction') == 'in')
                self.raw_writes = sum(1 for r in records if r.get('direction') == 'out')
        self.result = result
        return device, result

    def test_plan_has_no_usb_import(self):
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == 'usb' or name.startswith('usb.'):
                raise AssertionError('default mode imported USB')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', guarded), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.main([]), 0)

    def test_approved_run_needs_explicit_target(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in (['--approved-phone-tunnel-probe', '--output', 'x', '--bus', '3'],
                         ['--approved-phone-tunnel-probe', '--bus', '3', '--address', '4'],
                         ['--approved-phone-tunnel-probe', '--output', 'x', '--bus', '0',
                          '--address', '4']):
                with self.assertRaises(SystemExit):
                    p.main(argv)

    def test_happy_path_sends_no_payload_and_cleans_up(self):
        phone = Phone(usb_buffer_bytes=4096)
        device, result = self.run_probe(phone)
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 4, 0x15])
        self.assertEqual(phone.host_data, [])
        self.assertEqual(phone.config_id, 123)
        self.assertEqual(phone.host_port, 41000)
        self.assertEqual((result['daemon_version'], result['connection_key']), ('2.17.21.0', 1000))
        self.assertEqual((result['disconnect_status'], result['close_status']), (0, 0))
        self.assertEqual(phone.disconnect_ports, [1000])
        self.assertFalse(result['closed_by_phone'])
        self.assertEqual(device.calls[:3], ['config', 'kernel', 'claim'])
        self.assertEqual(device.calls[-2:], ['release', 'dispose'])
        self.assertIn('usb_write', self.events)
        self.assertEqual(self.raw_writes, device.calls.count('write'))
        self.assertGreater(self.raw_reads, 0)

    def test_first_error_kept_when_cleanup_fails(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.connect_status = 1
        original = phone._handle
        def handle(frame):
            if frame.command == 0x15:
                return  # close reply never comes
            original(frame)
        phone._handle = handle
        result = {}
        with self.assertRaises(TunnelError), tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stdout(io.StringIO()):
            p.probe(Device(phone), Util(), FakeTimeout, Path(directory), 7, 123, 41000, result,
                    clock=phone.clock)
        self.assertTrue(result['first_error'].startswith('TunnelError: connect status 1'))

    def test_phone_data_is_acked_with_exact_size(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.on_connect = lambda ph: ph.push_data(900, ph.host_port, b'hello-host')
        _, result = self.run_probe(phone)
        self.assertEqual(result['received_hex'], b'hello-host'.hex())
        self.assertEqual(phone.acked_sizes, [20 + 36 + len(b'hello-host')])
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 4, 0x15])

    def test_phone_disconnect_skips_host_disconnect(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.on_connect = lambda ph: ph.push_disconnect(901, ph.host_port)
        _, result = self.run_probe(phone, listen_s=30)
        self.assertTrue(result['closed_by_phone'])
        self.assertLess(result['listened_seconds'], 1)
        self.assertEqual(phone.disconnect_acked, [901])
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 0x15])

    def test_failed_connect_still_closes_config(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.connect_status = 1
        with self.assertRaises(TunnelError):
            device, _ = self.run_probe(phone)
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 0x15])

    def test_exchange_rejection_opens_nothing(self):
        phone = Phone(usb_buffer_bytes=p.MAX_FRAME_BYTES + 1)
        device = Device(phone)
        with self.assertRaises(TunnelError):
            self.run_probe(phone, device)
        self.assertEqual(phone.commands, [2, 0x16])
        self.assertEqual(device.calls[-2:], ['release', 'dispose'])

    def test_busy_interface_never_claims_or_writes(self):
        phone = Phone()
        device = Device(phone, busy=True)
        with self.assertRaises(RuntimeError):
            self.run_probe(phone, device)
        self.assertEqual(device.calls, ['config', 'kernel', 'dispose'])

    def test_link_budgets_and_timeout_mapping(self):
        phone = Phone()
        link = p.Link(Device(phone), FakeTimeout, max_requests=1, max_acks=1,
                      max_reads=3, cleanup_reads=1)
        request = encode(Frame(2, 1, 1, b''))
        ack = encode(Frame(5, 2, 1, bytes(12)))
        self.assertEqual(link.read(512, 10), b'')
        self.assertEqual(link.read(512, 10), b'')
        with self.assertRaises(TunnelError):
            link.read(512, 10)  # last read is the cleanup reserve
        link.write(request, 10)
        with self.assertRaises(TunnelError):
            link.write(request, 10)
        link.write(ack, 10)
        with self.assertRaises(TunnelError):
            link.write(ack, 10)
        link.begin_cleanup()
        link.read(512, 10)  # the reserve opens
        self.assertEqual(link.write(ack, 10), len(ack))  # suppressed, not sent
        self.assertEqual(phone.acked_sizes, [0])

    def test_data_flood_still_tears_down(self):
        phone = Phone(usb_buffer_bytes=4096)
        def flood(ph):
            for n in range(p.MAX_ACKS + 20):
                ph.push_data(1000 + n, ph.host_port, b'x')
        phone.on_connect = flood
        with self.assertRaises(TunnelError):
            self.run_probe(phone)
        self.assertEqual(phone.commands[-2:], [4, 0x15])
        self.assertIn('ack budget', self.result['first_error'])
        self.assertEqual(self.result['close_status'], 0)

    def test_lost_open_reply_still_closes(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.silent = {0x14}
        with self.assertRaises(TunnelError):
            self.run_probe(phone)
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 0x15])

    def test_bad_connect_key_recorded_and_config_closed(self):
        phone = Phone(usb_buffer_bytes=4096, key=0xfffa)
        with self.assertRaises(TunnelError):
            self.run_probe(phone)
        # Disconnect needs the key, so only the config close can be tried.
        self.assertEqual(phone.commands, [2, 0x16, 0x14, 3, 0x15])
        self.assertIn('without a key', self.result['disconnect_error'])

    def test_partial_evidence_kept_on_failure(self):
        phone = Phone(usb_buffer_bytes=4096)
        def greet_then_keepalive(ph):
            ph.push_data(900, ph.host_port, b'greeting')
            ph.push_raw(Frame(10, 1, 901, b''))
        phone.on_connect = greet_then_keepalive
        with self.assertRaises(TunnelError):
            self.run_probe(phone)
        self.assertEqual(self.result['received_hex'], b'greeting'.hex())
        self.assertIn('listened_seconds', self.result)
        self.assertFalse(self.result['closed_by_phone'])
        self.assertEqual(phone.commands[-2:], [4, 0x15])

    def test_usb_error_propagates_after_teardown(self):
        phone = Phone(usb_buffer_bytes=4096)
        device = Device(phone)
        device.read_error = OSError('pipe error')
        with self.assertRaises(OSError):
            self.run_probe(phone, device)
        self.assertEqual(phone.commands[-2:], [4, 0x15])
        self.assertEqual(device.calls[-2:], ['release', 'dispose'])

    def test_disconnect_and_close_errors_both_recorded(self):
        phone = Phone(usb_buffer_bytes=4096)
        phone.on_connect = lambda ph: ph.silent.update({4, 0x15})
        with self.assertRaises(TunnelError):
            self.run_probe(phone)
        self.assertIn('disconnect_error', self.result)
        self.assertIn('close_error', self.result)
        self.assertNotIn('first_error', self.result)

    def test_run_refuses_device_count_and_writes_result(self):
        core = NS(find=lambda **kw: iter([]), USBTimeoutError=FakeTimeout)
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.run(Path(directory), 3, 4, core, Util()), 1)
            result = json.loads((Path(directory) / 'result.json').read_text())
        self.assertFalse(result['success'])
        self.assertIn('exactly one', result['error'])

    def test_run_writes_plan_and_result(self):
        phone = Phone(usb_buffer_bytes=4096)
        device = Device(phone)
        found = {}
        def find(**kw):
            found.update(kw)
            return iter([device])
        core = NS(find=find, USBTimeoutError=FakeTimeout)
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.run(Path(directory), 3, 4, core, Util(), clock=phone.clock), 0)
            plan = json.loads((Path(directory) / 'plan.json').read_text())
            result = json.loads((Path(directory) / 'result.json').read_text())
        self.assertEqual((found['bus'], found['address']), (3, 4))
        self.assertTrue(1 <= plan['config_id'] <= 999)
        self.assertFalse(plan['payload_sent'])
        self.assertTrue(result['success'])
        self.assertEqual(result['close_status'], 0)

    def test_sigterm_during_listen_is_recorded_as_failure(self):
        phone = Phone(usb_buffer_bytes=4096)
        device = Device(phone)
        device.read_error = p.Terminated('terminated by signal 15')
        with self.assertRaises(p.Terminated):
            self.run_probe(phone, device)
        self.assertTrue(self.result['first_error'].startswith('Terminated'))
        self.assertEqual(phone.commands[-2:], [4, 0x15])
        with self.assertRaises(p.Terminated):
            p._terminated(15, None)

if __name__ == '__main__':
    unittest.main()
