"""Offline wrapper tests. 'timeout' is replaced by a nonexecuting argument recorder."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / 'reconnect_bootstrap.sh').read_text()


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'research/native-usb').mkdir(parents=True)
        (self.root / 'research/native-usb/app_bootstrap.py').write_bytes(
            (ROOT / 'app_bootstrap.py').read_bytes())
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.script = self.root / 'launch.sh'
        self.script.write_text(SOURCE.replace('cd /home/dex/dex-experiment', 'cd "' + str(self.root) + '"', 1))
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        DEX_TEST_ARGS=str(self.root / 'args'), DEX_TEST_STATUS='0')
        self.mock('timeout', 'printf "%s\\n" "$@" > "$DEX_TEST_ARGS"\nexit "$DEX_TEST_STATUS"\n')
        self.mock('date', 'if [ "$1" = "+%s" ]; then echo 2000000000; else /usr/bin/date "$@"; fi\n')

    def mock(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/sh\n' + body)
        p.chmod(0o700)

    def run_launch(self, *args):
        return subprocess.run(['bash', str(self.script), *args], env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=5)

    def test_default_and_expired_make_no_backend_calls(self):
        self.assertEqual(self.run_launch().returncode, 64)
        self.assertEqual(self.run_launch('003', '003', '0000000000').returncode, 1)
        self.assertFalse((self.root / 'args').exists())

    def test_fresh_invokes_exact_reviewed_command_once(self):
        first = self.run_launch('003', '003', '2000000000')
        self.assertEqual(first.returncode, 0, first.stdout)
        args = (self.root / 'args').read_text().splitlines()
        self.assertEqual(args[:5], ['-k', '2', '90', 'python3', '-u'])
        self.assertEqual(args[5:12], ['research/native-usb/app_bootstrap.py',
                         '--phone-bootstrap-approved', '--retain-started-service',
                         '--bus', '003', '--address', '003'])
        self.assertEqual(args[12], '--output')
        self.assertTrue(args[13].startswith('research/native-usb/bootstrap-'))
        self.assertEqual(len(args), 14)
        self.assertEqual(self.run_launch('003', '003', '2000000000').returncode, 1)
        self.assertEqual((self.root / 'args').read_text().splitlines(), args)

    def test_bootstrap_failure_preserved(self):
        self.env['DEX_TEST_STATUS'] = '7'
        self.assertEqual(self.run_launch('003', '003', '2000000000').returncode, 7)

    def test_tee_failure_propagated(self):
        self.env['DEX_TEST_TEE_SEEN'] = str(self.root / 'tee-seen')
        self.mock('tee', '/usr/bin/tee "$@"\nif [ ! -e "$DEX_TEST_TEE_SEEN" ]; then : > "$DEX_TEST_TEE_SEEN"; exit 23; fi\nexit 0\n')
        self.assertEqual(self.run_launch('003', '003', '2000000000').returncode, 23)

    def test_bootstrap_failure_preserved_when_tee_also_fails(self):
        self.env['DEX_TEST_STATUS'] = '7'
        self.mock('tee', '/usr/bin/tee "$@"\nexit 23\n')
        self.assertEqual(self.run_launch('003', '003', '2000000000').returncode, 7)

    def test_log_open_failure_prevents_backend(self):
        self.mock('date', 'if [ "$1" = "+%s" ]; then echo 2000000000; else echo absent/subdir; fi\n')
        self.assertNotEqual(self.run_launch('003', '003', '2000000000').returncode, 0)
        self.assertFalse((self.root / 'args').exists())

    def test_changed_bootstrap_hash_prevents_backend(self):
        (self.root / 'research/native-usb/app_bootstrap.py').write_text('altered')
        self.assertNotEqual(self.run_launch('003', '003', '2000000000').returncode, 0)
        self.assertFalse((self.root / 'args').exists())


if __name__ == '__main__':
    unittest.main()
