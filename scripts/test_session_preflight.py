"""Focused regressions for the persistent startup gate; local temporary files only."""

import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("session_preflight", Path(__file__).with_name("session-preflight.py"))
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class StartupGateTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(preflight.LEDGER.read_text())

    def run_gate(self, data, *args):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            ledger.write_text(json.dumps(data))
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                result = preflight.main(["--ledger", str(ledger), *args])
            return result, output.getvalue()

    def test_real_ledger_and_all_local_references(self):
        result, output = self.run_gate(self.data, "--check")
        self.assertEqual(result, 0, output)

    def test_known_transport_gap_blocks_readiness(self):
        # Construct the historical gap; the real padding row is now verified offline.
        for row in self.data["rows"]:
            if row["id"] == "usb-transfer-padding":
                row["status"] = "gap"
        result, output = self.run_gate(self.data, "--scope", "transport", "--require-ready")
        self.assertEqual(result, 1, output)
        self.assertIn("usb-transfer-padding: gap", output)
        self.assertIn("NOT READY", output)

    def test_other_unresolved_statuses_also_block(self):
        for status in ("limited", "unverified", "deferred"):
            with self.subTest(status=status):
                for row in self.data["rows"]:
                    if row["scope"] == "transport":
                        row["status"] = status
                result, output = self.run_gate(self.data, "--scope", "transport", "--require-ready")
                self.assertEqual(result, 1, output)

    def test_known_case_cannot_be_deleted_to_hide_gap(self):
        self.data["rows"] = [row for row in self.data["rows"] if row["id"] != "usb-transfer-padding"]
        result, output = self.run_gate(self.data, "--check")
        self.assertEqual(result, 2, output)
        self.assertIn("required historical cases missing", output)

    def test_broken_external_references_and_duplicate_requirements_rejected(self):
        for reference in ("docs/does-not-exist.md", "../outside.md", "/etc/passwd"):
            with self.subTest(reference=reference):
                self.data["rows"][0]["evidence"] = [reference]
                result, output = self.run_gate(self.data, "--check")
                self.assertEqual(result, 2, output)
        self.data["rows"] = [self.data["rows"][0], self.data["rows"][0]]
        self.data["rows"][0]["evidence"] = ["CODEX_HANDOFF.md"]
        result, output = self.run_gate(self.data, "--check")
        self.assertEqual(result, 2, output)
        self.assertIn("duplicate requirement", output)

    def test_scope_does_not_claim_whole_project_readiness(self):
        for row in self.data["rows"]:
            if row["scope"] == "windows":
                row["status"] = "verified"
        result, output = self.run_gate(self.data, "--scope", "windows", "--require-ready")
        self.assertEqual(result, 0, output)
        self.assertIn("selected rows only", output)
        self.assertIn("grants no phone/deployment permission", output)
        result, output = self.run_gate(self.data, "--require-ready")
        self.assertEqual(result, 1, output)

    def test_all_offline_rows_verified_still_does_not_complete_delivery(self):
        for row in self.data["rows"]:
            row["status"] = "verified"
        result, output = self.run_gate(self.data, "--require-complete")
        self.assertEqual(result, 1, output)
        self.assertIn("NOT DELIVERED", output)
        self.assertIn("DELIVERY OBJECTIVE", output)

    def test_delivery_cannot_be_dropped_or_replaced_with_test_counts(self):
        del self.data["delivery"]
        result, output = self.run_gate(self.data, "--check")
        self.assertEqual(result, 2, output)
        self.assertIn("delivery objective/state missing", output)

    def test_accepted_without_live_evidence_is_rejected(self):
        self.data["delivery"]["accepted"] = True
        self.data["delivery"]["remaining_work"] = []
        self.data["delivery"]["acceptance_evidence"] = []
        result, output = self.run_gate(self.data, "--require-complete")
        self.assertEqual(result, 2, output)
        self.assertIn("requires live acceptance evidence", output)

    def test_objective_printed_before_diagnostics(self):
        result, output = self.run_gate(self.data)
        self.assertEqual(result, 0, output)
        self.assertLess(output.index("DELIVERY OBJECTIVE"), output.index("transport/"))
        self.assertIn("Independent authorized work", output)

    def test_delivery_cannot_silently_omit_input(self):
        self.data["delivery"]["required_scopes"].remove("input")
        result, output = self.run_gate(self.data, "--check")
        self.assertEqual(result, 2, output)
        self.assertIn("all required pipeline scopes", output)

    def test_handoff_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_text("ok")
            (root / "CODEX_HANDOFF.md").write_bytes(b"x" * 8193)
            with patch.object(preflight, "ROOT", root):
                result, output = self.run_gate(self.data, "--check")
            self.assertEqual(result, 2, output)
            self.assertIn("CODEX_HANDOFF.md exceeds", output)


if __name__ == "__main__":
    unittest.main()
