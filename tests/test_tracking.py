import json
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(ENGINE))
from case_store import create_case, get_case_by_hash, get_case_info
from common import write_json


class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "tracking.db"
        self.case_path = self.root / "CASE-TEST"
        (self.case_path / "analysis").mkdir(parents=True)
        create_case(self.db, {
            "case_id": "CASE-TEST", "case_path": str(self.case_path),
            "source_sha256": "a" * 64, "subject": "Test", "sender": "sender@example.test",
        })
        write_json(self.case_path / "analysis" / "state.json", {
            "schema_version": "1.0", "case_id": "CASE-TEST", "updated_utc": "2026-11-08T12:00:00Z",
            "verdict": "pending", "severity": "unknown", "confidence": "unknown", "finalized": False,
            "stages": {"triage": {"status": "pending", "input_fingerprint": "b" * 64}},
        })
        write_json(self.case_path / "analysis" / "findings.json", {"schema_version": "1.0", "case_id": "CASE-TEST", "findings": []})

    def tearDown(self):
        self.temp.cleanup()

    def test_sqlite_index_deduplicates_source_hash(self):
        self.assertEqual(get_case_by_hash(self.db, "a" * 64)["case_id"], "CASE-TEST")
        self.assertEqual(get_case_info(self.db, "CASE-TEST")["subject"], "Test")
        with self.assertRaises(Exception):
            create_case(self.db, {
                "case_id": "CASE-OTHER", "case_path": str(self.root / "other"),
                "source_sha256": "a" * 64,
            })

    def test_project_tracking_files_are_small_and_separate(self):
        state = json.loads((self.case_path / "analysis/state.json").read_text())
        findings = json.loads((self.case_path / "analysis/findings.json").read_text())
        self.assertEqual(state["stages"]["triage"]["status"], "pending")
        self.assertEqual(findings["findings"], [])
        self.assertFalse(state["finalized"])


if __name__ == "__main__":
    unittest.main()
