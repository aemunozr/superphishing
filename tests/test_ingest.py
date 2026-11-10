import json
import hashlib
from email.message import EmailMessage
from email import policy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))
import ingest_msg


class FakeAttachment:
    longFilename = "invoice.pdf"
    shortFilename = "invoice.pdf"

    def __init__(self, data: bytes):
        self.data = data


class FakeMessage:
    subject = "Invoice review"
    sender = "Billing <billing@example.test>"
    to = "Analyst <analyst@example.test>"
    cc = ""
    bcc = ""
    date = "Sat, 08 Nov 2026 12:00:00 +0000"
    body = "Please review https://login.example.test/path and contact 198.51.100.25"
    htmlBody = '<html><body><a href="https://login.example.test/path">Open invoice</a></body></html>'
    header = "From: Billing <billing@example.test>\r\nReply-To: billing-verify@other.example.test\r\nReceived: from mail.example.test ([203.0.113.10])\r\n"
    attachments = [FakeAttachment(b"%PDF-1.7\nexample")]

    def __init__(self, _path):
        pass

    def close(self):
        pass


class IngestionTests(unittest.TestCase):
    def test_msg_ingestion_creates_deterministic_case_and_tracking(self):
        fake_module = types.SimpleNamespace(Message=FakeMessage)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            msg_path = root / "mail.msg"
            msg_path.write_bytes(b"synthetic MSG placeholder")
            output = root / "cases"
            db = root / "storage" / "cases.db"
            with patch.dict(sys.modules, {"extract_msg": fake_module}):
                result = ingest_msg.process_case(msg_path, "CASE-TEST-001", output, db)

            case_dir = Path(result["case_path"])
            self.assertTrue((case_dir / "READY").is_file())
            self.assertTrue((case_dir / "original/mail.msg").is_file())
            self.assertTrue((case_dir / "normalized/message.eml").is_file())
            self.assertTrue((case_dir / "attachments/001_invoice.pdf").is_file())
            state = json.loads((case_dir / "analysis/state.json").read_text())
            findings = json.loads((case_dir / "analysis/findings.json").read_text())
            self.assertEqual(state["stages"]["ingestion"]["status"], "completed")
            self.assertEqual(state["stages"]["triage"]["status"], "pending")
            self.assertEqual(state["stages"]["url_analysis"]["status"], "pending")
            self.assertEqual(findings["findings"], [])
            urls = json.loads((case_dir / "extracted/urls.json").read_text())
            ips = json.loads((case_dir / "extracted/ips.json").read_text())
            domains = json.loads((case_dir / "extracted/domains.json").read_text())
            attachments = json.loads((case_dir / "extracted/attachments.json").read_text())
            self.assertTrue(any("login.example.test" in row["value"] for row in urls))
            self.assertTrue(any(row["normalized"] == "198.51.100.25" for row in ips))
            self.assertTrue(any(row["value"] == "other.example.test" for row in domains))
            self.assertEqual(attachments[0]["magic_type"], "pdf")
            self.assertEqual(state["case_id"], "CASE-TEST-001")
            self.assertEqual(result["counts"]["attachments"], 1)

            with patch.dict(sys.modules, {"extract_msg": fake_module}):
                with self.assertRaises(FileExistsError):
                    ingest_msg.process_case(msg_path, None, output, db)

    def test_reuses_collector_eml_only_when_metadata_hashes_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sample_dir = root / "collector" / "SAMPLE-001"
            sample_dir.mkdir(parents=True)
            msg_path = sample_dir / "mail.msg"
            msg_bytes = b"synthetic collector MSG"
            msg_path.write_bytes(msg_bytes)

            eml = EmailMessage(policy=policy.SMTP)
            eml["From"] = "sender@example.test"
            eml["To"] = "analyst@example.test"
            eml["Subject"] = "Verify your account"
            eml.set_content("Visit https://login.example.test/verify")
            eml.add_attachment(b"%PDF-1.7\ncollector pdf", maintype="application", subtype="pdf", filename="notice.pdf")
            eml_path = sample_dir / "mail.eml"
            eml_path.write_bytes(eml.as_bytes(policy=policy.SMTP))
            metadata = {
                "sample_id": "SAMPLE-001",
                "files": {"msg": "mail.msg", "eml": "mail.eml"},
                "hashes": {
                    "sha256_msg": hashlib.sha256(msg_bytes).hexdigest(),
                    "sha256_eml": hashlib.sha256(eml_path.read_bytes()).hexdigest(),
                },
            }
            metadata_path = sample_dir / "metadata.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            output = root / "cases"
            db = root / "storage" / "cases.db"

            # If the verified EML is reused, the extract_msg converter must never be loaded.
            fake_module = types.SimpleNamespace(Message=lambda _path: (_ for _ in ()).throw(AssertionError("MSG converted again")))
            with patch.dict(sys.modules, {"extract_msg": fake_module}):
                result = ingest_msg.process_case(msg_path, "CASE-COLLECTOR-001", output, db, metadata_path)

            case_dir = Path(result["case_path"])
            self.assertEqual((case_dir / "normalized/message.eml").read_bytes(), eml_path.read_bytes())
            manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["normalized"]["source"], "collector_verified")
            self.assertTrue((case_dir / "attachments/001_notice.pdf").is_file())
            urls = json.loads((case_dir / "extracted/urls.json").read_text(encoding="utf-8"))
            self.assertTrue(any("login.example.test" in item["value"] for item in urls))

    def test_rejects_collector_msg_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            msg_path = root / "mail.msg"
            msg_path.write_bytes(b"MSG bytes")
            metadata_path = root / "metadata.json"
            metadata_path.write_text(json.dumps({"hashes": {"sha256_msg": "0" * 64}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no coincide"):
                ingest_msg.process_case(msg_path, "CASE-BAD-META", root / "cases", root / "db.sqlite", metadata_path)
            self.assertFalse((root / "cases/CASE-BAD-META").exists())


if __name__ == "__main__":
    unittest.main()
