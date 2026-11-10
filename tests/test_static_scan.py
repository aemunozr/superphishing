import json
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

from common import sha256_bytes
from static_scan import compact, scan_case, scan_pdf


def make_pdf(body: bytes, stream: bytes | None = None) -> bytes:
    parts = [b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R " + body + b" >>\nendobj\n",
             b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
             b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"]
    if stream is not None:
        packed = zlib.compress(stream)
        parts.append(b"4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(packed)
                     + packed + b"\nendstream\nendobj\n")
    parts.append(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")
    return b"".join(parts)


class StaticScanTests(unittest.TestCase):
    def test_clean_pdf_is_low_risk(self):
        result = scan_pdf(make_pdf(b"/Producer (Generador de recibos)"))
        self.assertEqual(result["risk"], "low")
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["flags"], [])

    def test_obfuscated_javascript_inside_compressed_stream(self):
        hidden = b"<< /Type /Action /S /J#61vaScript /JS (app.alert(1)) >>"
        result = scan_pdf(make_pdf(b"/OpenAction 4 0 R", stream=hidden))
        self.assertEqual(result["risk"], "high")
        self.assertIn("JavaScript", result["flags"])
        self.assertIn("JS", result["flags"])
        self.assertIn("obfuscated_names", result["flags"])
        self.assertIn("OpenAction", result["review"])
        self.assertEqual(result["streams"]["inflated"], 1)

    def test_uri_is_review_and_extracted(self):
        result = scan_pdf(make_pdf(b"/A << /S /URI /URI (https://example.test/pago) >>"))
        self.assertEqual(result["risk"], "review")
        self.assertEqual(result["uris"], ["https://example.test/pago"])

    def test_hex_escaped_font_names_are_not_obfuscation(self):
        result = scan_pdf(make_pdf(b"/Font << /F1 << /BaseFont /Arial#20Bold#2CItalic >> >>"))
        self.assertEqual(result["risk"], "low")
        self.assertNotIn("obfuscated_names", result["flags"])

    def test_name_boundaries_avoid_false_positives(self):
        result = scan_pdf(make_pdf(b"/JSONData (x) /URIList (y)"))
        self.assertNotIn("JS", result["keyword_counts"])
        self.assertNotIn("URI", result["keyword_counts"])
        self.assertEqual(result["keyword_counts"]["Page"], 1)

    def test_case_scan_verifies_hash_and_marks_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp)
            (case / "extracted").mkdir()
            (case / "attachments").mkdir()
            bad = make_pdf(b"/OpenAction << /S /Launch /F (cmd.exe) >>")
            good = make_pdf(b"")
            (case / "attachments" / "001_bad.pdf").write_bytes(bad)
            (case / "attachments" / "002_good.pdf").write_bytes(good)
            (case / "attachments" / "003_img.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            original_good = make_pdf(b"/Producer (original)")
            rows = [
                {"index": 1, "original_name": "bad.pdf", "stored_name": "001_bad.pdf", "status": "extracted",
                 "sha256": sha256_bytes(bad), "magic_type": "pdf"},
                # La copia en disco fue reescrita (p. ej. por un CDR): el hash es el del original del MSG.
                {"index": 2, "original_name": "good.pdf", "stored_name": "002_good.pdf", "status": "extracted",
                 "sha256": sha256_bytes(original_good), "magic_type": "pdf"},
                {"index": 3, "original_name": "img.png", "stored_name": "003_img.png", "status": "extracted",
                 "sha256": None, "magic_type": "png"},
                {"index": 4, "original_name": "lost.pdf", "stored_name": "004_lost.pdf", "status": "extracted",
                 "sha256": "0" * 64, "magic_type": "pdf"},
            ]
            (case / "extracted" / "attachments.json").write_text(json.dumps(rows), encoding="utf-8")
            calls = []

            def fake_loader(case_dir):
                calls.append(case_dir)
                return {2: original_good}, None

            report = scan_case(case, msg_loader=fake_loader)
        self.assertEqual(len(calls), 1)                         # el MSG se abre una sola vez
        self.assertEqual(report["overall_risk"], "high")
        good = report["files"][1]
        self.assertEqual((good["status"], good["integrity"], good["origin"]), ("scanned", "disk_altered", "msg_original"))
        self.assertEqual(report["files"][2]["status"], "not_supported")
        self.assertEqual(report["files"][3]["status"], "unverifiable")
        self.assertEqual(report["integrity_alerts"], ["good.pdf", "lost.pdf"])
        self.assertEqual(report["escalate_to_remnux"], ["bad.pdf", "lost.pdf"])
        self.assertEqual(compact(report)["files"][0]["flags"], ["Launch"])


if __name__ == "__main__":
    unittest.main()
