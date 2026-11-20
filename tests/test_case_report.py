import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

import case_report


def make_case(root: Path, rel: str, case_id: str, date_text: str, sender: str, subject: str,
              verdict: str | None) -> Path:
    case = root / rel / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "summary.json").write_text(json.dumps(
        {"case_id": case_id, "date": date_text, "sender": sender, "subject": subject}), encoding="utf-8")
    if verdict is not None:
        (case / "analysis" / "state.json").write_text(json.dumps({"verdict": verdict}), encoding="utf-8")
    return case


class CaseReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        make_case(self.root, "2026/11/13", "CASE-B", "2026-11-12 10:54:07-03:00",
                  "CMF\t<webmaster@cmfchile.cl>", "Carta | Gerencia", "legitimate")
        make_case(self.root, "2026/11/13", "CASE-A", "2026-11-10 18:51:56-03:00",
                  "Victor <vgodoy@liceolastarria.cl>", "Embargo", "phishing")
        make_case(self.root, "2026/11/20", "CASE-C", "2026-10-31 02:26:08-03:00",
                  "peena@beetech.co.in", "PP2", None)
        make_case(self.root, "2026/11/20", "CASE-D", "", "x@y.z", "Sin fecha", "spam")

    def tearDown(self):
        self.tmp.cleanup()

    def test_collects_sorts_and_defaults_pending(self):
        rows = case_report.collect(self.root)
        self.assertEqual([r["case_id"] for r in rows], ["CASE-C", "CASE-A", "CASE-B", "CASE-D"])
        self.assertEqual(rows[0]["verdict"], "pending")
        self.assertEqual(rows[2]["sender"], "CMF <webmaster@cmfchile.cl>")   # tabulador normalizado

    def test_date_filter_excludes_out_of_range_and_undated(self):
        rows = case_report.collect(self.root, date(2026, 11, 1), date(2026, 11, 30))
        self.assertEqual([r["case_id"] for r in rows], ["CASE-A", "CASE-B"])

    def test_counts_follow_fixed_vocabulary_order(self):
        counts = case_report.count_verdicts(case_report.collect(self.root))
        self.assertEqual(counts, [("phishing", 1), ("spam", 1), ("legitimate", 1), ("pending", 1)])

    def test_markdown_has_summary_and_escaped_table(self):
        text = case_report.render_markdown(case_report.collect(self.root), self.root)
        self.assertIn("**Total de correos:** 4", text)
        self.assertIn("| phishing | 1 | 25.0 |", text)
        self.assertIn("Carta \\| Gerencia", text)
        self.assertIn("&lt;webmaster@cmfchile.cl&gt;", text)
        self.assertIn("| Fecha | Origen | Asunto | Veredicto |", text)

    def test_cli_writes_tsv_without_touching_cases(self):
        before = {p: p.read_bytes() for p in self.root.rglob("*.json")}
        out = self.root / "out" / "r.tsv"
        self.assertEqual(case_report.main([str(self.root), "--formato", "tsv", "--incluir-caso",
                                           "--output", str(out)]), 0)
        lines = out.read_text(encoding="utf-8-sig").splitlines()
        self.assertEqual(lines[0].split("\t"), ["Fecha", "Origen", "Asunto", "Veredicto", "Caso"])
        self.assertIn("Total\t4", lines)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*.json")})


if __name__ == "__main__":
    unittest.main()
