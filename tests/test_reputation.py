import base64
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

import reputation
from reputation import VTClient, VTError, collect_indicators, enrich_case

PDF_SHA = "a" * 64
PNG_SHA = "b" * 64
LINK = "https://share.google/AbC123?_task=mail&_action=get"
NOW = datetime(2026, 11, 10, 15, 0, tzinfo=timezone.utc)


def make_case(root: Path) -> Path:
    case = root / "CASE-TEST"
    (case / "extracted").mkdir(parents=True)
    (case / "summary.json").write_text(json.dumps({
        "sender": "Cristian <cristian.opazo@turismolatrach.cl>",
        "key_headers": {"Return-Path": ["bounce@turismolatrach.cl"]},
    }), encoding="utf-8")
    (case / "extracted" / "attachments.json").write_text(json.dumps([
        {"original_name": "recibo.pdf", "sha256": PDF_SHA, "magic_type": "pdf"},
        {"original_name": "logo.png", "sha256": PNG_SHA, "magic_type": "png"},
    ]), encoding="utf-8")
    (case / "extracted" / "urls.json").write_text(json.dumps([
        {"value": LINK.replace("&", "&amp;"), "normalized_for_parsing": LINK.replace("&", "&amp;"),
         "host": "share.google", "sources": ["body_html"]},
        {"value": LINK, "normalized_for_parsing": LINK, "host": "share.google", "sources": ["html:a.href"]},
        {"value": "https://ci3.googleusercontent.com/mail-sig/x", "normalized_for_parsing": "https://ci3.googleusercontent.com/mail-sig/x",
         "host": "ci3.googleusercontent.com", "sources": ["html:img.src"]},
        {"value": "https://www.evil-portal.test/login", "normalized_for_parsing": "https://www.evil-portal.test/login",
         "host": "www.evil-portal.test", "sources": ["html:a.href"]},
    ]), encoding="utf-8")
    return case


def vt_payload(malicious=0, suspicious=0, **attrs):
    return json.dumps({"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 50, "undetected": 20},
        **attrs}}}).encode()


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append(url)
        assert headers["x-apikey"] == "test-key"
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        return 404, b"{}"


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = make_case(self.root)
        self.db = self.root / "cases.db"

    def tearDown(self):
        self.tmp.cleanup()

    def client(self, transport):
        return VTClient("test-key", transport=transport, min_interval=0, sleep=lambda s: None)

    def test_collects_only_context_iocs(self):
        rows = collect_indicators(self.case)
        pairs = [(r["kind"], r["ioc"]) for r in rows]
        self.assertIn(("file", PDF_SHA), pairs)
        self.assertNotIn(("file", PNG_SHA), pairs)           # imágenes omitidas por defecto
        self.assertIn(("domain", "turismolatrach.cl"), pairs)  # remitente y Return-Path deduplicados
        self.assertEqual(sum(p == ("domain", "turismolatrach.cl") for p in pairs), 1)
        self.assertIn(("url", LINK), pairs)                   # &amp; desescapado y deduplicado
        self.assertEqual(sum(k == "url" and "share.google" in v for k, v in pairs), 1)
        self.assertIn(("domain", "evil-portal.test"), pairs)
        self.assertNotIn(("domain", "share.google"), pairs)   # plataforma masiva: sin valor de dominio
        self.assertFalse(any("googleusercontent" in v for _, v in pairs))
        self.assertFalse(any("@" in v for _, v in pairs))      # nunca direcciones de correo

    def test_enrich_classifies_and_caches(self):
        url_id = base64.urlsafe_b64encode(LINK.encode()).decode().rstrip("=")
        transport = FakeTransport({
            f"/files/{PDF_SHA}": (404, b"{}"),
            "/domains/turismolatrach.cl": (200, vt_payload(0, 0, creation_date=1600000000)),
            f"/urls/{url_id}": (200, vt_payload(6, 1, last_final_url="https://evil.test/a", url=LINK)),
            "/domains/evil-portal.test": (200, vt_payload(2, 0)),
        })
        report = enrich_case(self.case, self.client(transport), self.db, NOW)
        self.assertEqual(report["summary"]["malicious"], [LINK])
        self.assertEqual(report["summary"]["suspicious"], ["evil-portal.test"])
        self.assertEqual(report["summary"]["unknown"], 2)       # PDF y la URL de evil-portal (404)
        by_ioc = {r["ioc"]: r for r in report["indicators"]}
        self.assertEqual(by_ioc[LINK]["final_url"], "https://evil.test/a")
        self.assertTrue((self.case / "extracted" / "reputation.json").is_file())
        first_calls = len(transport.calls)

        # Segunda pasada: todo sale de la caché, cero consultas.
        again = enrich_case(self.case, self.client(transport), self.db, NOW + timedelta(hours=1))
        self.assertEqual(len(transport.calls), first_calls)
        self.assertTrue(all(r["source"] == "cache" for r in again["indicators"]))

        # El "no encontrado" caduca antes que el "encontrado".
        later = enrich_case(self.case, self.client(transport), self.db, NOW + timedelta(days=2))
        refreshed = {r["ioc"] for r in later["indicators"] if r["source"] == "api"}
        self.assertIn(PDF_SHA, refreshed)
        self.assertNotIn("turismolatrach.cl", refreshed)

    def test_single_detection_on_domain_is_noise(self):
        self.assertEqual(reputation.classify("found", {"malicious": 1}, "domain"), "no_detections")
        self.assertEqual(reputation.classify("found", {"malicious": 1}, "url"), "suspicious")
        self.assertEqual(reputation.classify("found", {"malicious": 3}, "domain"), "malicious")

    def test_quota_defers_remaining_without_caching(self):
        transport = FakeTransport({"/files/": (429, b"{}")})
        report = enrich_case(self.case, self.client(transport), self.db, NOW)
        self.assertTrue(report["summary"]["quota_exceeded"])
        self.assertEqual(len(transport.calls), 1)               # se detiene en la primera 429
        self.assertEqual(report["summary"]["pending"], len(report["indicators"]))
        offline = enrich_case(self.case, None, self.db, NOW)
        self.assertEqual(offline["summary"]["pending"], len(offline["indicators"]))

    def test_bad_credentials_abort(self):
        with self.assertRaises(VTError):
            enrich_case(self.case, self.client(FakeTransport({"/files/": (401, b"{}")})), self.db, NOW)

    def test_endpoint_url_id_is_unpadded_base64url(self):
        url = reputation.endpoint("url", "https://a.test/?x=1")
        self.assertNotIn("=", url.rsplit("/", 1)[1])


if __name__ == "__main__":
    unittest.main()
