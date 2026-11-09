import unittest
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

from common import (extract_domains, extract_html_evidence, extract_ips,
                    extract_urls, safe_name, sniff_file_type, parse_raw_headers)


class ExtractorTests(unittest.TestCase):
    def test_url_dedup_and_host(self):
        rows = extract_urls("Visita https://example.test/login). y https://example.test/login", "body")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "example.test")

    def test_defanged_url(self):
        rows = extract_urls("hxxps://example[.]test/path", "body")
        self.assertEqual(rows[0]["host"], "example.test")
        self.assertTrue(rows[0]["value"].startswith("hxxps://"))

    def test_ip_scope(self):
        rows = extract_ips("8.8.8.8 192.168.1.1 999.1.1.1", "body")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["scope"], "global")
        self.assertEqual(rows[1]["scope"], "private_or_special")

    def test_ipv6(self):
        rows = extract_ips("host 2001:4860:4860::8888", "body")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["version"], 6)

    def test_html_links_and_visible_text(self):
        links, visible = extract_html_evidence('<a href="https://example.test/a">Click here</a><script>bad()</script>')
        self.assertEqual(links[0]["value"], "https://example.test/a")
        self.assertIn("Click here", visible)
        self.assertNotIn("bad()", visible)

    def test_domains(self):
        urls = extract_urls("https://one.example.test", "body")
        rows = extract_domains("contact security@example.org", urls, "body")
        values = {row["value"] for row in rows}
        self.assertIn("one.example.test", values)
        self.assertIn("example.org", values)

    def test_safe_filename(self):
        self.assertEqual(safe_name("../../evil.exe", "fallback"), "evil.exe")

    def test_magic_bytes(self):
        self.assertEqual(sniff_file_type(b"%PDF-1.7", "fake.exe")["magic_type"], "pdf")
        self.assertEqual(sniff_file_type(b"MZ" + b"\0" * 20, "x.bin")["magic_type"], "pe_or_dos_executable")

    def test_original_headers(self):
        headers = parse_raw_headers("From: sender@example.org\r\nReceived: from mx.example.org\r\nAuthentication-Results: mx; dkim=pass")
        self.assertEqual(headers["From"][0], "sender@example.org")
        self.assertEqual(headers["Authentication-Results"][0], "mx; dkim=pass")


if __name__ == "__main__":
    unittest.main()
