import json
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))
import graph_import
import revision
from graph_import import GraphClient

MADRID = ZoneInfo("Europe/Madrid")
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
MAILBOX = "reportes@example.com"


class ParseTests(unittest.TestCase):
    def test_formats(self):
        today = date(2026, 11, 8)
        self.assertEqual(revision.parse_day("09-10", today), date(2026, 10, 9))
        self.assertEqual(revision.parse_day("9/10", today), date(2026, 10, 9))
        self.assertEqual(revision.parse_day("09-10-2025", today), date(2025, 10, 9))
        self.assertEqual(revision.parse_day("2025-10-09", today), date(2025, 10, 9))
        # DD-MM aún no alcanzado este año: se toma el año anterior.
        self.assertEqual(revision.parse_day("20-12", today), date(2025, 12, 20))
        for bad in ("31-02", "10", "2026/10/09", "hoy"):
            with self.assertRaises(ValueError):
                revision.parse_day(bad, today)

    def test_single_day_covers_whole_local_day(self):
        start, end = revision.resolve_range("09-10", "09-10", MADRID, NOW)
        self.assertEqual(start, datetime(2026, 10, 8, 22, 0, tzinfo=timezone.utc))  # CEST, UTC+2
        self.assertEqual(end, datetime(2026, 10, 9, 22, 0, tzinfo=timezone.utc))

    def test_range_inclusive_across_dst(self):
        start, end = revision.resolve_range("20-10", "30-10", MADRID, NOW)
        self.assertEqual(start, datetime(2026, 10, 19, 22, 0, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 10, 30, 23, 0, tzinfo=timezone.utc))  # ya en CET, UTC+1

    def test_open_range_ends_now_and_rejects_inverted(self):
        start, end = revision.resolve_range("01-11", None, MADRID, NOW)
        self.assertEqual(end, NOW)
        with self.assertRaises(ValueError):
            revision.resolve_range("15-10", "09-10", MADRID, NOW)
        with self.assertRaises(ValueError):
            revision.resolve_range(None, "09-10", MADRID, NOW)


class ReviewTests(unittest.TestCase):
    def make_client(self, requested):
        messages = [{"id": "C1", "receivedDateTime": "2026-10-09T08:00:00Z", "subject": "s", "from": {}}]

        def transport(method, url, headers, body):
            if "oauth2/v2.0/token" in url:
                return 200, {}, json.dumps({"access_token": "t", "expires_in": 3600}).encode()
            requested.append(url)
            if "/attachments?" in url:
                return 200, {}, json.dumps({"value": [{"@odata.type": "#microsoft.graph.fileAttachment",
                                                       "name": "orig.msg", "size": 10}]}).encode()
            return 200, {}, json.dumps({"value": messages}).encode()
        return GraphClient("t", "c", "s", transport)

    def test_review_filters_range_skips_done_and_keeps_checkpoint(self):
        requested = []
        client = self.make_client(requested)
        start, end = revision.resolve_range("09-10", "09-10", MADRID, NOW)
        fake = mock.Mock(return_value=[{"container": "C1", "status": "imported"}])
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(graph_import, "import_container", fake):
            root = Path(temp)
            args = (client, MAILBOX, "inbox", root / "s", root / "c", root / "db.sqlite", start, end)
            first = revision.review(*args)
            self.assertIn("receivedDateTime%20ge%202026-10-08T22%3A00%3A00Z", requested[0])
            self.assertIn("receivedDateTime%20lt%202026-10-09T22%3A00%3A00Z", requested[0])
            self.assertEqual(first["counts"], {"imported": 1})
            second = revision.review(*args)
            self.assertEqual(second["counts"], {"skipped_already_processed": 1})
            third = revision.review(*args, reprocess=True)
            self.assertEqual(third["counts"], {"imported": 1})
            self.assertEqual(fake.call_count, 2)
            # La revisión por fechas no toca el checkpoint del sondeo periódico.
            self.assertIsNone(graph_import.get_checkpoint(root / "db.sqlite", graph_import.source_key(MAILBOX, "inbox")))

    def test_dry_run_lists_without_importing(self):
        client = self.make_client([])
        start, end = revision.resolve_range("09-10", None, MADRID, NOW)
        fake = mock.Mock()
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(graph_import, "import_container", fake):
            root = Path(temp)
            result = revision.review(client, MAILBOX, "inbox", root / "s", root / "c", root / "db.sqlite",
                                     start, end, dry_run=True)
        fake.assert_not_called()
        self.assertEqual(result["counts"], {"listed": 1})
        self.assertEqual(result["results"][0]["adjuntos"][0]["tipo"], "msg")


if __name__ == "__main__":
    unittest.main()
