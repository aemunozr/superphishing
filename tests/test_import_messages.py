import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))
from import_messages import find_case_file


class ImportSidecarTests(unittest.TestCase):
    def test_finds_ready_and_metadata_in_case_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "CASE-1"
            original = case / "original"
            original.mkdir(parents=True)
            msg = original / "mail.msg"
            msg.write_bytes(b"msg")
            (case / "READY").write_text("ready")
            (case / "metadata.json").write_text("{}")
            self.assertEqual(find_case_file(msg, root, "READY"), case / "READY")
            self.assertEqual(find_case_file(msg, root, "metadata.json"), case / "metadata.json")

    def test_does_not_search_outside_import_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            case = root / "CASE-1"
            original = case / "original"
            original.mkdir(parents=True)
            msg = original / "mail.msg"
            msg.write_bytes(b"msg")
            (Path(temp) / "READY").write_text("outside")
            self.assertIsNone(find_case_file(msg, root, "READY"))


if __name__ == "__main__":
    unittest.main()
