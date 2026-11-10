import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))
import graph_import
from graph_import import GRAPH_ROOT, OLE_MAGIC, GraphClient, GraphError, import_container

MAILBOX = "reportes@example.com"
INNER_MSG = OLE_MAGIC + b"fake-msg-payload"


def fake_transport(attachments, blobs):
    def transport(method, url, headers, body):
        if "oauth2/v2.0/token" in url:
            return 200, {}, json.dumps({"access_token": "t", "expires_in": 3600}).encode()
        if url.endswith("/$value"):
            attachment_id = url.rsplit("/", 2)[-2]
            return 200, {}, blobs[attachment_id]
        if "/attachments?" in url:
            return 200, {}, json.dumps({"value": attachments}).encode()
        return 404, {}, b""
    return transport


class GraphImportTests(unittest.TestCase):
    def run_import(self, attachments, blobs):
        client = GraphClient("tenant", "client", "secret", fake_transport(attachments, blobs))
        message = {"id": "CONTAINER-1", "subject": "Reporte phishing",
                   "from": {"emailAddress": {"address": "usuario@example.com"}},
                   "receivedDateTime": "2026-11-08T10:00:00Z", "internetMessageId": "<c1@example.com>"}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            calls = []

            def fake_process(msg_path, case_id, output, db, metadata_path):
                calls.append((msg_path.read_bytes(), json.loads(metadata_path.read_text())))
                # Igual que el real: process_case incluye "status" con las etapas del caso.
                return {"case_id": "CASE-X", "status": {"ingestion": "completed"}}

            with mock.patch.object(graph_import, "process_case", side_effect=fake_process):
                rows = import_container(client, MAILBOX, message, root / "staging", root / "cases", root / "cases.db")
            return rows, calls

    def test_imports_only_attached_msg_not_container(self):
        attachments = [
            {"@odata.type": "#microsoft.graph.fileAttachment", "id": "A1", "name": "original.msg",
             "contentType": "application/vnd.ms-outlook", "size": len(INNER_MSG)},
            {"@odata.type": "#microsoft.graph.fileAttachment", "id": "A2", "name": "logo.png",
             "contentType": "image/png", "size": 10},
        ]
        rows, calls = self.run_import(attachments, {"A1": INNER_MSG})
        self.assertEqual(len(calls), 1)
        content, metadata = calls[0]
        self.assertEqual(content, INNER_MSG)
        self.assertEqual(metadata["container"]["reported_by"], "usuario@example.com")
        self.assertEqual(len(metadata["hashes"]["sha256_msg"]), 64)
        self.assertEqual([r["status"] for r in rows], ["imported", "skipped_not_msg"])

    def test_rejects_msg_without_ole_signature(self):
        attachments = [{"@odata.type": "#microsoft.graph.fileAttachment", "id": "A1",
                        "name": "trampa.msg", "contentType": "application/octet-stream", "size": 5}]
        rows, calls = self.run_import(attachments, {"A1": b"MZ\x90\x00\x03"})
        self.assertEqual(calls, [])
        self.assertEqual(rows[0]["status"], "rejected_not_ole")

    def test_item_attachment_is_reported_not_imported(self):
        attachments = [{"@odata.type": "#microsoft.graph.itemAttachment", "id": "I1",
                        "name": "Correo sospechoso", "contentType": None, "size": 2000}]
        rows, calls = self.run_import(attachments, {})
        self.assertEqual(calls, [])
        self.assertEqual(rows[0]["status"], "skipped_item_attachment")

    def test_poll_is_incremental_and_retries_errors(self):
        messages = [
            {"id": "OK-1", "receivedDateTime": "2026-11-08T10:00:00Z", "from": {}},
            {"id": "BAD-1", "receivedDateTime": "2026-11-08T09:00:00Z", "from": {}},
        ]
        requested = []

        def transport(method, url, headers, body):
            if "oauth2/v2.0/token" in url:
                return 200, {}, json.dumps({"access_token": "t", "expires_in": 3600}).encode()
            requested.append(url)
            return 200, {}, json.dumps({"value": messages}).encode()

        def fake_container(client, mailbox, message, staging, output, db):
            status = "error" if message["id"] == "BAD-1" else "imported"
            return [{"container": message["id"], "status": status, "detail": "x"}]

        client = GraphClient("tenant", "client", "secret", transport)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = root / "cases.db"
            args = (client, MAILBOX, "inbox", root / "s", root / "c", db, None, 24, 15, 50)
            with mock.patch.object(graph_import, "import_container", side_effect=fake_container) as imp:
                first = graph_import.poll(*args)
                # El checkpoint no supera el contenedor con error pendiente de reintento.
                self.assertEqual(first["checkpoint_utc"], "2026-11-08T09:00:00Z")
                second = graph_import.poll(*args)
                self.assertIn("receivedDateTime%20ge%202026-11-08T08%3A45%3A00Z", requested[-1])
                # OK-1 ya está hecho: en la segunda pasada solo se reintenta BAD-1.
                self.assertEqual([c.args[2]["id"] for c in imp.call_args_list], ["OK-1", "BAD-1", "BAD-1"])
                graph_import.poll(*args)  # tercer intento: BAD-1 pasa a failed
                final = graph_import.poll(*args)
                self.assertEqual(final["counts"], {})
                # Sin reintentos pendientes, el checkpoint avanza al más reciente.
                self.assertEqual(final["checkpoint_utc"], "2026-11-08T10:00:00Z")
                self.assertEqual(second["counts"], {"error": 1})

    def test_rejects_urls_outside_graph(self):
        client = GraphClient("tenant", "client", "secret", fake_transport([], {}))
        with self.assertRaises(GraphError):
            client.request("https://evil.example/v1.0/users")
        self.assertTrue(graph_import.messages_url(MAILBOX, "inbox", None, 10).startswith(GRAPH_ROOT))


class EnvFileTests(unittest.TestCase):
    def test_loads_only_graph_vars_without_overriding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "# comentario\n"
                "GRAPH_TENANT_ID=tenant\n"
                'GRAPH_CLIENT_ID="client"\n'
                "export GRAPH_CLIENT_SECRET='secret'\n"
                "GRAPH_MAILBOX=nuevo@example.com\n"
                "GRAPH_FOLDER=\n"
                "DARKNET_MCP_TOKEN=no-cargar\n",
                encoding="utf-8")
            env = {"GRAPH_MAILBOX": "existente@example.com"}
            loaded = graph_import.load_env_file(path, env)
        self.assertEqual(loaded, ["GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET"])
        self.assertEqual(env["GRAPH_CLIENT_ID"], "client")
        self.assertEqual(env["GRAPH_CLIENT_SECRET"], "secret")
        self.assertEqual(env["GRAPH_MAILBOX"], "existente@example.com")
        self.assertNotIn("GRAPH_FOLDER", env)
        self.assertNotIn("DARKNET_MCP_TOKEN", env)


if __name__ == "__main__":
    unittest.main()
