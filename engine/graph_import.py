#!/usr/bin/env python3
"""Importa desde Microsoft Graph los MSG adjuntos a correos reportados.

El correo contenedor (el reporte del usuario) NO se convierte en expediente:
solo se descarga cada adjunto .msg, se valida como OLE y se ingesta con el
pipeline local (un MSG = un caso). Del contenedor se conservan únicamente
metadatos del reporte en metadata.json.

Credenciales (solo variables de entorno, nunca en archivos):
  GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, GRAPH_MAILBOX
Opcional: GRAPH_FOLDER (por defecto "inbox").
Permiso de aplicación requerido: Mail.Read (restringido al buzón con
Application Access Policy / RBAC for Applications).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from case_store import db_session, get_case_by_hash
from common import safe_name, sha256_bytes, write_json
from ingest_msg import MAX_MSG_BYTES, process_case

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
LOGIN_ROOT = "https://login.microsoftonline.com"
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"
ITEM_ATTACHMENT = "#microsoft.graph.itemAttachment"
REQUIRED_ENV = ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "GRAPH_MAILBOX")
HTTP_TIMEOUT = 60
MAX_RETRIES = 4
MAX_CONTAINER_ATTEMPTS = 3

# Firma del transporte HTTP: (method, url, headers, body) -> (status, headers, bytes)
Transport = Callable[[str, str, Dict, Optional[bytes]], Tuple[int, Dict, bytes]]


class GraphError(RuntimeError):
    pass


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, dict(response.headers), response.read(MAX_MSG_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(64 * 1024)


class GraphClient:
    def __init__(self, tenant: str, client_id: str, client_secret: str,
                 transport: Transport = urllib_transport):
        self._tenant = tenant
        self._client_id = client_id
        self._client_secret = client_secret
        self._transport = transport
        self._token: str | None = None
        self._token_expiry = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        url = f"{LOGIN_ROOT}/{urllib.parse.quote(self._tenant, safe='')}/oauth2/v2.0/token"
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }).encode()
        status, _, data = self._transport("POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, body)
        if status != 200:
            # No se incluye el cuerpo completo para no reflejar datos sensibles.
            raise GraphError(f"Fallo de autenticación en Graph (HTTP {status}).")
        payload = json.loads(data)
        self._token = payload["access_token"]
        self._token_expiry = time.time() + int(payload.get("expires_in", 3600))
        return self._token

    def request(self, url: str, accept: str = "application/json") -> bytes:
        if not url.startswith(GRAPH_ROOT + "/"):
            raise GraphError("URL fuera de Microsoft Graph rechazada.")
        for attempt in range(MAX_RETRIES + 1):
            headers = {"Authorization": f"Bearer {self._get_token()}", "Accept": accept}
            status, response_headers, data = self._transport("GET", url, headers, None)
            if status == 200:
                return data
            if status in (429, 503, 504) and attempt < MAX_RETRIES:
                retry_after = response_headers.get("Retry-After") or response_headers.get("retry-after") or "5"
                time.sleep(min(int(retry_after) if str(retry_after).isdigit() else 5, 60))
                continue
            if status == 401 and attempt == 0:
                self._token = None
                continue
            raise GraphError(f"Graph devolvió HTTP {status} para {url.split('?')[0]}")
        raise GraphError("Reintentos agotados contra Graph.")

    def get_json(self, url: str) -> dict:
        return json.loads(self.request(url))

    def paged(self, url: str):
        while url:
            page = self.get_json(url)
            yield from page.get("value", [])
            url = page.get("@odata.nextLink")


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def messages_url(mailbox: str, folder: str, since: str | None, top: int, until: str | None = None) -> str:
    filters = ["hasAttachments eq true"]
    if since:
        filters.append(f"receivedDateTime ge {since}")
    if until:
        filters.append(f"receivedDateTime lt {until}")
    query = urllib.parse.urlencode({
        "$filter": " and ".join(filters),
        "$select": "id,subject,from,sender,receivedDateTime,internetMessageId",
        "$top": str(top),
    }, quote_via=urllib.parse.quote)
    return f"{GRAPH_ROOT}/users/{quote(mailbox)}/mailFolders/{quote(folder)}/messages?{query}"


def is_msg_candidate(attachment: dict) -> bool:
    name = str(attachment.get("name") or "").lower()
    content_type = str(attachment.get("contentType") or "").lower()
    return attachment.get("@odata.type") == FILE_ATTACHMENT and (
        name.endswith(".msg") or content_type == "application/vnd.ms-outlook")


def container_metadata(message: dict) -> dict:
    sender = (message.get("from") or message.get("sender") or {}).get("emailAddress", {})
    return {
        "graph_message_id": message.get("id"),
        "internet_message_id": message.get("internetMessageId"),
        "subject": message.get("subject"),
        "reported_by": sender.get("address"),
        "received_utc": message.get("receivedDateTime"),
    }


def import_container(client: GraphClient, mailbox: str, message: dict, staging: Path,
                     output: Path, db_path: Path) -> list[dict]:
    """Procesa un correo contenedor: solo sus adjuntos MSG generan expediente."""
    base = f"{GRAPH_ROOT}/users/{quote(mailbox)}/messages/{quote(message['id'])}/attachments"
    container = container_metadata(message)
    rows = []
    for attachment in client.paged(f"{base}?$select=id,name,contentType,size,isInline"):
        row = {"container": container["graph_message_id"], "attachment": attachment.get("name")}
        if attachment.get("@odata.type") == ITEM_ATTACHMENT:
            rows.append({**row, "status": "skipped_item_attachment",
                         "detail": "Adjunto como elemento de Outlook, no como archivo .msg; Graph solo expone su MIME."})
            continue
        if not is_msg_candidate(attachment):
            rows.append({**row, "status": "skipped_not_msg"})
            continue
        if int(attachment.get("size") or 0) > MAX_MSG_BYTES:
            rows.append({**row, "status": "skipped_size_limit"})
            continue
        raw = client.request(f"{base}/{quote(attachment['id'])}/$value", accept="application/octet-stream")
        if len(raw) > MAX_MSG_BYTES:
            rows.append({**row, "status": "skipped_size_limit"})
            continue
        if not raw.startswith(OLE_MAGIC):
            rows.append({**row, "status": "rejected_not_ole", "detail": "El adjunto .msg no tiene firma OLE."})
            continue
        digest = sha256_bytes(raw)
        existing = get_case_by_hash(db_path, digest)
        if existing:
            rows.append({**row, "status": "duplicate", "sha256": digest, "case_id": existing["case_id"]})
            continue
        drop = staging / digest[:16]
        drop.mkdir(parents=True, exist_ok=True)
        msg_path = drop / safe_name(str(attachment.get("name") or ""), "reported.msg")
        if msg_path.suffix.lower() != ".msg":
            msg_path = msg_path.with_name(msg_path.name + ".msg")
        temp = msg_path.with_name(msg_path.name + ".part")
        temp.write_bytes(raw)
        temp.replace(msg_path)
        metadata_path = drop / "metadata.json"
        write_json(metadata_path, {
            "collector": "microsoft_graph",
            "collected_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mailbox": mailbox,
            "container": container,
            "attachment": {"graph_attachment_id": attachment.get("id"), "name": attachment.get("name"),
                           "content_type": attachment.get("contentType"), "size": len(raw)},
            "hashes": {"sha256_msg": digest},
            "note": "El contenedor es el reporte; el expediente se crea solo con el MSG adjunto.",
        })
        try:
            result = process_case(msg_path, None, output, db_path, metadata_path)
            # process_case devuelve "status" con las etapas del caso; no debe pisar el estado de importación.
            stages = result.pop("status", None)
            rows.append({**row, **result, "status": "imported", "sha256": digest, "stages": stages})
        except FileExistsError as exc:
            rows.append({**row, "status": "duplicate", "sha256": digest, "detail": str(exc)})
        except Exception as exc:
            rows.append({**row, "status": "error", "sha256": digest, "detail": str(exc)[:500]})
    if not rows:
        rows.append({"container": container["graph_message_id"], "attachment": None, "status": "no_attachments"})
    return rows


# --- Estado incremental del sondeo (misma SQLite que el índice de casos) ---

def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_poll_state(db_path: Path) -> None:
    with db_session(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS graph_checkpoint (
            source TEXT PRIMARY KEY,
            received_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS graph_containers (
            source TEXT NOT NULL,
            graph_message_id TEXT NOT NULL,
            received_utc TEXT,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            detail TEXT NOT NULL DEFAULT '',
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (source, graph_message_id))""")


def get_checkpoint(db_path: Path, source: str) -> Optional[str]:
    with db_session(db_path) as con:
        row = con.execute("SELECT received_utc FROM graph_checkpoint WHERE source=?", (source,)).fetchone()
        return row["received_utc"] if row else None


def set_checkpoint(db_path: Path, source: str, received_utc: str) -> None:
    with db_session(db_path) as con:
        con.execute("""INSERT INTO graph_checkpoint (source, received_utc, updated_utc) VALUES (?,?,?)
            ON CONFLICT(source) DO UPDATE SET received_utc=excluded.received_utc, updated_utc=excluded.updated_utc""",
            (source, received_utc, format_utc(datetime.now(timezone.utc))))


def get_container(db_path: Path, source: str, message_id: str) -> Optional[dict]:
    with db_session(db_path) as con:
        row = con.execute("SELECT status, attempts FROM graph_containers WHERE source=? AND graph_message_id=?",
                          (source, message_id)).fetchone()
        return dict(row) if row else None


def record_container(db_path: Path, source: str, message: dict, status: str, attempts: int, detail: str) -> None:
    with db_session(db_path) as con:
        con.execute("""INSERT INTO graph_containers
            (source, graph_message_id, received_utc, status, attempts, detail, updated_utc) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(source, graph_message_id) DO UPDATE SET status=excluded.status,
            attempts=excluded.attempts, detail=excluded.detail, updated_utc=excluded.updated_utc""",
            (source, message.get("id"), message.get("receivedDateTime"), status, attempts, detail[:500],
             format_utc(datetime.now(timezone.utc))))


def source_key(mailbox: str, folder: str) -> str:
    return f"{mailbox.casefold()}/{folder}"


def handle_container(client: GraphClient, mailbox: str, source: str, message: dict, known: Optional[dict],
                     staging: Path, output: Path, db_path: Path) -> Tuple[list, str]:
    """Importa un contenedor y registra su estado: done, retry o failed."""
    attempts = (known["attempts"] if known else 0) + 1
    try:
        rows = import_container(client, mailbox, message, staging, output, db_path)
    except GraphError as exc:
        rows = [{"container": message.get("id"), "status": "error", "detail": str(exc)}]
    errors = [row for row in rows if row["status"] == "error"]
    if not errors:
        state = "done"
    elif attempts >= MAX_CONTAINER_ATTEMPTS:
        # Se deja de reintentar para no bloquear el checkpoint; queda registrado para revisión.
        state = "failed"
    else:
        state = "retry"
    record_container(db_path, source, message, state, attempts, errors[0].get("detail", "") if errors else "")
    return rows, state


def poll(client: GraphClient, mailbox: str, folder: str, staging: Path, output: Path, db_path: Path,
         since_override: Optional[str], lookback_hours: int, overlap_minutes: int, top: int) -> dict:
    """Una pasada de sondeo incremental. Pensada para ejecutarse cada X minutos."""
    source = source_key(mailbox, folder)
    init_poll_state(db_path)
    checkpoint = get_checkpoint(db_path, source)
    if since_override:
        since = parse_utc(since_override)
    elif checkpoint:
        # Solape para correos indexados con retraso; los ya procesados se omiten por id.
        since = parse_utc(checkpoint) - timedelta(minutes=overlap_minutes)
    else:
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    results, newest_ok, oldest_retry = [], None, None
    for message in client.paged(messages_url(mailbox, folder, format_utc(since), top)):
        message_id = message.get("id")
        received = message.get("receivedDateTime")
        known = get_container(db_path, source, message_id)
        if known and known["status"] in ("done", "failed"):
            if received and (newest_ok is None or parse_utc(received) > newest_ok):
                newest_ok = parse_utc(received)
            continue
        rows, state = handle_container(client, mailbox, source, message, known, staging, output, db_path)
        results.extend(rows)
        if state == "retry":
            if received and (oldest_retry is None or parse_utc(received) < oldest_retry):
                oldest_retry = parse_utc(received)
            continue
        if received and (newest_ok is None or parse_utc(received) > newest_ok):
            newest_ok = parse_utc(received)

    # El checkpoint nunca avanza más allá de un contenedor pendiente de reintento.
    if oldest_retry is not None:
        set_checkpoint(db_path, source, format_utc(oldest_retry))
    elif newest_ok is not None:
        set_checkpoint(db_path, source, format_utc(newest_ok))
    elif not checkpoint and not since_override:
        set_checkpoint(db_path, source, format_utc(since))

    counts: dict = {}
    for row in results:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"mailbox": mailbox, "folder": folder, "since_utc": format_utc(since),
            "checkpoint_utc": get_checkpoint(db_path, source), "counts": counts, "results": results}


def load_env_file(path: Path, environ=os.environ, prefixes: tuple = ("GRAPH_",)) -> list[str]:
    """Carga solo variables con los prefijos indicados de un archivo KEY=VALUE. No pisa el entorno ni imprime valores.

    Devuelve los nombres cargados (sin valores) para diagnóstico.
    """
    loaded = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key.startswith(prefixes):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if value and not environ.get(key):
            environ[key] = value
            loaded.append(key)
    return loaded


ENV_FILE_HELP = "Archivo KEY=VALUE del que cargar solo variables GRAPH_* (p. ej. .env); no pisa el entorno"


def preload_env_file() -> bool:
    """Procesa --env-file antes de construir el parser, cuyos defaults leen os.environ.

    Devuelve False si el archivo indicado no existe.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", type=Path)
    pre_args, _ = pre.parse_known_args()
    if not pre_args.env_file:
        return True
    if not pre_args.env_file.is_file():
        print(f"ERROR: no existe el archivo de entorno {pre_args.env_file}", file=sys.stderr)
        return False
    loaded = load_env_file(pre_args.env_file)
    print(f"Variables cargadas de {pre_args.env_file}: {', '.join(loaded) or 'ninguna'}", file=sys.stderr)
    return True


def main() -> int:
    if not preload_env_file():
        return 2
    parser = argparse.ArgumentParser(description="Importa los MSG adjuntos de correos reportados en un buzón vía Microsoft Graph (sondeo incremental).")
    parser.add_argument("--env-file", type=Path, help=ENV_FILE_HELP)
    parser.add_argument("--mailbox", default=os.environ.get("GRAPH_MAILBOX"), help="UPN o id del buzón (GRAPH_MAILBOX)")
    parser.add_argument("--folder", default=os.environ.get("GRAPH_FOLDER") or "inbox", help="Carpeta o id (GRAPH_FOLDER, por defecto inbox)")
    parser.add_argument("--since", help="Ignora el checkpoint y procesa desde esta fecha ISO 8601 UTC, p. ej. 2026-11-01T00:00:00Z")
    parser.add_argument("--lookback-hours", type=int, default=24, help="Ventana de la primera ejecución sin checkpoint")
    parser.add_argument("--overlap-minutes", type=int, default=15, help="Solape sobre el checkpoint para correos indexados tarde")
    parser.add_argument("--top", type=int, default=50, help="Tamaño de página de Graph")
    parser.add_argument("--staging", type=Path, default=Path("storage/graph_inbox"))
    parser.add_argument("--output", type=Path, default=Path("cases"))
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    args = parser.parse_args()

    missing = [name for name in REQUIRED_ENV if not (args.mailbox if name == "GRAPH_MAILBOX" else os.environ.get(name))]
    if missing:
        parser.error("Faltan variables de entorno: " + ", ".join(missing))
    if args.since:
        try:
            parse_utc(args.since)
        except ValueError:
            parser.error("--since debe ser ISO 8601, p. ej. 2026-11-01T00:00:00Z")

    client = GraphClient(os.environ["GRAPH_TENANT_ID"], os.environ["GRAPH_CLIENT_ID"], os.environ["GRAPH_CLIENT_SECRET"])
    try:
        summary = poll(client, args.mailbox, args.folder, args.staging, args.output, args.db,
                       args.since, args.lookback_hours, args.overlap_minutes, args.top)
    except GraphError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if summary["counts"].get("error") else 0


if __name__ == "__main__":
    # En Windows la salida redirigida usa cp1252 y falla con emojis en asuntos; se fuerza UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
