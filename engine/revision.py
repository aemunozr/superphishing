#!/usr/bin/env python3
"""Revisión del buzón de reportes por fechas (Microsoft Graph).

Ejemplos:
  revision.py 09-10                       # todo el día 9 de octubre
  revision.py 09-10 15-10                 # del 9 al 15 de octubre, ambos incluidos
  revision.py --desde 09-10 --hasta 15-10 # igual que el anterior
  revision.py --desde 01-11               # del 1 de noviembre hasta ahora
  revision.py 09-10 --listar              # solo lista, no descarga ni crea casos

Formatos de fecha: DD-MM, DD/MM, DD-MM-AAAA o AAAA-MM-DD. Las fechas se
interpretan en la zona horaria local (o --tz) y "hasta" incluye el día completo.
Con DD-MM se usa el año en curso; si esa fecha aún no ha llegado, el anterior.

Independiente del sondeo periódico: no modifica su checkpoint. Comparte el
registro de contenedores y la deduplicación por SHA-256, así que no crea
expedientes repetidos.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Optional, Tuple

from graph_import import (ENV_FILE_HELP, GRAPH_ROOT, REQUIRED_ENV, GraphClient, preload_env_file, GraphError, format_utc,
                          get_container, handle_container, init_poll_state, is_msg_candidate,
                          messages_url, quote, source_key, container_metadata)

DAY_MONTH = re.compile(r"^(\d{1,2})[-/](\d{1,2})$")
DAY_MONTH_YEAR = re.compile(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$")
ISO_DATE = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$")


def parse_day(value: str, today: date) -> date:
    text = value.strip()
    try:
        match = DAY_MONTH.match(text)
        if match:
            day, month = int(match.group(1)), int(match.group(2))
            candidate = date(today.year, month, day)
            return candidate if candidate <= today else date(today.year - 1, month, day)
        match = DAY_MONTH_YEAR.match(text)
        if match:
            return date(int(match.group(3)), int(match.group(2)), int(match.group(1)))
        match = ISO_DATE.match(text)
        if match:
            return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError as exc:
        raise ValueError(f"Fecha inválida '{value}': {exc}") from None
    raise ValueError(f"Formato de fecha no reconocido '{value}'. Usa DD-MM, DD-MM-AAAA o AAAA-MM-DD.")


def local_midnight(day: date, tz: Optional[tzinfo]) -> datetime:
    # Sin tz explícita se usan las reglas locales del sistema (respeta cambios de horario).
    return datetime.combine(day, time.min, tz) if tz else datetime.combine(day, time.min).astimezone()


def resolve_range(desde: Optional[str], hasta: Optional[str], tz: Optional[tzinfo],
                  now: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """Devuelve [inicio, fin) en UTC. 'hasta' incluye el día completo."""
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(tz).date()
    if not desde:
        raise ValueError("Indica al menos la fecha inicial (desde).")
    start = local_midnight(parse_day(desde, today), tz)
    end = local_midnight(parse_day(hasta, today) + timedelta(days=1), tz) if hasta else now
    if end <= start:
        raise ValueError("La fecha 'hasta' debe ser igual o posterior a 'desde'.")
    return start.astimezone(timezone.utc), min(end.astimezone(timezone.utc), now.astimezone(timezone.utc))


def list_msg_attachments(client: GraphClient, mailbox: str, message: dict) -> list:
    url = (f"{GRAPH_ROOT}/users/{quote(mailbox)}/messages/{quote(message['id'])}/attachments"
           "?$select=id,name,contentType,size,isInline")
    return [{"name": item.get("name"), "size": item.get("size"),
             "tipo": "msg" if is_msg_candidate(item) else
                     ("elemento_outlook" if item.get("@odata.type") == "#microsoft.graph.itemAttachment" else "otro")}
            for item in client.paged(url)]


def review(client: GraphClient, mailbox: str, folder: str, staging: Path, output: Path, db_path: Path,
           start_utc: datetime, end_utc: datetime, top: int = 50,
           reprocess: bool = False, dry_run: bool = False) -> dict:
    source = source_key(mailbox, folder)
    init_poll_state(db_path)
    results = []
    url = messages_url(mailbox, folder, format_utc(start_utc), top, until=format_utc(end_utc))
    for message in client.paged(url):
        known = get_container(db_path, source, message.get("id"))
        container = container_metadata(message)
        if dry_run:
            results.append({**container, "estado_previo": known["status"] if known else None,
                            "adjuntos": list_msg_attachments(client, mailbox, message)})
            continue
        if known and known["status"] in ("done", "failed") and not reprocess:
            results.append({"container": message.get("id"), "received_utc": container["received_utc"],
                            "status": "skipped_already_processed", "estado_previo": known["status"]})
            continue
        # Con --reprocesar se reinician los intentos; los MSG ya ingestados siguen deduplicados por hash.
        rows, _ = handle_container(client, mailbox, source, message, None if reprocess else known,
                                   staging, output, db_path)
        results.extend({**row, "received_utc": container["received_utc"]} for row in rows)

    counts: dict = {}
    for row in results:
        key = "listed" if dry_run else row["status"]
        counts[key] = counts.get(key, 0) + 1
    return {"mailbox": mailbox, "folder": folder, "desde_utc": format_utc(start_utc),
            "hasta_utc": format_utc(end_utc), "modo": "listar" if dry_run else "importar",
            "counts": counts, "results": results}


def main() -> int:
    if not preload_env_file():
        return 2
    parser = argparse.ArgumentParser(
        description="Revisa el buzón de reportes por fechas e importa los MSG adjuntos.",
        epilog="Ejemplos: revision.py 09-10 | revision.py 09-10 15-10 | revision.py --desde 01-11 --listar")
    parser.add_argument("fechas", nargs="*", metavar="FECHA", help="Un día, o desde y hasta")
    parser.add_argument("--env-file", type=Path, help=ENV_FILE_HELP)
    parser.add_argument("--desde", help="Fecha inicial (incluida)")
    parser.add_argument("--hasta", help="Fecha final (incluida); por defecto hasta ahora")
    parser.add_argument("--listar", action="store_true", help="Solo lista correos y adjuntos; no descarga ni crea casos")
    parser.add_argument("--reprocesar", action="store_true", help="Revisa también contenedores ya procesados o fallidos")
    parser.add_argument("--tz", help="Zona horaria IANA para interpretar las fechas (por defecto la del sistema)")
    parser.add_argument("--mailbox", default=os.environ.get("GRAPH_MAILBOX"))
    parser.add_argument("--folder", default=os.environ.get("GRAPH_FOLDER") or "inbox")
    parser.add_argument("--top", type=int, default=50)
    parser.add_argument("--staging", type=Path, default=Path("storage/graph_inbox"))
    parser.add_argument("--output", type=Path, default=Path("cases"))
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    args = parser.parse_args()

    if len(args.fechas) > 2:
        parser.error("Indica como máximo dos fechas posicionales: desde y hasta.")
    if args.fechas and (args.desde or args.hasta):
        parser.error("Usa fechas posicionales o --desde/--hasta, no ambas.")
    if len(args.fechas) == 1:
        desde = hasta = args.fechas[0]
    elif len(args.fechas) == 2:
        desde, hasta = args.fechas
    else:
        desde, hasta = args.desde, args.hasta

    if args.tz:
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(args.tz)
        except Exception:
            parser.error(f"Zona horaria desconocida: {args.tz}")
    else:
        tz = None
    try:
        start_utc, end_utc = resolve_range(desde, hasta, tz)
    except ValueError as exc:
        parser.error(str(exc))

    missing = [name for name in REQUIRED_ENV if not (args.mailbox if name == "GRAPH_MAILBOX" else os.environ.get(name))]
    if missing:
        parser.error("Faltan variables de entorno: " + ", ".join(missing))

    print(f"Revisando {args.mailbox}/{args.folder} desde {start_utc.astimezone(tz):%Y-%m-%d %H:%M %Z} "
          f"hasta {end_utc.astimezone(tz):%Y-%m-%d %H:%M %Z}", file=sys.stderr)
    client = GraphClient(os.environ["GRAPH_TENANT_ID"], os.environ["GRAPH_CLIENT_ID"], os.environ["GRAPH_CLIENT_SECRET"])
    try:
        summary = review(client, args.mailbox, args.folder, args.staging, args.output, args.db,
                         start_utc, end_utc, args.top, args.reprocesar, args.listar)
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
