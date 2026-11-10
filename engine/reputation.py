#!/usr/bin/env python3
"""Reputación determinística en VirusTotal (API v3, solo lectura) con caché local.

Consulta únicamente IOC de contexto de un expediente:
  - SHA-256 de adjuntos (se omiten imágenes salvo --include-images),
  - dominio del remitente y Return-Path,
  - URLs clicables (a.href / texto) y sus hosts,
excluyendo la infraestructura propia, proveedores de correo y servicios masivos.

Solo hace GET (files/domains/urls): nunca sube archivos ni solicita escaneos, así
que no alerta al atacante. Cada IOC se cachea en storage/cases.db para no repetir
consultas entre expedientes. El resultado compacto queda en
extracted/reputation.json; el agente lee ese resumen y no consume tokens en la consulta.

Credencial: VT_API_KEY (entorno o --env-file .env).
"""
from __future__ import annotations

import argparse
import base64
import glob
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional, Tuple
from urllib.parse import urlsplit

from case_store import db_session
from common import write_json
from graph_import import load_env_file

VT_ROOT = "https://www.virustotal.com/api/v3"
SCHEMA_VERSION = "1.0"
HTTP_TIMEOUT = 30
FOUND_TTL = timedelta(days=7)
NOT_FOUND_TTL = timedelta(days=1)
MAX_HASHES = 10
MAX_URLS = 5
LOW_RISK_MAGIC = {"png", "jpeg", "gif"}
CLICKABLE_SOURCES = ("html:a.href", "html:area.href", "html:form.action", "body_text")
# Reputación de dominio sin valor: infraestructura propia, correo gratuito y plataformas masivas.
SKIP_DOMAINS = (
    "itau.cl", "iphmx.com", "outlook.com", "office.com", "office365.com", "microsoft.com",
    "google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "share.google",
    "hotmail.com", "live.com", "yahoo.com", "icloud.com", "126.com", "163.com", "qq.com",
    # Plataformas de envío masivo (ESP): aparecen en Return-Path de cualquier campaña legítima.
    "amazonses.com", "sendgrid.net", "mailchimpapp.net", "mcsv.net", "mandrillapp.com", "sparkpostmail.com",
    "mailgun.org", "mailjet.com", "sendinblue.com", "brevo.com", "exacttarget.com", "salesforce.com",
    "hubspotemail.net", "constantcontact.com", "rsgsv.net", "cmail19.com", "cmail20.com",
)
# URLs que no se consultan (recursos estáticos o infraestructura propia).
SKIP_URL_HOSTS = ("itau.cl", "iphmx.com", "googleusercontent.com", "gstatic.com")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})")

Transport = Callable[[str, dict], Tuple[int, bytes]]


class VTError(RuntimeError):
    pass


class QuotaExceeded(VTError):
    pass


def urllib_transport(url: str, headers: dict) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read(4 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(64 * 1024)


def _matches(host: str, suffixes: tuple) -> bool:
    return any(host == item or host.endswith("." + item) for item in suffixes)


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def collect_indicators(case_dir: Path, include_images: bool = False) -> list[dict]:
    """IOC de contexto, deduplicados y acotados. No incluye direcciones de correo ni datos personales."""
    summary = _load(case_dir / "summary.json", {})
    attachments = _load(case_dir / "extracted" / "attachments.json", [])
    urls = _load(case_dir / "extracted" / "urls.json", [])
    rows, seen = [], set()

    def add(kind: str, ioc: str, context: str) -> None:
        if (kind, ioc) not in seen:
            seen.add((kind, ioc))
            rows.append({"kind": kind, "ioc": ioc, "context": context})

    for item in attachments:
        sha = str(item.get("sha256") or "").lower()
        if len(sha) != 64 or (not include_images and item.get("magic_type") in LOW_RISK_MAGIC):
            continue
        if sum(r["kind"] == "file" for r in rows) < MAX_HASHES:
            add("file", sha, f"attachment:{item.get('original_name')}")

    senders = [summary.get("sender", "")] + list((summary.get("key_headers") or {}).get("Return-Path", []))
    for value in senders:
        for domain in EMAIL_RE.findall(str(value)):
            domain = domain.lower().rstrip(".")
            if not _matches(domain, SKIP_DOMAINS):
                add("domain", domain, "sender")

    url_count = 0
    for item in urls:
        if not any(src in CLICKABLE_SOURCES for src in item.get("sources", [])):
            continue
        value = html.unescape(str(item.get("normalized_for_parsing") or item.get("value") or ""))
        try:
            host = (urlsplit(value).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host or _matches(host, SKIP_URL_HOSTS):
            continue
        if url_count < MAX_URLS and ("url", value) not in seen:
            add("url", value, "link")
            url_count += 1
        domain = host[4:] if host.startswith("www.") else host
        if not _matches(domain, SKIP_DOMAINS):
            add("domain", domain, "link_host")
    return rows


# --- Caché en la SQLite de casos ---

def init_cache(db_path: Path) -> None:
    with db_session(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS vt_cache (
            kind TEXT NOT NULL, ioc TEXT NOT NULL, status TEXT NOT NULL,
            result_json TEXT NOT NULL DEFAULT '{}', fetched_utc TEXT NOT NULL,
            PRIMARY KEY (kind, ioc))""")


def cache_get(db_path: Path, kind: str, ioc: str, now: datetime) -> Optional[dict]:
    with db_session(db_path) as con:
        row = con.execute("SELECT status, result_json, fetched_utc FROM vt_cache WHERE kind=? AND ioc=?",
                          (kind, ioc)).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_utc"])
    ttl = FOUND_TTL if row["status"] == "found" else NOT_FOUND_TTL
    if now - fetched > ttl:
        return None
    return {"status": row["status"], "result": json.loads(row["result_json"]), "fetched_utc": row["fetched_utc"]}


def cache_put(db_path: Path, kind: str, ioc: str, status: str, result: dict, now: datetime) -> None:
    with db_session(db_path) as con:
        con.execute("""INSERT INTO vt_cache (kind, ioc, status, result_json, fetched_utc) VALUES (?,?,?,?,?)
            ON CONFLICT(kind, ioc) DO UPDATE SET status=excluded.status, result_json=excluded.result_json,
            fetched_utc=excluded.fetched_utc""",
                    (kind, ioc, status, json.dumps(result, ensure_ascii=False), now.isoformat(timespec="seconds")))


# --- Cliente VirusTotal ---

def _ts(value) -> Optional[str]:
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def summarize(kind: str, payload: dict) -> dict:
    """Reduce la respuesta de VT a los campos útiles para decidir (pocos tokens)."""
    attr = (payload.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    out = {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": attr.get("reputation"),
        "tags": list(attr.get("tags") or [])[:5],
        "last_analysis_utc": _ts(attr.get("last_analysis_date")),
    }
    categories = sorted(set((attr.get("categories") or {}).values()))[:3]
    if categories:
        out["categories"] = categories
    if kind == "file":
        out["type"] = attr.get("type_description")
        out["first_seen_utc"] = _ts(attr.get("first_submission_date"))
        label = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            out["threat_label"] = label
    elif kind == "url":
        out["first_seen_utc"] = _ts(attr.get("first_submission_date"))
        final_url = attr.get("last_final_url")
        if final_url and final_url != attr.get("url"):
            out["final_url"] = final_url  # destino observado por VT, no por nosotros
    else:
        out["created_utc"] = _ts(attr.get("creation_date"))
        if attr.get("registrar"):
            out["registrar"] = attr.get("registrar")
    return out


def endpoint(kind: str, ioc: str) -> str:
    if kind == "file":
        return f"{VT_ROOT}/files/{ioc}"
    if kind == "domain":
        return f"{VT_ROOT}/domains/{urllib.parse.quote(ioc, safe='')}"
    if kind == "url":
        return f"{VT_ROOT}/urls/{base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')}"
    raise ValueError(f"Tipo de IOC no soportado: {kind}")


class VTClient:
    def __init__(self, api_key: str, transport: Transport = urllib_transport, min_interval: float = 15.0,
                 sleep=time.sleep, clock=time.monotonic):
        self._key = api_key
        self._transport = transport
        self._min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._last = None
        self.requests = 0

    def lookup(self, kind: str, ioc: str) -> tuple[str, dict]:
        if self._last is not None:
            wait = self._min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        status, body = self._transport(endpoint(kind, ioc), {"x-apikey": self._key, "Accept": "application/json"})
        self._last = self._clock()
        self.requests += 1
        if status == 200:
            return "found", summarize(kind, json.loads(body))
        if status == 404:
            return "not_found", {}
        if status == 429:
            raise QuotaExceeded("Cuota de VirusTotal agotada (HTTP 429).")
        if status in (401, 403):
            raise VTError(f"VirusTotal rechazó la credencial (HTTP {status}).")
        return "error", {"http_status": status}


def classify(status: str, result: dict, kind: str = "file") -> str:
    if status == "found":
        malicious, suspicious = result.get("malicious", 0), result.get("suspicious", 0)
        if malicious >= 3:
            return "malicious"
        # En dominios, una única detección aislada es ruido habitual (listas de spam, CDN, ESP).
        threshold = 2 if kind == "domain" else 1
        if malicious >= threshold or suspicious >= threshold:
            return "suspicious"
        return "no_detections"
    return {"not_found": "unknown", "deferred": "pending"}.get(status, "error")


def enrich_case(case_dir: Path, client: Optional[VTClient], db_path: Path, now: Optional[datetime] = None,
                include_images: bool = False) -> dict:
    now = now or datetime.now(timezone.utc)
    init_cache(db_path)
    rows, quota_hit = [], False
    for indicator in collect_indicators(case_dir, include_images):
        kind, ioc = indicator["kind"], indicator["ioc"]
        cached = cache_get(db_path, kind, ioc, now)
        if cached:
            status, result, source = cached["status"], cached["result"], "cache"
        elif client is None or quota_hit:
            status, result, source = "deferred", {}, "none"
        else:
            try:
                status, result = client.lookup(kind, ioc)
                source = "api"
            except QuotaExceeded:
                quota_hit = True
                status, result, source = "deferred", {}, "none"
            if status in ("found", "not_found"):
                cache_put(db_path, kind, ioc, status, result, now)
        rows.append({**indicator, "status": status, "verdict": classify(status, result, kind), "source": source, **result})

    def pick(verdict: str) -> list:
        return [row["ioc"] for row in rows if row["verdict"] == verdict]

    report = {
        "schema_version": SCHEMA_VERSION,
        "provider": "virustotal_api_v3_read_only",
        "queried_utc": now.isoformat(timespec="seconds"),
        "summary": {"malicious": pick("malicious"), "suspicious": pick("suspicious"),
                    "unknown": len(pick("unknown")), "no_detections": len(pick("no_detections")),
                    "pending": len(pick("pending")), "errors": len(pick("error")),
                    "quota_exceeded": quota_hit},
        "indicators": rows,
    }
    write_json(case_dir / "extracted" / "reputation.json", report)
    return report


def compact(report: dict) -> dict:
    return {"summary": report["summary"],
            "indicators": [{"kind": r["kind"], "ioc": r["ioc"][:90], "verdict": r["verdict"],
                            **({"mal": r["malicious"]} if r.get("malicious") else {}),
                            **({"final_url": r["final_url"][:90]} if r.get("final_url") else {})}
                           for r in report["indicators"]]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Reputación VirusTotal (solo lectura, con caché) de expedientes.")
    parser.add_argument("case_dir", type=Path, nargs="+", help="Directorio(s) de expediente en cases/")
    parser.add_argument("--env-file", type=Path, help="Archivo KEY=VALUE del que cargar VT_API_KEY")
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    parser.add_argument("--min-interval", type=float, default=15.0,
                        help="Segundos entre consultas (15 = límite de la API pública, 4/min)")
    parser.add_argument("--include-images", action="store_true", help="Consulta también hashes de imágenes")
    parser.add_argument("--offline", action="store_true", help="Usa solo la caché; no consulta la API")
    args = parser.parse_args()

    if args.env_file:
        if not args.env_file.is_file():
            parser.error(f"No existe el archivo de entorno {args.env_file}")
        load_env_file(args.env_file, prefixes=("VT_",))
    client = None
    if not args.offline:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            parser.error("Falta VT_API_KEY (entorno o --env-file).")
        client = VTClient(api_key, min_interval=args.min_interval)

    # cmd.exe no expande comodines: se resuelven aquí para que funcione igual en Windows, macOS y Linux.
    case_dirs = []
    for item in args.case_dir:
        matches = sorted(Path(p) for p in glob.glob(str(item))) if glob.has_magic(str(item)) else [item]
        case_dirs.extend(p for p in matches if p.is_dir())

    status = 0
    for case_dir in case_dirs:
        try:
            report = enrich_case(case_dir, client, args.db, include_images=args.include_images)
        except VTError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"ERROR {case_dir}: {exc}", file=sys.stderr)
            status = 1
            continue
        print(json.dumps({"case": case_dir.name, **compact(report)}, ensure_ascii=False))
    if client:
        print(f"Consultas a la API: {client.requests}", file=sys.stderr)
    return status


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
