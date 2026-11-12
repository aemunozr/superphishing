#!/usr/bin/env python3
"""Escaneo estático local y determinístico de adjuntos (sin ejecutar, sin red).

Objetivo: resolver localmente la mayoría de adjuntos y dejar un resumen corto
(extracted/static_scan.json) que el agente pueda leer con pocos tokens. Solo los
adjuntos marcados como riesgo justifican escalar a REMnux.

Soporta PDF (solo librería estándar): normaliza nombres ofuscados (#xx), descomprime
streams FlateDecode con límites anti-bomba y busca JavaScript, acciones automáticas,
lanzamientos, URIs, formularios, archivos embebidos y cifrado.

Soporta SVG/HTML/XML como texto: scripts, manejadores de eventos, redirecciones,
decodificación base64 (atob), iframes, formularios y URLs externas. Nunca renderiza
ni ejecuta el contenido.

Los tipos que pueden llevar contenido activo y no tienen escáner local (ejecutables,
scripts, Office, contenedores, accesos directos) se marcan para escalar a REMnux.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import glob
import json
import re
import sys
import zlib
from pathlib import Path

from common import sha256_bytes, write_json

SCAN_VERSION = "1.1"
MAX_FILE_BYTES = 30 * 1024 * 1024
MAX_STREAM_OUT = 8 * 1024 * 1024        # por stream descomprimido
MAX_TOTAL_OUT = 64 * 1024 * 1024        # total descomprimido por archivo
MAX_STREAMS = 5000
MAX_URIS = 25

# Claves PDF relevantes. HIGH: capacidad activa; MEDIUM: interacción o contenido externo.
HIGH_KEYS = ("JavaScript", "JS", "Launch", "EmbeddedFile", "RichMedia", "XFA")
MEDIUM_KEYS = ("OpenAction", "AA", "SubmitForm", "ImportData", "GoToR", "GoToE", "AcroForm", "URI", "JBIG2Decode")
INFO_KEYS = ("Encrypt", "ObjStm", "Page")
ALL_KEYS = HIGH_KEYS + MEDIUM_KEYS + INFO_KEYS
RISKY_NAMES = frozenset(HIGH_KEYS + MEDIUM_KEYS)

NAME_HEX_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
NAME_RE = re.compile(rb"/[A-Za-z0-9#]+")
STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.S)
URI_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){1,2048})\)")
META_RE = {name: re.compile(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\)]){0,200})\)")
           for name in ("Producer", "Creator", "Author", "Title")}

# Marcado (SVG/HTML/XML). HIGH: capacidad de ejecutar o navegar sin intervención; REVIEW: enlaces externos.
MARKUP_HIGH = {
    "script": re.compile(r"<script\b", re.I),
    "event_handler": re.compile(r"\son[a-z]{3,20}\s*=", re.I),
    "javascript_uri": re.compile(r"javascript\s*:", re.I),
    "base64_decode": re.compile(r"\batob\s*\(", re.I),
    "dynamic_code": re.compile(r"\b(eval|Function|setTimeout|setInterval)\s*\(\s*['\"]|\bnew\s+Function\b|fromCharCode|unescape\s*\(|document\.write", re.I),
    "redirect": re.compile(r"location(\.href)?\s*=|location\.(replace|assign)\s*\(|window\.open\s*\(|http-equiv\s*=\s*['\"]?refresh", re.I),
    "iframe": re.compile(r"<i?frame\b|<embed\b|<object\b", re.I),
    "foreign_object": re.compile(r"<foreignObject\b", re.I),
    "form": re.compile(r"<form\b|<input\b[^>]*type\s*=\s*['\"]?password", re.I),
}
MARKUP_SNIFF_RE = re.compile(r"<svg\b|<html\b|<!doctype\s+html|<script\b|<body\b", re.I)
MARKUP_URL_RE = re.compile(r"https?://[^\s\"'<>()\\]{3,2048}", re.I)
ATOB_RE = re.compile(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=_-]{8,4096})['\"]\s*\)", re.I)
NAMESPACE_PREFIXES = ("http://www.w3.org/", "https://www.w3.org/", "http://purl.org/", "http://ns.adobe.com/",
                      "http://creativecommons.org/", "http://schemas.")

# Tipos sin escáner local que pueden contener contenido activo: se escalan a REMnux.
ACTIVE_MAGIC = frozenset({"pe_or_dos_executable", "elf_executable", "zip_container", "ole_compound", "rtf",
                          "gzip", "rar_container", "7z_container"})
ACTIVE_EXTENSIONS = frozenset({
    "exe", "dll", "scr", "com", "cpl", "msi", "msix", "appx", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "iso", "img", "vhd", "vhdx", "jar", "apk",
    "zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj",
    "doc", "docm", "dot", "dotm", "xls", "xlsm", "xlsb", "xlam", "ppt", "pptm", "ppam", "rtf", "one",
    "docx", "xlsx", "pptx", "chm", "reg",
})


def _normalize_names(data: bytes) -> tuple[bytes, int]:
    """Decodifica escapes #xx dentro de nombres PDF.

    Solo cuenta como ofuscación cuando el nombre decodificado es una clave de riesgo
    (p. ej. /J#61vaScript); los escapes en nombres de fuentes (/Arial#20Bold) son legítimos.
    """
    hits = 0

    def fix(match: re.Match) -> bytes:
        nonlocal hits
        token = match.group(0)
        if b"#" not in token:
            return token
        decoded = NAME_HEX_RE.sub(lambda m: bytes([int(m.group(1), 16)]), token)
        if decoded[1:].decode("latin-1") in RISKY_NAMES:
            hits += 1
        return decoded

    return NAME_RE.sub(fix, data), hits


def _inflate(raw: bytes, budget: int) -> bytes | None:
    """Descomprime zlib/deflate tolerando streams truncados, con límite de salida."""
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            engine = zlib.decompressobj(wbits)
            out = engine.decompress(raw, min(MAX_STREAM_OUT, budget))
            if out:
                return out
        except zlib.error:
            continue
    return None


def _count_keys(blob: bytes) -> dict[str, int]:
    counts = {}
    for key in ALL_KEYS:
        # Límite de nombre: evita contar /JS dentro de /JSON, /Page dentro de /Pages, etc.
        found = len(re.findall(rb"/" + key.encode() + rb"(?![A-Za-z0-9])", blob))
        if found:
            counts[key] = found
    return counts


def _decode_literal(raw: bytes) -> str:
    text = raw.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\", b"\\")
    if text.startswith(b"\xfe\xff"):
        return text[2:].decode("utf-16-be", "replace")
    return text.decode("latin-1", "replace")


def scan_pdf(data: bytes) -> dict:
    header = data[:1024]
    version_match = re.search(rb"%PDF-(\d\.\d)", header)
    normalized, obfuscated_names = _normalize_names(data)

    blobs, inflated, failed, total_out = [normalized], 0, 0, 0
    for index, match in enumerate(STREAM_RE.finditer(data)):
        if index >= MAX_STREAMS or total_out >= MAX_TOTAL_OUT:
            break
        out = _inflate(match.group(1), MAX_TOTAL_OUT - total_out)
        if out is None:
            failed += 1
            continue
        inflated += 1
        total_out += len(out)
        clean, stream_hits = _normalize_names(out)
        obfuscated_names += stream_hits
        blobs.append(clean)

    counts: dict[str, int] = {}
    uris: list[str] = []
    for blob in blobs:
        for key, value in _count_keys(blob).items():
            counts[key] = counts.get(key, 0) + value
        for raw_uri in URI_RE.findall(blob):
            uri = _decode_literal(raw_uri).strip()
            if uri and uri not in uris and len(uris) < MAX_URIS:
                uris.append(uri)

    metadata = {}
    for name, regex in META_RE.items():
        found = regex.search(normalized)
        if found:
            metadata[name.lower()] = _decode_literal(found.group(1))[:120]

    last_eof = data.rfind(b"%%EOF")
    trailing = len(data) - (last_eof + 5) if last_eof >= 0 else None
    flags = [key for key in HIGH_KEYS if counts.get(key)]
    review = [key for key in MEDIUM_KEYS if counts.get(key)]
    notes = []
    if obfuscated_names:
        flags.append("obfuscated_names")
    if trailing is not None and trailing > 32:
        review.append("data_after_eof")
    if counts.get("Encrypt"):
        notes.append("PDF cifrado: streams no inspeccionables localmente; análisis incompleto.")
    if failed:
        notes.append(f"{failed} streams no descomprimibles con Flate (otros filtros o datos binarios).")

    if flags:
        risk = "high"
    elif counts.get("Encrypt"):
        risk = "incomplete"
    elif review:
        risk = "review"
    else:
        risk = "low"
    return {
        "format": "pdf",
        "pdf_version": version_match.group(1).decode() if version_match else None,
        "pages": counts.get("Page", 0),
        "risk": risk,
        "flags": flags,
        "review": review,
        "keyword_counts": counts,
        "uris": uris,
        "metadata": metadata,
        "streams": {"inflated": inflated, "not_inflated": failed},
        "bytes_after_eof": trailing,
        "notes": notes,
    }


def scan_bytes(data: bytes, magic_type: str | None) -> dict:
    if magic_type == "pdf" or data.startswith(b"%PDF-"):
        return {"status": "scanned", **scan_pdf(data)}
    if magic_type in (None, "unknown") and is_markup(data):
        return {"status": "scanned", **scan_markup(data)}
    return {"status": "not_supported"}


def is_markup(data: bytes) -> bool:
    """SVG/HTML/XML reconocible por las primeras líneas (texto, sin firma binaria)."""
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").decode("utf-8", "ignore")
    return bool(head.startswith("<") and MARKUP_SNIFF_RE.search(head))


def _decode_atob(value: str) -> str | None:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_" if "-" in value or "_" in value else None)
        text = decoded.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if text.isprintable() else None


def scan_markup(data: bytes) -> dict:
    """Busca capacidades activas en SVG/HTML como texto. No renderiza ni ejecuta."""
    text = data.decode("utf-8", "ignore")
    lowered_head = text[:4096].lower()
    fmt = "svg" if "<svg" in lowered_head else "html" if ("<html" in lowered_head or "<!doctype html" in lowered_head) else "xml"
    flags = [name for name, regex in MARKUP_HIGH.items() if regex.search(text)]
    decoded = [d for d in (_decode_atob(m) for m in ATOB_RE.findall(text)) if d]
    uris = []
    for candidate in MARKUP_URL_RE.findall(text) + [d for d in decoded if d.lower().startswith(("http://", "https://"))]:
        candidate = candidate.rstrip(".,;")
        if candidate.startswith(NAMESPACE_PREFIXES) or candidate in uris:
            continue
        uris.append(candidate)
        if len(uris) >= MAX_URIS:
            break
    review = ["external_links"] if uris else []
    risk = "high" if flags else "review" if uris else "low"
    return {"format": fmt, "risk": risk, "flags": flags, "review": review, "uris": uris,
            "decoded_base64": decoded[:MAX_URIS], "size": len(data)}


def msg_attachment_bytes(case_dir: Path) -> tuple[dict[int, bytes], str | None]:
    """Lee los adjuntos en memoria desde el MSG original (verificado por SHA-256), sin escribir a disco.

    Sirve cuando un agente de endpoint (AV/EDR/DLP/CDR) reescribe los adjuntos al crearse en disco.
    Devuelve {índice (1..n, mismo orden que la ingesta): bytes} y un motivo si no fue posible.
    """
    try:
        manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        source = manifest["source"]
        msg_path = case_dir / source["original_msg"]
        if sha256_bytes(msg_path.read_bytes()) != str(source["sha256"]).lower():
            return {}, "msg_hash_mismatch"
    except (OSError, KeyError, ValueError):
        return {}, "msg_unavailable"
    try:
        import extract_msg
    except ImportError:
        return {}, "extract_msg_unavailable"
    try:
        try:
            msg = extract_msg.Message(str(msg_path))
        except Exception as exc:
            if type(exc).__name__ != "OleFileError":
                raise
            from extract_msg.enums import ErrorBehavior
            msg = extract_msg.Message(str(msg_path), errorBehavior=ErrorBehavior.OLE_DEFECT_INCORRECT)
        try:
            result = {}
            for index, attachment in enumerate(list(getattr(msg, "attachments", None) or []), 1):
                raw = getattr(attachment, "data", None)
                if isinstance(raw, (bytes, bytearray)):
                    result[index] = bytes(raw)
            return result, None
        finally:
            msg.close()
    except Exception as exc:  # parser de terceros: cualquier fallo deja el escaneo como incompleto
        return {}, f"msg_parse_error:{type(exc).__name__}"


def scan_case(case_dir: Path, msg_loader=msg_attachment_bytes) -> dict:
    """Escanea los adjuntos de extracted/attachments.json verificando su SHA-256.

    Si la copia en disco falta o no coincide con el hash de la ingesta, usa los bytes del MSG
    original en memoria y registra una alerta de integridad. No modifica artefactos existentes.
    """
    rows = json.loads((case_dir / "extracted" / "attachments.json").read_text(encoding="utf-8"))
    results, integrity_alerts = [], []
    msg_cache: dict | None = None
    msg_problem: str | None = None
    for row in rows:
        stored = row.get("stored_name")
        if not stored or row.get("status") != "extracted":
            continue
        expected = str(row.get("sha256") or "").lower()
        base = {"name": row.get("original_name"), "stored_name": stored, "sha256": expected or None}
        path = case_dir / "attachments" / stored
        data, integrity, origin = None, "ok", "disk"
        if not path.is_file():
            integrity = "disk_missing"
        elif path.stat().st_size > MAX_FILE_BYTES:
            results.append({**base, "status": "skipped_size_limit"})
            continue
        else:
            data = path.read_bytes()
            if expected and sha256_bytes(data) != expected:
                integrity, data = "disk_altered", None
        if data is None:
            if msg_cache is None:
                msg_cache, msg_problem = msg_loader(case_dir)
            candidate = msg_cache.get(int(row.get("index") or 0))
            if candidate is not None and (not expected or sha256_bytes(candidate) == expected):
                data, origin = candidate, "msg_original"
            integrity_alerts.append(base["name"])
        if data is None:
            results.append({**base, "status": "unverifiable", "integrity": integrity,
                            "detail": msg_problem or "adjunto no recuperable con hash coincidente"})
            continue
        result = {**base, "integrity": integrity, "origin": origin, **scan_bytes(data, row.get("magic_type"))}
        if result.get("status") == "not_supported" and _is_active_type(row):
            # Sin escáner local pero con posible contenido activo: lo resuelve REMnux, no se da por limpio.
            result.update({"escalate": True, "reason": "tipo con posible contenido activo sin escáner local"})
        results.append(result)
    order = {"high": 0, "incomplete": 1, "review": 2, "low": 3}
    scanned = [r for r in results if r.get("status") == "scanned"]
    overall = min((r["risk"] for r in scanned), key=lambda r: order[r], default="none")
    if (any(r.get("status") == "unverifiable" or r.get("escalate") for r in results)
            and order.get(overall, 9) > order["incomplete"]):
        overall = "incomplete"
    return {"scan_version": SCAN_VERSION, "overall_risk": overall,
            "scanned": len(scanned), "not_supported": sum(r.get("status") == "not_supported" for r in results),
            "integrity_alerts": integrity_alerts,
            "escalate_to_remnux": [r["name"] for r in results
                                   if r.get("risk") in ("high", "incomplete") or r.get("status") == "unverifiable"
                                   or r.get("escalate")],
            "files": results}


def _is_active_type(row: dict) -> bool:
    name = str(row.get("original_name") or row.get("stored_name") or "")
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return row.get("magic_type") in ACTIVE_MAGIC or extension in ACTIVE_EXTENSIONS


def compact(report: dict) -> dict:
    """Vista mínima para summary.json / consola: lo único que necesita leer el agente."""
    return {"overall_risk": report["overall_risk"], "scanned": report["scanned"],
            "integrity_alerts": report.get("integrity_alerts", []),
            "escalate_to_remnux": report["escalate_to_remnux"],
            "files": [{"name": r.get("name"), "risk": r.get("risk", r.get("status")),
                       "flags": r.get("flags", []), "review": r.get("review", []),
                       "uris": len(r.get("uris", []))}
                      for r in report["files"] if r.get("status") == "scanned" or r.get("escalate")]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Escaneo estático local de los adjuntos de un expediente.")
    parser.add_argument("case_dir", type=Path, nargs="+", help="Directorio(s) de expediente en cases/")
    parser.add_argument("--full", action="store_true", help="Imprime el informe completo en vez del compacto")
    parser.add_argument("--no-write", action="store_true", help="Solo imprime; no reescribe extracted/static_scan.json")
    args = parser.parse_args()
    # cmd.exe no expande comodines: se resuelven aquí (mismo comportamiento en Windows, macOS y Linux).
    case_dirs = []
    for item in args.case_dir:
        matches = sorted(Path(p) for p in glob.glob(str(item))) if glob.has_magic(str(item)) else [item]
        case_dirs.extend(p for p in matches if (p / "extracted" / "attachments.json").is_file())

    status = 0
    for case_dir in case_dirs:
        try:
            report = scan_case(case_dir)
        except (OSError, ValueError) as exc:
            print(f"ERROR {case_dir}: {exc}", file=sys.stderr)
            status = 1
            continue
        if not args.no_write:
            write_json(case_dir / "extracted" / "static_scan.json", report)
        print(json.dumps({"case": case_dir.name, **(report if args.full else compact(report))}, ensure_ascii=False))
    return status


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
