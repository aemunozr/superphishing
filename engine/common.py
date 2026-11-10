#!/usr/bin/env python3
"""Reusable deterministic parsing and evidence helpers."""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import mimetypes
import re
from email.parser import BytesParser
from email import policy
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"']+")
BARE_DOMAIN_RE = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])")
EMAIL_DOMAIN_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
WINDOWS_RESERVED_RE = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?$")
IPV6_RE = re.compile(r"(?<![0-9a-f:])[0-9a-f:]{2,}(?![0-9a-f:])", re.I)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: str | Path, data) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".part")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    temp.replace(target)


def safe_name(name: str, fallback: str = "artifact") -> str:
    leaf = (name or fallback).replace("\\", "/").split("/")[-1]
    leaf = re.sub(r"[^A-Za-z0-9._() -]+", "_", leaf).strip(" .")
    leaf = leaf[:140].rstrip(" .")
    # Nombres reservados de Windows (CON, NUL, COM1...) fallan aunque lleven extensión.
    if WINDOWS_RESERVED_RE.match(leaf):
        leaf = "_" + leaf
    return leaf or fallback


def defang_to_parse(value: str) -> str:
    value = value.strip()
    value = re.sub(r"(?i)^hxxps://", "https://", value)
    value = re.sub(r"(?i)^hxxp://", "http://", value)
    value = re.sub(r"(?i)\[\.\]|\(\.\)|\{\.\}", ".", value)
    value = re.sub(r"(?i)\[:\]", ":", value)
    return value


def _merge_source(record: dict, source: str) -> None:
    sources = record.setdefault("sources", [])
    if source not in sources:
        sources.append(source)


def extract_urls(text: str, source: str) -> list[dict]:
    rows: dict[str, dict] = {}
    for match in URL_RE.finditer(text or ""):
        raw = match.group(0).rstrip(".,;:!?)]}\"'")
        normalized = defang_to_parse(raw)
        candidate = "http://" + normalized if normalized.lower().startswith("www.") else normalized
        try:
            parts = urlsplit(candidate)
            host = (parts.hostname or "").lower().rstrip(".") or None
        except ValueError:
            host = None
        key = normalized.casefold()
        if key not in rows:
            rows[key] = {"value": raw, "normalized_for_parsing": candidate,
                         "host": host, "sources": [source]}
        else:
            _merge_source(rows[key], source)
    return list(rows.values())


def extract_ips(text: str, source: str) -> list[dict]:
    rows: dict[str, dict] = {}
    for regex in (IPV4_RE, IPV6_RE):
        for match in regex.finditer(text or ""):
            raw = match.group(0).strip("[](){}.,;:!\"'")
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError:
                continue
            normalized = parsed.compressed.lower()
            if normalized not in rows:
                rows[normalized] = {"value": raw, "normalized": normalized,
                                    "version": parsed.version,
                                    "scope": "global" if parsed.is_global else "private_or_special",
                                    "sources": [source]}
            else:
                _merge_source(rows[normalized], source)
    return list(rows.values())


def extract_domains(text: str, urls: list[dict], source: str) -> list[dict]:
    rows: dict[str, dict] = {}
    for item in urls:
        host = item.get("host")
        if host:
            rows.setdefault(host, {"value": host, "sources": []})
            for s in item.get("sources", [source]):
                _merge_source(rows[host], s)
    for match in EMAIL_DOMAIN_RE.finditer(text or ""):
        host = match.group(1).lower().rstrip(".")
        rows.setdefault(host, {"value": host, "sources": []})
        _merge_source(rows[host], source + ":email_address")
    # Bare domains are extracted from text but exclude common file suffixes and email fragments.
    for match in BARE_DOMAIN_RE.finditer(text or ""):
        host = match.group(0).lower().rstrip(".")
        rows.setdefault(host, {"value": host, "sources": []})
        _merge_source(rows[host], source + ":bare_domain")
    return list(rows.values())


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._skip_depth = 0
        self.visible_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for attr in ("href", "src", "action", "formaction"):
            value = attrs.get(attr)
            if value and isinstance(value, str) and value.strip().lower().startswith(("http://", "https://", "hxxp://", "hxxps://", "www.")):
                self.links.append({"value": value.strip(), "source": f"html:{tag}.{attr}"})
        if tag.lower() in {"script", "style", "noscript"}:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth and data.strip():
            self.visible_parts.append(data.strip())


def extract_html_evidence(content: str) -> tuple[list[dict], str]:
    parser = LinkParser()
    try:
        parser.feed(content or "")
        parser.close()
    except Exception:
        pass
    return parser.links, " ".join(parser.visible_parts)


def sniff_file_type(data: bytes, filename: str = "") -> dict:
    head = data[:16]
    signatures = [
        (b"MZ", "pe_or_dos_executable", "application/vnd.microsoft.portable-executable"),
        (b"%PDF-", "pdf", "application/pdf"),
        (b"PK\x03\x04", "zip_container", "application/zip"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole_compound", "application/x-ole-storage"),
        (b"{\\rtf", "rtf", "application/rtf"),
        (b"\x7fELF", "elf_executable", "application/x-elf"),
        (b"\x1f\x8b", "gzip", "application/gzip"),
        (b"Rar!\x1a\x07", "rar_container", "application/vnd.rar"),
        (b"7z\xbc\xaf\x27\x1c", "7z_container", "application/x-7z-compressed"),
        (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
        (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
        (b"GIF87a", "gif", "image/gif"),
        (b"GIF89a", "gif", "image/gif"),
    ]
    for signature, label, mime in signatures:
        if data.startswith(signature):
            return {"magic_type": label, "mime_detected": mime, "extension_mismatch_possible": bool(filename and mimetypes.guess_type(filename)[0] not in (None, mime))}
    guessed, _ = mimetypes.guess_type(filename)
    return {"magic_type": "unknown", "mime_detected": guessed or "application/octet-stream", "extension_mismatch_possible": False}


def parse_raw_headers(raw_headers: str) -> dict[str, list[str]]:
    if not raw_headers.strip():
        return {}
    try:
        msg = BytesParser(policy=policy.default).parsebytes((raw_headers.rstrip() + "\r\n\r\n").encode("utf-8", "replace"))
        result = {}
        for name in ("From", "To", "Cc", "Reply-To", "Return-Path", "Sender", "Subject", "Date", "Message-ID", "Received", "Authentication-Results", "Received-SPF", "DKIM-Signature", "ARC-Authentication-Results"):
            values = msg.get_all(name, [])
            if values:
                result[name] = [str(value) for value in values]
        return result
    except Exception:
        return {"_parse_error": ["No fue posible parsear los headers originales expuestos por el parser MSG."]}
