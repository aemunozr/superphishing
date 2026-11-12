#!/usr/bin/env python3
"""MSG -> EML + deterministic local evidence extraction. No network, no execution."""
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path

from common import (extract_domains, extract_html_evidence, extract_ips, extract_urls,
                    parse_raw_headers, safe_name, sha256_bytes, sha256_file,
                    sniff_file_type, write_json)
from case_store import create_case, get_case_by_hash
from static_scan import compact as compact_static_scan, scan_case
from remnux_stage import compact as compact_remnux_stage, stage_to_remnux

MAX_MSG_BYTES = 150 * 1024 * 1024
MAX_ATTACHMENTS = 200
MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 500 * 1024 * 1024
BODY_PREVIEW_CHARS = 2500


def getv(obj, *names, default=None):
    for name in names:
        try:
            value = getattr(obj, name)
            if callable(value):
                value = value()
            if value not in (None, ""):
                return value
        except Exception:
            pass
    return default


def as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for encoding in ("utf-8", "cp1252", "latin-1"):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                continue
        return value.decode("utf-8", "replace")
    return str(value)


def atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".part")
    shutil.copyfile(source, temp)
    temp.replace(target)


def extract_msg_to_eml(msg_path: Path, eml_path: Path, attachment_dir: Path) -> dict:
    try:
        import extract_msg
    except ImportError as exc:
        venv_python = r".venv\Scripts\python" if os.name == "nt" else ".venv/bin/python"
        raise RuntimeError("Falta extract-msg para convertir el MSG. Ejecuta el motor desde el venv del proyecto: "
                           f"{venv_python} -m pip install -r requirements.txt") from exc

    ole_tolerance_note = ""
    try:
        msg = extract_msg.Message(str(msg_path))
    except Exception as exc:
        # Algunos MSG (p. ej. generados por botones de reporte) tienen streams vacíos mal indexados.
        # Solo para defectos OLE se reintenta en modo tolerante y se deja constancia en el expediente.
        if type(exc).__name__ != "OleFileError":
            raise
        from extract_msg.enums import ErrorBehavior
        msg = extract_msg.Message(str(msg_path), errorBehavior=ErrorBehavior.OLE_DEFECT_INCORRECT)
        ole_tolerance_note = f" Parseo estricto falló ({exc}); se usó extract-msg con OLE_DEFECT_INCORRECT."
    try:
        subject = as_text(getv(msg, "subject", default=""))
        sender = as_text(getv(msg, "sender", default=""))
        to = as_text(getv(msg, "to", default=""))
        cc = as_text(getv(msg, "cc", default=""))
        bcc = as_text(getv(msg, "bcc", default=""))
        date_value = getv(msg, "date")
        body = as_text(getv(msg, "body", default=""))
        html_body = as_text(getv(msg, "htmlBody", "html_body", default=""))
        raw_headers = as_text(getv(msg, "header", "headers", default=""))

        eml = EmailMessage(policy=policy.SMTP)
        for header, value in (("Subject", subject), ("From", sender), ("To", to), ("Cc", cc), ("Bcc", bcc)):
            if value:
                try:
                    eml[header] = value
                except Exception:
                    pass
        if date_value:
            try:
                dt = date_value if isinstance(date_value, datetime) else parsedate_to_datetime(str(date_value))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                eml["Date"] = format_datetime(dt)
            except Exception:
                pass
        if html_body:
            eml.set_content(body or "HTML body disponible; consultar alternativa HTML.")
            eml.add_alternative(html_body, subtype="html")
        else:
            eml.set_content(body)

        attachment_dir.mkdir(parents=True, exist_ok=True)
        attachment_rows = []
        attachments = list(getv(msg, "attachments", default=[]) or [])
        if len(attachments) > MAX_ATTACHMENTS:
            raise RuntimeError(f"Cantidad de adjuntos supera el límite seguro ({MAX_ATTACHMENTS}).")
        total_size = 0
        for index, attachment in enumerate(attachments, 1):
            raw = getv(attachment, "data", default=b"")
            if not isinstance(raw, bytes):
                try:
                    raw = bytes(raw)
                except Exception:
                    raw = b""
            original_name = as_text(getv(attachment, "longFilename", "shortFilename", "filename", default=f"attachment_{index}.bin"))
            filename = safe_name(original_name, f"attachment_{index}.bin")
            digest = sha256_bytes(raw)
            total_size += len(raw)
            base = {"index": index, "original_name": original_name, "stored_name": None,
                    "size": len(raw), "sha256": digest}
            if len(raw) > MAX_ATTACHMENT_BYTES or total_size > MAX_TOTAL_ATTACHMENT_BYTES:
                attachment_rows.append({**base, "status": "omitted_size_limit", **sniff_file_type(raw[:32], filename)})
                continue
            stored_name = f"{index:03d}_{filename}"
            target = attachment_dir / stored_name
            temp = target.with_name(target.name + ".part")
            temp.write_bytes(raw)
            temp.replace(target)
            guessed, _ = mimetypes.guess_type(filename)
            maintype, subtype = guessed.split("/", 1) if guessed else ("application", "octet-stream")
            eml.add_attachment(raw, maintype=maintype, subtype=subtype, filename=filename)
            attachment_rows.append({**base, "stored_name": stored_name, "status": "extracted",
                                    "mime_guessed": guessed, **sniff_file_type(raw[:32], filename)})
        eml_path.parent.mkdir(parents=True, exist_ok=True)
        temp_eml = eml_path.with_name(eml_path.name + ".part")
        temp_eml.write_bytes(eml.as_bytes(policy=policy.SMTP))
        temp_eml.replace(eml_path)
        return {"subject": subject, "from": sender, "to": to, "cc": cc, "bcc": bcc,
                "date": as_text(date_value), "raw_headers": raw_headers, "body_text": body,
                "body_html": html_body, "attachments": attachment_rows,
                "original_headers": parse_raw_headers(raw_headers),
                "conversion_note": "EML reconstruido desde propiedades MSG expuestas por extract-msg; no equivale a una copia forense exacta del contenedor MAPI." + ole_tolerance_note}
    finally:
        try:
            msg.close()
        except Exception:
            pass


def extract_existing_eml(eml_source: Path, eml_target: Path, attachment_dir: Path) -> dict:
    """Reuse a collector-generated EML and extract its MIME attachments without reopening MSG."""
    if not eml_source.is_file() or eml_source.stat().st_size == 0:
        raise ValueError("El EML preexistente está vacío o no existe.")
    if eml_source.stat().st_size > MAX_MSG_BYTES:
        raise ValueError("El EML preexistente supera el límite de tamaño permitido.")
    atomic_copy(eml_source, eml_target)
    parsed = BytesParser(policy=policy.default).parsebytes(eml_target.read_bytes())
    attachment_dir.mkdir(parents=True, exist_ok=True)
    attachment_rows = []
    total_size = 0
    attachment_parts = [part for part in parsed.walk() if not part.is_multipart() and part.get_filename()]
    if len(attachment_parts) > MAX_ATTACHMENTS:
        raise RuntimeError(f"Cantidad de adjuntos supera el límite seguro ({MAX_ATTACHMENTS}).")
    for index, part in enumerate(attachment_parts, 1):
        raw = part.get_payload(decode=True) or b""
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        original_name = as_text(part.get_filename()) or f"attachment_{index}.bin"
        filename = safe_name(original_name, f"attachment_{index}.bin")
        digest = sha256_bytes(raw)
        total_size += len(raw)
        base = {"index": index, "original_name": original_name, "stored_name": None,
                "size": len(raw), "sha256": digest}
        if len(raw) > MAX_ATTACHMENT_BYTES or total_size > MAX_TOTAL_ATTACHMENT_BYTES:
            attachment_rows.append({**base, "status": "omitted_size_limit", **sniff_file_type(raw[:32], filename)})
            continue
        stored_name = f"{index:03d}_{filename}"
        target = attachment_dir / stored_name
        temp = target.with_name(target.name + ".part")
        temp.write_bytes(raw)
        temp.replace(target)
        attachment_rows.append({**base, "stored_name": stored_name, "status": "extracted",
                                "mime_declared": part.get_content_type(),
                                **sniff_file_type(raw[:32], filename)})
    return {
        "subject": as_text(parsed.get("Subject", "")),
        "from": as_text(parsed.get("From", "")),
        "to": as_text(parsed.get("To", "")),
        "cc": as_text(parsed.get("Cc", "")),
        "bcc": as_text(parsed.get("Bcc", "")),
        "date": as_text(parsed.get("Date", "")),
        "raw_headers": "",
        "attachments": attachment_rows,
        "original_headers": {},
        "conversion_note": "Se reutilizó el EML preexistente del colector tras validar su SHA-256 contra metadata.json; no se volvió a convertir el MSG.",
    }


def resolve_verified_collector_eml(source: Path, metadata_path: Path | None,
                                    source_metadata: dict, original_hash: str) -> Path | None:
    """Return an adjacent EML only when collector metadata binds it to the MSG and EML hashes."""
    hashes = source_metadata.get("hashes", {}) if isinstance(source_metadata, dict) else {}
    files = source_metadata.get("files", {}) if isinstance(source_metadata, dict) else {}
    expected_msg = str(hashes.get("sha256_msg", "")).lower()
    expected_eml = str(hashes.get("sha256_eml", "")).lower()
    if expected_msg and expected_msg != original_hash.lower():
        raise ValueError("El SHA-256 del MSG no coincide con metadata.json del colector.")
    if not metadata_path or not expected_eml or len(expected_eml) != 64:
        return None
    base_dir = metadata_path.resolve().parent
    candidates = []
    eml_relative = files.get("eml") if isinstance(files, dict) else None
    if isinstance(eml_relative, str) and eml_relative.strip():
        candidate = (base_dir / eml_relative).resolve()
        if base_dir == candidate or base_dir in candidate.parents:
            candidates.append(candidate)
    sibling = source.with_suffix(".eml").resolve()
    if sibling not in candidates and (base_dir == sibling or base_dir in sibling.parents):
        candidates.append(sibling)
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size <= MAX_MSG_BYTES:
            if sha256_file(candidate).lower() == expected_eml:
                return candidate
    return None


def extract_body_from_eml(eml_path: Path) -> tuple[dict, dict, str]:
    parsed = BytesParser(policy=policy.default).parsebytes(eml_path.read_bytes())
    header_names = ("From", "To", "Cc", "Reply-To", "Return-Path", "Sender", "Subject", "Date", "Message-ID", "Received", "Authentication-Results", "Received-SPF", "DKIM-Signature", "ARC-Authentication-Results")
    normalized_headers = {name: [str(v) for v in parsed.get_all(name, [])] for name in header_names if parsed.get_all(name, [])}
    text_parts, html_parts = [], []
    for part in parsed.walk():
        if part.is_multipart() or part.get_filename():
            continue
        content_type = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            content = ""
        if isinstance(content, bytes):
            content = content.decode("utf-8", "replace")
        if content_type == "text/plain":
            text_parts.append(str(content))
        elif content_type == "text/html":
            html_parts.append(str(content))
    text_content = "\n".join(text_parts)
    html_content = "\n".join(html_parts)
    return normalized_headers, {"text": text_content, "html": html_content}, parsed.get("Message-ID", "") or ""


def merge_iocs(rows: list[dict], key_field: str) -> list[dict]:
    merged = {}
    for row in rows:
        key = str(row.get(key_field, "")).casefold()
        if not key:
            continue
        if key not in merged:
            merged[key] = row
        else:
            for source in row.get("sources", []):
                if source not in merged[key].setdefault("sources", []):
                    merged[key]["sources"].append(source)
    return list(merged.values())


def make_summary(case_id: str, conversion: dict, normalized_headers: dict,
                 original_headers: dict, body: dict, urls: list[dict], ips: list[dict],
                 domains: list[dict], attachments: list[dict], original_hash: str,
                 eml_hash: str) -> dict:
    plain_text = body["text"]
    html_links, visible_html = extract_html_evidence(body["html"])
    visible = "\n".join([plain_text, visible_html]).strip()
    key_headers = {}
    for name in ("From", "Reply-To", "Return-Path", "Sender", "To", "Subject", "Date", "Message-ID", "Authentication-Results", "Received-SPF"):
        values = original_headers.get(name) or normalized_headers.get(name)
        if values:
            key_headers[name] = [str(value)[:500] for value in values[:2]]
    return {
        "case_id": case_id, "source_sha256": original_hash, "eml_sha256": eml_hash,
        "subject": conversion.get("subject", ""), "sender": conversion.get("from", ""),
        "date": conversion.get("date", ""), "key_headers": key_headers,
        "received_header_count": len(original_headers.get("Received", normalized_headers.get("Received", []))),
        "body_preview": visible[:BODY_PREVIEW_CHARS],
        "body_preview_truncated": len(visible) > BODY_PREVIEW_CHARS,
        "counts": {"urls": len(urls), "ips": len(ips), "domains": len(domains), "attachments": len(attachments)},
        "url_preview": [{"value": x["value"][:280], "host": x.get("host"), "sources": x.get("sources", [])} for x in urls[:10]],
        "attachment_preview": [{"name": x.get("original_name"), "size": x.get("size"),
                                "sha256": x.get("sha256"), "magic_type": x.get("magic_type"),
                                "status": x.get("status")} for x in attachments[:12]],
        "handling": {"network_used": False, "urls_opened": False, "attachments_executed": False,
                     "archive_contents_extracted": False},
    }


def process_case(source: Path, case_id: str | None, output: Path, db_path: Path,
                 source_metadata_path: Path | None = None) -> dict:
    source = source.resolve()
    if not source.is_file() or source.suffix.lower() != ".msg":
        raise ValueError("La entrada debe ser un archivo MSG existente.")
    if source.stat().st_size > MAX_MSG_BYTES:
        raise ValueError(f"MSG supera el límite de {MAX_MSG_BYTES // (1024*1024)} MiB")
    case_root = output.resolve()
    case_root.mkdir(parents=True, exist_ok=True)
    original_hash = sha256_file(source)
    source_metadata = {}
    if source_metadata_path:
        source_metadata = json.loads(source_metadata_path.read_text(encoding="utf-8"))
        if not isinstance(source_metadata, dict):
            raise ValueError("El archivo de metadatos de origen debe ser un objeto JSON")
    reusable_eml = resolve_verified_collector_eml(source, source_metadata_path, source_metadata, original_hash)
    existing = get_case_by_hash(db_path, original_hash)
    if existing:
        raise FileExistsError(f"MSG duplicado: ya existe {existing['case_id']} ({existing['case_path']}). No se creó otro caso.")
    now_utc = datetime.now(timezone.utc)
    generated_id = f"CASE-{now_utc:%Y%m%d-%H%M%S}-{original_hash[:8]}"
    chosen_id = safe_name(case_id or generated_id, "case")
    # Los expedientes se agrupan por fecha de creación (UTC): cases/AAAA/MM/DD/CASE-...
    case_root = case_root / f"{now_utc:%Y}" / f"{now_utc:%m}" / f"{now_utc:%d}"
    case_root.mkdir(parents=True, exist_ok=True)
    final_case = case_root / chosen_id
    if final_case.exists():
        raise FileExistsError(f"El expediente ya existe y no se sobrescribe: {final_case}")
    stage_case = case_root / f".{chosen_id}.{uuid.uuid4().hex}.part"
    try:
        for folder in ("original", "normalized", "extracted", "attachments", "analysis", "report"):
            (stage_case / folder).mkdir(parents=True, exist_ok=True)
        original_target = stage_case / "original" / safe_name(source.name, "original.msg")
        atomic_copy(source, original_target)
        normalized_target = stage_case / "normalized" / "message.eml"
        if reusable_eml:
            conversion = extract_existing_eml(reusable_eml, normalized_target, stage_case / "attachments")
        else:
            conversion = extract_msg_to_eml(original_target, normalized_target, stage_case / "attachments")
        normalized_headers, body, _ = extract_body_from_eml(normalized_target)
        original_headers = conversion.get("original_headers", {})
        # Prefer original transport headers exposed by the MSG parser; keep reconstructed headers separately.
        headers_bundle = {"original_msg_headers": original_headers,
                          "normalized_eml_headers": normalized_headers,
                          "header_source_note": "Los headers originales solo están disponibles cuando extract-msg los expone."}
        header_values = []
        for header_map in (original_headers, normalized_headers):
            for values in header_map.values():
                header_values.extend(str(value) for value in values)
        message_properties = [conversion.get(key, "") for key in ("subject", "from", "to", "cc", "bcc")]
        analysis_text = "\n".join(
            [body["text"], body["html"], conversion.get("raw_headers", ""),
             *message_properties, *header_values]
        )
        html_links, visible_html = extract_html_evidence(body["html"])
        url_rows = extract_urls(body["text"], "body_text") + extract_urls(body["html"], "body_html")
        for link in html_links:
            url_rows.extend(extract_urls(link["value"], link["source"]))
        for name, values in original_headers.items():
            for value in values:
                url_rows.extend(extract_urls(str(value), f"original_header:{name}"))
        for name, values in normalized_headers.items():
            for value in values:
                url_rows.extend(extract_urls(str(value), f"normalized_header:{name}"))
        urls = merge_iocs(url_rows, "normalized_for_parsing")
        ip_rows = extract_ips(analysis_text, "message_body")
        for name, values in {**normalized_headers, **original_headers}.items():
            for value in values:
                ip_rows.extend(extract_ips(str(value), f"header:{name}"))
        ips = merge_iocs(ip_rows, "normalized")
        domains = extract_domains(analysis_text, urls, "message_body")
        attachments = conversion["attachments"]
        if source_metadata:
            write_json(stage_case / "source_metadata.json", source_metadata)
        write_json(stage_case / "extracted" / "headers.json", headers_bundle)
        write_json(stage_case / "extracted" / "msg_properties.json", {
            "subject": conversion.get("subject", ""), "from": conversion.get("from", ""),
            "to": conversion.get("to", ""), "cc": conversion.get("cc", ""),
            "bcc": conversion.get("bcc", ""), "date": conversion.get("date", ""),
            "raw_headers": conversion.get("raw_headers", ""),
            "conversion_note": conversion.get("conversion_note", "")})
        write_json(stage_case / "extracted" / "body.json", body)
        write_json(stage_case / "extracted" / "urls.json", urls)
        write_json(stage_case / "extracted" / "ips.json", ips)
        write_json(stage_case / "extracted" / "domains.json", domains)
        write_json(stage_case / "extracted" / "attachments.json", attachments)
        summary = make_summary(chosen_id, conversion, normalized_headers,
                               original_headers, body, urls, ips, domains, attachments, original_hash,
                               sha256_file(stage_case / "normalized" / "message.eml"))
        if attachments:
            # Escaneo local determinístico: el agente lee solo el resumen compacto.
            static_report = scan_case(stage_case)
            write_json(stage_case / "extracted" / "static_scan.json", static_report)
            summary["static_scan"] = compact_static_scan(static_report)
        remnux_report = None
        if attachments and static_report.get("escalate_to_remnux"):
            # Antes de READY: el agente encuentra la muestra ya en REMnux. Un fallo nunca aborta la ingesta.
            try:
                remnux_report = stage_to_remnux(stage_case, case_id=chosen_id)
            except Exception as exc:
                remnux_report = {"status": "error", "mode": None, "files": [], "detail": str(exc)[:400]}
                write_json(stage_case / "extracted" / "remnux_stage.json", remnux_report)
            summary["remnux_stage"] = compact_remnux_stage(remnux_report)
        write_json(stage_case / "summary.json", summary)
        eml_hash = sha256_file(stage_case / "normalized" / "message.eml")
        fingerprint_paths = {
            "triage": stage_case / "summary.json",
            "url_analysis": stage_case / "extracted" / "urls.json",
            "static_analysis": stage_case / "extracted" / "attachments.json",
            "reverse_engineering": stage_case / "extracted" / "attachments.json",
            "dynamic_analysis": stage_case / "extracted" / "attachments.json",
        }
        fingerprints = {name: sha256_file(path) for name, path in fingerprint_paths.items()}
        ioc_material = ((stage_case / "extracted" / "ips.json").read_bytes() +
                        (stage_case / "extracted" / "domains.json").read_bytes())
        fingerprints["ioc_analysis"] = sha256_bytes(ioc_material)
        fingerprints["ingestion"] = original_hash
        fingerprints["extraction"] = original_hash
        manifest = {
            "schema_version": "2.0", "case_id": chosen_id,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": {"ingestion": "completed", "extraction": "completed", "triage": "pending",
                       "url_analysis": "pending" if urls else "not_applicable",
                       "ioc_analysis": "pending" if (ips or domains) else "not_applicable",
                       "static_analysis": "pending" if attachments else "not_applicable",
                       "reverse_engineering": "pending" if any(item.get("magic_type") in {"pe_or_dos_executable", "elf_executable"} for item in attachments) else "not_applicable",
                       "dynamic_analysis": "not_applicable", "report": "pending"},
            "source": {"original_msg": f"original/{original_target.name}", "size": original_target.stat().st_size, "sha256": original_hash},
            "normalized": {"eml": "normalized/message.eml", "sha256": eml_hash,
                           "source": "collector_verified" if reusable_eml else "generated_from_msg",
                           "note": conversion.get("conversion_note", "")},
            "artifacts": {"summary": "summary.json", "headers": "extracted/headers.json",
                          "body": "extracted/body.json", "urls": "extracted/urls.json",
                          "ips": "extracted/ips.json", "domains": "extracted/domains.json",
                          "attachments": "extracted/attachments.json",
                          **({"static_scan": "extracted/static_scan.json"} if attachments else {}),
                          **({"remnux_stage": "extracted/remnux_stage.json"} if remnux_report else {})},
            "counts": {"urls": len(urls), "ips": len(ips), "domains": len(domains), "attachments": len(attachments)},
            "fingerprints": fingerprints,
            "safety": {"network_used": bool(remnux_report and remnux_report.get("mode") == "scp"
                                            and remnux_report.get("status") in ("staged", "partial", "error")),
                       "attachments_executed": False, "urls_opened": False,
                       "archive_extraction_performed": False,
                       "remnux_staging": (remnux_report or {}).get("status", "not_applicable")},
        }
        write_json(stage_case / "case.json", manifest)
        created_utc = manifest["created_utc"]
        stage_rows = {}
        stage_notes = {
            "ingestion": "MSG original preservado y hash calculado por el motor local.",
            "extraction": "EML normalizado y artefactos extraídos localmente.",
            "triage": "Pendiente de evaluación del agente.",
            "url_analysis": "Pendiente solo si existen URLs.",
            "ioc_analysis": "Pendiente solo si existen IPs o dominios.",
            "static_analysis": "Pendiente solo si existen adjuntos.",
            "reverse_engineering": "Pendiente solo si existe un binario que lo justifique.",
            "dynamic_analysis": "No se ejecuta por defecto; requiere autorización específica y laboratorio aislado.",
            "report": "Pendiente de cierre del análisis.",
        }
        for stage_name, stage_status in manifest["status"].items():
            stage_rows[stage_name] = {
                "status": stage_status,
                "input_fingerprint": fingerprints.get(stage_name, ""),
                "note": stage_notes.get(stage_name, ""),
                "updated_utc": created_utc,
                "started_utc": created_utc if stage_status == "completed" else None,
                "completed_utc": created_utc if stage_status == "completed" else None,
                "authorization_reference": "",
            }
        write_json(stage_case / "analysis" / "state.json", {
            "schema_version": "1.0", "case_id": chosen_id,
            "created_utc": created_utc, "updated_utc": created_utc,
            "verdict": "pending", "severity": "unknown", "confidence": "unknown",
            "finalized": False, "stages": stage_rows,
        })
        write_json(stage_case / "analysis" / "findings.json", {
            "schema_version": "1.0", "case_id": chosen_id, "findings": []
        })
        (stage_case / "READY").write_text("ingestion and extraction complete\n", encoding="utf-8")
        stage_case.replace(final_case)
        try:
            create_case(db_path, {
                "case_id": chosen_id, "case_path": str(final_case), "source_sha256": original_hash,
                "subject": conversion.get("subject", ""), "sender": conversion.get("from", ""),
                "metadata": source_metadata, "url_count": len(urls),
                "ioc_count": len(ips) + len(domains), "attachment_count": len(attachments),
                "binary_count": sum(1 for item in attachments if item.get("magic_type") in {"pe_or_dos_executable", "elf_executable"})})
        except Exception:
            shutil.rmtree(final_case, ignore_errors=True)
            raise
        return {"case_id": chosen_id, "case_path": str(final_case), "source_sha256": original_hash,
                "eml_sha256": eml_hash, "counts": manifest["counts"], "status": manifest["status"]}
    except Exception:
        if stage_case.exists():
            shutil.rmtree(stage_case, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingesta un MSG, crea un expediente y extrae evidencias localmente sin IA ni red.")
    parser.add_argument("msg", type=Path, help="Correo MSG descargado previamente")
    parser.add_argument("--case-id", help="ID opcional del expediente")
    parser.add_argument("--output", type=Path, default=Path("cases"), help="Raíz de expedientes")
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"), help="Base SQLite de tracking")
    parser.add_argument("--source-metadata", type=Path, help="JSON opcional con metadatos del colector de correo")
    args = parser.parse_args()
    try:
        result = process_case(args.msg, args.case_id, args.output, args.db, args.source_metadata)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
