#!/usr/bin/env python3
"""Resumen de expedientes bajo una ruta: total, conteo por veredicto y tabla de correos.

Solo lectura y sin red. Recorre la ruta indicada, toma como expediente cada carpeta que tenga
summary.json y lee de ahí la fecha, el remitente y el asunto del correo reportado; el veredicto
sale de analysis/state.json (o "pending" si no existe) y la campaña de analysis/findings.json
(bloque "campaign": {"id", "name", "primary_case", "role", "basis"}). No modifica ningún expediente.

El informe avisa de los state.json/findings.json mal formados y de los casos phishing, malware o
fraud sin campaña; con --estricto, esos avisos devuelven código 1.

Ejemplos:
  case_report.py cases\\2026\\11
  case_report.py cases --desde 2026-11-01 --hasta 2026-11-30 --output storage\\resumen-noviembre.md
  case_report.py cases\\2026\\11 --formato tsv --incluir-caso
  case_report.py cases\\2026\\11 --incluir-campana --estricto
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter
from datetime import date, datetime
from pathlib import Path

# Orden de presentación: vocabulario fijo del proyecto y luego estados no finales.
VERDICT_ORDER = ["phishing", "malware", "fraud", "suspicious", "spam", "legitimate", "inconclusive", "pending"]
COLUMNS = ["Fecha", "Origen", "Asunto", "Veredicto"]


def _read_json(path: Path) -> dict:
    return _read_json_checked(path)[0]


def _read_json_checked(path: Path) -> tuple[dict, bool]:
    """(datos, inválido). Un archivo ausente no es inválido; uno ilegible o mal formado sí."""
    if not path.is_file():
        return {}, False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, True
    return (data, False) if isinstance(data, dict) else ({}, True)


def _clean(value) -> str:
    """Colapsa tabuladores, saltos de línea y espacios repetidos."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _parse_date(value: str) -> datetime | None:
    value = _clean(value)
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def find_case_dirs(root: Path) -> list[Path]:
    """Carpetas con summary.json bajo root (incluida root si es un expediente)."""
    root = Path(root)
    if (root / "summary.json").is_file():
        return [root]
    return sorted({p.parent for p in root.rglob("summary.json")
                   if not any(part.startswith(".") for part in p.parent.relative_to(root).parts)})


def _campaign(findings: dict) -> tuple[str, str, str]:
    """(id, nombre, rol) desde findings.json. Admite el bloque normalizado o un texto heredado."""
    value = findings.get("campaign")
    if isinstance(value, dict):
        return _clean(value.get("id")), _clean(value.get("name")), _clean(value.get("role")).lower()
    if isinstance(value, str):
        return _clean(value), "", ""
    return "", "", ""


def load_row(case_dir: Path) -> dict:
    summary = _read_json(case_dir / "summary.json")
    state = _read_json(case_dir / "analysis" / "state.json")
    state_path = case_dir / "analysis" / "state.json"
    findings_path = case_dir / "analysis" / "findings.json"
    findings, findings_bad = _read_json_checked(findings_path)
    _, state_bad = _read_json_checked(state_path)
    camp_id, camp_name, camp_role = _campaign(findings)
    raw_date = _clean(summary.get("date"))
    return {
        "case_id": _clean(summary.get("case_id")) or case_dir.name,
        "date": _parse_date(raw_date),
        "date_text": raw_date,
        "sender": _clean(summary.get("sender")),
        "subject": _clean(summary.get("subject")),
        "verdict": _clean(state.get("verdict")).lower() or "pending",
        "campaign": camp_id,
        "campaign_name": camp_name,
        "campaign_role": camp_role,
        "invalid_json": [p.name for p, bad in ((state_path, state_bad), (findings_path, findings_bad)) if bad],
    }


def collect(root: Path, desde: date | None = None, hasta: date | None = None) -> list[dict]:
    rows = [load_row(d) for d in find_case_dirs(root)]
    if desde or hasta:
        kept = []
        for row in rows:
            if row["date"] is None:
                continue  # sin fecha no se puede filtrar; se excluye y se informa en el resumen
            day = row["date"].date()
            if (desde and day < desde) or (hasta and day > hasta):
                continue
            kept.append(row)
        rows = kept
    # Sin fecha al final; con fecha, orden cronológico por el instante real (respeta la zona horaria).
    rows.sort(key=lambda r: (r["date"] is None, r["date"].timestamp() if r["date"] else 0, r["case_id"]))
    return rows


def count_verdicts(rows: list[dict]) -> list[tuple[str, int]]:
    counts = Counter(r["verdict"] for r in rows)
    ordered = [(v, counts[v]) for v in VERDICT_ORDER if counts.get(v)]
    ordered += sorted((v, n) for v, n in counts.items() if v not in VERDICT_ORDER)
    return ordered


def count_campaigns(rows: list[dict]) -> list[dict]:
    """Campañas con su nombre, caso principal (si consta) y correos por veredicto, ordenadas por ID."""
    groups: dict[str, dict] = {}
    for row in rows:
        if not row["campaign"]:
            continue
        group = groups.setdefault(row["campaign"], {"id": row["campaign"], "name": "", "primary": "",
                                                     "total": 0, "verdicts": Counter()})
        group["name"] = group["name"] or row["campaign_name"]
        if row["campaign_role"] == "primary":
            group["primary"] = row["case_id"]
        group["total"] += 1
        group["verdicts"][row["verdict"]] += 1
    return [groups[k] for k in sorted(groups)]


def _verdict_mix(counter: Counter) -> str:
    order = {v: i for i, v in enumerate(VERDICT_ORDER)}
    return ", ".join(f"{v} {n}" for v, n in sorted(counter.items(), key=lambda x: (order.get(x[0], 99), x[0])))


def _cells(row: dict, include_campaign: bool, include_case: bool) -> list[str]:
    cells = [_fmt_date(row), row["sender"], row["subject"], row["verdict"]]
    if include_campaign:
        cells.append(row["campaign"])
    if include_case:
        cells.append(row["case_id"])
    return cells


def _columns(include_campaign: bool, include_case: bool) -> list[str]:
    return COLUMNS + (["Campaña"] if include_campaign else []) + (["Caso"] if include_case else [])


def _fmt_date(row: dict) -> str:
    return row["date"].strftime("%Y-%m-%d %H:%M %z") if row["date"] else (row["date_text"] or "sin fecha")


def _md_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


MALICIOUS = ("phishing", "malware", "fraud")


def quality_issues(rows: list[dict]) -> dict:
    """Problemas de datos que el informe debe hacer visibles en lugar de ocultar."""
    return {
        "invalid_json": [(r["case_id"], ", ".join(r["invalid_json"])) for r in rows if r["invalid_json"]],
        "malicious_without_campaign": [r["case_id"] for r in rows if r["verdict"] in MALICIOUS and not r["campaign"]],
    }


def render_markdown(rows: list[dict], root: Path, include_case: bool = False, title: str | None = None,
                    include_campaign: bool = False) -> str:
    counts = count_verdicts(rows)
    total = len(rows)
    out = [f"# {title or 'Resumen de correos revisados'}", "",
           f"Ruta: `{root}`", "", "## Resumen", "", f"**Total de correos:** {total}", "",
           "| Veredicto | Correos | % |", "|---|---:|---:|"]
    for verdict, n in counts:
        out.append(f"| {verdict} | {n} | {n * 100 / total:.1f} |")
    undated = sum(1 for r in rows if r["date"] is None)
    if undated:
        out += ["", f"{undated} correo(s) sin fecha válida en summary.json, listados al final."]

    campaigns = count_campaigns(rows)
    if campaigns:
        out += ["", "## Campañas", "", f"**Campañas registradas:** {len(campaigns)}", "",
                "| Campaña | Nombre | Caso principal | Correos | Veredictos |", "|---|---|---|---:|---|"]
        for c in campaigns:
            out.append("| " + " | ".join(_md_cell(x) for x in (
                c["id"], c["name"], c["primary"] or "no consta", str(c["total"]), _verdict_mix(c["verdicts"]))) + " |")

    issues = quality_issues(rows)
    if issues["invalid_json"] or issues["malicious_without_campaign"]:
        out += ["", "## Avisos de calidad de datos", ""]
        for case_id, files in issues["invalid_json"]:
            out.append(f"- `{case_id}`: JSON mal formado o ilegible ({files}); sus datos de análisis no se leyeron.")
        if issues["malicious_without_campaign"]:
            out.append("- Casos phishing, malware o fraud sin campaña registrada: "
                       + ", ".join(f"`{c}`" for c in issues["malicious_without_campaign"]))

    columns = _columns(include_campaign, include_case)
    out += ["", "## Correos", "", "| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for row in rows:
        out.append("| " + " | ".join(_md_cell(c) for c in _cells(row, include_campaign, include_case)) + " |")
    return "\n".join(out) + "\n"


def render_delimited(rows: list[dict], delimiter: str, include_case: bool = False,
                     include_campaign: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\n")
    writer.writerow(_columns(include_campaign, include_case))
    for row in rows:
        writer.writerow(_cells(row, include_campaign, include_case))
    writer.writerow([])
    writer.writerow(["Total", len(rows)])
    for verdict, n in count_verdicts(rows):
        writer.writerow([verdict, n])
    campaigns = count_campaigns(rows)
    if campaigns:
        writer.writerow([])
        writer.writerow(["Campaña", "Nombre", "Caso principal", "Correos", "Veredictos"])
        for c in campaigns:
            writer.writerow([c["id"], c["name"], c["primary"], c["total"], _verdict_mix(c["verdicts"])])
    return buffer.getvalue()


def _parse_day(value: str | None, parser: argparse.ArgumentParser, name: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        parser.error(f"{name} debe tener formato AAAA-MM-DD")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Resume los expedientes de una ruta: total, conteo por veredicto y tabla de correos.")
    parser.add_argument("ruta", type=Path, help="Carpeta raíz (p. ej. cases\\2026\\11) o un expediente")
    parser.add_argument("--desde", help="Fecha del correo inicial, incluida (AAAA-MM-DD)")
    parser.add_argument("--hasta", help="Fecha del correo final, incluida (AAAA-MM-DD)")
    parser.add_argument("--formato", choices=["md", "tsv", "csv"], default="md")
    parser.add_argument("--incluir-caso", action="store_true", help="Añade la columna con el ID del expediente")
    parser.add_argument("--incluir-campana", action="store_true",
                        help="Añade la columna con el ID de campaña (findings.json → campaign.id)")
    parser.add_argument("--estricto", action="store_true",
                        help="Termina con código 1 si hay JSON inválidos o casos maliciosos sin campaña")
    parser.add_argument("--titulo", help="Título del informe Markdown")
    parser.add_argument("--output", type=Path, help="Archivo de salida (UTF-8); por defecto, la consola")
    args = parser.parse_args(argv)

    if not args.ruta.is_dir():
        parser.error(f"no existe la carpeta {args.ruta}")
    desde = _parse_day(args.desde, parser, "--desde")
    hasta = _parse_day(args.hasta, parser, "--hasta")
    if desde and hasta and hasta < desde:
        parser.error("--hasta debe ser igual o posterior a --desde")

    rows = collect(args.ruta, desde, hasta)
    if args.formato == "md":
        text = render_markdown(rows, args.ruta, args.incluir_caso, args.titulo, args.incluir_campana)
    else:
        text = render_delimited(rows, "\t" if args.formato == "tsv" else ",", args.incluir_caso,
                                args.incluir_campana)
    issues = quality_issues(rows)
    for case_id, files in issues["invalid_json"]:
        print(f"AVISO {case_id}: JSON inválido ({files})", file=sys.stderr)
    if issues["malicious_without_campaign"]:
        print(f"AVISO {len(issues['malicious_without_campaign'])} caso(s) maliciosos sin campaña: "
              + ", ".join(issues["malicious_without_campaign"]), file=sys.stderr)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # utf-8-sig en CSV/TSV para que Excel reconozca los acentos.
        args.output.write_text(text, encoding="utf-8-sig" if args.formato != "md" else "utf-8")
        print(f"{len(rows)} correos -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.estricto and (issues["invalid_json"] or issues["malicious_without_campaign"]):
        return 1
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
