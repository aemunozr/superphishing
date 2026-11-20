#!/usr/bin/env python3
"""Resumen de expedientes bajo una ruta: total, conteo por veredicto y tabla de correos.

Solo lectura y sin red. Recorre la ruta indicada, toma como expediente cada carpeta que tenga
summary.json y lee de ahí la fecha, el remitente y el asunto del correo reportado; el veredicto
sale de analysis/state.json (o "pending" si no existe). No modifica ningún expediente.

Ejemplos:
  case_report.py cases\\2026\\11
  case_report.py cases --desde 2026-11-01 --hasta 2026-11-30 --output storage\\resumen-noviembre.md
  case_report.py cases\\2026\\11 --formato tsv --incluir-caso
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
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


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


def load_row(case_dir: Path) -> dict:
    summary = _read_json(case_dir / "summary.json")
    state = _read_json(case_dir / "analysis" / "state.json")
    raw_date = _clean(summary.get("date"))
    return {
        "case_id": _clean(summary.get("case_id")) or case_dir.name,
        "date": _parse_date(raw_date),
        "date_text": raw_date,
        "sender": _clean(summary.get("sender")),
        "subject": _clean(summary.get("subject")),
        "verdict": _clean(state.get("verdict")).lower() or "pending",
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


def _fmt_date(row: dict) -> str:
    return row["date"].strftime("%Y-%m-%d %H:%M %z") if row["date"] else (row["date_text"] or "sin fecha")


def _md_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(rows: list[dict], root: Path, include_case: bool = False, title: str | None = None) -> str:
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
    columns = COLUMNS + (["Caso"] if include_case else [])
    out += ["", "## Correos", "", "| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for row in rows:
        cells = [_fmt_date(row), row["sender"], row["subject"], row["verdict"]]
        if include_case:
            cells.append(row["case_id"])
        out.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    return "\n".join(out) + "\n"


def render_delimited(rows: list[dict], delimiter: str, include_case: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\n")
    writer.writerow(COLUMNS + (["Caso"] if include_case else []))
    for row in rows:
        cells = [_fmt_date(row), row["sender"], row["subject"], row["verdict"]]
        if include_case:
            cells.append(row["case_id"])
        writer.writerow(cells)
    writer.writerow([])
    writer.writerow(["Total", len(rows)])
    for verdict, n in count_verdicts(rows):
        writer.writerow([verdict, n])
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
        text = render_markdown(rows, args.ruta, args.incluir_caso, args.titulo)
    else:
        text = render_delimited(rows, "\t" if args.formato == "tsv" else ",", args.incluir_caso)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # utf-8-sig en CSV/TSV para que Excel reconozca los acentos.
        args.output.write_text(text, encoding="utf-8-sig" if args.formato != "md" else "utf-8")
        print(f"{len(rows)} correos -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
