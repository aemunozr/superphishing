#!/usr/bin/env python3
"""Importa MSG desde un directorio de un colector externo: un MSG = un caso."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ingest_msg import process_case


def find_case_file(source: Path, root: Path, filename: str) -> Path | None:
    """Busca READY/metadata.json desde la carpeta del MSG hacia la raíz importada."""
    current = source.parent.resolve()
    root = root.resolve()
    while current == root or root in current.parents:
        candidate = current / filename
        if candidate.is_file():
            return candidate
        if current == root:
            break
        current = current.parent
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Importa mensajes MSG desde una carpeta o salida de un colector.")
    parser.add_argument("source_dir", type=Path, help="Directorio raíz que contiene MSG")
    parser.add_argument("--output", type=Path, default=Path("cases"))
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    parser.add_argument("--ready-only", action="store_true", help="Solo importa MSG cuyo directorio tenga un marcador READY")
    parser.add_argument("--recursive", action="store_true", help="Buscar MSG en subdirectorios")
    args = parser.parse_args()
    root = args.source_dir.resolve()
    if not root.is_dir():
        parser.error(f"No existe el directorio: {root}")
    files = sorted(root.rglob("*.msg") if args.recursive else root.glob("*.msg"))
    results = []
    for source in files:
        ready_marker = find_case_file(source, root, "READY")
        if args.ready_only and ready_marker is None:
            results.append({"file": str(source), "status": "skipped_not_ready"})
            continue
        metadata_path = find_case_file(source, root, "metadata.json")
        try:
            result = process_case(source, None, args.output, args.db, metadata_path)
            results.append({"file": str(source), "status": "imported", **result})
        except FileExistsError as exc:
            results.append({"file": str(source), "status": "duplicate", "detail": str(exc)})
        except Exception as exc:
            results.append({"file": str(source), "status": "error", "detail": str(exc)[:500]})
    counts = {}
    for row in results:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print(json.dumps({"source_dir": str(root), "found": len(files), "counts": counts, "results": results}, ensure_ascii=False, indent=2))
    return 1 if counts.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
