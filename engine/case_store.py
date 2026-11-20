#!/usr/bin/env python3
"""Deterministic SQLite index for imported cases. Analysis state lives in case-local JSON."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db_session(db_path: str | Path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | Path) -> None:
    with db_session(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_path TEXT NOT NULL,
            source_sha256 TEXT NOT NULL UNIQUE,
            subject TEXT NOT NULL DEFAULT '',
            sender TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at)")


def create_case(db_path: str | Path, record: dict[str, Any]) -> None:
    init_db(db_path)
    with db_session(db_path) as con:
        con.execute("""INSERT INTO cases
            (case_id,case_path,source_sha256,subject,sender,created_at,metadata_json)
            VALUES (?,?,?,?,?,?,?)""",
            (record["case_id"], record["case_path"], record["source_sha256"],
             record.get("subject", ""), record.get("sender", ""), utcnow(),
             json.dumps(record.get("metadata", {}), ensure_ascii=False)))


def get_case_by_hash(db_path: str | Path, source_sha256: str) -> dict[str, Any] | None:
    init_db(db_path)
    with db_session(db_path) as con:
        row = con.execute("""SELECT case_id,case_path,source_sha256,created_at
            FROM cases WHERE source_sha256=? ORDER BY created_at LIMIT 1""",
            (source_sha256,)).fetchone()
        return dict(row) if row else None


def get_case_info(db_path: str | Path, case_id: str) -> dict[str, Any]:
    init_db(db_path)
    with db_session(db_path) as con:
        row = con.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError(f"Caso no encontrado: {case_id}")
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json") or "{}")
        return result


def find_missing_cases(db_path: str | Path, base: Path | None = None) -> list[dict[str, Any]]:
    """Casos indexados cuya carpeta ya no existe en disco. Rutas relativas se resuelven contra base."""
    init_db(db_path)
    base = base or Path.cwd()
    with db_session(db_path) as con:
        rows = con.execute("SELECT case_id,case_path,source_sha256,created_at FROM cases ORDER BY created_at").fetchall()
    missing = []
    for row in rows:
        path = Path(row["case_path"])
        if not path.is_absolute():
            path = base / path
        if not path.is_dir():
            missing.append(dict(row))
    return missing


def purge_missing_cases(db_path: str | Path, apply: bool = False, base: Path | None = None) -> dict[str, Any]:
    """Elimina del índice los casos sin carpeta para permitir reimportar su MSG. Sin apply solo lista."""
    missing = find_missing_cases(db_path, base)
    if apply and missing:
        with db_session(db_path) as con:
            con.executemany("DELETE FROM cases WHERE case_id=?", [(item["case_id"],) for item in missing])
    return {"mode": "apply" if apply else "dry_run", "missing": len(missing),
            "purged": len(missing) if apply else 0, "cases": missing}


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Mantenimiento del índice SQLite de expedientes.")
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    parser.add_argument("--purge-missing", action="store_true",
                        help="Lista los casos indexados cuya carpeta ya no existe")
    parser.add_argument("--apply", action="store_true", help="Con --purge-missing, borra esas filas del índice")
    args = parser.parse_args()
    if not args.purge_missing:
        parser.error("Indica una operación: --purge-missing")
    if not args.db.exists():
        parser.error(f"No existe la base: {args.db}")
    print(json.dumps(purge_missing_cases(args.db, args.apply), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
