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
