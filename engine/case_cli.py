#!/usr/bin/env python3
"""Read-only CLI for the local case index and project-level analysis state."""
import argparse
import json
from pathlib import Path
from case_store import get_case_info


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def main():
    parser = argparse.ArgumentParser(description="Consulta el expediente y su tracking local.")
    parser.add_argument("case_id", help="ID del expediente")
    parser.add_argument("--db", type=Path, default=Path("storage/cases.db"))
    parser.add_argument("--findings", action="store_true", help="Incluir hallazgos del agente")
    args = parser.parse_args()

    record = get_case_info(args.db, args.case_id)
    case_path = Path(record["case_path"])
    state = read_json(case_path / "analysis" / "state.json", {})
    result = {
        "case_id": record["case_id"],
        "case_path": record["case_path"],
        "source_sha256": record["source_sha256"],
        "subject": record["subject"],
        "sender": record["sender"],
        "created_at": record["created_at"],
        "updated_utc": state.get("updated_utc"),
        "verdict": state.get("verdict", "pending"),
        "severity": state.get("severity", "unknown"),
        "confidence": state.get("confidence", "unknown"),
        "finalized": state.get("finalized", False),
        "stages": state.get("stages", {}),
    }
    if args.findings:
        findings = read_json(case_path / "analysis" / "findings.json", {"findings": []})
        result["findings"] = findings.get("findings", [])
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
