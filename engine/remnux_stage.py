#!/usr/bin/env python3
"""Deja en el directorio de muestras de REMnux los adjuntos que static_scan marca para escalar.

Las herramientas MCP de REMnux (analyze_file, get_file_info, run_tool) solo ven archivos del
propio host REMnux; no pueden leer la estación del analista. Este paso determinístico copia
los adjuntos de riesgo allí, verifica el SHA-256 en destino y deja el resultado en
extracted/remnux_stage.json, que el agente lee para analizar sin transferir bytes por el LLM.

Nunca ejecuta ni abre los adjuntos. Solo actúa si REMNUX_STAGE_MODE está configurado; si no,
registra "not_configured" para que el agente lo deje como verificación pendiente.

Configuración (entorno o --env-file; solo se cargan variables REMNUX_STAGE_*):
  REMNUX_STAGE_MODE        copy | scp | off (por defecto off)
  REMNUX_STAGE_SUBDIR      subcarpeta dentro del directorio de muestras de REMnux (por defecto "cases")
  REMNUX_STAGE_SAMPLES_DIR directorio de muestras visto por el MCP (por defecto /home/remnux/files/samples)
  copy: REMNUX_STAGE_DIR   ruta local, montada o UNC que corresponde a <muestras>/<subdir>
  scp:  REMNUX_STAGE_SSH_TARGET  usuario@host del servidor REMnux
        REMNUX_STAGE_REMOTE_DIR  ruta en ese host que corresponde a <muestras>/<subdir>
        REMNUX_STAGE_SSH_PORT    (opcional, 22)
        REMNUX_STAGE_SSH_KEY     (opcional) clave privada; la clave del host debe estar en known_hosts
        REMNUX_STAGE_KNOWN_HOSTS (opcional) archivo known_hosts, p. ej. para servicios con ProtectHome=yes

Cada muestra queda en <subdir>/<CASE_ID>/<sha256>.bin, sin extensión ejecutable.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from common import sha256_bytes, write_json
from static_scan import msg_attachment_bytes

STAGE_VERSION = "1.0"
DEFAULT_SAMPLES_DIR = "/home/remnux/files/samples"
COMMAND_TIMEOUT = 180
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_REMOTE_DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,512}$")
SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StageConfigError(ValueError):
    """Configuración REMNUX_STAGE_* incompleta o insegura."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config(environ=os.environ) -> dict | None:
    """Devuelve la configuración validada, o None si el envío está desactivado."""
    mode = (environ.get("REMNUX_STAGE_MODE") or "off").strip().lower()
    if mode in ("", "off", "none", "disabled"):
        return None
    subdir = (environ.get("REMNUX_STAGE_SUBDIR") or "cases").strip().strip("/")
    if not SAFE_ID_RE.match(subdir):
        raise StageConfigError("REMNUX_STAGE_SUBDIR solo admite letras, números, '.', '_' y '-'.")
    config = {"mode": mode, "subdir": subdir,
              "samples_dir": (environ.get("REMNUX_STAGE_SAMPLES_DIR") or DEFAULT_SAMPLES_DIR).rstrip("/")}
    if mode == "copy":
        target = (environ.get("REMNUX_STAGE_DIR") or "").strip()
        if not target:
            raise StageConfigError("REMNUX_STAGE_MODE=copy requiere REMNUX_STAGE_DIR.")
        config["stage_dir"] = target
    elif mode == "scp":
        ssh_target = (environ.get("REMNUX_STAGE_SSH_TARGET") or "").strip()
        remote_dir = (environ.get("REMNUX_STAGE_REMOTE_DIR") or "").strip().rstrip("/")
        port = (environ.get("REMNUX_STAGE_SSH_PORT") or "22").strip()
        if not SAFE_TARGET_RE.match(ssh_target):
            raise StageConfigError("REMNUX_STAGE_SSH_TARGET debe ser usuario@host.")
        if not SAFE_REMOTE_DIR_RE.match(remote_dir):
            raise StageConfigError("REMNUX_STAGE_REMOTE_DIR debe ser una ruta absoluta sin espacios ni comillas.")
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise StageConfigError("REMNUX_STAGE_SSH_PORT no es un puerto válido.")
        config.update({"ssh_target": ssh_target, "remote_dir": remote_dir, "port": port,
                       "ssh_key": (environ.get("REMNUX_STAGE_SSH_KEY") or "").strip(),
                       "known_hosts": (environ.get("REMNUX_STAGE_KNOWN_HOSTS") or "").strip()})
    else:
        raise StageConfigError("REMNUX_STAGE_MODE debe ser copy, scp u off.")
    return config


def _ssh_options(config: dict) -> list[str]:
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
    if config.get("ssh_key"):
        options += ["-i", config["ssh_key"]]
    if config.get("known_hosts"):
        # Para servicios con ProtectHome=yes: known_hosts fuera de ~/.ssh.
        options += ["-o", f"UserKnownHostsFile={config['known_hosts']}"]
    return options


def _run(runner, args: list[str]) -> str:
    completed = runner(args, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise RuntimeError(f"{Path(args[0]).name} terminó con código {completed.returncode}: "
                           f"{detail[-1][:300] if detail else 'sin detalle'}")
    return completed.stdout or ""


def _verified_bytes(case_dir: Path, row: dict, msg_cache: dict) -> tuple[bytes | None, str]:
    """Bytes del adjunto con el SHA-256 de la ingesta: copia en disco o, si fue alterada, el MSG original."""
    expected = str(row.get("sha256") or "").lower()
    path = case_dir / "attachments" / str(row.get("stored_name") or "")
    if path.is_file():
        data = path.read_bytes()
        if expected and sha256_bytes(data) == expected:
            return data, "disk"
    if "data" not in msg_cache:
        msg_cache["data"], msg_cache["problem"] = msg_cache["loader"](case_dir)
    candidate = msg_cache["data"].get(int(row.get("index") or 0))
    if candidate is not None and expected and sha256_bytes(candidate) == expected:
        return candidate, "msg_original"
    return None, msg_cache.get("problem") or "adjunto no recuperable con hash coincidente"


def _deliver_copy(config: dict, case_id: str, file_name: str, data: bytes) -> None:
    target_dir = Path(config["stage_dir"]) / case_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / file_name
    temp = target.with_name(target.name + ".part")
    temp.write_bytes(data)
    temp.replace(target)
    if sha256_bytes(target.read_bytes()) != sha256_bytes(data):
        raise RuntimeError("el SHA-256 en destino no coincide (posible reescritura por un agente de endpoint)")


def _deliver_scp(config: dict, case_id: str, file_name: str, data: bytes, runner) -> None:
    remote_dir = f"{config['remote_dir']}/{case_id}"
    remote_file = f"{remote_dir}/{file_name}"
    options = _ssh_options(config)
    _run(runner, ["ssh", *options, "-p", config["port"], config["ssh_target"], f"mkdir -p -- '{remote_dir}'"])
    # Fichero temporal propio (los bytes vienen verificados en memoria); se borra siempre.
    handle, temp_name = tempfile.mkstemp(prefix="remnux_stage_", suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        _run(runner, ["scp", *options, "-P", config["port"], "-q", temp_name,
                      f"{config['ssh_target']}:{remote_file}"])
    finally:
        try:
            os.remove(temp_name)
        except OSError:
            pass
    output = _run(runner, ["ssh", *options, "-p", config["port"], config["ssh_target"],
                           f"sha256sum -- '{remote_file}'"])
    remote_hash = output.strip().split(" ", 1)[0].lower() if output.strip() else ""
    if remote_hash != sha256_bytes(data):
        raise RuntimeError("el SHA-256 en REMnux no coincide con el de la ingesta")


def stage_to_remnux(case_dir: Path, case_id: str | None = None, config: dict | None = None,
                    runner=subprocess.run, msg_loader=msg_attachment_bytes, force: bool = False,
                    environ=os.environ) -> dict:
    """Envía a REMnux los adjuntos de escalate_to_remnux y escribe extracted/remnux_stage.json."""
    case_dir = Path(case_dir)
    if case_id is None:
        try:
            case_id = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))["case_id"]
        except (OSError, KeyError, ValueError):
            case_id = case_dir.name
    if not SAFE_ID_RE.match(case_id):
        raise ValueError(f"case_id no seguro para rutas remotas: {case_id!r}")
    report_path = case_dir / "extracted" / "remnux_stage.json"
    previous = {}
    if report_path.is_file() and not force:
        try:
            previous = {f["sha256"]: f for f in json.loads(report_path.read_text(encoding="utf-8")).get("files", [])
                        if f.get("status") == "staged"}
        except (OSError, ValueError):
            previous = {}

    report = {"stage_version": STAGE_VERSION, "case_id": case_id, "updated_utc": utcnow(),
              "mode": "off", "status": "nothing_to_stage", "samples_dir": None, "files": []}
    try:
        config = config if config is not None else load_config(environ)
    except StageConfigError as exc:
        report.update({"status": "error", "detail": f"configuración inválida: {exc}"})
        write_json(report_path, report)
        return report

    try:
        scan = json.loads((case_dir / "extracted" / "static_scan.json").read_text(encoding="utf-8"))
        rows = json.loads((case_dir / "extracted" / "attachments.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        write_json(report_path, report)
        return report
    names = list(dict.fromkeys(scan.get("escalate_to_remnux") or []))
    if not names:
        write_json(report_path, report)
        return report

    by_name = {row.get("original_name"): row for row in rows if row.get("status") == "extracted"}
    if config:
        report.update({"mode": config["mode"],
                       "samples_dir": f"{config['samples_dir']}/{config['subdir']}/{case_id}"})
    msg_cache = {"loader": msg_loader}
    for name in names:
        row = by_name.get(name)
        sha = str((row or {}).get("sha256") or "").lower()
        entry = {"name": name, "sha256": sha or None, "status": "pending"}
        if not row or not SHA256_RE.match(sha):
            entry.update({"status": "unverifiable", "detail": "sin fila de adjunto o sin SHA-256 de ingesta"})
            report["files"].append(entry)
            continue
        file_name = f"{sha}.bin"
        entry["mcp_path"] = f"{config['subdir'] if config else 'cases'}/{case_id}/{file_name}"
        if not config:
            entry["detail"] = "REMNUX_STAGE_MODE no configurado"
            report["files"].append(entry)
            continue
        if sha in previous:
            report["files"].append({**previous[sha], "status": "staged"})
            continue
        data, origin = _verified_bytes(case_dir, row, msg_cache)
        if data is None:
            entry.update({"status": "unverifiable", "detail": origin})
            report["files"].append(entry)
            continue
        try:
            if config["mode"] == "copy":
                _deliver_copy(config, case_id, file_name, data)
            else:
                _deliver_scp(config, case_id, file_name, data, runner)
            entry.update({"status": "staged", "origin": origin, "size": len(data), "staged_utc": utcnow()})
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            entry.update({"status": "error", "detail": str(exc)[:400]})
        report["files"].append(entry)

    statuses = {f["status"] for f in report["files"]}
    if not config:
        report["status"] = "not_configured"
    elif statuses == {"staged"}:
        report["status"] = "staged"
    elif "staged" in statuses:
        report["status"] = "partial"
    else:
        report["status"] = "error"
    write_json(report_path, report)
    return report


def compact(report: dict) -> dict:
    """Vista mínima para summary.json."""
    return {"status": report.get("status"), "mode": report.get("mode"),
            "files": [{"name": f.get("name"), "status": f.get("status"), "mcp_path": f.get("mcp_path")}
                      for f in report.get("files", [])]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Envía a REMnux los adjuntos de riesgo de uno o varios expedientes.")
    parser.add_argument("case_dir", type=Path, nargs="+", help="Directorio(s) de expediente; admite comodines")
    parser.add_argument("--env-file", type=Path, help="Archivo KEY=VALUE del que cargar solo variables REMNUX_STAGE_*")
    parser.add_argument("--force", action="store_true", help="Reenvía aunque ya conste como enviado")
    args = parser.parse_args()
    if args.env_file:
        from graph_import import load_env_file
        if not args.env_file.is_file():
            parser.error(f"no existe el archivo de entorno {args.env_file}")
        load_env_file(args.env_file, prefixes=("REMNUX_STAGE_",))
    try:
        config = load_config()
    except StageConfigError as exc:
        parser.error(str(exc))
    case_dirs = []
    for item in args.case_dir:
        matches = sorted(Path(p) for p in glob.glob(str(item))) if glob.has_magic(str(item)) else [item]
        case_dirs.extend(p for p in matches if (p / "extracted" / "attachments.json").is_file())
    status = 0
    for case_dir in case_dirs:
        try:
            report = stage_to_remnux(case_dir, config=config, force=args.force)
        except (OSError, ValueError) as exc:
            print(f"ERROR {case_dir}: {exc}", file=sys.stderr)
            status = 1
            continue
        print(json.dumps({"case": report["case_id"], **compact(report)}, ensure_ascii=False))
        if report["status"] in ("error", "partial"):
            status = 1
    return status


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
