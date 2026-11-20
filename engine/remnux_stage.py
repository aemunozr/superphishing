#!/usr/bin/env python3
"""Deja en el directorio de muestras de REMnux los adjuntos que static_scan marca para escalar.

Las herramientas MCP de REMnux (analyze_file, get_file_info, run_tool) solo ven archivos del
propio host REMnux; no pueden leer la estación del analista. Este paso determinístico copia
los adjuntos de riesgo allí, verifica el SHA-256 en destino y deja el resultado en
extracted/remnux_stage.json, que el agente lee para analizar sin transferir bytes por el LLM.

Nunca ejecuta ni abre los adjuntos. Solo actúa si REMNUX_STAGE_MODE está configurado; si no,
registra "not_configured" para que el agente lo deje como verificación pendiente.

Configuración (entorno o --env-file; solo se cargan variables REMNUX_STAGE_* y WEBDAV_*):
  REMNUX_STAGE_MODE        copy | scp | webdav | off (por defecto off; si no está definido y
                           WEBDAV_BASE_URL sí, se usa webdav)
  REMNUX_STAGE_SUBDIR      subcarpeta dentro del directorio de muestras de REMnux (por defecto "cases")
  REMNUX_STAGE_SAMPLES_DIR directorio de muestras visto por el MCP (por defecto /opt/samples)
  copy: REMNUX_STAGE_DIR   ruta local, montada o UNC que corresponde a <muestras>/<subdir>
  scp:  REMNUX_STAGE_SSH_TARGET  usuario@host del servidor REMnux
        REMNUX_STAGE_REMOTE_DIR  ruta en ese host que corresponde a <muestras>/<subdir>
        REMNUX_STAGE_SSH_PORT    (opcional, 22)
        REMNUX_STAGE_SSH_KEY     (opcional) clave privada; la clave del host debe estar en known_hosts
        REMNUX_STAGE_KNOWN_HOSTS (opcional) archivo known_hosts, p. ej. para servicios con ProtectHome=yes
  webdav: WEBDAV_BASE_URL     URL https que corresponde a <muestras> (la subcarpeta se añade aquí)
          WEBDAV_USERNAME / WEBDAV_PASSWORD  autenticación Basic (solo sobre https)
          WEBDAV_TIMEOUT      (opcional, segundos, 300; también WEBDAV_TIMEOUT_SECONDS)
          WEBDAV_VERIFY_SSL   (opcional, true)
          WEBDAV_FLAT         (opcional, false) servidor de solo PUT: sube a <base>/<CASE_ID>__<sha256>.bin
                              sin MKCOL ni GET; la base corresponde a la raíz de <muestras>, sin subcarpeta.
                              El hash queda sin verificar en origen (hash_verified=false): el agente lo
                              compara en REMnux antes de analizar.
        Sin redirecciones (reenviarían la credencial). Sin WEBDAV_FLAT, tras el PUT se descarga y se compara
        el SHA-256. --check hace PROPFIND Depth 0; con WEBDAV_FLAT sube el archivo fijo superphishing-check.txt.

Cada muestra queda en <subdir>/<CASE_ID>/<sha256>.bin, sin extensión ejecutable.
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from common import sha256_bytes, write_json
from static_scan import msg_attachment_bytes

STAGE_VERSION = "1.0"
DEFAULT_SAMPLES_DIR = "/opt/samples"
COMMAND_TIMEOUT = 180
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_REMOTE_DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,512}$")
SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StageConfigError(ValueError):
    """Configuración REMNUX_STAGE_* incompleta o insegura."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _webdav_config(environ) -> dict:
    url = (environ.get("WEBDAV_BASE_URL") or "").strip()
    if not url:
        raise StageConfigError("REMNUX_STAGE_MODE=webdav requiere WEBDAV_BASE_URL.")
    if re.search(r"[\s'\"<>\\]", url):
        raise StageConfigError("WEBDAV_BASE_URL contiene comillas, espacios o caracteres no válidos; revisa .env.")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise StageConfigError("WEBDAV_BASE_URL debe ser una URL https con host.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise StageConfigError("WEBDAV_BASE_URL no debe incluir credenciales, query ni fragmento.")
    user = environ.get("WEBDAV_USERNAME") or ""
    password = environ.get("WEBDAV_PASSWORD") or ""
    if bool(user) != bool(password):
        raise StageConfigError("WEBDAV_USERNAME y WEBDAV_PASSWORD deben definirse juntos.")
    raw_timeout = (environ.get("WEBDAV_TIMEOUT") or environ.get("WEBDAV_TIMEOUT_SECONDS") or "300").strip()
    if not raw_timeout.isdigit() or not 0 < int(raw_timeout) <= 3600:
        raise StageConfigError("WEBDAV_TIMEOUT debe ser un número de segundos entre 1 y 3600.")
    flags = {}
    for name, default in (("WEBDAV_VERIFY_SSL", "true"), ("WEBDAV_FLAT", "false")):
        value = (environ.get(name) or default).strip().lower()
        if value not in ("true", "false", "1", "0", "yes", "no"):
            raise StageConfigError(f"{name} debe ser true o false.")
        flags[name] = value in ("true", "1", "yes")
    return {"base_url": url.rstrip("/"), "username": user, "password": password,
            "timeout": int(raw_timeout), "verify_ssl": flags["WEBDAV_VERIFY_SSL"], "flat": flags["WEBDAV_FLAT"]}


def load_config(environ=os.environ) -> dict | None:
    """Devuelve la configuración validada, o None si el envío está desactivado."""
    raw_mode = environ.get("REMNUX_STAGE_MODE")
    if not (raw_mode or "").strip() and (environ.get("WEBDAV_BASE_URL") or "").strip():
        raw_mode = "webdav"
    mode = (raw_mode or "off").strip().lower()
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
    elif mode == "webdav":
        config["webdav"] = _webdav_config(environ)
    else:
        raise StageConfigError("REMNUX_STAGE_MODE debe ser copy, scp, webdav u off.")
    return config


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Una redirección reenviaría la cabecera Authorization a otro destino: se trata como error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def webdav_transport(webdav: dict):
    """Devuelve http(method, url, data, headers) -> (status, headers, body) sin redirecciones."""
    context = ssl.create_default_context()
    if not webdav["verify_ssl"]:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))
    auth = None
    if webdav["username"]:
        token = base64.b64encode(f"{webdav['username']}:{webdav['password']}".encode("utf-8")).decode("ascii")
        auth = f"Basic {token}"

    def http(method: str, url: str, data: bytes | None = None, headers: dict | None = None):
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        if auth:
            request.add_header("Authorization", auth)
        try:
            with opener.open(request, timeout=webdav["timeout"]) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), b""
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(f"WebDAV {method} sin respuesta: {str(reason)[:200]}") from None
    return http


def _webdav_url(config: dict, *segments: str) -> str:
    return "/".join([config["webdav"]["base_url"], *(quote(s, safe="") for s in segments)])


def _webdav_status_error(method: str, status: int) -> RuntimeError:
    hints = {401: "credenciales rechazadas", 403: "sin permiso", 404: "ruta no encontrada",
             405: "método no permitido", 409: "falta la carpeta padre", 507: "sin espacio"}
    if 300 <= status < 400:
        hint = "redirección rechazada (revisa WEBDAV_BASE_URL)"
    else:
        hint = hints.get(status, "respuesta inesperada")
    return RuntimeError(f"WebDAV {method} devolvió {status}: {hint}")


def flat_name(case_id: str, file_name: str) -> str:
    return f"{case_id}__{file_name}"


def _put(http, url: str, data: bytes) -> None:
    status, _, _ = http("PUT", url, data, {"Content-Type": "application/octet-stream"})
    if status not in (200, 201, 204):
        raise _webdav_status_error("PUT", status)


def _deliver_webdav(config: dict, case_id: str, file_name: str, data: bytes, http) -> str:
    if config["webdav"]["flat"]:
        # Servidor de solo PUT: sin carpetas ni descarga. La verificación del hash la hace el agente en REMnux.
        target = _webdav_url(config, flat_name(case_id, file_name))
        _put(http, target, data)
        return target
    # MKCOL de cada nivel: 201 creada; 405 ya existe (RFC 4918).
    for segments in ((config["subdir"],), (config["subdir"], case_id)):
        status, _, _ = http("MKCOL", _webdav_url(config, *segments) + "/")
        if status not in (201, 405):
            raise _webdav_status_error("MKCOL", status)
    target = _webdav_url(config, config["subdir"], case_id, file_name)
    _put(http, target, data)
    status, _, body = http("GET", target)
    if status != 200:
        raise _webdav_status_error("GET", status)
    if sha256_bytes(body) != sha256_bytes(data):
        raise RuntimeError("el SHA-256 descargado de WebDAV no coincide con el de la ingesta")
    return target


CHECK_FILE = "superphishing-check.txt"
CHECK_BODY = b"superphishing remnux_stage --check\n"


def webdav_check(config: dict, http=None) -> dict:
    """PROPFIND Depth 0 sobre la base y la subcarpeta; con WEBDAV_FLAT, PUT de un archivo fijo inofensivo."""
    http = http or webdav_transport(config["webdav"])
    if config["webdav"]["flat"]:
        result = {"base_url": config["webdav"]["base_url"], "tls_verify": config["webdav"]["verify_ssl"],
                  "auth": bool(config["webdav"]["username"]), "flat": True,
                  "check_file": CHECK_FILE, "check_sha256": sha256_bytes(CHECK_BODY),
                  "mcp_path": CHECK_FILE}
        try:
            _put(http, _webdav_url(config, CHECK_FILE), CHECK_BODY)
            result.update({"reachable": True, "ok": True})
        except RuntimeError as exc:
            result.update({"reachable": "sin respuesta" not in str(exc), "ok": False, "detail": str(exc)})
        return result
    body = (b'<?xml version="1.0" encoding="utf-8"?>'
            b'<propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>')
    headers = {"Depth": "0", "Content-Type": "application/xml; charset=utf-8"}
    result = {"base_url": config["webdav"]["base_url"], "tls_verify": config["webdav"]["verify_ssl"],
              "auth": bool(config["webdav"]["username"]), "checks": []}
    for label, url in (("base", config["webdav"]["base_url"] + "/"),
                       ("subdir", _webdav_url(config, config["subdir"]) + "/")):
        try:
            status, response_headers, _ = http("PROPFIND", url, body, headers)
        except RuntimeError as exc:
            result["checks"].append({"target": label, "status": None, "detail": str(exc)})
            continue
        entry = {"target": label, "status": status, "dav": response_headers.get("DAV") or response_headers.get("Dav")}
        if status != 207:
            entry["detail"] = str(_webdav_status_error("PROPFIND", status)).split(": ", 1)[-1]
        result["checks"].append(entry)
    base = result["checks"][0]
    result["reachable"] = base["status"] is not None
    result["ok"] = base["status"] == 207
    result["subdir_exists"] = result["checks"][1]["status"] == 207
    return result


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
                    environ=os.environ, http=None) -> dict:
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
    flat = bool(config and config["mode"] == "webdav" and config["webdav"]["flat"])
    if config:
        report.update({"mode": config["mode"],
                       "samples_dir": config["samples_dir"] if flat
                       else f"{config['samples_dir']}/{config['subdir']}/{case_id}"})
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
        entry["mcp_path"] = (flat_name(case_id, file_name) if flat
                             else f"{config['subdir'] if config else 'cases'}/{case_id}/{file_name}")
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
            elif config["mode"] == "webdav":
                if http is None:
                    http = webdav_transport(config["webdav"])
                _deliver_webdav(config, case_id, file_name, data, http)
            else:
                _deliver_scp(config, case_id, file_name, data, runner)
            entry.update({"status": "staged", "origin": origin, "size": len(data), "staged_utc": utcnow(),
                          "hash_verified": not flat})
            if flat:
                entry["verification"] = "pendiente: comparar sha256 en REMnux (get_file_info) antes de analizar"
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
    parser.add_argument("case_dir", type=Path, nargs="*", help="Directorio(s) de expediente; admite comodines")
    parser.add_argument("--env-file", type=Path,
                        help="Archivo KEY=VALUE del que cargar solo variables REMNUX_STAGE_* y WEBDAV_*")
    parser.add_argument("--force", action="store_true", help="Reenvía aunque ya conste como enviado")
    parser.add_argument("--check", action="store_true",
                        help="Solo comprueba el acceso al destino WebDAV (PROPFIND); no sube nada")
    args = parser.parse_args()
    if args.env_file:
        from graph_import import load_env_file
        if not args.env_file.is_file():
            parser.error(f"no existe el archivo de entorno {args.env_file}")
        load_env_file(args.env_file, prefixes=("REMNUX_STAGE_", "WEBDAV_"))
    try:
        config = load_config()
    except StageConfigError as exc:
        parser.error(str(exc))
    if args.check:
        if not config or config["mode"] != "webdav":
            parser.error("--check solo aplica al modo webdav (define WEBDAV_BASE_URL o REMNUX_STAGE_MODE=webdav).")
        result = webdav_check(config)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    if not args.case_dir:
        parser.error("indica al menos un directorio de expediente o --check")
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
