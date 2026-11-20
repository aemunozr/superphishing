import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

from common import sha256_bytes
from remnux_stage import StageConfigError, load_config, stage_to_remnux, webdav_check

SAMPLE = b'<svg xmlns="http://www.w3.org/2000/svg"><script>location.href="https://evil.example.test"</script></svg>'
SHA = sha256_bytes(SAMPLE)
CASE_ID = "CASE-20261112-000000-abcdef12"


def make_case(root: Path, disk_bytes: bytes = SAMPLE) -> Path:
    case = root / CASE_ID
    (case / "extracted").mkdir(parents=True)
    (case / "attachments").mkdir()
    (case / "attachments" / "001_pago.svg").write_bytes(disk_bytes)
    rows = [{"index": 1, "original_name": "pago.svg", "stored_name": "001_pago.svg", "status": "extracted",
             "sha256": SHA, "magic_type": "unknown"},
            {"index": 2, "original_name": "logo.png", "stored_name": "002_logo.png", "status": "extracted",
             "sha256": "1" * 64, "magic_type": "png"}]
    (case / "extracted" / "attachments.json").write_text(json.dumps(rows), encoding="utf-8")
    (case / "extracted" / "static_scan.json").write_text(json.dumps({"escalate_to_remnux": ["pago.svg"]}), encoding="utf-8")
    (case / "case.json").write_text(json.dumps({"case_id": CASE_ID}), encoding="utf-8")
    return case


class FakeRunner:
    """Simula ssh/scp: guarda lo copiado y responde a sha256sum como lo haría el host REMnux."""

    def __init__(self, remote_hash: str | None = None, fail_on: str | None = None):
        self.calls, self.remote_hash, self.fail_on, self.uploaded = [], remote_hash, fail_on, None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if self.fail_on and args[0] == self.fail_on:
            return subprocess.CompletedProcess(args, 255, "", "Host key verification failed.")
        if args[0] == "scp":
            self.uploaded = Path(args[-2]).read_bytes()
            return subprocess.CompletedProcess(args, 0, "", "")
        if "sha256sum" in args[-1]:
            digest = self.remote_hash or sha256_bytes(self.uploaded or b"")
            return subprocess.CompletedProcess(args, 0, f"{digest}  {args[-1]}\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


SCP_ENV = {"REMNUX_STAGE_MODE": "scp", "REMNUX_STAGE_SSH_TARGET": "analyst@remnux.lab.test",
           "REMNUX_STAGE_REMOTE_DIR": "/srv/remnux/samples/cases", "REMNUX_STAGE_SSH_PORT": "2222",
           "REMNUX_STAGE_KNOWN_HOSTS": "/etc/superphishing/remnux_known_hosts"}


class RemnuxStageTests(unittest.TestCase):
    def test_not_configured_is_recorded_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            runner = FakeRunner()
            report = stage_to_remnux(case, environ={}, runner=runner)
            saved = json.loads((case / "extracted" / "remnux_stage.json").read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "not_configured")
        self.assertEqual(runner.calls, [])
        self.assertEqual(saved["files"][0]["mcp_path"], f"cases/{CASE_ID}/{SHA}.bin")

    def test_copy_mode_writes_verified_sample_without_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            share = Path(tmp) / "remnux_share"
            report = stage_to_remnux(case, environ={"REMNUX_STAGE_MODE": "copy", "REMNUX_STAGE_DIR": str(share)})
            staged = share / CASE_ID / f"{SHA}.bin"
            self.assertEqual(staged.read_bytes(), SAMPLE)
        self.assertEqual(report["status"], "staged")
        self.assertEqual(report["samples_dir"], f"/opt/samples/cases/{CASE_ID}")
        self.assertEqual([f["name"] for f in report["files"]], ["pago.svg"])     # solo lo escalado

    def test_scp_mode_uses_safe_arguments_and_verifies_remote_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            runner = FakeRunner()
            report = stage_to_remnux(case, environ=SCP_ENV, runner=runner)
        self.assertEqual(report["status"], "staged")
        self.assertEqual(runner.uploaded, SAMPLE)
        programs = [call[0] for call in runner.calls]
        self.assertEqual(programs, ["ssh", "scp", "ssh"])
        for call in runner.calls:
            self.assertIn("BatchMode=yes", call)
            self.assertIn("StrictHostKeyChecking=yes", call)
            self.assertIn("UserKnownHostsFile=/etc/superphishing/remnux_known_hosts", call)
        self.assertEqual(runner.calls[1][-1], f"analyst@remnux.lab.test:/srv/remnux/samples/cases/{CASE_ID}/{SHA}.bin")
        self.assertIn("2222", runner.calls[1])

    def test_remote_hash_mismatch_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            report = stage_to_remnux(case, environ=SCP_ENV, runner=FakeRunner(remote_hash="0" * 64))
        self.assertEqual(report["status"], "error")
        self.assertIn("no coincide", report["files"][0]["detail"])

    def test_ssh_failure_is_recorded_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            report = stage_to_remnux(case, environ=SCP_ENV, runner=FakeRunner(fail_on="ssh"))
        self.assertEqual(report["status"], "error")
        self.assertIn("Host key verification failed", report["files"][0]["detail"])

    def test_altered_disk_copy_falls_back_to_original_msg_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp), disk_bytes=b"reescrito por CDR")
            share = Path(tmp) / "share"
            report = stage_to_remnux(case, environ={"REMNUX_STAGE_MODE": "copy", "REMNUX_STAGE_DIR": str(share)},
                                     msg_loader=lambda c: ({1: SAMPLE}, None))
            self.assertEqual((share / CASE_ID / f"{SHA}.bin").read_bytes(), SAMPLE)
        self.assertEqual(report["files"][0]["origin"], "msg_original")

    def test_already_staged_is_not_resent(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            stage_to_remnux(case, environ=SCP_ENV, runner=FakeRunner())
            runner = FakeRunner()
            report = stage_to_remnux(case, environ=SCP_ENV, runner=runner)
        self.assertEqual(report["status"], "staged")
        self.assertEqual(runner.calls, [])

    def test_unsafe_configuration_is_rejected(self):
        for env in ({"REMNUX_STAGE_MODE": "scp", "REMNUX_STAGE_SSH_TARGET": "x@h; rm -rf /",
                     "REMNUX_STAGE_REMOTE_DIR": "/srv/x"},
                    {"REMNUX_STAGE_MODE": "scp", "REMNUX_STAGE_SSH_TARGET": "a@h",
                     "REMNUX_STAGE_REMOTE_DIR": "/srv/x'$(id)"},
                    {"REMNUX_STAGE_MODE": "copy"},
                    {"REMNUX_STAGE_MODE": "ftp"}):
            with self.assertRaises(StageConfigError):
                load_config(env)
        self.assertIsNone(load_config({}))


class FakeDav:
    """Simula un servidor WebDAV en memoria: MKCOL, PUT, GET y PROPFIND."""

    def __init__(self, tamper: bool = False, put_status: int | None = None, propfind_status: int = 207):
        self.calls, self.files, self.dirs = [], {}, set()
        self.tamper, self.put_status, self.propfind_status = tamper, put_status, propfind_status

    def __call__(self, method, url, data=None, headers=None):
        self.calls.append((method, url, dict(headers or {})))
        if method == "MKCOL":
            if url in self.dirs:
                return 405, {}, b""
            self.dirs.add(url)
            return 201, {}, b""
        if method == "PUT":
            if self.put_status:
                return self.put_status, {}, b""
            self.files[url] = b"alterado" if self.tamper else data
            return 201, {}, b""
        if method == "GET":
            return (200, {}, self.files[url]) if url in self.files else (404, {}, b"")
        if method == "PROPFIND":
            return self.propfind_status, {"DAV": "1,2"}, b"<multistatus/>"
        return 405, {}, b""


DAV_BASE = "https://dav.lab.test/data_upload"
DAV_ENV = {"WEBDAV_BASE_URL": DAV_BASE + "/", "WEBDAV_USERNAME": "u", "WEBDAV_PASSWORD": "p"}


class WebdavStageTests(unittest.TestCase):
    def test_webdav_is_selected_from_webdav_vars_and_validated(self):
        config = load_config(DAV_ENV)
        self.assertEqual(config["mode"], "webdav")
        self.assertEqual(config["webdav"]["base_url"], DAV_BASE)
        self.assertTrue(config["webdav"]["verify_ssl"])
        self.assertIsNone(load_config({**DAV_ENV, "REMNUX_STAGE_MODE": "off"}))

    def test_unsafe_webdav_configuration_is_rejected(self):
        for env in ({"WEBDAV_BASE_URL": DAV_BASE + '/"'},                       # comilla sobrante de .env
                    {"WEBDAV_BASE_URL": "http://dav.lab.test/x"},               # sin TLS
                    {"WEBDAV_BASE_URL": "https://u:p@dav.lab.test/x"},          # credencial en la URL
                    {"WEBDAV_BASE_URL": DAV_BASE, "WEBDAV_USERNAME": "u"},      # usuario sin contraseña
                    {**DAV_ENV, "WEBDAV_TIMEOUT": "0"},
                    {"REMNUX_STAGE_MODE": "webdav"}):
            with self.assertRaises(StageConfigError, msg=env):
                load_config(env)

    def test_webdav_upload_creates_folders_and_verifies_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            dav = FakeDav()
            report = stage_to_remnux(case, environ=DAV_ENV, http=dav)
        self.assertEqual(report["status"], "staged")
        target = f"{DAV_BASE}/cases/{CASE_ID}/{SHA}.bin"
        self.assertEqual(dav.files[target], SAMPLE)
        self.assertEqual([c[0] for c in dav.calls], ["MKCOL", "MKCOL", "PUT", "GET"])
        self.assertEqual(report["files"][0]["mcp_path"], f"cases/{CASE_ID}/{SHA}.bin")
        self.assertNotIn("Authorization", json.dumps(report))

    def test_webdav_existing_folders_and_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            dav = FakeDav()
            dav.dirs.update({f"{DAV_BASE}/cases/", f"{DAV_BASE}/cases/{CASE_ID}/"})
            self.assertEqual(stage_to_remnux(case, environ=DAV_ENV, http=dav)["status"], "staged")
            tampered = stage_to_remnux(case, environ=DAV_ENV, http=FakeDav(tamper=True), force=True)
            denied = stage_to_remnux(case, environ=DAV_ENV, http=FakeDav(put_status=401), force=True)
            redirected = stage_to_remnux(case, environ=DAV_ENV, http=FakeDav(put_status=302), force=True)
        self.assertIn("no coincide", tampered["files"][0]["detail"])
        self.assertIn("401", denied["files"][0]["detail"])
        self.assertIn("redirección", redirected["files"][0]["detail"])

    def test_webdav_check_only_uses_propfind(self):
        dav = FakeDav()
        result = webdav_check(load_config(DAV_ENV), http=dav)
        self.assertTrue(result["ok"])
        self.assertEqual({c[0] for c in dav.calls}, {"PROPFIND"})
        self.assertEqual(dav.calls[0][2]["Depth"], "0")
        denied = webdav_check(load_config(DAV_ENV), http=FakeDav(propfind_status=401))
        self.assertFalse(denied["ok"])
        self.assertIn("credenciales", denied["checks"][0]["detail"])

    def test_flat_mode_only_puts_to_root_and_marks_hash_unverified(self):
        env = {**DAV_ENV, "WEBDAV_FLAT": "true"}
        with tempfile.TemporaryDirectory() as tmp:
            case = make_case(Path(tmp))
            dav = FakeDav()
            report = stage_to_remnux(case, environ=env, http=dav)
        self.assertEqual(report["status"], "staged")
        self.assertEqual([c[0] for c in dav.calls], ["PUT"])
        self.assertEqual(dav.files[f"{DAV_BASE}/{CASE_ID}__{SHA}.bin"], SAMPLE)
        entry = report["files"][0]
        self.assertEqual(entry["mcp_path"], f"{CASE_ID}__{SHA}.bin")
        self.assertFalse(entry["hash_verified"])
        self.assertEqual(report["samples_dir"], "/opt/samples")

    def test_flat_check_puts_fixed_probe_file(self):
        dav = FakeDav()
        result = webdav_check(load_config({**DAV_ENV, "WEBDAV_FLAT": "true"}), http=dav)
        self.assertTrue(result["ok"])
        self.assertEqual([(c[0], c[1]) for c in dav.calls], [("PUT", f"{DAV_BASE}/superphishing-check.txt")])
        denied = webdav_check(load_config({**DAV_ENV, "WEBDAV_FLAT": "true"}), http=FakeDav(put_status=403))
        self.assertFalse(denied["ok"])
        self.assertIn("403", denied["detail"])


if __name__ == "__main__":
    unittest.main()
