import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "engine"
sys.path.insert(0, str(TOOLS))

from common import sha256_bytes
from remnux_stage import StageConfigError, load_config, stage_to_remnux

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
        self.assertEqual(report["samples_dir"], f"/home/remnux/files/samples/cases/{CASE_ID}")
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


if __name__ == "__main__":
    unittest.main()
