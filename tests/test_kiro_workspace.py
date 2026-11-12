import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class KiroWorkspaceTests(unittest.TestCase):
    def test_agent_uses_powers_but_not_global_mcp_inventory(self):
        config = json.loads((ROOT / ".kiro/agents/security-analyst.json").read_text())
        self.assertEqual(config["name"], "security-analyst")
        self.assertTrue(config["includePowers"])
        self.assertFalse(config["includeMcpJson"])
        self.assertIn("skill://.kiro/skills/**/SKILL.md", config["resources"])
        self.assertNotIn("shell", config["tools"])

    def test_general_workspace_skills_are_minimal_and_expected(self):
        expected = {
            "triage", "email-analysis", "url-analysis",
            "mcp-tool-discovery", "evidence-reporting",
        }
        actual = {p.parent.name for p in (ROOT / ".kiro/skills").glob("*/SKILL.md")}
        self.assertEqual(actual, expected)

    def test_four_native_power_packages_have_valid_manifests_skills_and_mcp(self):
        expected = {
            "threat-intelligence": ("ioc-correlation", {"darknet", "gti-agentic"}),
            "static-analysis": ("file-analysis", {"remnux", "remnux-docs"}),
            "reverse-engineering": ("reverse-engineering", {"ghidra", "radare2"}),
            "dynamic-analysis": ("dynamic-analysis", {"x64dbg"}),
        }
        power_dirs = {p.name for p in (ROOT / "powers").iterdir() if p.is_dir()}
        self.assertEqual(power_dirs, set(expected) | {"exposure-hunting"})
        for power, (skill, servers) in expected.items():
            directory = ROOT / "powers" / power
            manifest = json.loads((directory / "plugin.json").read_text())
            self.assertEqual(manifest["name"], power)
            self.assertEqual(manifest["version"], "1.3.0")
            self.assertTrue(manifest["keywords"])
            skill_file = directory / "skills" / skill / "SKILL.md"
            self.assertTrue(skill_file.is_file())
            self.assertIn(f'name: "{skill}"', skill_file.read_text())
            # Se valida la plantilla versionada: mcp.json es local, lleva credenciales y está en .gitignore.
            mcp = json.loads((directory / "mcp.json.example").read_text(encoding="utf-8"))
            self.assertEqual(set(mcp["mcpServers"]), servers)
            self.assertIn("agent-plugins.org/schemas/1.0.0/mcp.schema.json", mcp["$schema"])
            for server in mcp["mcpServers"].values():
                # Esquema Agent Plugins 1.0.0: 'type' obligatorio, sin campos adicionales como 'disabled'.
                self.assertEqual(server["type"], "streamable-http")
                self.assertIn("url", server)
                self.assertLessEqual(set(server), {"type", "url", "headers"})

    def test_exposure_hunting_power_is_read_only_and_lean(self):
        directory = ROOT / "powers" / "exposure-hunting"
        manifest = json.loads((directory / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "exposure-hunting")
        skill = (directory / "skills" / "exposure-assessment" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn('name: "exposure-assessment"', skill)
        self.assertIn("Solo lectura", skill)
        self.assertIn("Una vez por campaña", skill)
        example = json.loads((directory / "mcp.json.example").read_text(encoding="utf-8"))
        self.assertEqual(set(example["mcpServers"]), {"falcon-mcp", "cisco-secure-access"})
        falcon_env = example["mcpServers"]["falcon-mcp"]["env"]
        self.assertEqual(falcon_env["FALCON_MCP_READ_ONLY"], "true")
        self.assertEqual(falcon_env["FALCON_MCP_DYNAMIC"], "true")
        cisco_auth = example["mcpServers"]["cisco-secure-access"]["headers"]["Authorization"]
        self.assertRegex(cisco_auth, r"\$\{[A-Z0-9_]+\}")   # nunca un token literal

    def test_power_mcp_auth_uses_environment_placeholders_only(self):
        expected = {
            "DARKNET_MCP_TOKEN", "GTI_MCP_API_KEY", "REMNUX_MCP_TOKEN", "GHIDRA_MCP_BASIC_AUTH",
            "RADARE2_MCP_TOKEN", "X64DBG_MCP_BASIC_AUTH", "CISCO_SA_MCP_TOKEN",
        }
        found = set()
        for path in (ROOT / "powers").glob("*/mcp.json.example"):
            data = json.loads(path.read_text(encoding="utf-8"))
            for name, server in data["mcpServers"].items():
                for header, value in server.get("headers", {}).items():
                    match = re.search(r"\$\{([A-Z0-9_]+)\}", value)
                    # Toda cabecera de las plantillas versionadas debe ser un placeholder, nunca un secreto literal.
                    self.assertIsNotNone(match, f"{path.parent.name}/{name}: cabecera {header} sin placeholder")
                    found.add(match.group(1))
        self.assertEqual(found, expected)

    def test_local_power_mcp_files_are_git_ignored(self):
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("powers/*/mcp.json", ignored)
        self.assertIn(".kiro/settings/mcp.json", ignored)

    def test_workspace_disables_only_same_named_global_servers(self):
        path = ROOT / ".kiro/settings/mcp.json"
        if not path.is_file():
            self.skipTest(".kiro/settings/mcp.json es local y no está versionado")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(set(config["mcpServers"]), {
            "remnux", "remnux-docs", "ghidra", "radare2", "darknet", "x64dbg",
        })
        self.assertTrue(all(v == {"disabled": True} for v in config["mcpServers"].values()))

    def test_no_procmon_is_claimed_as_configured(self):
        dynamic_mcp = json.loads((ROOT / "powers/dynamic-analysis/mcp.json").read_text())
        self.assertEqual(set(dynamic_mcp["mcpServers"]), {"x64dbg"})
        self.assertIn("Procmon", (ROOT / "docs/KIRO-SETUP.md").read_text())

    def test_macos_secret_helper_does_not_persist_values(self):
        script = (ROOT / "scripts/macos/set-mcp-env.sh").read_text()
        self.assertIn("read -r -s", script)
        self.assertIn("launchctl setenv", script)
        self.assertNotIn("echo \"$value\"", script)
        self.assertNotIn(".env", script)
        clear = (ROOT / "scripts/macos/clear-mcp-env.sh").read_text()
        self.assertIn("launchctl unsetenv", clear)

    def test_agent_write_permissions_are_narrow(self):
        config = json.loads((ROOT / ".kiro/agents/security-analyst.json").read_text())
        rules = config["permissions"]["rules"]
        allowed = [r for r in rules if r["capability"] == "fs_write" and r["effect"] == "allow"]
        denied_shell = [r for r in rules if r["capability"] == "shell" and r["effect"] == "deny"]
        denied_powers = [r for r in rules if r["capability"] == "fs_write" and r["effect"] == "deny" and "powers/**" in r["match"]]
        self.assertEqual(len(allowed), 1)
        self.assertEqual(set(allowed[0]["match"]), {
            "cases/**/analysis/state.json",
            "cases/**/analysis/findings.json",
            "cases/**/report/final-report.md",
        })
        self.assertEqual(len(denied_shell), 1)
        self.assertEqual(len(denied_powers), 1)


if __name__ == "__main__":
    unittest.main()
