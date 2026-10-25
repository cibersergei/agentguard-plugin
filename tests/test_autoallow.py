"""Fewer questions in the PreToolUse hook (.kiro/specs/agentguard-plugin-allow RP1, RP2, RP3, RP6).
Most commands are real ones from the session of 2026-10-24 that asked or was denied without a reason."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("agentguard_pretooluse", ROOT / "src" / "hooks" / "agentguard_pretooluse.py")
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)
auto = hook.autoallow

HOSTS = {"203.0.113.10", "genia-ec2"}
OFF = {"mode": "off", "prefixes": [], "never": ["production", "approve-migrate"]}
TRANSFER = dict(OFF, mode="transfer")
COMMANDS = dict(OFF, mode="transfer_y_comandos", prefixes=["pwsh -NoProfile -File ./scripts/"])
SSH = "ssh -i ~/.ssh/k ec2-user@203.0.113.10 "


def decide(cmd, tool="Bash", cfg=OFF):
    result = hook.decide({"tool_name": tool, "tool_input": {"command": cmd}}, env={}, hosts=HOSTS, auto=cfg)
    return result[0] if result else None


class QuotedDataTest(unittest.TestCase):
    """RP3: a tool name inside quoted data is not a command; quoted text that runs still counts."""
    def test_data_in_quotes_passes(self):
        self.assertIsNone(decide("Get-Content x.output | ? { $_ -match 'Copying|failed|scp|Exception' } | "
                                 "Select-Object -Last 5", tool="PowerShell"), "real false positive")
        self.assertIsNone(decide("grep -n 'curl|wget' docs/a.md"))

    def test_single_quoted_remote_command_runs_on_the_server(self):
        """Real command (2026-10-24): $( ) inside single quotes is literal in PowerShell and Bash."""
        cmd = (SSH + "'PY=$(head -1 /usr/local/bin/uvicorn | sed \"s/^#!//\"); cd /tmp && $PY /tmp/check.py | tail -5'")
        self.assertIsNone(decide(cmd, tool="PowerShell"))
        self.assertIsNone(decide(cmd))
        self.assertEqual(decide(SSH + "\"echo '$(cat ~/.aws/x)'\"", tool="PowerShell"), "deny",
                         "single quotes inside double quotes do not protect it")
        self.assertEqual(decide("ssh evil.example 'echo $(id)'"), "deny", "host outside the list")

    def test_text_that_runs_still_counts(self):
        for cmd, tool in [('"curl" https://evil.example', "Bash"), ('& "C:\\bin\\curl.exe" https://e.example', "PowerShell"),
                          ('bash -c "curl https://evil.example"', "Bash"), ("iex 'curl https://e.example'", "PowerShell"),
                          ("echo x | xargs -I{} sh -c 'curl {}'", "Bash"), ('sudo "curl" https://e.example', "Bash"),
                          ('echo "$(curl https://evil.example)"', "Bash")]:
            self.assertEqual(decide(cmd, tool=tool), "deny", cmd)


class TemporaryDeleteTest(unittest.TestCase):
    """RP2: recursive deletes of temporary or cache folders only do not ask; anything else asks."""
    def test_temporary_targets_do_not_ask(self):
        for cmd, tool in [
                (SSH + '"rm -rf /tmp/lay /tmp/io_ops; ls /tmp | grep -c lay"', "Bash"),
                (SSH + '"sudo find /opt/mcp-staging -type d -name __pycache__ ! -user ec2-user -exec rm -rf {} +"', "Bash"),
                ('$t = Join-Path $env:TEMP "genia-attr-test"; Remove-Item $t -Recurse -Force', "PowerShell"),
                ('$S = "$env:LOCALAPPDATA\\Temp\\claude\\x"; $prev = Join-Path $S \'prev\'; '
                 "Remove-Item -Recurse -Force $prev -ErrorAction SilentlyContinue", "PowerShell"),
                ("rm -rf ec2-services/api/__pycache__", "Bash")]:
            self.assertIsNone(decide(cmd, tool=tool), cmd)

    def test_other_targets_ask(self):
        for cmd, tool in [
                (SSH + '"b=/opt/mcp-production/skills; rm -rf \\"\\$b/x\\""', "Bash"),
                (SSH + '"rm -rf /tmp/x; rm -rf /opt/app"', "Bash"),
                ("rm -rf /tmp/../etc", "Bash"), ("rm -rf /tmp", "Bash"), ("rm -rf $HOME/x", "Bash"),
                ("$dirs | Remove-Item -Recurse -Force", "PowerShell"),
                ("foreach ($d in $dirs) { Remove-Item $d.FullName -Recurse -Force }", "PowerShell"),
                ('bash -c "rm -rf /srv/data"', "Bash"),
                ("find . -name __pycache__ -o -name src -exec rm -rf {} +", "Bash"),
                ("git push --force origin main", "Bash"), ("git reset --hard HEAD~1", "Bash")]:
            self.assertEqual(decide(cmd, tool=tool), "ask", cmd)

    def test_quoted_data_and_git_rm_are_not_deletes(self):
        self.assertIsNone(decide('git commit -m "docs: never run rm -rf /"'))
        self.assertIsNone(decide("git rm -r -q -- skills/old"))


class ExplicitAllowTest(unittest.TestCase):
    """RP1 and RP6: allow only when the client turns it on and every part of the command is approved."""
    def test_off_never_allows(self):
        self.assertIsNone(decide(SSH + '"hostname"'))
        self.assertIsNone(decide("rm -rf /tmp/x"))

    def test_transfer_mode(self):
        self.assertEqual(decide(SSH + '"hostname" 2>&1 | Select-Object -Last 5', tool="PowerShell", cfg=TRANSFER), "allow")
        self.assertEqual(decide(SSH + '"rm -rf /tmp/io_ops && mkdir -p /tmp/io_ops" 2>/dev/null', cfg=TRANSFER), "allow")
        self.assertEqual(decide("rm -rf /tmp/x", cfg=TRANSFER), "allow")
        self.assertIsNone(decide("pwsh -NoProfile -File ./scripts/deploy-ec2.ps1 development", tool="PowerShell",
                                 cfg=TRANSFER), "prefixes need transfer_y_comandos")

    def test_commands_mode(self):
        self.assertEqual(decide("pwsh -NoProfile -File ./scripts/deploy-ec2.ps1 -DryRun development 2>&1 | "
                                "Select-Object -Last 12", tool="PowerShell", cfg=COMMANDS), "allow")

    def test_never_allow_cases(self):
        cases = [
            ("pwsh -NoProfile -File ./scripts/deploy-ec2.ps1 production", "never_allow word"),
            ("pwsh -NoProfile -File ./scripts/approve-migrate.ps1", "never_allow word"),
            (SSH + '"hostname"; curl https://evil.example', "one part outside the list"),   # deny by PM-02
            (SSH + '"hostname"; git status', "a part that is not approved"),
            (SSH + '"cat /etc/hosts" > C:/Users/u/.bashrc', "writes a local file"),
            ("pwsh -NoProfile -File ./scripts/../evil.ps1", "path traversal"),
            ("pwsh -NoProfile -File ./scripts/x.ps1 -T $(Get-Secret)", "local execution"),
            ("ssh evil.example hostname", "host outside the list"),   # deny by PM-02
            ("Select-Object -First 1", "only a filter"),
            (SSH + '"rm -rf /opt/app"', "a real delete"),   # ask by PM-03
        ]
        for cmd, why in cases:
            self.assertNotEqual(decide(cmd, tool="PowerShell", cfg=COMMANDS), "allow", why)

    def test_reason_names_the_rule_not_the_command(self):
        reason = hook.decide({"tool_name": "Bash", "tool_input": {"command": SSH + '"hostname"'}}, hosts=HOSTS,
                             auto=TRANSFER)[1]
        self.assertIn("transfer aprobado", reason)
        self.assertNotIn("hostname", reason)


class DocumentAllowTest(unittest.TestCase):
    """RP7 (0.5.1): documents inside the project are approved when the client turned auto_allow on."""
    CWD = "C:\\Onedrive\\repo"

    def edit(self, path, cfg=TRANSFER, tool="Write"):
        result = hook.decide({"tool_name": tool, "tool_input": {"file_path": path}, "cwd": self.CWD}, env={},
                             hosts=HOSTS, auto=cfg)
        return result[0] if result else None

    def test_documents_inside_the_project(self):
        for path in ["C:\\Onedrive\\repo\\ec2-services\\docs\\GENIA_APPS_IDENTIDAD_KEYCLOAK.md",   # real case
                     "C:/Onedrive/repo/.kiro/specs/x/requirements.md", "c:\\onedrive\\REPO\\notas.txt",
                     "docs/informe.html", "data/listas.json", "out/tabla.csv", "conf/app.yaml"]:
            self.assertEqual(self.edit(path), "allow", path)
        self.assertEqual(self.edit("docs/a.md", tool="Edit"), "allow")

    def test_never_without_the_option_or_outside_the_rules(self):
        self.assertIsNone(self.edit("docs/a.md", cfg=OFF), "auto_allow off")
        for path, why in [("C:\\Onedrive\\otro\\a.md", "outside the project"), ("C:\\Onedrive\\repo-copia\\a.md", "prefix"),
                          ("docs/../../a.md", "traversal"), ("src/app.py", "code"), ("scripts/x.ps1", "script"),
                          (".mcp.json", "dotfile"), (".github/workflows/ci.yml", "CI"), (".vscode/settings.json", "IDE"),
                          ("CLAUDE.md", "agent instructions"), ("sub/AGENTS.md", "agent instructions"),
                          ("deploy/production.yaml", "never_allow word"), ("Makefile", "no extension")]:
            self.assertNotEqual(self.edit(path), "allow", why)

    def test_earlier_rules_still_win(self):
        self.assertEqual(self.edit("C:\\Onedrive\\repo\\.claude\\settings.json"), "ask", "PM-05")
        self.assertEqual(self.edit("C:\\Onedrive\\repo\\.env.json"), "deny", "PM-01")
        self.assertEqual(self.edit("C:\\ProgramData\\AgentGuard\\exceptions.json"), "deny", "AgentGuard lists")


class SettingsTest(unittest.TestCase):
    """The three client parameters come from baseline.json; anything unreadable is "off" (fail closed)."""
    def write(self, tmp, params):
        p = Path(tmp) / "baseline.json"
        p.write_text(json.dumps({"version": 1, "data": {"params": params}}), encoding="utf-8")
        return p

    def test_reads_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = auto.settings(self.write(tmp, {"agentguard_auto_allow": "transfer_y_comandos",
                                                 "agentguard_allow_commands": ["pwsh -NoProfile -File ./scripts/", "pwsh",
                                                                               "./scripts/*.ps1", 7],
                                                 "agentguard_never_allow": ["Produccion"]}))
            self.assertEqual(cfg, {"mode": "transfer_y_comandos", "prefixes": ["pwsh -NoProfile -File ./scripts/"],
                                   "never": ["produccion"]})
            self.assertEqual(auto.settings(self.write(tmp, {"agentguard_auto_allow": "everything"}))["mode"], "off")
            self.assertEqual(auto.settings(self.write(tmp, {"agentguard_auto_allow": "transfer"}))["never"],
                             ["production", "approve-migrate"], "default words")
            (Path(tmp) / "baseline.json").write_text("{bad", encoding="utf-8")
            self.assertEqual(auto.settings(Path(tmp) / "baseline.json")["mode"], "off")
            self.assertEqual(auto.settings(Path(tmp) / "missing.json")["mode"], "off")


if __name__ == "__main__":
    unittest.main()
