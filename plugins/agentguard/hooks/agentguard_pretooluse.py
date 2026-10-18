"""GenIA AgentGuard - PreToolUse hook (Capa C). Python standard library only, Python 3.9+.

Blocks inside the agent session what the AgentGuard catalog checks from outside:
  deny  - shell commands that send data out (PM-02): curl, wget, scp, sftp, nc, Invoke-WebRequest, iwr, irm, ...
  deny  - shell commands or file tools on secret locations (PM-01): .ssh, .env, .env.*, .aws, .azure, gcloud, .kube,
          .credentials.json
  deny  - --dangerously-skip-permissions / --permission-mode bypassPermissions (CF-03)
  deny  - edits of Claude's own policy and settings (PM-05): .claude/settings*.json, ~/.claude.json, managed folder
  ask   - destructive commands (PM-03): rm -rf, git push --force, git reset --hard, git clean -fd, Remove-Item -Recurse, ...

Protocol (code.claude.com/docs/en/hooks): JSON on stdin with tool_name and tool_input. A decision is printed as
hookSpecificOutput.permissionDecision ("deny" or "ask") with a reason, exit 0. Nothing printed = normal flow.
Input that cannot be parsed is not blocked (fail open), so a broken hook never stops the user's work; managed
permission rules (templates/) are the hard barrier. The reason names the rule, never the command or file content.
"""

from __future__ import annotations   # Python 3.9: the "X | None" annotations below

import json
import re
import sys

SHELL_TOOLS = {"Bash", "PowerShell"}
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}

_START = r"(?:^|[;&|\n(`]\s*|\b(?:sudo|exec|xargs|env)\s+)"
EGRESS = re.compile(_START + r"(curl|wget|scp|sftp|ftp|nc|ncat|netcat|invoke-webrequest|iwr|invoke-restmethod|irm"
                    r"|start-bitstransfer)(?:\.exe)?\b", re.IGNORECASE)
WEBCLIENT = re.compile(r"new-object\s+(system\.)?net\.webclient", re.IGNORECASE)
SECRET_PATH = re.compile(
    r"(?:^|[\\/\s\"'=:])(?:\.ssh[\\/]|\.aws[\\/]|\.azure[\\/]|gcloud[\\/]|\.kube[\\/]|\.credentials\.json"
    r"|\.env(?:\.[\w.-]+)?(?=$|[\s\"';|&)]))", re.IGNORECASE)
BYPASS = re.compile(r"--dangerously-skip-permissions|--permission-mode[ =]+bypassPermissions", re.IGNORECASE)
POLICY_PATH = re.compile(r"(?:[\\/]\.claude[\\/]settings(?:\.local)?\.json$|[\\/]\.claude\.json$|[\\/]ClaudeCode[\\/]"
                         r"|[\\/]managed-settings(?:\.d)?)", re.IGNORECASE)
DESTRUCTIVE = re.compile(
    _START + r"(rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|git\s+push\s+(?:.*\s)?(?:--force|-f)\b|git\s+reset\s+--hard"
    r"|git\s+clean\s+-[a-z]*f|remove-item\b.*-recurse|format-volume|stop-computer|set-executionpolicy|mkfs|dd\s+if=)",
    re.IGNORECASE)


def decide(event: dict) -> tuple[str, str] | None:
    """(decision, reason) or None when this hook has nothing to say."""
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool in SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        if BYPASS.search(command):
            return "deny", "AgentGuard: no se permite desactivar los permisos de Claude Code (CF-03)."
        match = EGRESS.search(command)
        if match or WEBCLIENT.search(command):
            name = match.group(1) if match else "Net.WebClient"
            return "deny", f"AgentGuard: comando de salida de datos bloqueado ({name}) (PM-02)."
        if SECRET_PATH.search(command):
            return "deny", "AgentGuard: el comando usa una ruta con secretos (PM-01)."
        if DESTRUCTIVE.search(command):
            return "ask", "AgentGuard: comando destructivo. Confirmar solo si es intencional (PM-03)."
    elif tool in FILE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm = path.replace("\\", "/")
        if SECRET_PATH.search(norm):
            return "deny", "AgentGuard: acceso a un archivo con secretos bloqueado (PM-01)."
        if tool in WRITE_TOOLS and POLICY_PATH.search(norm):
            return "deny", "AgentGuard: el agente no puede modificar la configuracion de seguridad de Claude (PM-05)."
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    result = decide(event) if isinstance(event, dict) else None
    if result:
        decision, reason = result
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                          "permissionDecisionReason": reason}}, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
