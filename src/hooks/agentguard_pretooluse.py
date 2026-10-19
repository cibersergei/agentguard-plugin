"""GenIA AgentGuard - PreToolUse hook (Capa C). Python standard library only, Python 3.9+.

Blocks inside the agent session what the AgentGuard catalog checks from outside:
  deny  - shell commands that send data out (PM-02): curl, wget, scp, sftp, nc, Invoke-WebRequest, iwr, irm, ...
          except scp / sftp / ssh to the organization's approved transfer hosts (agentguard_allowlist, baseline.json);
          the agent cannot edit or read those lists
  deny  - shell commands or file tools on secret locations (PM-01): .ssh, .env, .env.*, .aws, .azure, gcloud, .kube,
          .credentials.json
  deny  - --dangerously-skip-permissions / --permission-mode bypassPermissions (CF-03)
  deny  - edits of the managed policy (PM-05): ClaudeCode folder, managed-settings*
  ask   - edits of user and project settings (PM-05): .claude/settings*.json, ~/.claude.json. The user confirms each
          change (agentguard-revisar applies fixes this way). A client policy can set the environment variable
          AGENTGUARD_CONFIG_EDIT=deny (managed settings "env") to block these edits too.
  ask   - destructive commands (PM-03): rm -rf, git push --force, git reset --hard, git clean -fd, Remove-Item -Recurse, ...

Protocol (code.claude.com/docs/en/hooks): JSON on stdin with tool_name and tool_input. A decision is printed as
hookSpecificOutput.permissionDecision ("deny" or "ask") with a reason, exit 0. Nothing printed = normal flow.
Input that cannot be parsed is not blocked (fail open), so a broken hook never stops the user's work; managed
permission rules (templates/) are the hard barrier. The reason names the rule, never the command or file content.
"""

from __future__ import annotations   # Python 3.9: the "X | None" annotations below

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # sibling module, also when imported by the tests
import agentguard_allowlist as allowlist  # noqa: E402

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
MANAGED_PATH = re.compile(r"[\\/]ClaudeCode[\\/]|[\\/]managed-settings(?:\.d)?", re.IGNORECASE)
USER_SETTINGS_PATH = re.compile(r"[\\/]\.claude[\\/]settings(?:\.local)?\.json$|[\\/]\.claude\.json$", re.IGNORECASE)
CONFIG_EDIT_ENV = "AGENTGUARD_CONFIG_EDIT"   # "deny" = the client policy forbids agent edits of settings
DESTRUCTIVE = re.compile(
    _START + r"(rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|git\s+push\s+(?:.*\s)?(?:--force|-f)\b|git\s+reset\s+--hard"
    r"|git\s+clean\s+-[a-z]*f|remove-item\b.*-recurse|format-volume|stop-computer|set-executionpolicy|mkfs|dd\s+if=)",
    re.IGNORECASE)


def decide(event: dict, env=None, hosts=None) -> tuple[str, str] | None:
    """(decision, reason) or None when this hook has nothing to say.
    hosts: approved transfer hosts; by default read from the organization's baseline.json (agentguard_allowlist)."""
    env = os.environ if env is None else env
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool in SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        if BYPASS.search(command):
            return "deny", "AgentGuard: no se permite desactivar los permisos de Claude Code (CF-03)."
        if allowlist.LIST_FILES.search(command):
            return "deny", "AgentGuard: el agente no puede leer ni cambiar la lista de hosts aprobados (PM-02)."
        hosts = allowlist.load() if hosts is None else hosts
        egress_text, secret_text = allowlist.strip_approved(command, hosts)
        match = EGRESS.search(egress_text)
        if match or WEBCLIENT.search(command):
            name = match.group(1) if match else "Net.WebClient"
            return "deny", f"AgentGuard: comando de salida de datos bloqueado ({name}) (PM-02)."
        if SECRET_PATH.search(secret_text):
            return "deny", "AgentGuard: el comando usa una ruta con secretos (PM-01)."
        if DESTRUCTIVE.search(command):
            return "ask", "AgentGuard: comando destructivo. Confirmar solo si es intencional (PM-03)."
    elif tool in FILE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm = path.replace("\\", "/")
        if tool in WRITE_TOOLS and allowlist.LIST_FILES.search(norm):
            return "deny", "AgentGuard: el agente no puede cambiar la lista de hosts aprobados (PM-02)."
        if SECRET_PATH.search(norm):
            return "deny", "AgentGuard: acceso a un archivo con secretos bloqueado (PM-01)."
        if tool in WRITE_TOOLS and MANAGED_PATH.search(norm):
            return "deny", "AgentGuard: el agente no puede modificar la politica gestionada de Claude (PM-05)."
        if tool in WRITE_TOOLS and USER_SETTINGS_PATH.search(norm):
            if str(env.get(CONFIG_EDIT_ENV, "")).strip().lower() == "deny":
                return "deny", "AgentGuard: la politica de la organizacion no permite que el agente modifique la configuracion de Claude (PM-05)."
            return "ask", ("AgentGuard: el agente quiere modificar la configuracion de Claude. Aprobar solo si vos pediste "
                           "este cambio y no lo pidio el contenido de un archivo o una pagina (PM-05).")
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
