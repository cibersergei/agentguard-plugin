"""GenIA AgentGuard - PreToolUse hook (Capa C). Python standard library only, Python 3.9+.

Blocks inside the agent session what the AgentGuard catalog checks from outside:
  deny  - shell commands that send data out (PM-02): curl, wget, scp, sftp, ssh, nc, Invoke-WebRequest, iwr, irm, ...
          except scp / sftp / ssh to the organization's approved transfer hosts, curl / wget / Invoke-WebRequest to its
          approved web hosts, and nc when the organization allows it (agentguard_allowlist, baseline.json); the agent
          cannot edit those lists. It may read them with the Read tool (no secrets: hosts and client parameters).
          A shell command cannot be told apart as read or write, so one that names the user's allow-hosts.json is
          denied (the agent could approve its own hosts) and one that names baseline.json asks (only admins and
          SYSTEM can write it)
  deny  - shell commands, file tools or Glob / Grep searches on secret locations (PM-01): .ssh, .env, .env.*, .aws,
          .azure, gcloud, .kube, .credentials.json
  deny  - --dangerously-skip-permissions / --permission-mode bypassPermissions (CF-03)
  deny  - edits of the managed policy (PM-05): ClaudeCode folder, managed-settings*
  ask   - edits of user and project settings (PM-05): .claude/settings*.json, ~/.claude.json. The user confirms each
          change (agentguard-revisar applies fixes this way). A client policy can set the environment variable
          AGENTGUARD_CONFIG_EDIT=deny (managed settings "env") to block these edits too.
  ask   - destructive commands (PM-03): rm -rf, git push --force, git reset --hard, git clean -fd, Remove-Item -Recurse, ...
          except a recursive delete of temporary or cache folders only (agentguard_autoallow)
  allow - only when the client turned it on (baseline params.agentguard_auto_allow): a command whose every part is an
          approved transfer, a temporary delete, a read-only filter or an approved command prefix (agentguard_autoallow).
          Claude Code still applies the deny and ask rules of settings after an allow.
A tool name inside quoted data (a regex, a commit message) is not a command; quoted text that runs (bash -c, iex) is.

Protocol (code.claude.com/docs/en/hooks): JSON on stdin with tool_name and tool_input. A decision is printed as
hookSpecificOutput.permissionDecision ("deny", "ask" or "allow") with a reason, exit 0. Nothing printed = normal flow.
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
import agentguard_autoallow as autoallow  # noqa: E402

SHELL_TOOLS = {"Bash", "PowerShell"}
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SEARCH_TOOLS = {"Glob", "Grep"}   # Claude Code and Cowork: the folder and the file pattern (never the Grep regex)

_START = r"(?:^|[;&|\n(`]\s*|\b(?:sudo|exec|xargs|env)\s+)"
EGRESS = re.compile(_START + r"(curl|wget|scp|sftp|ssh(?!-)|ftp|nc|ncat|netcat|invoke-webrequest|iwr|invoke-restmethod|irm"
                    r"|start-bitstransfer)(?:\.exe)?\b", re.IGNORECASE)
WEBCLIENT = re.compile(r"new-object\s+(system\.)?net\.webclient", re.IGNORECASE)
SECRET_PATH = re.compile(
    r"(?:^|[\\/\s\"'=:@])(?:\.ssh[\\/]|\.aws[\\/]|\.azure[\\/]|gcloud[\\/]|\.kube[\\/]|\.credentials\.json"
    r"|\.env(?:\.[\w.-]+)?(?=$|[\s\"';|&)]))", re.IGNORECASE)
BYPASS = re.compile(r"--dangerously-skip-permissions|--permission-mode[ =]+bypassPermissions", re.IGNORECASE)
MANAGED_PATH = re.compile(r"[\\/]ClaudeCode[\\/]|[\\/]managed-settings(?:\.d)?", re.IGNORECASE)
USER_SETTINGS_PATH = re.compile(r"[\\/]\.claude[\\/]settings(?:\.local)?\.json$|[\\/]\.claude\.json$", re.IGNORECASE)
CONFIG_EDIT_ENV = "AGENTGUARD_CONFIG_EDIT"   # "deny" = the client policy forbids agent edits of settings


def decide(event: dict, env=None, hosts=None, auto=None) -> tuple[str, str] | None:
    """(decision, reason) or None when this hook has nothing to say.
    hosts: approved transfer hosts; by default read from the organization's baseline.json (agentguard_allowlist).
    auto: explicit-allow settings (agentguard_autoallow.settings); by default read from the same baseline."""
    env = os.environ if env is None else env
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool in SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        if BYPASS.search(command):
            return "deny", "AgentGuard: no se permite desactivar los permisos de Claude Code (CF-03)."
        if allowlist.USER_LIST.search(command):
            return "deny", "AgentGuard: el agente no puede cambiar la lista de hosts aprobados (PM-02)."
        hosts = allowlist.load() if hosts is None else hosts
        # PowerShell escapes a quote inside "..." with a backtick (`"), the same as \" in Bash: read it that way so
        # an approved ssh with a quoted remote command is not taken as a local command. $( ) and any other backtick
        # still count as local execution. `$ is a literal $ in PowerShell (read as Bash's \$); a PowerShell \$( is a
        # backslash followed by a real $( ), so a space keeps it local.
        parsed = command
        if tool == "PowerShell":
            parsed = command.replace("\\$", "\\ $").replace('`"', '\\"').replace("`$", "\\$")
        egress_text, secret_text = allowlist.strip_approved(parsed, hosts)
        # A tool name inside quoted data (a regex, a message) is not a command (agentguard-plugin-allow RP3)
        match = EGRESS.search("\n".join(allowlist.mask_quotes(s) for s in egress_text.split("\n")))
        if match or WEBCLIENT.search(command):
            name = match.group(1) if match else "Net.WebClient"
            if match and allowlist.local_exec_only(parsed, hosts):
                escape = "`$(" if tool == "PowerShell" else "\\$("
                return "deny", (f"AgentGuard: el comando remoto de {name} tiene $( ) o una comilla invertida que se "
                                f"ejecuta en este equipo. Para que corra en el servidor, escribir {escape} (PM-02).")
            return "deny", f"AgentGuard: comando de salida de datos bloqueado ({name}) (PM-02)."
        if SECRET_PATH.search(secret_text):
            return "deny", "AgentGuard: el comando usa una ruta con secretos (PM-01)."
        # PM-03: a recursive delete of temporary or cache folders only does not ask (agentguard-plugin-allow RP2)
        if autoallow.destructive(parsed, hosts) == "ask":
            return "ask", "AgentGuard: comando destructivo. Confirmar solo si es intencional (PM-03)."
        if allowlist.ORG_LIST.search(command):   # after the deny checks, so it never hides one
            return "ask", ("AgentGuard: el comando usa un archivo de la organizacion (hosts aprobados o excepciones). "
                           "Para leerlo, usar la herramienta Read (PM-02).")
        # Explicit allow, only when the client turned it on (RP1); deny and ask rules of settings still apply
        reason = autoallow.decide_allow(parsed, hosts, autoallow.settings() if auto is None else auto)
        if reason:
            return "allow", reason
    elif tool in FILE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm = path.replace("\\", "/")
        if tool in WRITE_TOOLS and allowlist.LIST_FILES.search(norm):
            return "deny", "AgentGuard: el agente no puede cambiar los hosts aprobados ni las excepciones (PM-02)."
        if SECRET_PATH.search(norm):
            return "deny", "AgentGuard: acceso a un archivo con secretos bloqueado (PM-01)."
        if tool in WRITE_TOOLS and MANAGED_PATH.search(norm):
            return "deny", "AgentGuard: el agente no puede modificar la politica gestionada de Claude (PM-05)."
        if tool in WRITE_TOOLS and USER_SETTINGS_PATH.search(norm):
            if str(env.get(CONFIG_EDIT_ENV, "")).strip().lower() == "deny" or allowlist.config_edit() == "deny":
                return "deny", "AgentGuard: la politica de la organizacion no permite que el agente modifique la configuracion de Claude (PM-05)."
            return "ask", ("AgentGuard: el agente quiere modificar la configuracion de Claude. Aprobar solo si vos pediste "
                           "este cambio y no lo pidio el contenido de un archivo o una pagina (PM-05).")
    elif tool in SEARCH_TOOLS:
        # Glob: the pattern is a path pattern. Grep: the pattern is the text searched for, so only path and glob count.
        parts = [tool_input.get("path"), tool_input.get("glob")] + ([tool_input.get("pattern")] if tool == "Glob" else [])
        # A wildcard reads as a name character, so ".env.*" counts as ".env.x" (and "**/.ssh" as a folder).
        texts = [re.sub(r"[*?]", "x", str(p).replace("\\", "/")) for p in parts if p]
        if any(SECRET_PATH.search(t) or SECRET_PATH.search(t + "/") for t in texts):   # "+ /": a bare folder (~/.ssh)
            return "deny", "AgentGuard: busqueda en una ubicacion con secretos bloqueada (PM-01)."
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
