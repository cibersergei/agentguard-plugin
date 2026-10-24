"""GenIA AgentGuard - fewer questions in the PreToolUse hook (.kiro/specs/agentguard-plugin-allow RP1, RP2, RP6).

- PM-03 for recursive deletes: a delete whose targets are ALL temporary or cache folders (/tmp/..., $env:TEMP,
  Local/Temp, __pycache__) does not ask, also inside the remote command of an approved ssh. A target that cannot be
  resolved (loop variable, pipe, "..") still asks. git push --force, reset --hard, clean, Format-Volume... always ask.
- Explicit allow, an opt-in of the client (baseline params.agentguard_auto_allow): "transfer" approves a command whose
  every part is an approved scp / sftp / ssh, a temporary delete or a read-only output filter; "transfer_y_comandos"
  also approves parts that start with a prefix of params.agentguard_allow_commands. Never with a word of
  params.agentguard_never_allow, a file redirection, or without a readable baseline (fail closed).
Claude Code still applies the deny and ask rules of settings after an allow. Python standard library only, 3.9+.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import agentguard_allowlist as allowlist

MODES = ("off", "transfer", "transfer_y_comandos")
NEVER_DEFAULT = ["production", "approve-migrate"]
MAX_PREFIXES = 50
ALWAYS_ASK = re.compile(r"git\s+push\s+(?:.*\s)?(?:--force|-f)\b|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|format-volume"
                        r"|stop-computer|set-executionpolicy|mkfs|dd\s+if=", re.IGNORECASE)
# rm -rf (not git rm: git keeps the files in its history) and Remove-Item -Recurse, as PM-03 asked before 0.5.0
RECURSIVE_DELETE = re.compile(r"(?<!git )\brm\s+-[a-z]*(?:r[a-z]*f|f[a-z]*r)|remove-item\b.*-recurse", re.IGNORECASE)
TEMP_PREFIX = re.compile(r"^(?:/tmp/|/var/tmp/|\$env:temp/|\$temp/|\$tmpdir/|\$env:tmp/|\$env:localappdata/temp/"
                         r"|\$localappdata/temp/|[a-z]:/users/[^/]+/appdata/local/temp/)(?=.)", re.IGNORECASE)
READ_ONLY = {"select-object", "select", "select-string", "sls", "where-object", "sort-object", "sort", "measure-object",
             "measure", "out-string", "out-null", "format-table", "ft", "format-list", "fl", "grep", "head", "tail",
             "wc", "cut", "uniq"}
SHELL_WORDS = {"do", "then", "else", "{", "}"}
RM_SWITCHES = {"-recurse", "-force", "-confirm:$false", "-whatif", "-verbose"}
RM_VALUED = {"-path", "-literalpath", "-erroraction", "-ea", "-include", "-exclude", "-filter"}
HARMLESS_REDIRECT = re.compile(r"\d?\*?&?>>?\s*(?:&\d|/dev/null|\$null)", re.IGNORECASE)


def settings(path: Path | None = None) -> dict:
    """{"mode", "prefixes", "never"} from the organization's baseline; mode "off" when it cannot be read."""
    off = {"mode": "off", "prefixes": [], "never": list(NEVER_DEFAULT)}
    try:
        params = json.loads((path or allowlist.baseline_path()).read_text(encoding="utf-8"))["data"]["params"]
    except (OSError, ValueError, KeyError, TypeError):
        return off
    if not isinstance(params, dict) or params.get("agentguard_auto_allow") not in MODES:
        return off
    raw = params.get("agentguard_allow_commands")
    prefixes = [p.strip() for p in raw if isinstance(p, str) and 6 <= len(p.strip()) <= 200 and not re.search(r"[*?]", p)
                ][:MAX_PREFIXES] if isinstance(raw, list) else []
    never = params.get("agentguard_never_allow")
    never = [w.strip().lower() for w in never if isinstance(w, str) and w.strip()] if isinstance(never, list) else NEVER_DEFAULT
    return {"mode": params["agentguard_auto_allow"], "prefixes": prefixes, "never": never}


def _assignments(command: str) -> dict:
    """Simple variables set in the same command: $S = "..."; $p = Join-Path $S 'x'; S="..." (Bash)."""
    out = {}
    for seg in allowlist.segments(command):
        try:
            tokens = allowlist.tokenize(seg)
        except ValueError:
            continue
        while tokens and tokens[0].lower() in SHELL_WORDS:
            tokens = tokens[1:]
        if len(tokens) == 3 and re.match(r"^\$\w+$", tokens[0]) and tokens[1] == "=":
            out[tokens[0][1:].lower()] = tokens[2]
        elif len(tokens) == 5 and re.match(r"^\$\w+$", tokens[0]) and tokens[1] == "=" and tokens[2].lower() == "join-path":
            out[tokens[0][1:].lower()] = tokens[3] + "/" + tokens[4]
        elif len(tokens) == 1 and re.match(r"^\w+=.", tokens[0]):
            name, value = tokens[0].split("=", 1)
            out[name.lower()] = value
    return out


def _expand(value: str, names: dict) -> str:
    for _ in range(3):   # nested: $prev = Join-Path $S 'prev', $S = "$env:LOCALAPPDATA\Temp\..."
        value = re.sub(r"\$\{?(\w+)\}?", lambda m: names.get(m.group(1).lower(), m.group(0)), value)
    return value


def is_temp(target: str, names: dict) -> bool:
    t = _expand(target, names).replace("\\", "/").strip()
    if not t or ".." in t:
        return False
    return bool(TEMP_PREFIX.match(t)) or t.rstrip("/").split("/")[-1].lower() == "__pycache__"


def _delete_targets(seg: str) -> list[str] | None:
    """Targets of an rm / Remove-Item / find -exec rm segment, or None when it is not one of those."""
    try:
        tokens = allowlist.tokenize(seg)
    except ValueError:
        return None
    while tokens and tokens[0].lower() in SHELL_WORDS:
        tokens = tokens[1:]
    tool, args = allowlist._tool(tokens)
    if tool == "rm":
        return [a for a in args if not a.startswith("-")]
    if tool in ("remove-item", "ri"):
        targets, i = [], 0
        while i < len(args):
            a = args[i].lower()
            if a in RM_VALUED:
                if a in ("-path", "-literalpath") and i + 1 < len(args):
                    targets += args[i + 1].split(",")
                i += 2
                continue
            if a not in RM_SWITCHES:
                if a.startswith("-"):
                    return [""]   # unknown option: not resolvable
                targets.append(args[i])
            i += 1
        return targets
    if tool == "find" and "-exec" in args:
        name = args[args.index("-name") + 1] if "-name" in args and args.index("-name") + 1 < len(args) else ""
        alternatives = {"-o", "-or", "-path", "-regex", "-iname"} & set(args)
        return ["__pycache__"] if name == "__pycache__" and not alternatives else [""]
    return None


def _segment_delete(seg: str, names: dict) -> str | None:
    """"temp", "ask" or None (no recursive delete in this segment). Quoted data (a commit message) does not count;
    quoted text that runs (bash -c "rm -rf x") does."""
    bare = allowlist.unquoted(seg)
    if not RECURSIVE_DELETE.search(seg if allowlist.EXECUTES_TEXT.search(bare) else bare):
        return None
    targets = _delete_targets(seg)
    return "temp" if targets and all(is_temp(t, names) for t in targets) else "ask"


def _remote(seg: str, hosts) -> str | None:
    """The remote command of an approved ssh segment, None for any other segment."""
    info = allowlist.parse(seg)
    if info and info.get("remote") and not allowlist.runs_here(seg) and allowlist._ok(info, _allow(hosts)):
        return info["remote"]
    return None


def _allow(hosts) -> dict:
    return {**allowlist.empty(), "transfer": hosts} if isinstance(hosts, set) else hosts


def destructive(command: str, hosts) -> str | None:
    """PM-03: "ask", "temp" (every recursive delete is temporary) or None (nothing destructive)."""
    if ALWAYS_ASK.search(command):
        return "ask"
    found = []
    for seg in allowlist.segments(command):
        remote = _remote(seg, hosts)
        parts, names = ((allowlist.segments(remote), _assignments(remote)) if remote is not None
                        else ([seg], _assignments(command)))
        found += [k for k in (_segment_delete(p, names) for p in parts) if k]
    if not found:
        return None
    return "ask" if "ask" in found else "temp"


def decide_allow(command: str, hosts, cfg: dict) -> str | None:
    """The reason of an explicit allow, or None (the normal flow of Claude Code goes on)."""
    if cfg.get("mode") not in ("transfer", "transfer_y_comandos"):
        return None
    if any(w in command.lower() for w in cfg.get("never", [])):
        return None
    names, kinds = _assignments(command), set()
    for seg in allowlist.segments(command):
        if ">" in HARMLESS_REDIRECT.sub(" ", allowlist.unquoted(seg)):
            return None   # writes a file here
        info = allowlist.parse(seg)
        try:
            tool = allowlist._tool(allowlist.tokenize(seg))[0] if info is None else ""
        except ValueError:
            return None
        if info and info["list"] == "transfer" and not allowlist.runs_here(seg) and allowlist._ok(info, _allow(hosts)):
            kinds.add("transfer aprobado")
        elif _segment_delete(seg, names) == "temp":
            kinds.add("borrado temporal")
        elif tool in READ_ONLY and not re.search(r"[{`]|\$\(", seg):
            continue
        elif cfg["mode"] == "transfer_y_comandos" and ".." not in seg and not allowlist.runs_here(seg) and any(
                seg.lower().startswith(p.lower()) for p in cfg.get("prefixes", [])):
            kinds.add("comando aprobado")
        elif re.match(r"^\$\w+\s*=\s*(?:\"(?:[^\"`$]|\$(?!\())*\"|'[^']*'|join-path\s+\$\w+\s+'[\w.-]+')$", seg,
                      re.IGNORECASE):
            continue   # a plain variable for a temporary delete ($S = "...")
        else:
            return None
    if not kinds:
        return None
    return f"AgentGuard: aprobado por la politica de la organizacion ({', '.join(sorted(kinds))})."
