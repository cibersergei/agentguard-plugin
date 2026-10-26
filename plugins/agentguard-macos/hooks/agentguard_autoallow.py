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


# RP7 (plugin 0.5.1): documents the agent may write inside the project without asking, when auto_allow is on
DOC_EXT = {"md", "markdown", "txt", "rst", "adoc", "html", "htm", "css", "json", "jsonc", "csv", "tsv", "yaml", "yml",
           "xml", "svg", "log"}
CONFIG_DIRS = {".git", ".claude", ".github", ".gitlab", ".vscode", ".idea", ".husky", ".devcontainer", ".circleci"}
AGENT_FILES = {"claude.md", "claude.local.md", "agents.md", ".clinerules"}   # instructions for the agent itself


def decide_doc_allow(path: str, cwd: str, cfg: dict) -> str | None:
    """The reason of an explicit allow for a document inside the project, or None (RP7)."""
    if cfg.get("mode") not in ("transfer", "transfer_y_comandos") or not path or not cwd:
        return None
    norm = path.replace("\\", "/")
    root = cwd.replace("\\", "/").rstrip("/")
    if not re.match(r"^(?:[a-zA-Z]:)?/", norm):   # relative to the project
        norm = root + "/" + norm
    if "/../" in norm + "/" or "/./" in norm + "/" or not norm.lower().startswith(root.lower() + "/"):
        return None
    parts = norm[len(root) + 1:].split("/")
    name = parts[-1]
    if not name or name.startswith(".") or name.lower() in AGENT_FILES:
        return None
    if any(p.lower() in CONFIG_DIRS for p in parts[:-1]):
        return None
    every_file = cfg.get("edits") == "todo"   # RP9: like acceptEdits, without depending on the session mode
    if not every_file and ("." not in name or name.rsplit(".", 1)[1].lower() not in DOC_EXT):
        return None
    if any(w in norm.lower() for w in cfg.get("never", [])):
        return None
    what = "archivo del proyecto" if every_file else "documento del proyecto"
    return f"AgentGuard: aprobado por la politica de la organizacion ({what})."


WEBFETCH_MODES = ("off", "lista", "libre")
MAX_WEBFETCH_DOMAINS = 100
PRIVATE_HOST = re.compile(r"^(?:localhost|.*\.(?:local|internal|lan|localdomain|home|corp))$", re.IGNORECASE)


def decide_webfetch(url: str, cfg: dict) -> str | None:
    """RP10: the reason of an explicit allow for a WebFetch, or None (Claude Code asks as usual). Never a deny."""
    mode = cfg.get("webfetch")
    if mode not in ("lista", "libre") or not isinstance(url, str) or len(url) > 2000:
        return None
    from urllib.parse import unquote, urlsplit
    try:
        u = urlsplit(url.strip())
        host = (u.hostname or "").lower().rstrip(".")
        port = u.port
    except ValueError:
        return None
    if u.scheme.lower() != "https" or u.username or u.password or not host or "." not in host:
        return None
    if port not in (None, 443) or PRIVATE_HOST.match(host) or re.fullmatch(r"[\d.]+", host) or ":" in host:
        return None   # an IP, a private name or another port: not a public web page
    query = unquote(u.query)
    if len(query) > 100 or any(len(v) > 64 for v in re.split(r"[&=]", query)):
        return None   # data in the URL
    if any(len(p) > 100 for p in unquote(u.path).split("/")):
        return None
    if any(w in url.lower() for w in cfg.get("never", [])):
        return None
    if mode == "lista" and not allowlist.approved(host, set(cfg.get("webfetch_domains", []))):
        return None
    return f"AgentGuard: aprobado por la politica de la organizacion (WebFetch {'de la lista' if mode == 'lista' else 'con resguardo'})."


def _words(raw, default) -> list[str]:
    return [w.strip().lower() for w in raw if isinstance(w, str) and w.strip()] if isinstance(raw, list) else list(default)


def settings(path: Path | None = None) -> dict:
    """The explicit-allow parameters of the organization's baseline; everything "off" when it cannot be read."""
    off = {"mode": "off", "prefixes": [], "never": list(NEVER_DEFAULT), "edits": "docs", "webfetch": "off",
           "webfetch_domains": []}
    try:
        params = json.loads((path or allowlist.baseline_path()).read_text(encoding="utf-8"))["data"]["params"]
    except (OSError, ValueError, KeyError, TypeError):
        return off
    if not isinstance(params, dict):
        return off
    out = dict(off, never=_words(params.get("agentguard_never_allow"), NEVER_DEFAULT))
    if params.get("agentguard_webfetch") in WEBFETCH_MODES:
        out["webfetch"] = params["agentguard_webfetch"]
        out["webfetch_domains"] = sorted(allowlist._hosts(params.get("agentguard_webfetch_domains")))[:MAX_WEBFETCH_DOMAINS]
    if params.get("agentguard_auto_allow") not in MODES:
        return out
    raw = params.get("agentguard_allow_commands")
    out["prefixes"] = [p.strip() for p in raw if isinstance(p, str) and 6 <= len(p.strip()) <= 200
                       and not re.search(r"[*?]", p)][:MAX_PREFIXES] if isinstance(raw, list) else []
    out["mode"] = params["agentguard_auto_allow"]
    out["edits"] = "todo" if params.get("agentguard_allow_project_edits") == "todo" else "docs"
    return out


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


def is_temp(target: str, names: dict, base: str = "") -> bool:
    """base: the folder of the last absolute `cd` of the same command; a relative target is resolved against it (RP8)."""
    t = _expand(target, names).replace("\\", "/").strip()
    if t and base and not re.match(r"^(?:/|[a-zA-Z]:|\$|~)", t):
        t = base.rstrip("/") + "/" + t
    if not t or ".." in t:
        return False
    return bool(TEMP_PREFIX.match(t)) or t.rstrip("/").split("/")[-1].lower() == "__pycache__"


REDIRECT = re.compile(r"^\d*&?(?:>>?|<)")


def _drop_redirects(args: list[str]) -> list[str]:
    """2>&1, >/dev/null, 2> file are redirections, not targets (RP8); a bare operator takes the next token."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif REDIRECT.match(a):
            skip = bool(re.fullmatch(r"\d*&?(?:>>?|<)", a))
        else:
            out.append(a)
    return out


def _cd_target(seg: str) -> str | None:
    """The folder of `cd <absolute folder>`, None for any other segment."""
    try:
        tokens = allowlist.tokenize(seg)
    except ValueError:
        return None
    while tokens and tokens[0].lower() in SHELL_WORDS:
        tokens = tokens[1:]
    if len(tokens) == 2 and tokens[0].lower() in ("cd", "set-location", "pushd"):
        path = tokens[1].replace("\\", "/")
        return path if re.match(r"^(?:/|[a-zA-Z]:/)", path) else None
    return None


def _delete_targets(seg: str) -> list[str] | None:
    """Targets of an rm / Remove-Item / find -exec rm segment, or None when it is not one of those."""
    try:
        tokens = allowlist.tokenize(seg)
    except ValueError:
        return None
    while tokens and tokens[0].lower() in SHELL_WORDS:
        tokens = tokens[1:]
    tool, args = allowlist._tool(tokens)
    args = _drop_redirects(args)
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


def _segment_delete(seg: str, names: dict, base: str = "") -> str | None:
    """"temp", "ask" or None (no recursive delete in this segment). Quoted data (a commit message) does not count;
    quoted text that runs (bash -c "rm -rf x") does."""
    bare = allowlist.unquoted(seg)
    if not RECURSIVE_DELETE.search(seg if allowlist.EXECUTES_TEXT.search(bare) else bare):
        return None
    targets = _delete_targets(seg)
    return "temp" if targets and all(is_temp(t, names, base) for t in targets) else "ask"


def _deletes(parts: list[str], names: dict) -> list[tuple[str, str | None]]:
    """(segment, delete kind) of consecutive segments, following the last absolute cd (RP8)."""
    out, base = [], ""
    for p in parts:
        base = _cd_target(p) or base
        out.append((p, _segment_delete(p, names, base)))
    return out


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
    found, local = [], []
    for seg in allowlist.segments(command):
        remote = _remote(seg, hosts)
        if remote is not None:
            found += [k for _p, k in _deletes(allowlist.segments(remote), _assignments(remote)) if k]
        else:
            local.append(seg)
    found += [k for _p, k in _deletes(local, _assignments(command)) if k]
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
    temp_deletes = {p for p, k in _deletes(allowlist.segments(command), names) if k == "temp"}
    for seg in allowlist.segments(command):
        if re.match(r"^(?:cd|set-location|pushd)\s+(?:\"[^\"$`]*\"|'[^']*'|[^\s;&|$`]+)$", seg, re.IGNORECASE):
            continue   # cd to a folder: changes nothing by itself
        if ">" in HARMLESS_REDIRECT.sub(" ", allowlist.unquoted(seg)):
            return None   # writes a file here
        info = allowlist.parse(seg)
        try:
            tool = allowlist._tool(allowlist.tokenize(seg))[0] if info is None else ""
        except ValueError:
            return None
        if info and info["list"] == "transfer" and not allowlist.runs_here(seg) and allowlist._ok(info, _allow(hosts)):
            kinds.add("transfer aprobado")
        elif seg in temp_deletes:
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
