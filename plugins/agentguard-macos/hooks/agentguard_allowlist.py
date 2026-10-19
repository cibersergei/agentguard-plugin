"""GenIA AgentGuard - approved transfer hosts for the PreToolUse hook (.kiro/specs/agentguard-baseline RB2, RB3, RB7).

The organization's list comes ONLY from baseline.json, written by the AgentGuard verifier as SYSTEM/root (users and the
agent cannot change it). Environment variables and project settings are never read for this: a repository could bring
its own. With management "self" the user's ~/.agentguard/allow-hosts.json adds hosts.

Approved: scp, sftp and ssh whose every remote host (destinations, -J / ProxyJump hops) is in the list; then
`-i ~/.ssh/<key>` in that same command does not trigger PM-01. Anything that cannot be parsed, ProxyCommand /
LocalCommand / -S program, or one host outside the list keeps the previous behaviour (deny). Python standard library
only, Python 3.9+.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

HOST = re.compile(r"^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*$")
SPLIT = re.compile(r"&&|\|\||[;&|\n]")
WRAPPERS = {"sudo", "exec", "env", "nohup", "time", "command", "&"}
TOOLS = {"scp", "sftp", "ssh"}
WITH_VALUE = {"scp": set("cDFiJloPSX"), "sftp": set("BbcDFiJloPRSsX"), "ssh": set("BbcDEeFIiJLlmOoPpQRSWw")}
REMOTE = re.compile(r"^(?:[^@\s]+@)?(\[[^\]]+\]|[^:/\\\s]+):")
URI = re.compile(r"^(?:scp|sftp|ssh)://(?:[^@/]+@)?(\[[^\]]+\]|[^:/]+)", re.IGNORECASE)
RISKY_OPTION = re.compile(r"proxycommand|localcommand|permitlocalcommand", re.IGNORECASE)
LIST_FILES = re.compile(r"allow-hosts\.json|agentguard(?:[\\/]| baseline[\\/])baseline\.json", re.IGNORECASE)


def baseline_path() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/AgentGuard Baseline/baseline.json")
    return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "AgentGuard" / "baseline.json"


def _hosts(values) -> set[str]:
    out = set()
    for v in values if isinstance(values, list) else []:
        v = str(v).strip().lower()
        if HOST.match(v) and (not v.startswith("*.") or v.count(".") >= 2):
            out.add(v)
    return out


def load(path: Path | None = None, home: Path | None = None) -> set[str]:
    """Approved transfer hosts. A missing or malformed file approves nothing (fail closed)."""
    try:
        record = json.loads((path or baseline_path()).read_text(encoding="utf-8"))
        egress = record["data"]["egress"]
    except (OSError, ValueError, KeyError, TypeError):
        return set()
    if not isinstance(egress, dict):
        return set()
    hosts = _hosts(egress.get("transfer_hosts"))
    if egress.get("management") == "self":   # RB3: the user's own list, only when the organization allows it
        try:
            own = json.loads(((home or Path.home()) / ".agentguard" / "allow-hosts.json").read_text(encoding="utf-8"))
            hosts |= _hosts(own.get("transfer_hosts") if isinstance(own, dict) else None)
        except (OSError, ValueError):
            pass
    return hosts


def approved(host: str, hosts: set[str]) -> bool:
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    return host in hosts or any(h.startswith("*.") and host.endswith(h[1:]) for h in hosts)


def _host_of(spec: str) -> str:
    spec = spec.split("@")[-1]
    return spec.split(":")[0] if not spec.startswith("[") else spec.split("]")[0] + "]"


def parse(segment: str) -> dict | None:
    """{"hosts", "keys", "ok"} for an scp/sftp/ssh command, None for anything else."""
    try:
        tokens = [t.strip("\"'") for t in shlex.split(segment, posix=False)]
    except ValueError:
        return {"hosts": [], "keys": [], "ok": False} if re.search(r"\b(scp|sftp|ssh)\b", segment, re.I) else None
    while tokens and (tokens[0].lower() in WRAPPERS or re.match(r"^\w+=", tokens[0])):
        tokens = tokens[1:]
    if not tokens:
        return None
    tool = re.split(r"[\\/]", tokens[0])[-1].lower()
    tool = tool[:-4] if tool.endswith(".exe") else tool
    if tool not in TOOLS:
        return None
    hosts, keys, positional, ok, i = [], [], [], True, 1
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-") and len(tok) > 1:
            flags = tok[1:]
            for n, ch in enumerate(flags):
                if ch in WITH_VALUE[tool]:
                    value = flags[n + 1:] or (tokens[i + 1] if i + 1 < len(tokens) else "")
                    if not flags[n + 1:]:
                        i += 1
                    if ch == "i":
                        keys.append(value)
                    elif ch == "J":
                        hosts += [_host_of(h) for h in value.split(",") if h]
                    elif ch == "o":
                        if RISKY_OPTION.search(value):
                            ok = False
                        m = re.match(r"(?i)proxyjump\s*=?\s*(.+)", value)
                        if m:
                            hosts += [_host_of(h) for h in m.group(1).split(",") if h]
                    elif ch == "S" and tool in ("scp", "sftp"):
                        ok = False   # -S runs another program
                    break
        else:
            positional.append(tok)
        i += 1
    if tool == "scp":
        for p in positional:
            m = URI.match(p) or REMOTE.match(p)
            if m and len(m.group(1).strip("[]")) > 1:   # "C:\..." is a Windows drive, not a host
                hosts.append(m.group(1))
    elif positional:   # sftp and ssh: the first positional argument is the destination
        m = URI.match(positional[0])
        hosts.append(m.group(1) if m else _host_of(positional[0]))
    return {"hosts": hosts, "keys": keys, "ok": ok and bool(hosts)}


def strip_approved(command: str, hosts: set[str]) -> tuple[str, str]:
    """(text for the egress check, text for the secret-path check). An approved scp/sftp/ssh leaves the egress text,
    and its -i key leaves the secret text; everything else stays, so the usual rules still apply to it."""
    if not hosts:
        return command, command
    egress_parts, secret_parts = [], []
    for segment in (s.strip() for s in SPLIT.split(command)):   # stripped: the egress rule anchors at the start
        info = parse(segment)
        if info and info["ok"] and all(approved(h, hosts) for h in info["hosts"]):
            secret = segment
            for key in info["keys"]:
                if re.search(r"[\\/]\.ssh[\\/]", key.replace("~", "/")):
                    secret = secret.replace(key, " ")
            secret_parts.append(secret)
            continue
        egress_parts.append(segment)
        secret_parts.append(segment)
    return "\n".join(egress_parts), "\n".join(secret_parts)
