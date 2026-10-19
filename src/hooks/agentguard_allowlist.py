"""GenIA AgentGuard - approved hosts for the PreToolUse hook (.kiro/specs/agentguard-baseline RB2, RB3, RB7).

The organization's lists come ONLY from baseline.json, written by the AgentGuard verifier as SYSTEM/root (users and the
agent cannot change it). Environment variables and project settings are never read for this: a repository could bring
its own. With management "self" the user's ~/.agentguard/allow-hosts.json adds hosts.

- Transfer list: scp, sftp and ssh whose every remote host (destinations, -J / ProxyJump hops) is approved; then
  `-i ~/.ssh/<key>` in that same command does not trigger PM-01.
- Web list: curl, wget, Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer whose every URL host is approved.
- nc / ncat / netcat: only when the organization allows it, towards transfer hosts.
Anything that cannot be parsed (open quotes, variables, $(...) or backticks), proxies, config files, ProxyCommand,
-S programs, nc -e, or one host outside the list keeps the previous behaviour (deny). Python standard library only,
Python 3.9+.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

HOST = re.compile(r"^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*$")
WRAPPERS = {"sudo", "exec", "env", "nohup", "time", "command", "&"}
TRANSFER = {"scp", "sftp", "ssh"}
WEB = {"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer"}
NC = {"nc", "ncat", "netcat"}
WITH_VALUE = {"scp": set("cDFiJloPSX"), "sftp": set("BbcDFiJloPRSsX"), "ssh": set("BbcDEeFIiJLlmOoPpQRSWw")}
REMOTE = re.compile(r"^(?:[^@\s]+@)?(\[[^\]]+\]|[^:/\\\s]+):")
URI = re.compile(r"^(?:scp|sftp|ssh)://(?:[^@/]+@)?(\[[^\]]+\]|[^:/]+)", re.IGNORECASE)
URL = re.compile(r"^(?:https?|ftps?)://(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)", re.IGNORECASE)
RISKY_OPTION = re.compile(r"proxycommand|localcommand|permitlocalcommand", re.IGNORECASE)
USER_LIST = re.compile(r"allow-hosts\.json", re.IGNORECASE)   # the user (and so the agent) can write it
ORG_LIST = re.compile(r"agentguard(?:[\\/]| baseline[\\/])baseline\.json", re.IGNORECASE)   # admin/SYSTEM only
LIST_FILES = re.compile(f"{USER_LIST.pattern}|{ORG_LIST.pattern}", re.IGNORECASE)
LOCAL_EXEC = re.compile(r"\$\(|`|<\(|>\(")   # inside quotes these still run a command on THIS machine
# Web tool options whose next token is a value (not a URL), and options that route or configure the request elsewhere
CURL_VALUE = {"-o", "--output", "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json", "-H", "--header",
              "-X", "--request", "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c",
              "--cookie-jar", "-F", "--form", "-T", "--upload-file", "-w", "--write-out", "-m", "--max-time",
              "--connect-timeout", "-r", "--range", "-C", "--continue-at", "-E", "--cert", "--key", "--cacert", "--capath",
              "-z", "--time-cond", "--limit-rate", "--retry", "--retry-delay", "--retry-max-time", "--max-filesize",
              "--oauth2-bearer", "--output-dir", "-t", "--ciphers", "-Y", "-y", "--interface", "--dns-servers",
              "--url-query"}
WGET_VALUE = {"-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-P", "--directory-prefix",
              "-U", "--user-agent", "--header", "--post-data", "--post-file", "--body-data", "--body-file", "--method",
              "-t", "--tries", "-T", "--timeout", "-w", "--wait", "--user", "--password", "--load-cookies",
              "--save-cookies", "-Q", "--quota", "--limit-rate", "-A", "--accept", "-R", "--reject", "-l", "--level"}
RISKY = {"curl": {"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--resolve",
                  "--connect-to", "-K", "--config", "-:", "--next", "--unix-socket", "--abstract-unix-socket"},
         "wget": {"-e", "--execute", "-i", "--input-file", "--config", "-b", "--background"},
         "powershell": {"-proxy"}}
PS_SWITCHES = {"-usebasicparsing", "-usedefaultcredentials", "-skipcertificatecheck", "-passthru", "-disablekeepalive",
               "-noproxy", "-allowunencryptedauthentication", "-resume", "-skipheadervalidation", "-skiphttperrorcheck",
               "-preserveauthorizationonredirect", "-asynchronous"}


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


def empty() -> dict:
    return {"transfer": set(), "web": set(), "allow_nc": False}


def load(path: Path | None = None, home: Path | None = None) -> dict:
    """{"transfer", "web", "allow_nc"}. A missing or malformed file approves nothing (fail closed)."""
    try:
        record = json.loads((path or baseline_path()).read_text(encoding="utf-8"))
        egress = record["data"]["egress"]
    except (OSError, ValueError, KeyError, TypeError):
        return empty()
    if not isinstance(egress, dict):
        return empty()
    allow = {"transfer": _hosts(egress.get("transfer_hosts")), "web": _hosts(egress.get("web_hosts")),
             "allow_nc": egress.get("allow_nc") is True}
    if egress.get("management") == "self":   # RB3: the user's own lists, only when the organization allows it
        try:
            own = json.loads(((home or Path.home()) / ".agentguard" / "allow-hosts.json").read_text(encoding="utf-8"))
            if isinstance(own, dict):
                allow["transfer"] |= _hosts(own.get("transfer_hosts"))
                allow["web"] |= _hosts(own.get("web_hosts"))
        except (OSError, ValueError):
            pass
    return allow


def approved(host: str, hosts: set[str]) -> bool:
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    return host in hosts or any(h.startswith("*.") and host.endswith(h[1:]) for h in hosts)


def _host_of(spec: str) -> str:
    spec = spec.split("@")[-1]
    return spec.split(":")[0] if not spec.startswith("[") else spec.split("]")[0] + "]"


def segments(command: str) -> list[str]:
    """Split a command line into commands at ; && || | & and newlines that are OUTSIDE quotes. `2>&1` and `&>` are
    redirections, not separators."""
    out, cur, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                cur.append(command[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in ";|\n" or (ch == "&" and not (i and command[i - 1] == ">") and command[i + 1:i + 2] != ">"):
            out.append("".join(cur))
            cur = []
            if command[i:i + 2] in ("&&", "||"):
                i += 1
            i += 1
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def tokenize(segment: str) -> list[str]:
    """Split at whitespace outside quotes and drop the quotes. Backslashes stay literal (Windows paths such as
    $HOME\\.ssh\\key), except \\" inside double quotes, which is an escaped quote. Raises ValueError on an open quote."""
    tokens, cur, quote, has, i = [], [], None, False, 0
    while i < len(segment):
        ch = segment[i]
        if quote == '"' and ch == "\\" and segment[i + 1:i + 2] == '"':
            cur.append('"')
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            else:
                cur.append(ch)
        elif ch in "\"'":
            quote, has = ch, True
        elif ch.isspace():
            if cur or has:
                tokens.append("".join(cur))
            cur, has = [], False
        else:
            cur.append(ch)
        i += 1
    if quote:
        raise ValueError("open quote")
    if cur or has:
        tokens.append("".join(cur))
    return tokens


def _tool(tokens: list[str]) -> tuple[str, list[str]]:
    while tokens and (tokens[0].lower() in WRAPPERS or re.match(r"^\w+=", tokens[0])):
        tokens = tokens[1:]
    if not tokens:
        return "", []
    tool = re.split(r"[\\/]", tokens[0])[-1].lower()
    return (tool[:-4] if tool.endswith(".exe") else tool), tokens[1:]


def _transfer(tool: str, args: list[str]) -> dict:
    hosts, keys, positional, ok, i = [], [], [], True, 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-") and len(tok) > 1:
            flags = tok[1:]
            for n, ch in enumerate(flags):
                if ch in WITH_VALUE[tool]:
                    value = flags[n + 1:] or (args[i + 1] if i + 1 < len(args) else "")
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
    return {"list": "transfer", "hosts": hosts, "keys": keys, "ok": ok and bool(hosts)}


def _web(tool: str, args: list[str]) -> dict:
    """URL hosts of curl / wget / Invoke-WebRequest and friends. Option values are skipped; a bare positional is a
    host too (curl accepts example.com without a scheme); variables and routing options fail closed."""
    powershell = tool not in ("curl", "wget")
    values = CURL_VALUE if tool == "curl" else WGET_VALUE
    risky = RISKY["powershell" if powershell else tool]
    hosts, ok, i = [], True, 0
    while i < len(args):
        tok = args[i]
        low = tok.lower()
        name = tok.split("=", 1)[0] if not powershell else low.split("=", 1)[0]
        if name in risky:   # case matters for curl and wget (-K is --config, -k is --insecure)
            ok = False
        if tok.startswith("-") and len(tok) > 1:
            if powershell:
                if low not in PS_SWITCHES:
                    value = args[i + 1] if i + 1 < len(args) else ""
                    i += 1
                    if low in ("-uri", "-source"):
                        hosts.append(value)
            elif "=" not in tok and (tok in values or name in values):
                i += 1
            i += 1
            continue
        hosts.append(tok)
        i += 1
    out = []
    for h in hosts:
        if h.startswith("$") or not h:
            ok = False
            continue
        m = URL.match(h)
        out.append(m.group(1) if m else re.split(r"[/:?#]", h.split("@")[-1])[0])
    return {"list": "web", "hosts": out, "keys": [], "ok": ok and bool(out)}


def _nc(args: list[str]) -> dict:
    hosts, ok, i = [], True, 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-") and len(tok) > 1:
            if re.search(r"[ecx]", tok[1:]):     # -e / -c run a program, -x uses a proxy
                ok = False
            if tok[-1] in "pswiqX":
                i += 1
        elif not hosts:
            hosts.append(tok)
        i += 1
    return {"list": "nc", "hosts": hosts, "keys": [], "ok": ok and bool(hosts)}


def parse(segment: str) -> dict | None:
    """{"list", "hosts", "keys", "ok"} for a transfer, web or nc command, None for anything else."""
    try:
        tool, args = _tool(tokenize(segment))
    except ValueError:
        return {"list": "", "hosts": [], "keys": [], "ok": False} if re.search(
            r"\b(scp|sftp|ssh|curl|wget|nc|ncat|netcat|iwr|irm|invoke-webrequest|invoke-restmethod)\b", segment, re.I) else None
    if tool in TRANSFER:
        return _transfer(tool, args)
    if tool in WEB:
        return _web(tool, args)
    if tool in NC:
        return _nc(args)
    return None


def _ok(info: dict, allow: dict) -> bool:
    if not info["ok"]:
        return False
    hosts = allow["web"] if info["list"] == "web" else allow["transfer"]
    if info["list"] == "nc" and not allow.get("allow_nc"):
        return False
    return all(approved(h, hosts) for h in info["hosts"])


def strip_approved(command: str, allow) -> tuple[str, str]:
    """(text for the egress check, text for the secret-path check). An approved command leaves the egress text, and
    its -i key leaves the secret text; everything else stays, so the usual rules still apply to it.
    allow: load() result, or a set of transfer hosts."""
    if isinstance(allow, set):
        allow = {**empty(), "transfer": allow}
    if not (allow["transfer"] or allow["web"]):
        return command, command
    egress_parts, secret_parts = [], []
    for segment in segments(command):   # stripped: the egress rule anchors at the start
        info = parse(segment)
        if info and not LOCAL_EXEC.search(segment) and _ok(info, allow):
            secret = segment
            for key in info["keys"]:
                if re.search(r"[\\/]\.ssh[\\/]", key.replace("~", "/")):
                    secret = secret.replace(key, " ")
            secret_parts.append(secret)
            continue
        egress_parts.append(segment)
        secret_parts.append(segment)
    return "\n".join(egress_parts), "\n".join(secret_parts)
