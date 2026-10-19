"""Build the two plugin variants of the marketplace from src/ (run from the repository root: python tools/build.py).

Claude Code runs exec-form hooks by resolving `command` on PATH, with no way to pick it per operating system
(code.claude.com/docs/en/hooks, "Exec form and shell form"). Python is `python` on Windows and `python3` on macOS,
so the marketplace ships two plugins with the same content and different hook commands:
  plugins/agentguard        -> Windows (python)
  plugins/agentguard-macos  -> macOS and Linux (python3)
Exec form (`args`) is used so ${CLAUDE_PLUGIN_ROOT} is substituted without depending on Git Bash or PowerShell.
`python tools/build.py --check` fails when the committed plugins differ from what src/ would build (used by tests).
"""

import json
import os
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
VERSION = "0.4.0"
VARIANTS = {"agentguard": ("python", "Windows"), "agentguard-macos": ("python3", "macOS y Linux")}
DESCRIPTION = ("GenIA AgentGuard (IMR): politica de seguridad para agentes de IA. Skill de politica, skill para revisar "
               "y corregir los resultados del equipo, recordatorio al iniciar sesion y hooks que bloquean secretos y "
               "salida de datos y piden confirmacion para cambiar la configuracion de Claude")


def manifest(name: str, platform: str) -> dict:
    return {"name": name, "displayName": f"GenIA AgentGuard ({platform})", "version": VERSION,
            "description": DESCRIPTION, "author": {"name": "IMR Consulting"}, "license": "Apache-2.0",
            "homepage": "https://github.com/cibersergei/agentguard-plugin", "keywords": ["security", "governance", "agentguard"]}


def hooks(python: str) -> dict:
    def handler(script: str, timeout: int) -> dict:
        return {"type": "command", "command": python, "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/" + script], "timeout": timeout}
    return {"hooks": {
        "SessionStart": [{"hooks": [handler("agentguard_session.py", 10)]}],
        "PreToolUse": [{"matcher": "Bash|PowerShell|Read|Edit|Write|MultiEdit|NotebookEdit",
                        "hooks": [handler("agentguard_pretooluse.py", 10)]}],
    }}


def marketplace() -> dict:
    return {"name": "imr-agentguard", "description": "Plugins de GenIA AgentGuard (IMR Consulting)",
            "owner": {"name": "IMR Consulting"},
            "plugins": [{"name": n, "source": f"./plugins/{n}", "description": f"{DESCRIPTION}. Variante {p}.",
                         "version": VERSION} for n, (_py, p) in VARIANTS.items()]}


def build(out: Path) -> None:
    for name, (python, platform) in VARIANTS.items():
        target = out / "plugins" / name
        if target.exists():
            shutil.rmtree(target, onerror=_writable_retry)
        shutil.copytree(SRC, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        _write(target / ".claude-plugin" / "plugin.json", manifest(name, platform))
        _write(target / "hooks" / "hooks.json", hooks(python))
    _write(out / ".claude-plugin" / "marketplace.json", marketplace())


def _writable_retry(func, path, _exc) -> None:
    """OneDrive marks synced folders read-only + pinned, so rmdir fails: clear read-only and retry once."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def _snapshot(base: Path) -> dict:
    files = {}
    for sub in ("plugins", ".claude-plugin"):
        for p in sorted((base / sub).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                files[str(p.relative_to(base)).replace("\\", "/")] = p.read_bytes().replace(b"\r\n", b"\n")
    return files


if __name__ == "__main__":
    if "--check" in sys.argv:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp))
            same = _snapshot(Path(tmp)) == _snapshot(ROOT)
        print("plugins al dia" if same else "plugins desactualizados: correr python tools/build.py")
        sys.exit(0 if same else 1)
    build(ROOT)
    print("plugins generados en", ROOT / "plugins")
