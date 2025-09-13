import json
import os
import sys
from typing import Optional
import subprocess
import venv


def _repo_root() -> str:
    # plugin/utils/auto_setup.py -> plugin/utils -> plugin -> repo_root
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _bridge_entrypoint() -> str:
    return os.path.join(_repo_root(), "bridge", "binja_mcp_bridge.py")


def _sentinel_path() -> str:
    return os.path.join(_repo_root(), ".mcp_auto_setup_done")


def _venv_dir() -> str:
    return os.path.join(_repo_root(), ".venv")


def _venv_python() -> str:
    d = _venv_dir()
    if sys.platform == "win32":
        # Always prefer a real Python interpreter (python.exe) for MCP stdio servers.
        # Returning binaryninja.exe here causes the MCP client to fail on Windows.
        py = os.path.join(d, "Scripts", "python.exe")
        return py
    return os.path.join(d, "bin", "python3")


def _looks_like_binja_embedded(py_path: str) -> bool:
    """Detect venvs built from Binary Ninja's embedded interpreter on macOS."""
    try:
        bin_dir = os.path.dirname(py_path)
        bn = os.path.join(bin_dir, "binaryninja")
        if os.path.exists(bn) and os.path.exists(py_path):
            sp = os.stat(py_path)
            sb = os.stat(bn)
            if sp.st_size == sb.st_size:
                return True
        base = os.path.basename(py_path).lower()
        if base.startswith("binaryninja") or "Binary Ninja.app" in py_path:
            return True
    except Exception:
        pass
    return False


def _select_system_python(min_major: int = 3, min_minor: int = 10) -> str | None:
    def ok(p: str) -> bool:
        try:
            r = subprocess.run([p, "-c", "import sys;print(f'{sys.version_info[0]}.{sys.version_info[1]}')"], capture_output=True, text=True, check=False)
            if r.returncode == 0:
                s = (r.stdout or "").strip()
                parts = s.split(".")
                if len(parts) >= 2:
                    maj, minor = int(parts[0]), int(parts[1])
                    return (maj > min_major) or (maj == min_major and minor >= min_minor)
        except Exception:
            pass
        return False

    env_p = os.environ.get("BINJA_MCP_PYTHON")
    if env_p and ok(env_p):
        return env_p
    if ok(sys.executable):
        return sys.executable
    candidates: list[str] = []
    if sys.platform == "darwin":
        candidates += [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
        ]
    candidates += [
        "python3",
        "python3.12",
        "python3.11",
        "python3.10",
        "/usr/bin/python3",
    ]
    for c in candidates:
        if ok(c):
            return c
    return None


def _ensure_local_venv() -> str:
    """Create a local venv under the plugin root if missing.

    Returns path to the venv's python executable; falls back to sys.executable
    on failure.
    """
    vdir = _venv_dir()
    py = _venv_python()
    try:
        # If this looks missing or like a BN-embedded venv, (re)build using a real system Python.
        bn_launcher = os.path.join(vdir, "Scripts", "binaryninja.exe") if sys.platform == "win32" else None
        needs_build = not os.path.exists(py) or (sys.platform == "win32" and os.path.exists(bn_launcher))
        if not needs_build and sys.platform == "darwin" and _looks_like_binja_embedded(py):
            needs_build = True
        if needs_build:
            os.makedirs(vdir, exist_ok=True)
            created = False
            # On Windows, prefer system Python launcher to avoid embedding
            # Binary Ninja's interpreter into the venv.
            if sys.platform == "win32":
                try:
                    subprocess.run(["py", "-3", "-m", "venv", vdir], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    created = True
                except Exception:
                    created = False
            # On macOS, prefer a real Python >=3.10 (Homebrew if available)
            if sys.platform == "darwin" and not created:
                cand = _select_system_python(3, 10)
                if cand:
                    try:
                        subprocess.run([cand, "-m", "venv", vdir], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        created = True
                    except Exception:
                        created = False
            if not created:
                builder = venv.EnvBuilder(with_pip=True, upgrade=False)
                builder.create(vdir)
            # Re-evaluate interpreter path after creation (may be python.exe now)
            py = _venv_python()
            if sys.platform == "darwin" and _looks_like_binja_embedded(py):
                return _get_python_executable()
            # Best-effort: install bridge requirements
            req = os.path.join(_repo_root(), "bridge", "requirements.txt")
            if os.path.exists(req):
                try:
                    subprocess.run([py, "-m", "pip", "install", "-r", req], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass
    except Exception:
        return _get_python_executable()
    return py if os.path.exists(py) else _get_python_executable()


def _get_python_executable() -> str:
    # Mirror logic from server.py
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")
        parts = path.split(os.sep)
        if parts and parts[-1].endswith(".zip"):
            base = os.path.dirname(path)
            if sys.platform == "win32":
                cand = os.path.join(base, "python.exe")
            else:
                cand = os.path.abspath(os.path.join(base, "..", "bin", "python3"))
            if os.path.exists(cand):
                return cand
    return sys.executable


def _copy_python_env(env: dict) -> bool:
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    copied = False
    for var in python_vars:
        val = os.environ.get(var)
        if val:
            copied = True
            env[var] = val
    return copied


def _targets() -> dict:
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return {
            "Cline": (os.path.join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(appdata, "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        return {
            "Cline": (os.path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(home, "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        return {
            "Cline": (os.path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    else:
        return {}


def install_mcp_clients(quiet: bool = True) -> int:
    """Install MCP server entries for supported clients.

    Returns the number of configs modified. Creates a sentinel to avoid
    re-running on every Binary Ninja start.
    """
    sentinel = _sentinel_path()
    server_key = "binary_ninja_mcp"
    if os.path.exists(sentinel):
        # If sentinel exists but no client has our key yet, proceed anyway
        try:
            targets = _targets()
            for _name, (config_dir, config_file) in targets.items():
                config_path = os.path.join(config_dir, config_file)
                if not os.path.exists(config_path):
                    continue
                with open(config_path, "r", encoding="utf-8") as f:
                    data = f.read().strip()
                    if not data:
                        continue
                    cfg = json.loads(data)
                if isinstance(cfg, dict) and server_key in cfg.get("mcpServers", {}):
                    return 0
            # No installs found; ignore the sentinel and continue
        except Exception:
            # On any error, fall through and attempt install
            pass

    targets = _targets()
    if not targets:
        return 0

    env: dict[str, str] = {}
    _copy_python_env(env)
    bridge = _bridge_entrypoint()
    # Prefer local venv python for bridge execution
    command = _ensure_local_venv()

    modified = 0
    for _name, (config_dir, config_file) in targets.items():
        if not os.path.exists(config_dir):
            continue
        config_path = os.path.join(config_dir, config_file)
        if not os.path.exists(config_path):
            config = {}
        else:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = f.read().strip()
                    config = json.loads(data) if data else {}
            except Exception:
                continue

        config.setdefault("mcpServers", {})
        servers = config["mcpServers"]

        # If a legacy key exists, copy into new key without removing legacy
        legacy_key = "binary_ninja_mcp_max"
        if legacy_key in servers and server_key not in servers:
            try:
                legacy_cfg = dict(servers[legacy_key])
                # merge env
                if env:
                    merged_env = dict(legacy_cfg.get("env", {}))
                    merged_env.update(env)
                    legacy_cfg["env"] = merged_env
                servers[server_key] = legacy_cfg
            except Exception:
                pass
        else:
            servers[server_key] = {
                "command": command,
                "args": [bridge],
                "timeout": 1800,
                "disabled": False,
                **({"env": env} if env else {}),
            }

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            modified += 1
        except Exception:
            # Best-effort; skip failures silently in plugin context
            pass

    # Only write sentinel if we successfully modified at least one config
    if modified > 0:
        try:
            with open(sentinel, "w", encoding="utf-8") as f:
                f.write("ok")
        except Exception:
            pass

    return modified
