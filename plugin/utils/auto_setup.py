import json
import os
import sys
from typing import Optional
from .python_detection import get_python_executable, create_venv_with_system_python, copy_python_env


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


def _ensure_local_venv() -> str:
    """Create a local venv under the plugin root if missing.

    Returns path to the venv's python executable; falls back to get_python_executable
    on failure.
    """
    vdir = _venv_dir()
    req = os.path.join(_repo_root(), "bridge", "requirements.txt")
    
    try:
        py = create_venv_with_system_python(vdir, req if os.path.exists(req) else None)
        return py if os.path.exists(py) else get_python_executable()
    except Exception:
        return get_python_executable()


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
    copy_python_env(env)
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
