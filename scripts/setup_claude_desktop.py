#!/usr/bin/env python3

import json
import sys
import platform
import os
from pathlib import Path
import venv
import subprocess


def check_os():
    """Check if the operating system is Mac OS."""
    if platform.system() != "Darwin":
        print("Error: This setup script is only supported on Mac OS.")
        print(f"Current operating system: {platform.system()}")
        sys.exit(1)


def get_config_path():
    """Get the path to the Claude Desktop config file."""
    home = Path.home()
    return (
        home
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json"
    )


def _looks_like_binja_embedded(py_path: Path) -> bool:
    try:
        bin_dir = py_path.parent
        bn = bin_dir / "binaryninja"
        if bn.exists() and py_path.exists():
            sp = py_path.stat()
            sb = bn.stat()
            if sp.st_size == sb.st_size:
                return True
        base = py_path.name.lower()
        if base.startswith("binaryninja") or "Binary Ninja.app" in str(py_path):
            return True
    except Exception:
        pass
    return False


def _select_system_python() -> str | None:
    def ok(p: str) -> bool:
        try:
            r = subprocess.run([p, "-c", "import sys;print(f'{sys.version_info[0]}.{sys.version_info[1]}')"], capture_output=True, text=True, check=False)
            if r.returncode == 0:
                s = (r.stdout or "").strip()
                parts = s.split(".")
                if len(parts) >= 2:
                    maj, minor = int(parts[0]), int(parts[1])
                    return (maj > 3) or (maj == 3 and minor >= 10)
        except Exception:
            pass
        return False

    env_p = os.environ.get("BINJA_MCP_PYTHON")
    if env_p and ok(env_p):
        return env_p
    if ok(sys.executable):
        return sys.executable
    cands = [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "python3",
        "python3.12",
        "python3.11",
        "python3.10",
        "/usr/bin/python3",
    ]
    for c in cands:
        if ok(c):
            return c
    return None


def _ensure_plugin_venv(plugin_root: Path) -> str:
    vdir = plugin_root / ".venv"
    py = vdir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python3")
    try:
        needs_build = not py.exists() or (sys.platform == "darwin" and _looks_like_binja_embedded(py))
        if needs_build:
            vdir.mkdir(parents=True, exist_ok=True)
            created = False
            if sys.platform == "win32":
                try:
                    subprocess.run(["py", "-3", "-m", "venv", str(vdir)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    created = True
                except Exception:
                    created = False
            if sys.platform == "darwin" and not created:
                cand = _select_system_python()
                if cand:
                    try:
                        subprocess.run([cand, "-m", "venv", str(vdir)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        created = True
                    except Exception:
                        created = False
            if not created:
                venv.EnvBuilder(with_pip=True).create(str(vdir))
            py = vdir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python3")
            if sys.platform == "darwin" and _looks_like_binja_embedded(py):
                return sys.executable
            # Best-effort deps
            req = plugin_root / "bridge" / "requirements.txt"
            if req.exists():
                try:
                    subprocess.run([str(py), "-m", "pip", "install", "-r", str(req)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass
    except Exception:
        return sys.executable
    return str(py) if py.exists() else sys.executable


def setup_claude_desktop():
    """Set up Claude Desktop configuration for the current project."""
    check_os()

    config_path = get_config_path()

    if not config_path.exists():
        print(f"Error: Claude Desktop config not found at {config_path}")
        print("Please make sure Claude Desktop is installed and configured.")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        # Use the installed plugin path (works for Plugin Manager installs):
        # <BinaryNinja>/repositories/community/plugins/CX330Blake_binary_ninja_mcp
        plugin_root = Path(__file__).resolve().parent.parent
        src_dir = plugin_root / "bridge"

        if "mcpServers" not in config:
            config["mcpServers"] = {}

        config["mcpServers"]["binary_ninja_mcp"] = {
            "command": _ensure_plugin_venv(plugin_root),
            "args": [str(src_dir / "binja_mcp_bridge.py")],
        }

        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        print("Successfully updated Claude Desktop configuration.")

    except Exception as e:
        print(f"Error updating configuration: {e}")
        sys.exit(1)


if __name__ == "__main__":
    setup_claude_desktop()
