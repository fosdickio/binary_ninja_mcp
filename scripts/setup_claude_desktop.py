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


def _ensure_plugin_venv(plugin_root: Path) -> str:
    vdir = plugin_root / ".venv"
    py = vdir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python3")
    try:
        if not py.exists():
            venv.EnvBuilder(with_pip=True).create(str(vdir))
            req = plugin_root / "bridge" / "requirements.txt"
            if req.exists():
                try:
                    subprocess.run([str(py), "-m", "pip", "install", "-r", str(req)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass
    except Exception:
        return sys.executable
    return str(py) if py.exists() else sys.executable
    if sys.platform == "win32":
        cand = plugin_root / ".venv" / "Scripts" / "python.exe"
    else:
        cand = plugin_root / ".venv" / "bin" / "python3"
    if cand.exists():
        return str(cand)
    # Fallback for safety
    return sys.executable


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
