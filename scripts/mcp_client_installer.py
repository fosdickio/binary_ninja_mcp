import os
import sys
import json
import argparse
import subprocess
import venv


# Unique key used in MCP client configs
MCP_SERVER_KEY = "binary_ninja_mcp"


def _repo_root() -> str:
    """Return the repository root (one level above this scripts directory)."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _bridge_entrypoint() -> str:
    return os.path.join(_repo_root(), "bridge", "binja_mcp_bridge.py")


def _venv_dir() -> str:
    return os.path.join(_repo_root(), ".venv")


def _venv_python() -> str:
    d = _venv_dir()
    if sys.platform == "win32":
        # Always prefer a real Python interpreter for MCP stdio servers.
        # "binaryninja.exe" is an embedded interpreter launcher and does not
        # behave like a normal Python on stdio, causing MCP clients to fail.
        py = os.path.join(d, "Scripts", "python.exe")
        return py
    return os.path.join(d, "bin", "python3")


def _looks_like_binja_embedded(py_path: str) -> bool:
    """Heuristic to detect a venv built from Binary Ninja's embedded interpreter on macOS.

    Such venvs often place a "binaryninja" executable next to python3 and the
    copied binaries have identical sizes. These don't behave like a normal
    stdio Python and will be killed by MCP clients.
    """
    try:
        bin_dir = os.path.dirname(py_path)
        bn = os.path.join(bin_dir, "binaryninja")
        if os.path.exists(bn) and os.path.exists(py_path):
            sp = os.stat(py_path)
            sb = os.stat(bn)
            if sp.st_size == sb.st_size:
                return True
        # Path hints
        base = os.path.basename(py_path).lower()
        if base.startswith("binaryninja") or "Binary Ninja.app" in py_path:
            return True
    except Exception:
        pass
    return False


def _select_system_python(min_major: int = 3, min_minor: int = 10) -> str | None:
    """Select a real system Python meeting the minimum version.

    Order of preference (macOS):
      1) BINJA_MCP_PYTHON (if set and valid)
      2) sys.executable (if valid)
      3) Homebrew paths (/opt/homebrew, /usr/local)
      4) python3 on PATH, then specific versions (3.12..3.10)
      5) /usr/bin/python3 (last resort, may be too old)
    """
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


def ensure_local_venv() -> str:
    """Create a local venv under the plugin root if missing and return its python."""
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
            # On Windows, prefer using the system Python launcher to avoid
            # embedding Binary Ninja's interpreter into the venv.
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
            # If we still ended up with BN's embedded launcher on macOS, don't use it
            if sys.platform == "darwin" and _looks_like_binja_embedded(py):
                return get_python_executable()
            # Best-effort: install bridge requirements
            req = os.path.join(_repo_root(), "bridge", "requirements.txt")
            if os.path.exists(req):
                try:
                    subprocess.run([py, "-m", "pip", "install", "-r", req], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass
    except Exception:
        return get_python_executable()
    # If we still couldn't provision a python.exe in the venv, fall back to a
    # system Python to keep the bridge usable.
    return py if os.path.exists(py) else get_python_executable()


def get_python_executable() -> str:
    """Best-effort detection of a Python interpreter for running the bridge.

    Priority:
    1) VIRTUAL_ENV (if active)
    2) Inferred from sys.path zip/embedded layout
    3) Fallback to current interpreter
    """
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

        split = path.split(os.sep)
        if split and split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable

    return sys.executable


def copy_python_env(env: dict[str, str]) -> bool:
    """Copy Python-related environment variables that affect imports.

    MCP clients often run servers in a clean environment; forward variables
    that influence dependency resolution so the bridge can locate packages.
    """
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def print_mcp_config():
    """Print a generic MCP config snippet users can copy to unsupported clients."""
    mcp_config = {
        "command": ensure_local_venv(),
        "args": [
            _bridge_entrypoint(),
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        mcp_config["env"] = env
    print(json.dumps({"mcpServers": {MCP_SERVER_KEY: mcp_config}}, indent=2))


def _config_targets() -> dict[str, tuple[str, str]]:
    """Return supported MCP client config locations per platform.

    Value is (config_dir, filename).
    """
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


def install_mcp_servers(*, uninstall: bool = False, quiet: bool = False, env: dict[str, str] | None = None) -> int:
    """Install or remove MCP server entries for supported clients.

    Returns the number of configs modified.
    """
    env = {} if env is None else dict(env)
    targets = _config_targets()
    if not targets:
        if not quiet:
            print(f"Unsupported platform: {sys.platform}")
        return 0

    installed = 0
    for name, (config_dir, config_file) in targets.items():
        config_path = os.path.join(config_dir, config_file)
        action_word = "uninstall" if uninstall else "installation"

        if not os.path.exists(config_dir):
            if not quiet:
                print(f"Skipping {name} {action_word}\n  Config: {config_path} (not found)")
            continue

        if not os.path.exists(config_path):
            config: dict = {}
        else:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = f.read().strip()
                    config = json.loads(data) if data else {}
            except json.decoder.JSONDecodeError:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                continue

        config.setdefault("mcpServers", {})
        mcp_servers = config["mcpServers"]

        if uninstall:
            if MCP_SERVER_KEY not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[MCP_SERVER_KEY]
        else:
            # Preserve any existing env overrides for this server
            if MCP_SERVER_KEY in mcp_servers:
                for key, value in mcp_servers[MCP_SERVER_KEY].get("env", {}).items():
                    env[key] = value

            bridge = _bridge_entrypoint()
            if copy_python_env(env) and not quiet:
                print("[WARNING] Custom Python environment variables detected")

            server_cfg = {
                "command": ensure_local_venv(),
                "args": [bridge],
                "timeout": 1800,
                "disabled": False,
            }
            if env:
                server_cfg["env"] = env
            mcp_servers[MCP_SERVER_KEY] = server_cfg

        # Write back
        os.makedirs(config_dir, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        if not quiet:
            print(("Uninstalled" if uninstall else "Installed") + f" {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1

    if not uninstall and installed == 0 and not quiet:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

    return installed


def main():
    parser = argparse.ArgumentParser(description="Binary Ninja MCP Max - MCP Client Installer (CLI)")
    parser.add_argument("--install", action="store_true", help="Install MCP server entries for supported clients")
    parser.add_argument("--uninstall", action="store_true", help="Remove MCP server entries from supported clients")
    parser.add_argument("--config", action="store_true", help="Print generic MCP config JSON")
    parser.add_argument("--quiet", action="store_true", help="Reduce output noise")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.config:
        print_mcp_config()
        return

    if args.uninstall:
        install_mcp_servers(uninstall=True, quiet=args.quiet)
        # Also remove auto-setup sentinel so the plugin can re-run setup later
        sentinel = os.path.join(_repo_root(), ".mcp_auto_setup_done")
        try:
            os.remove(sentinel)
            if not args.quiet:
                print(f"Removed auto-setup marker: {sentinel}")
        except FileNotFoundError:
            pass
        except Exception as e:
            if not args.quiet:
                print(f"Warning: failed to remove auto-setup marker: {e}")
        return

    # Default action is install if no flag is provided
    if args.install or (not args.uninstall and not args.config):
        install_mcp_servers(quiet=args.quiet)


if __name__ == "__main__":
    main()
