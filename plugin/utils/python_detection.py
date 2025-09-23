"""
Shared utilities for Python interpreter detection and virtual environment management.
"""

import os
import sys
import subprocess
import venv
from typing import List


def get_system_python_candidates() -> List[str]:
    """Get a list of candidate system Python paths for the current platform.
    
    Returns:
        List of potential Python interpreter paths to try.
    """
    if sys.platform == "win32":
        return ["py", "python.exe", "python3.exe"]
    elif sys.platform == "darwin":
        return [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3"
        ]
    else:  # Linux and other Unix-like systems
        return [
            "/usr/bin/python3",
            "/usr/local/bin/python3"
        ]


def is_binary_ninja_python(python_path: str) -> bool:
    """Check if a Python path appears to be Binary Ninja's embedded Python.
    
    Args:
        python_path: Path to Python interpreter to check.
        
    Returns:
        True if this appears to be Binary Ninja's embedded Python.
    """
    return "Binary Ninja" in python_path or "binaryninja" in python_path.lower()


def get_python_executable() -> str:
    """Best-effort detection of a Python interpreter for running the bridge.

    Priority:
    1) VIRTUAL_ENV (if active)
    2) System Python (on macOS/Linux when running from Binary Ninja)
    3) Inferred from sys.path zip/embedded layout
    4) Fallback to current interpreter

    Returns:
        Path to the best available Python interpreter.
    """
    # Check for active virtual environment first
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        if sys.platform == "win32":
            python = os.path.join(venv_path, "Scripts", "python.exe")
        else:
            python = os.path.join(venv_path, "bin", "python3")
        if os.path.exists(python):
            return python

    # On macOS/Linux, if we're running from Binary Ninja, try to find system Python first
    if sys.platform in ("darwin", "linux"):
        if is_binary_ninja_python(sys.executable):
            candidates = get_system_python_candidates()
            for python_path in candidates:
                if os.path.exists(python_path):
                    return python_path

    # Try to infer from sys.path zip/embedded layout
    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")
        
        parts = path.split(os.sep)
        if parts and parts[-1].endswith(".zip"):
            base = os.path.dirname(path)
            if sys.platform == "win32":
                candidate = os.path.join(base, "python.exe")
            else:
                candidate = os.path.abspath(os.path.join(base, "..", "bin", "python3"))
            if os.path.exists(candidate):
                return candidate

    # Final fallback
    return sys.executable


def create_venv_with_system_python(venv_dir: str, requirements_file: str = None) -> str:
    """Create a virtual environment using system Python when possible.
    
    Args:
        venv_dir: Directory where the virtual environment should be created.
        requirements_file: Optional path to requirements.txt to install.
        
    Returns:
        Path to the Python interpreter in the created virtual environment.
        
    Raises:
        Exception: If virtual environment creation fails.
    """
    # Determine expected Python path in venv
    if sys.platform == "win32":
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python3")
    
    # Check if we need to recreate the venv
    should_recreate = not os.path.exists(venv_python)
    
    # On Windows, check for Binary Ninja launcher
    if sys.platform == "win32":
        bn_launcher = os.path.join(venv_dir, "Scripts", "binaryninja.exe")
        if os.path.exists(bn_launcher):
            should_recreate = True
    
    # On macOS/Linux, check if existing venv uses Binary Ninja's Python
    if sys.platform in ("darwin", "linux") and os.path.exists(venv_python):
        try:
            result = subprocess.run(
                [venv_python, "-c", "import sys; print(sys.executable)"], 
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and is_binary_ninja_python(result.stdout.strip()):
                should_recreate = True
        except Exception:
            pass
    
    if should_recreate:
        os.makedirs(venv_dir, exist_ok=True)
        created = False
        
        # Try to use system Python for venv creation
        if sys.platform == "win32":
            # Use Python launcher on Windows
            try:
                subprocess.run(
                    ["py", "-3", "-m", "venv", venv_dir], 
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                created = True
            except Exception:
                pass
        else:
            # On macOS/Linux, try system Python interpreters
            candidates = get_system_python_candidates()
            for python_path in candidates:
                if os.path.exists(python_path):
                    try:
                        subprocess.run(
                            [python_path, "-m", "venv", venv_dir], 
                            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
                        )
                        created = True
                        break
                    except Exception:
                        continue
        
        # Fallback to venv.EnvBuilder if system Python methods failed
        if not created:
            builder = venv.EnvBuilder(with_pip=True, upgrade=False)
            builder.create(venv_dir)
        
        # Install requirements if provided
        if requirements_file and os.path.exists(requirements_file):
            try:
                subprocess.run(
                    [venv_python, "-m", "pip", "install", "-r", requirements_file], 
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
                )
            except Exception:
                pass
    
    return venv_python


def copy_python_env(env: dict) -> bool:
    """Copy Python-related environment variables that affect imports.
    
    Args:
        env: Dictionary to copy environment variables into.
        
    Returns:
        True if any variables were copied, False otherwise.
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
    
    copied = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            copied = True
            env[var] = value
    
    return copied
