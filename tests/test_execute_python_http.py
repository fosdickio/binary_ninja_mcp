import importlib.util
import json
import sys
import types
import unittest
import urllib.request
from pathlib import Path


def _load_http_server_module():
    logs = {"debug": [], "info": [], "warn": [], "error": []}
    binaryninja = types.ModuleType("binaryninja")
    for level in logs:
        setattr(binaryninja, f"log_{level}", logs[level].append)
    settings = types.ModuleType("binaryninja.settings")
    settings.Settings = object
    sys.modules["binaryninja"] = binaryninja
    sys.modules["binaryninja.settings"] = settings

    for package in ("plugin", "plugin.server", "plugin.api", "plugin.core", "plugin.utils"):
        module = types.ModuleType(package)
        module.__path__ = []
        sys.modules[package] = module

    endpoints = types.ModuleType("plugin.api.endpoints")
    endpoints.BinaryNinjaEndpoints = object
    sys.modules[endpoints.__name__] = endpoints

    binary_operations = types.ModuleType("plugin.core.binary_operations")

    class BinaryOperations:
        def __init__(self, _config):
            self.current_view = None

    binary_operations.BinaryOperations = BinaryOperations
    sys.modules[binary_operations.__name__] = binary_operations

    config = types.ModuleType("plugin.core.config")
    config.Config = object
    sys.modules[config.__name__] = config

    scripting = types.ModuleType("plugin.core.scripting")

    class PythonScriptingExecutor:
        def __init__(self):
            self.calls = []

        def execute(self, code, view, timeout_seconds):
            self.calls.append((code, view, timeout_seconds))
            return {"success": True, "output": "script output\n", "errors": ""}

        def close(self):
            pass

    scripting.PythonScriptingExecutor = PythonScriptingExecutor
    sys.modules[scripting.__name__] = scripting

    number_utils = types.ModuleType("plugin.utils.number_utils")
    number_utils.convert_number = lambda value, size: (value, size)
    sys.modules[number_utils.__name__] = number_utils

    string_utils = types.ModuleType("plugin.utils.string_utils")
    string_utils.parse_int_or_default = lambda value, default: (
        int(value) if value is not None else default
    )
    sys.modules[string_utils.__name__] = string_utils

    path = Path(__file__).parents[1] / "plugin" / "server" / "http_server.py"
    spec = importlib.util.spec_from_file_location("plugin.server.http_server", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, logs


class ServerConfig:
    server = types.SimpleNamespace(host="127.0.0.1", port=0)
    binary_ninja = object()


class ExecutePythonHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.logs = _load_http_server_module()

    def setUp(self):
        self.server = self.module.MCPServer(ServerConfig())

    def tearDown(self):
        self.server.stop()

    def test_execute_python_uses_scripting_executor_without_logging_code(self):
        current_view = object()
        self.server.binary_ops.current_view = current_view
        self.server.start()
        port = self.server.server.server_address[1]
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/executePython",
            data=json.dumps({"code": "print(bv)", "timeout_seconds": 2}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=1) as response:
            result = json.load(response)

        self.assertEqual(result["output"], "script output\n")
        self.assertEqual(
            self.server.scripting_executor.calls,
            [("print(bv)", current_view, 2.0)],
        )
        self.assertFalse(any("print(bv)" in message for message in self.logs["info"]))


if __name__ == "__main__":
    unittest.main()
