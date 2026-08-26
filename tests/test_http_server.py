import importlib.util
import json
import sys
import threading
import time
import types
import unittest
import urllib.request
from pathlib import Path


def _load_http_server_module():
    log_messages = {"debug": [], "info": [], "warn": [], "error": []}
    binaryninja = types.ModuleType("binaryninja")
    for level in log_messages:
        setattr(binaryninja, f"log_{level}", log_messages[level].append)
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
    return module, log_messages


class ServerConfig:
    server = types.SimpleNamespace(host="127.0.0.1", port=0)
    binary_ninja = object()


class HTTPServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.logs = _load_http_server_module()

    def setUp(self):
        self.server = self.module.MCPServer(ServerConfig())

    def tearDown(self):
        self.server.stop()

    def url(self, path):
        port = self.server.server.server_address[1]
        return f"http://127.0.0.1:{port}{path}"

    def test_health_reports_live_server(self):
        self.server.start()
        with urllib.request.urlopen(self.url("/health"), timeout=1) as response:
            health = json.load(response)

        self.assertEqual(health["status"], "ok")
        self.assertTrue(health["server_thread_alive"])
        self.assertGreaterEqual(health["active_requests"], 1)

    def test_slow_request_does_not_block_other_requests(self):
        slow_started = threading.Event()
        release_slow = threading.Event()
        original_do_get = self.module.MCPRequestHandler.do_GET
        original_threshold = self.module.MCPRequestHandler.slow_request_seconds

        def do_get(handler):
            if handler.path == "/slow":
                slow_started.set()
                release_slow.wait(timeout=2)
            handler._send_json_response({"path": handler.path})

        self.module.MCPRequestHandler.do_GET = do_get
        self.module.MCPRequestHandler.slow_request_seconds = 0.05
        try:
            self.server.start()
            slow_request = threading.Thread(
                target=lambda: urllib.request.urlopen(self.url("/slow"), timeout=2).read()
            )
            slow_request.start()
            self.assertTrue(slow_started.wait(timeout=1))

            with urllib.request.urlopen(self.url("/fast"), timeout=1) as response:
                self.assertEqual(json.load(response), {"path": "/fast"})

            time.sleep(0.1)
            self.assertTrue(any("GET /slow" in message for message in self.logs["warn"]))

            stop_started = time.monotonic()
            self.server.stop()
            self.assertLess(time.monotonic() - stop_started, 1.0)

            release_slow.set()
            slow_request.join(timeout=1)
            self.assertFalse(slow_request.is_alive())
        finally:
            release_slow.set()
            self.module.MCPRequestHandler.do_GET = original_do_get
            self.module.MCPRequestHandler.slow_request_seconds = original_threshold


if __name__ == "__main__":
    unittest.main()
