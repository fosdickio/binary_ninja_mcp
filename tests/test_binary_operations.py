import importlib.util
import sys
import types
import unittest
from pathlib import Path


def _load_binary_operations_module():
    info_logs = []
    binaryninja = types.ModuleType("binaryninja")
    binaryninja.log_info = info_logs.append
    binaryninja.log_warn = lambda _message: None
    binaryninja.log_error = lambda _message: None

    def binaryninja_type(name):
        value = type(name, (), {})
        setattr(binaryninja, name, value)
        return value

    binaryninja.__getattr__ = binaryninja_type
    sys.modules["binaryninja"] = binaryninja

    enums = types.ModuleType("binaryninja.enums")
    enums.StructureVariant = type("StructureVariant", (), {})
    enums.TypeClass = type("TypeClass", (), {})
    sys.modules[enums.__name__] = enums

    for package in ("plugin", "plugin.core", "plugin.utils"):
        module = types.ModuleType(package)
        module.__path__ = []
        sys.modules[package] = module

    config = types.ModuleType("plugin.core.config")
    config.BinaryNinjaConfig = object
    sys.modules[config.__name__] = config

    string_utils = types.ModuleType("plugin.utils.string_utils")
    string_utils.escape_non_ascii = lambda value: value
    sys.modules[string_utils.__name__] = string_utils

    path = Path(__file__).parents[1] / "plugin" / "core" / "binary_operations.py"
    spec = importlib.util.spec_from_file_location("plugin.core.binary_operations", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, info_logs


class RenameThenCommentView:
    def __init__(self):
        self.file = types.SimpleNamespace(filename="rename-test.bndb")
        self.function = types.SimpleNamespace(name="sub_401000", start=0x401000)
        self.comments = {}

    def get_function_at(self, address):
        return self.function if address == self.function.start else None

    def get_functions_by_name(self, _name):
        return []

    def get_symbols_by_name(self, _name):
        return []

    def get_symbol_by_raw_name(self, _name):
        return None

    def set_comment_at(self, address, comment):
        self.comments[address] = comment

    @property
    def functions(self):
        raise AssertionError("renamed function lookup must not scan all functions")


class IndexedQualifiedFunctionView(RenameThenCommentView):
    def __init__(self):
        super().__init__()
        self.function.name = "send_activate_request_0x0193"

    def get_symbols_by_name(self, name):
        if name == "StaticObjectInteraction::send_activate_request_0x0193":
            return [types.SimpleNamespace(address=self.function.start)]
        return []


class BinaryOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.info_logs = _load_binary_operations_module()

    def setUp(self):
        self.info_logs.clear()
        self.operations = self.module.BinaryOperations(object())

    def test_renamed_function_can_be_commented_by_qualified_name(self):
        view = RenameThenCommentView()
        self.operations._current_view = view
        qualified_name = "StaticObjectInteraction::send_activate_request_0x0193"

        self.assertTrue(self.operations.rename_function("0x401000", qualified_name))
        self.assertTrue(self.operations.set_function_comment(qualified_name, "interaction handler"))

        self.assertEqual(view.comments, {0x401000: "interaction handler"})

    def test_qualified_function_name_uses_symbol_index(self):
        view = IndexedQualifiedFunctionView()
        self.operations._current_view = view

        function = self.operations.get_function_by_name_or_address(
            "StaticObjectInteraction::send_activate_request_0x0193"
        )

        self.assertIs(function, view.function)

    def test_function_lookup_applies_configured_rename_prefix(self):
        view = RenameThenCommentView()
        self.operations._current_view = view
        original_settings = self.module.bn.Settings
        self.module.bn.Settings = lambda: types.SimpleNamespace(get_string=lambda _key: "mcp_")
        try:
            self.assertTrue(
                self.operations.rename_function("0x401000", "mcp_MapForm_initialize_quest_ui")
            )
            self.assertTrue(
                self.operations.set_function_comment(
                    "MapForm_initialize_quest_ui", "quest UI initializer"
                )
            )
        finally:
            self.module.bn.Settings = original_settings

        self.assertEqual(view.comments, {0x401000: "quest UI initializer"})


if __name__ == "__main__":
    unittest.main()
