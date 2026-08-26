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


class FakeView:
    def __init__(self, filename):
        self.file = types.SimpleNamespace(filename=filename)


class BinaryOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.info_logs = _load_binary_operations_module()

    def setUp(self):
        self.info_logs.clear()
        self.operations = self.module.BinaryOperations(object())

    def test_first_assignment_remains_active_and_repeat_is_noop(self):
        view = FakeView("sample.bndb")

        self.operations.current_view = view
        self.operations.current_view = view

        self.assertIs(self.operations.current_view, view)
        self.assertEqual(len(self.operations._views_by_id), 1)
        self.assertEqual(self.info_logs, ["Set current binary view: sample.bndb"])

    def test_replacement_view_for_same_file_updates_silently(self):
        first_view = FakeView("sample.bndb")
        replacement_view = FakeView("sample.bndb")

        self.operations.current_view = first_view
        self.operations.current_view = replacement_view

        self.assertIs(self.operations.current_view, replacement_view)
        self.assertEqual(len(self.operations._views_by_id), 1)
        self.assertEqual(self.info_logs, ["Set current binary view: sample.bndb"])


if __name__ == "__main__":
    unittest.main()
