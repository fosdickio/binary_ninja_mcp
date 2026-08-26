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


class ExactTypeSearchView:
    def get_type_by_name(self, name):
        if name == "logic_iobj":
            return types.SimpleNamespace(type_class=None)
        return None

    @property
    def user_type_container(self):
        raise AssertionError("exact type search must not enumerate user types")

    @property
    def types(self):
        raise AssertionError("exact type search must not enumerate view types")


class CountingTypeMap:
    def __init__(self):
        self.iterated = 0

    def __bool__(self):
        return True

    def items(self):
        for index in range(100):
            self.iterated += 1
            name = "needle_type" if index == 1 else f"type_{index}"
            yield index, (name, types.SimpleNamespace(type_class=None))


class BoundedTypeSearchView:
    def __init__(self):
        self.type_map = CountingTypeMap()
        self.user_type_container = types.SimpleNamespace(types=self.type_map)

    def get_type_by_name(self, _name):
        return None

    @property
    def types(self):
        raise AssertionError("bounded search must stop before scanning view types")


class BinaryOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.info_logs = _load_binary_operations_module()

    def setUp(self):
        self.info_logs.clear()
        self.operations = self.module.BinaryOperations(object())

    def test_exact_type_search_does_not_enumerate_types(self):
        self.operations._current_view = ExactTypeSearchView()

        result = self.operations.search_local_types("logic_iobj")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "logic_iobj")

    def test_type_search_stops_at_scan_limit(self):
        view = BoundedTypeSearchView()
        self.operations._current_view = view

        result = self.operations.search_local_types("needle", limit=10, max_scan=3)

        self.assertEqual([entry["name"] for entry in result], ["needle_type"])
        self.assertLessEqual(view.type_map.iterated, 4)


if __name__ == "__main__":
    unittest.main()
