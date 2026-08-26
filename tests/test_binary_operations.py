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


class ConstantTimeSizeView:
    def __init__(self, width=None):
        self.width = width

    def get_data_var_at(self, _address):
        if self.width is None:
            return None
        return types.SimpleNamespace(type=types.SimpleNamespace(width=self.width))

    def get_type_at(self, _address):
        return None

    @property
    def functions(self):
        raise AssertionError("size inference must not scan functions")


class PaginatedDataView:
    def __init__(self):
        self.iterated = 0

    @property
    def data_vars(self):
        def addresses():
            for address in range(0x1000, 0x1100):
                self.iterated += 1
                yield address

        return addresses()

    def get_data_var_at(self, _address):
        return types.SimpleNamespace(type=types.SimpleNamespace(width=1))

    def read_int(self, address, _width):
        return address & 0xFF

    def read(self, address, length):
        return bytes([address & 0xFF]) * length

    def get_symbol_at(self, address):
        return types.SimpleNamespace(name=f"data_{address:x}", raw_name=f"data_{address:x}")


class BinaryOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.info_logs = _load_binary_operations_module()

    def setUp(self):
        self.info_logs.clear()
        self.operations = self.module.BinaryOperations(object())

    def test_size_inference_never_scans_program_functions(self):
        self.operations._current_view = ConstantTimeSizeView(width=8)
        self.assertEqual(self.operations.infer_data_size(0x1000), 8)

        self.operations._current_view = ConstantTimeSizeView()
        self.assertIsNone(self.operations.infer_data_size(0x1000))

    def test_defined_data_applies_pagination_during_iteration(self):
        view = PaginatedDataView()
        self.operations._current_view = view

        items = self.operations.get_defined_data(offset=1, limit=2, read_len=1)

        self.assertEqual([item["address"] for item in items], ["0x1001", "0x1002"])
        self.assertLessEqual(view.iterated, 4)


if __name__ == "__main__":
    unittest.main()
