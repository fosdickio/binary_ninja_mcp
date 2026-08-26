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


class IndexedFieldXrefView:
    def __init__(self):
        self.code_query = None
        self.data_query = None

    def get_type_by_name(self, name):
        if name != "Player":
            return None
        member = types.SimpleNamespace(name="health", offset=0x18)
        return types.SimpleNamespace(members=[member])

    def get_code_refs_for_type_field(self, name, offset, max_items=None):
        self.code_query = (name, offset, max_items)
        function = types.SimpleNamespace(name="update_player")
        return [types.SimpleNamespace(address=0x401000, function=function)]

    def get_data_refs_for_type_field(self, name, offset, max_items=None):
        self.data_query = (name, offset, max_items)
        return [0x500018]

    @property
    def functions(self):
        raise AssertionError("field xrefs must not scan functions or HLIL")

    @property
    def data_vars(self):
        raise AssertionError("field xrefs must not scan data variables")


class IndexedEnumXrefView:
    def __init__(self):
        self.code_query = None
        self.data_query = None

    def get_type_by_name(self, name):
        if name != "PlayerState":
            return None
        members = [
            types.SimpleNamespace(name="Idle", value=0),
            types.SimpleNamespace(name="Running", value=1),
        ]
        return types.SimpleNamespace(members=members)

    def get_code_refs_for_type(self, name, max_items=None):
        self.code_query = (name, max_items)
        function = types.SimpleNamespace(name="update_state")
        return [types.SimpleNamespace(address=0x402000, function=function)]

    def get_data_refs_for_type(self, name, max_items=None):
        self.data_query = (name, max_items)
        return [0x600000]

    @property
    def functions(self):
        raise AssertionError("enum xrefs must not scan functions or HLIL")

    @property
    def types(self):
        raise AssertionError("enum xrefs must not scan all types")


class IndexedNamedTypeXrefView:
    def __init__(self, type_name):
        self.type_name = type_name
        self.code_query = None
        self.data_query = None

    def get_type_by_name(self, name):
        if name != self.type_name:
            return None
        member = types.SimpleNamespace(name="value", offset=4, type="int32_t")
        return types.SimpleNamespace(members=[member])

    def get_code_refs_for_type(self, name, max_items=None):
        self.code_query = (name, max_items)
        function = types.SimpleNamespace(name="use_named_type")
        return [types.SimpleNamespace(address=0x403000, function=function)]

    def get_data_refs_for_type(self, name, max_items=None):
        self.data_query = (name, max_items)
        return [0x700000]

    @property
    def functions(self):
        raise AssertionError("named type xrefs must not scan functions or HLIL")

    @property
    def data_vars(self):
        raise AssertionError("named type xrefs must not scan data variables")

    @property
    def types(self):
        raise AssertionError("named type xrefs must not scan all types")

    def get_symbols(self):
        raise AssertionError("named type xrefs must not scan all symbols")


class BinaryOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.info_logs = _load_binary_operations_module()

    def setUp(self):
        self.info_logs.clear()
        self.operations = self.module.BinaryOperations(object())

    def test_field_xrefs_use_bounded_binary_ninja_indexes(self):
        view = IndexedFieldXrefView()
        self.operations._current_view = view

        refs = self.operations.get_xrefs_to_field("Player", "health", max_results=2)

        self.assertEqual(view.code_query, ("Player", 0x18, 2))
        self.assertEqual(view.data_query, ("Player", 0x18, 1))
        self.assertEqual(
            refs,
            [
                {
                    "kind": "code-field-ref",
                    "function": "update_player",
                    "address": "0x401000",
                    "field_offset": 0x18,
                },
                {
                    "kind": "data-field-ref",
                    "address": "0x500018",
                    "field_offset": 0x18,
                },
            ],
        )

    def test_enum_xrefs_use_bounded_binary_ninja_indexes(self):
        view = IndexedEnumXrefView()
        self.operations._current_view = view

        result = self.operations.get_xrefs_to_enum("PlayerState", max_results=2)

        self.assertEqual(view.code_query, ("PlayerState", 2))
        self.assertEqual(view.data_query, ("PlayerState", 1))
        self.assertEqual(
            result,
            {
                "enum": "PlayerState",
                "members": [
                    {"name": "Idle", "value": 0},
                    {"name": "Running", "value": 1},
                ],
                "usages": [
                    {
                        "kind": "code-type-ref",
                        "function": "update_state",
                        "address": "0x402000",
                    },
                    {"kind": "data-type-ref", "address": "0x600000"},
                ],
            },
        )

    def test_type_xrefs_use_bounded_binary_ninja_indexes(self):
        view = IndexedNamedTypeXrefView("Widget")
        self.operations._current_view = view

        result = self.operations.get_xrefs_to_type("Widget", max_results=2)

        self.assertEqual(view.code_query, ("Widget", 2))
        self.assertEqual(view.data_query, ("Widget", 1))
        self.assertEqual(result["resolved_type"], "Widget")
        self.assertEqual(result["functions_with_type"], ["use_named_type"])
        self.assertEqual(len(result["code_references"]), 1)
        self.assertEqual(len(result["data_instances"]), 1)

    def test_struct_xrefs_use_bounded_binary_ninja_indexes(self):
        view = IndexedNamedTypeXrefView("Player")
        self.operations._current_view = view

        result = self.operations.get_xrefs_to_struct("Player", max_results=2)

        self.assertEqual(view.code_query, ("Player", 2))
        self.assertEqual(view.data_query, ("Player", 1))
        self.assertEqual(result["resolved_type"], "Player")
        self.assertEqual(
            result["members"],
            [{"name": "value", "offset": 4, "type": "int32_t"}],
        )

    def test_union_xrefs_use_bounded_binary_ninja_indexes(self):
        view = IndexedNamedTypeXrefView("Value")
        self.operations._current_view = view

        result = self.operations.get_xrefs_to_union("Value", max_results=2)

        self.assertEqual(view.code_query, ("Value", 2))
        self.assertEqual(view.data_query, ("Value", 1))
        self.assertEqual(result["resolved_type"], "Value")
        self.assertEqual(
            result["members"],
            [{"name": "value", "offset": 4, "type": "int32_t"}],
        )


if __name__ == "__main__":
    unittest.main()
