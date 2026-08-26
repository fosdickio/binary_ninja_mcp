import importlib.util
import io
import sys
import types
import unittest
from contextlib import redirect_stdout
from enum import IntEnum
from pathlib import Path


class ExecuteResult(IntEnum):
    SuccessfulScriptExecution = 0
    IncompleteScriptInput = 1
    InvalidScriptInput = 2


class ReadyState(IntEnum):
    NotReadyForInput = 0
    ReadyForScriptExecution = 1
    ReadyForScriptProgramInput = 2


class FakeInstance:
    def __init__(self):
        self.listener = None
        self.views = []
        self.scripts = []
        self.stopped = False

    def register_output_listener(self, listener):
        self.listener = listener

    def unregister_output_listener(self, listener):
        if self.listener is listener:
            self.listener = None

    def set_current_binary_view(self, view):
        self.views.append(view)

    def execute_script_input(self, script):
        self.scripts.append(script)
        self.listener.notify_output(b"stdout\n")
        self.listener.notify_warning(b"warning\n")
        self.listener.notify_input_ready_state_changed(ReadyState.ReadyForScriptExecution)
        return ExecuteResult.SuccessfulScriptExecution

    def stop(self):
        self.stopped = True


class FakeProvider:
    def __init__(self, instance_class=FakeInstance):
        self.instance_class = instance_class
        self.instances = []

    def create_instance(self):
        instance = self.instance_class()
        self.instances.append(instance)
        return instance


class TimeoutInstance(FakeInstance):
    def __init__(self):
        super().__init__()
        self.cancelled = False

    def execute_script_input(self, script):
        self.scripts.append(script)
        return ExecuteResult.SuccessfulScriptExecution

    def cancel_script_input(self, _text):
        self.cancelled = True
        self.listener.notify_input_ready_state_changed(ReadyState.ReadyForScriptExecution)


def _load_scripting_module(provider):
    binaryninja = types.ModuleType("binaryninja")
    enums = types.ModuleType("binaryninja.enums")
    enums.ScriptingProviderExecuteResult = ExecuteResult
    enums.ScriptingProviderInputReadyState = ReadyState
    scripting_provider = types.ModuleType("binaryninja.scriptingprovider")

    class ScriptingOutputListener:
        pass

    class ScriptingProvider:
        @classmethod
        def __class_getitem__(cls, name):
            if name != "Python":
                raise KeyError(name)
            return provider

    scripting_provider.ScriptingOutputListener = ScriptingOutputListener
    scripting_provider.ScriptingProvider = ScriptingProvider
    sys.modules["binaryninja"] = binaryninja
    sys.modules[enums.__name__] = enums
    sys.modules[scripting_provider.__name__] = scripting_provider

    path = Path(__file__).parents[1] / "plugin" / "core" / "scripting.py"
    spec = importlib.util.spec_from_file_location("tested_scripting", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonScriptingExecutorTests(unittest.TestCase):
    def setUp(self):
        self.provider = FakeProvider()
        self.module = _load_scripting_module(self.provider)

    def test_executes_with_current_view_and_captures_streams(self):
        executor = self.module.PythonScriptingExecutor()
        view = object()

        result = executor.execute("print(bv)", view, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["output"], "stdout\n")
        self.assertEqual(result["warnings"], "warning\n")
        self.assertEqual(self.provider.instances[0].views, [view])
        self.assertEqual(
            self.provider.instances[0].scripts,
            ['exec(compile(\'print(bv)\', "<mcp>", "exec"), globals(), locals())\n'],
        )

    def test_wraps_multiline_program_with_blank_line_as_one_console_input(self):
        executor = self.module.PythonScriptingExecutor()
        code = 'for i in range(2):\n  print("works")\n\n  print("doesnt work")'

        executor.execute(code, object(), 1)

        script = self.provider.instances[0].scripts[0]
        self.assertEqual(script.count("\n"), 1)
        namespace = {}
        output = io.StringIO()
        with redirect_stdout(output):
            exec(script, namespace, namespace)
        self.assertEqual(output.getvalue(), "works\ndoesnt work\nworks\ndoesnt work\n")

    def test_reuses_context_until_closed(self):
        executor = self.module.PythonScriptingExecutor()

        executor.execute("value = 1", object(), 1)
        executor.execute("print(value)", object(), 1)
        executor.close()

        self.assertEqual(len(self.provider.instances), 1)
        self.assertTrue(self.provider.instances[0].stopped)
        self.assertIsNone(self.provider.instances[0].views[-1])

    def test_rejects_empty_code_and_out_of_range_timeout(self):
        executor = self.module.PythonScriptingExecutor()

        with self.assertRaises(ValueError):
            executor.execute(" ", object())
        with self.assertRaises(ValueError):
            executor.execute("pass", object(), 301)

    def test_timeout_cancels_and_discards_context(self):
        provider = FakeProvider(TimeoutInstance)
        module = _load_scripting_module(provider)
        executor = module.PythonScriptingExecutor()

        result = executor.execute("while True: pass", object(), 0.1)

        self.assertTrue(result["timed_out"])
        self.assertTrue(provider.instances[0].cancelled)
        self.assertTrue(provider.instances[0].stopped)
        self.assertIsNone(executor._instance)


if __name__ == "__main__":
    unittest.main()
