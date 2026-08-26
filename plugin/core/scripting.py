import threading
from typing import Any

from binaryninja.enums import ScriptingProviderExecuteResult, ScriptingProviderInputReadyState
from binaryninja.scriptingprovider import ScriptingOutputListener, ScriptingProvider

MAX_CAPTURE_CHARS = 1_000_000


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


class _CaptureListener(ScriptingOutputListener):
    def __init__(self):
        self.output_parts: list[str] = []
        self.warning_parts: list[str] = []
        self.error_parts: list[str] = []
        self.finished = threading.Event()
        self.truncated = False
        self._captured_chars = 0
        self._lock = threading.Lock()

    def _append(self, destination: list[str], text: str) -> None:
        with self._lock:
            remaining = MAX_CAPTURE_CHARS - self._captured_chars
            if remaining <= 0:
                self.truncated = True
                return
            value = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
            destination.append(value[:remaining])
            self._captured_chars += min(len(value), remaining)
            if len(value) > remaining:
                self.truncated = True

    def notify_output(self, text):
        self._append(self.output_parts, text)

    def notify_warning(self, text):
        self._append(self.warning_parts, text)

    def notify_error(self, text):
        self._append(self.error_parts, text)

    def notify_input_ready_state_changed(self, state):
        ready = _enum_value(ScriptingProviderInputReadyState.ReadyForScriptExecution)
        if _enum_value(state) == ready:
            self.finished.set()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "output": "".join(self.output_parts),
                "warnings": "".join(self.warning_parts),
                "errors": "".join(self.error_parts),
                "truncated": self.truncated,
            }


class PythonScriptingExecutor:
    """Execute code in a persistent Binary Ninja Python scripting context."""

    def __init__(self):
        self._instance = None
        self._lock = threading.Lock()

    def _get_instance(self):
        if self._instance is None:
            provider = ScriptingProvider["Python"]
            self._instance = provider.create_instance()
            if self._instance is None:
                raise RuntimeError("Binary Ninja Python scripting provider is unavailable")
        return self._instance

    @staticmethod
    def _cancel(instance) -> None:
        try:
            instance.cancel_script_input("")
        except TypeError:
            instance.cancel_script_input()

    @staticmethod
    def _wrap_script(code: str) -> str:
        """Keep a whole program in one InteractiveConsole input statement."""
        return f'exec(compile({code!r}, "<mcp>", "exec"), globals(), locals())\n'

    def execute(self, code: str, view, timeout_seconds: float = 30.0) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Python code must be a non-empty string")
        if not 0.1 <= timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be between 0.1 and 300")

        with self._lock:
            instance = self._get_instance()
            listener = _CaptureListener()
            instance.register_output_listener(listener)
            try:
                instance.set_current_binary_view(view)
                script = self._wrap_script(code)
                result = instance.execute_script_input(script)

                incomplete = _enum_value(ScriptingProviderExecuteResult.IncompleteScriptInput)
                successful = _enum_value(ScriptingProviderExecuteResult.SuccessfulScriptExecution)
                if _enum_value(result) == incomplete:
                    result = instance.execute_script_input(script + "\n")
                if _enum_value(result) != successful:
                    captured = listener.snapshot()
                    captured.update(
                        {
                            "success": False,
                            "timed_out": False,
                            "error": f"Scripting provider rejected the input: {result}",
                        }
                    )
                    return captured

                if not listener.finished.wait(timeout_seconds):
                    self._cancel(instance)
                    listener.finished.wait(1.0)
                    captured = listener.snapshot()
                    captured.update(
                        {
                            "success": False,
                            "timed_out": True,
                            "error": f"Python execution exceeded {timeout_seconds:g} seconds",
                        }
                    )
                    try:
                        instance.stop()
                    except Exception:
                        pass
                    self._instance = None
                    return captured

                captured = listener.snapshot()
                captured.update(
                    {
                        "success": not bool(captured["errors"]),
                        "timed_out": False,
                    }
                )
                return captured
            finally:
                try:
                    instance.unregister_output_listener(listener)
                except Exception:
                    pass

    def close(self) -> None:
        with self._lock:
            instance = self._instance
            self._instance = None
            if instance is None:
                return
            try:
                instance.set_current_binary_view(None)
            except Exception:
                pass
            try:
                instance.stop()
            except Exception:
                pass
