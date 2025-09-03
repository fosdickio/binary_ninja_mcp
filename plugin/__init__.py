import binaryninja as bn
from .core.config import Config
from .server.http_server import MCPServer


class BinaryNinjaMCP:
    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)

    def start_server(self, bv):
        try:
            # Require an active BinaryView (match menu behavior)
            if bv is None:
                bn.log_debug("MCP Max start requested but no BinaryView is active; deferring")
                _show_popup("MCP Server", "No BinaryView is active; cannot start.")
                return
            # Avoid duplicate starts
            if self.server and self.server.server:
                bn.log_info("MCP Max server already running; skip new start")
                # Ensure BV is set if not already
                if self.server.binary_ops.current_view is None:
                    self.server.binary_ops.current_view = bv
                _show_popup("MCP Server", "Server is already running.")
                return
            self.server.binary_ops.current_view = bv
            self.server.start()
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
            _show_popup(
                "MCP Server Started",
                f"Running at http://{self.config.server.host}:{self.config.server.port}",
            )
        except Exception as e:
            bn.log_error(f"Failed to start MCP server: {str(e)}")
            _show_popup("MCP Server Error", f"Failed to start: {e}")

    def stop_server(self, bv):
        try:
            # If not running, inform the user
            if not (self.server and self.server.server):
                bn.log_info("MCP Max server stop requested but server is not running")
                _show_popup("MCP Server", "Server is not running.")
                return
            self.server.binary_ops.current_view = None
            self.server.stop()
            bn.log_info("Binary Ninja MCP Max plugin stopped successfully")
            _show_popup("MCP Server Stopped", "Server has been stopped.")
        except Exception as e:
            bn.log_error(f"Failed to stop server: {str(e)}")
            _show_popup("MCP Server Error", f"Failed to stop: {e}")


plugin = BinaryNinjaMCP()


def _apply_settings_to_config():
    return


def _try_autostart_for_bv(bv):
    try:
        plugin.start_server(bv)
    except Exception as e:
        bn.log_error(f"MCP Max autostart failed: {e}")


def _show_popup(title: str, text: str, info: bool = True):
    """Show a popup if UI interaction is available; otherwise log the message.

    Uses Binary Ninja's interaction API when present; falls back to log messages
    to avoid breaking headless environments.
    """
    try:
        from binaryninja.interaction import (
            show_message_box,
            MessageBoxButtonSet,
            MessageBoxIcon,
        )

        icon = MessageBoxIcon.InformationIcon if info else MessageBoxIcon.WarningIcon
        show_message_box(title, text, MessageBoxButtonSet.OKButtonSet, icon)
    except Exception:
        try:
            # Best-effort fallback to UI thread; if unavailable, just log
            import binaryninjaui  # noqa: F401
        except Exception:
            pass
        bn.log_info(f"{title}: {text}")


# Install UI notifications (when UI is available)
try:
    import binaryninjaui as ui

    class _MCPMaxUINotification(ui.UIContextNotification):
        def _get_active_bv(self):
            try:
                ctx = ui.UIContext.activeContext()
                if ctx:
                    vf = ctx.getCurrentViewFrame()
                    if vf and hasattr(vf, "getCurrentBinaryView"):
                        return vf.getCurrentBinaryView()
            except Exception:
                pass
            return None

        def OnViewChange(self, *args):  # signature varies across versions
            try:
                bv = self._get_active_bv()
                if bv:
                    _try_autostart_for_bv(bv)
            except Exception as e:
                bn.log_error(f"MCP Max UI notification error: {e}")

        # Some versions provide OnAfterOpenFile; handle if present
        def OnAfterOpenFile(self, *args):  # type: ignore[override]
            try:
                bv = self._get_active_bv()
                if bv:
                    _try_autostart_for_bv(bv)
            except Exception as e:
                bn.log_error(f"MCP Max OnAfterOpenFile error: {e}")

    ui.UIContext.registerNotification(_MCPMaxUINotification())
    bn.log_info("MCP Max UI notifications installed")
except Exception as e:
    # UI not available (headless) or API mismatch; ignore
    bn.log_debug(f"MCP Max UI notifications not installed: {e}")

# Attempt an immediate autostart if a BV is already open (e.g., .bndb loaded)
try:
    from binaryninjaui import UIContext
    ctx = UIContext.activeContext()
    if ctx:
        vf = ctx.getCurrentViewFrame()
        if vf and hasattr(vf, "getCurrentBinaryView"):
            bv = vf.getCurrentBinaryView()
            if bv:
                _try_autostart_for_bv(bv)
    # Schedule a few retries on the UI thread to catch late BV availability
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        def _kick_autostart():
            try:
                ctx2 = UIContext.activeContext()
                if ctx2:
                    vf2 = ctx2.getCurrentViewFrame()
                    if vf2 and hasattr(vf2, "getCurrentBinaryView"):
                        bv2 = vf2.getCurrentBinaryView()
                        if bv2:
                            _try_autostart_for_bv(bv2)
            except Exception as _e:
                bn.log_debug(f"MCP Max auto-start retry error: {_e}")

        for delay in (200, 500, 1000, 1500, 2000):
            ui.execute_on_main_thread(lambda d=delay: QTimer.singleShot(d, _kick_autostart))
    except Exception:
        pass
except Exception:
    pass

def _is_server_running() -> bool:
    try:
        return bool(plugin.server and plugin.server.server)
    except Exception:
        return False


def _can_start(bv) -> bool:  # bv required by BN predicate signature
    return (bv is not None) and (not _is_server_running())


def _can_stop(bv) -> bool:
    return _is_server_running()


# Register menu actions (always visible)
bn.PluginCommand.register(
    "MCP Server\\Start MCP Server",
    "Start the Binary Ninja MCP server",
    plugin.start_server,
)
bn.PluginCommand.register(
    "MCP Server\\Stop MCP Server",
    "Stop the Binary Ninja MCP server",
    plugin.stop_server,
)

bn.log_info("Binary Ninja MCP plugin loaded successfully")

# Auto-start and settings UI removed
