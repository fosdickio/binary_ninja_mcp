import binaryninja as bn
from .core.config import Config
from .server.http_server import MCPServer


# When true, suppress auto-start while a BinaryView is open until the user
# explicitly starts the server again. This prevents immediate re-start after stop.
_mcp_user_stopped = False


class BinaryNinjaMCP:
    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)

    def start_server(self, bv):
        try:
            # Require an active BinaryView (match menu behavior)
            if bv is None:
                bn.log_debug("MCP Max start requested but no BinaryView is active; deferring")
                _show_no_bv_popup()
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
            global _mcp_user_stopped
            _mcp_user_stopped = False
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
            _set_status_indicator(True)
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
            global _mcp_user_stopped
            _mcp_user_stopped = True
            self.server.binary_ops.current_view = None
            self.server.stop()
            bn.log_info("Binary Ninja MCP Max plugin stopped successfully")
            _set_status_indicator(False)
            _show_popup("MCP Server Stopped", "Server has been stopped.")
        except Exception as e:
            bn.log_error(f"Failed to stop server: {str(e)}")
            _show_popup("MCP Server Error", f"Failed to stop: {e}")


plugin = BinaryNinjaMCP()


def _apply_settings_to_config():
    return


def _try_autostart_for_bv(bv):
    try:
        # Respect manual stop; do not auto-start until user starts explicitly
        global _mcp_user_stopped
        if _mcp_user_stopped:
            bn.log_debug("MCP Max autostart suppressed due to manual stop")
            return
        plugin.start_server(bv)
    except Exception as e:
        bn.log_error(f"MCP Max autostart failed: {e}")


def _show_popup(title: str, text: str, info: bool = True):
    """Disable UI popups; log message instead.

    This keeps the UX unobtrusive while preserving visibility in the log.
    """
    try:
        # Prefer informational logs; error cases are already logged elsewhere
        # at error level in their respective handlers.
        bn.log_info(f"{title}: {text}")
    except Exception:
        # As a last resort, swallow to avoid any UI disruption
        pass


def _show_no_bv_popup():
    """Show a focused popup for the 'no BinaryView' case only."""
    msg = "No BinaryView is active, please open a binary first"
    try:
        from binaryninja.interaction import (
            show_message_box,
            MessageBoxButtonSet,
            MessageBoxIcon,
        )

        show_message_box(
            "Binary Ninja MCP Max",
            msg,
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.WarningIcon,
        )
    except Exception:
        # Fall back to log if UI interaction is unavailable
        try:
            bn.log_warn(msg)
        except Exception:
            pass


# ------- Status bar indicator -------
_status_button = None
_indicator_timer = None


def _ensure_status_indicator():
    global _status_button
    try:
        import binaryninjaui as ui
        from PySide6.QtWidgets import QPushButton
        from PySide6.QtCore import Qt

        def _create():
            global _status_button
            if _status_button is not None:
                return
            ctx = ui.UIContext.activeContext()
            if not ctx:
                return
            mw = getattr(ctx, "mainWindow", None)
            mw = mw() if callable(mw) else mw
            if mw is None or not hasattr(mw, "statusBar"):
                return
            sb = mw.statusBar()
            if sb is None:
                return
            # Tighten status bar spacing
            try:
                sb.setContentsMargins(0, 0, 0, 0)
                if sb.layout():
                    sb.layout().setContentsMargins(0, 0, 0, 0)
                    sb.layout().setSpacing(0)
                sb.setStyleSheet("QStatusBar{padding:0;margin:0;} QStatusBar::item{margin:0;padding:0;border:0;}")
            except Exception:
                pass

            # Create a flat button as the indicator and control
            _status_button = QPushButton()
            _status_button.setObjectName("mcpStatusButton")
            _status_button.setFlat(True)
            _status_button.setCursor(Qt.PointingHandCursor)
            _status_button.setToolTip("Click to start/stop MCP server")
            _status_button.setContentsMargins(0, 0, 0, 0)
            _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")

            # Set initial visible state so the indicator shows up immediately
            try:
                running_now = bool(plugin.server and plugin.server.server)
            except Exception:
                running_now = False
            if running_now:
                _status_button.setText("🟢 MCP: Running")
                _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:2px;")
            else:
                _status_button.setText("🔴 MCP: Stopped")
                _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:2px;")

            # Click handler to toggle server state
            def _on_click():
                try:
                    running = bool(plugin.server and plugin.server.server)
                    if running:
                        plugin.stop_server(None)
                    else:
                        # Acquire active BinaryView for start
                        try:
                            from binaryninjaui import UIContext
                            ctx = UIContext.activeContext()
                            bv = None
                            if ctx:
                                vf = ctx.getCurrentViewFrame()
                                if vf and hasattr(vf, "getCurrentBinaryView"):
                                    bv = vf.getCurrentBinaryView()
                        except Exception:
                            bv = None
                        if not bv:
                            _show_no_bv_popup()
                            return
                        plugin.start_server(bv)
                finally:
                    _set_status_indicator(bool(plugin.server and plugin.server.server))

            _status_button.clicked.connect(_on_click)

            # Place as the first widget on the left
            try:
                sb.insertWidget(0, _status_button, 0)
            except Exception:
                try:
                    sb.addWidget(_status_button)
                except Exception:
                    sb.addPermanentWidget(_status_button)

        # Ensure we run on UI thread if available
        try:
            ui.execute_on_main_thread(_create)
        except Exception:
            _create()
    except Exception:
        pass


def _set_status_indicator(running: bool):
    try:
        import binaryninjaui as ui
        def _update():
            _ensure_status_indicator()
            if _status_button is None:
                return
            if running:
                _status_button.setText("🟢 MCP: Running")
                _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")
            else:
                _status_button.setText("🔴 MCP: Stopped")
                _status_button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")

        try:
            ui.execute_on_main_thread(_update)
        except Exception:
            _update()
    except Exception:
        pass


def _start_indicator_watcher():
    """Periodically ensure the indicator exists after UI becomes ready.

    Some environments initialize UI context late; this watcher is a light
    safety net that creates and updates the indicator shortly after load.
    It stops itself once the indicator exists.
    """
    global _indicator_timer
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        if _indicator_timer is not None:
            return

        def _tick():
            try:
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
                if _status_button is not None and hasattr(_indicator_timer, "stop"):
                    _indicator_timer.stop()
            except Exception:
                pass

        _indicator_timer = QTimer()
        _indicator_timer.setInterval(500)
        _indicator_timer.timeout.connect(_tick)

        def _start():
            try:
                _tick()
                _indicator_timer.start()
            except Exception:
                pass

        try:
            ui.execute_on_main_thread(_start)
        except Exception:
            _start()
    except Exception:
        pass


def _schedule_status_init():
    """Ensure the status control appears ASAP on app load."""
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        def _init_once():
            try:
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
            except Exception:
                pass

        # Attempt immediately and then with several short delays
        try:
            ui.execute_on_main_thread(_init_once)
        except Exception:
            _init_once()

        for delay in (200, 500, 1000, 1500, 2000):
            try:
                ui.execute_on_main_thread(lambda d=delay: QTimer.singleShot(d, _init_once))
            except Exception:
                pass
    except Exception:
        pass


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
                # Ensure the status indicator exists and reflects current state
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
                _start_indicator_watcher()
                if bv:
                    _try_autostart_for_bv(bv)
            except Exception as e:
                bn.log_error(f"MCP Max UI notification error: {e}")

        # Some versions provide OnAfterOpenFile; handle if present
        def OnAfterOpenFile(self, *args):  # type: ignore[override]
            try:
                bv = self._get_active_bv()
                # Ensure the status indicator is present as soon as a file opens
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
                _start_indicator_watcher()
                if bv:
                    _try_autostart_for_bv(bv)
            except Exception as e:
                bn.log_error(f"MCP Max OnAfterOpenFile error: {e}")

        # Ensure status indicator exists when a UI context opens
        def OnContextOpen(self, *args):  # type: ignore[override]
            try:
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
                _start_indicator_watcher()
            except Exception:
                pass

    ui.UIContext.registerNotification(_MCPMaxUINotification())
    bn.log_info("MCP Max UI notifications installed")
    # Ensure status control is present at startup with retries
    _schedule_status_init()
    _start_indicator_watcher()
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
                # also ensure status control exists after UI is fully ready
                _schedule_status_init()
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

# One-time MCP client auto-setup: install bridge entry into popular MCP clients
try:
    from .utils.auto_setup import install_mcp_clients
    _ = install_mcp_clients(quiet=True)
except Exception:
    # Best-effort; ignore failures to avoid disrupting plugin load
    pass
