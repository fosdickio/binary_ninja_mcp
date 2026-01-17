import binaryninja as bn
from binaryninja import Settings

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
                else:
                    # Register any newly seen view even if server is already running
                    try:
                        self.server.binary_ops.register_view(bv)
                    except Exception:
                        pass
                _show_popup("MCP Server", "Server is already running.")
                return
            self.server.binary_ops.current_view = bv
            try:
                self.server.binary_ops.register_view(bv)
            except Exception:
                pass
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
            bn.log_error(f"Failed to start MCP server: {e!s}")
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
            bn.log_error(f"Failed to stop server: {e!s}")
            _show_popup("MCP Server Error", f"Failed to stop: {e}")


plugin = BinaryNinjaMCP()


def _register_settings():
    settings = Settings()
    settings.register_group("mcp", "MCP Server")
    settings.register_setting(
        "mcp.renamePrefix",
        '{ "title": "Rename Prefix", "type": "string", "default": "mcp_", "description": "Prefix to prepend to renamed functions and variables (e.g. mcp_, mw_). Leave empty for no prefix." }',
    )
    settings.register_setting(
        "mcp.showStatusButton",
        '{ "title": "Show Status Button", "type": "boolean", "default": true, "description": "Show MCP server status button in the status bar." }',
    )


_register_settings()


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
            MessageBoxButtonSet,
            MessageBoxIcon,
            show_message_box,
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
_status_container = None
_indicator_timer = None
_bv_monitor_timer = None


def _sidebar_icon_margin_default() -> int:
    """Return a reasonable UI icon size to use as horizontal margin.

    Tries to query the Qt style's toolbar icon size (commonly 24). Falls back to 24 on failure.
    """
    try:
        import binaryninjaui as ui
        from PySide6.QtWidgets import QStyle

        ctx = ui.UIContext.activeContext()
        mw = getattr(ctx, "mainWindow", None)
        mw = mw() if callable(mw) else mw
        if mw and hasattr(mw, "style"):
            st = mw.style()
            if st:
                val = int(st.pixelMetric(QStyle.PM_ToolBarIconSize))
                if val > 0:
                    return val
    except Exception:
        pass
    return 24


def _ensure_status_indicator():
    global _status_button
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

        # Check if status button is disabled in settings
        settings = Settings()
        if not settings.get_bool("mcp.showStatusButton"):
            return

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
                sb.setStyleSheet(
                    "QStatusBar{padding:0;margin:0;} QStatusBar::item{margin:0;padding:0;border:0;}"
                )
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

            # Wrap the button in a container with side margins so the margin area is unclickable
            m = _sidebar_icon_margin_default()
            container = QWidget()
            container.setObjectName("mcpStatusContainer")
            lay = QHBoxLayout(container)
            lay.setContentsMargins(m, 0, 3, 0)  # left margin = icon size + 1; right margin = 3px
            lay.setSpacing(0)
            lay.addWidget(_status_button)
            global _status_container
            _status_container = container

            # Set initial visible state so the indicator shows up immediately
            try:
                running_now = bool(plugin.server and plugin.server.server)
            except Exception:
                running_now = False
            if running_now:
                _status_button.setText("🟢 MCP: Running")
                _status_button.setStyleSheet(
                    "margin:0; padding:0 6px; border:0; border-radius:2px;"
                )
            else:
                _status_button.setText("🔴 MCP: Stopped")
                _status_button.setStyleSheet(
                    "margin:0; padding:0 6px; border:0; border-radius:2px;"
                )

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

            # Place slightly to the right (not the far-right): index 1
            try:
                sb.insertWidget(1, container, 0)
            except Exception:
                try:
                    sb.addWidget(container)
                except Exception:
                    sb.addPermanentWidget(container)

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

        # Check if status button is disabled in settings
        settings = Settings()
        if not settings.get_bool("mcp.showStatusButton"):
            return

        def _update():
            _ensure_status_indicator()
            if _status_button is None:
                return
            if running:
                _status_button.setText("🟢 MCP: Running")
                _status_button.setStyleSheet(
                    "margin:0; padding:0 6px; border:0; border-radius:1px;"
                )
            else:
                _status_button.setText("🔴 MCP: Stopped")
                _status_button.setStyleSheet(
                    "margin:0; padding:0 6px; border:0; border-radius:1px;"
                )

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


def _start_bv_monitor():
    """Start a lightweight UI timer that keeps the server's BinaryView list in sync in near real-time.

    - Registers any newly opened views discovered via UI contexts
    - Prunes closed views so /binaries reflects current state without user interaction
    
    PATCHED: Removed the logic that constantly resets current_view based on UI focus.
    The current_view should only change via explicit select_binary MCP calls.
    """
    global _bv_monitor_timer
    try:
        import binaryninjaui as ui
        from PySide6.QtCore import QTimer

        if _bv_monitor_timer is not None:
            return

        def _discover_all_open_bvs(ops):
            """Heuristically discover all open BinaryViews from UI and sync registry.

            Attempts multiple UI paths defensively; safe if some APIs are unavailable.
            Also tries bn.BinaryViewType APIs as a fallback for non-UI discovery.
            """
            try:
                from binaryninjaui import UIContext
            except Exception:
                UIContext = None

            found_fns: set[str] = set()
            found_bvs: list = []
            contexts = []
            
            # Method 1: Try UIContext.allContexts()
            try:
                if UIContext and hasattr(UIContext, "allContexts"):
                    contexts = list(UIContext.allContexts())
            except Exception:
                contexts = []
            
            # Method 2: Try activeContext() if no contexts found
            if not contexts and UIContext:
                try:
                    ctx = UIContext.activeContext()
                    if ctx:
                        contexts = [ctx]
                except Exception:
                    contexts = []

            def _collect_from_frame(vf):
                try:
                    if vf and hasattr(vf, "getCurrentBinaryView"):
                        bv = vf.getCurrentBinaryView()
                        if bv:
                            found_bvs.append(bv)
                except Exception:
                    pass
                # Try alternative accessors
                try:
                    if vf and hasattr(vf, "getBinaryView"):
                        bv2 = vf.getBinaryView()
                        if bv2:
                            found_bvs.append(bv2)
                except Exception:
                    pass

            for ctx in contexts:
                # Current frame
                try:
                    vf = ctx.getCurrentViewFrame()
                    _collect_from_frame(vf)
                except Exception:
                    pass
                # Any additional frames if available
                for attr in ("getViewFrames", "viewFrames", "allViewFrames", "frames"):
                    try:
                        getter = getattr(ctx, attr, None)
                        frames = None
                        if callable(getter):
                            frames = getter()
                        elif getter is not None:
                            frames = getter
                        if frames:
                            for vf2 in list(frames):
                                _collect_from_frame(vf2)
                    except Exception:
                        continue
                
                # Method 3: Try context's openFileContainers or similar
                try:
                    if hasattr(ctx, "openFileContainers"):
                        containers = ctx.openFileContainers()
                        if containers:
                            for fc in list(containers):
                                try:
                                    if hasattr(fc, "getAllDataViews"):
                                        for dv in list(fc.getAllDataViews()):
                                            if dv:
                                                found_bvs.append(dv)
                                except Exception:
                                    pass
                except Exception:
                    pass

            # Method 4: Try FileContext/FileMetadata API
            try:
                if hasattr(bn, "FileMetadata") and hasattr(bn.FileMetadata, "__iter__"):
                    for fm in bn.FileMetadata:
                        try:
                            if hasattr(fm, "view") and fm.view:
                                found_bvs.append(fm.view)
                        except Exception:
                            pass
            except Exception:
                pass

            # Register discovered BVs and build set of filenames
            seen_ids = set()
            for bv in found_bvs:
                try:
                    # Deduplicate by object id
                    bv_id = id(bv)
                    if bv_id in seen_ids:
                        continue
                    seen_ids.add(bv_id)
                    
                    ops.register_view(bv)
                    fn = None
                    try:
                        if getattr(bv, "file", None):
                            fn = getattr(bv.file, "filename", None)
                    except Exception:
                        fn = None
                    if fn:
                        found_fns.add(str(fn))
                except Exception:
                    continue
            return found_fns

        def _tick():
            try:
                ops = (
                    plugin.server.binary_ops
                    if (plugin.server and plugin.server.binary_ops)
                    else None
                )
                if not ops:
                    return

                # First, prune internal weakrefs and get a snapshot of tracked views
                try:
                    ops.list_open_binaries()
                except Exception:
                    pass

                # Discover all open BVs from UI and sync registry (returns filenames)
                try:
                    _discover_all_open_bvs(ops) or set()
                except Exception:
                    pass

                # Do not prune solely based on UI heuristics; UI enumeration may miss open tabs.
                # Rely on explicit close notifications and weakref pruning in ops.

                # PATCHED: Removed the block that was resetting ops.current_view based on UI focus.
                # The MCP-selected active view should remain stable and only change via
                # explicit select_binary calls from the MCP client.
                # This prevents the constant "Cleared current binary view" / "Set current binary view" spam.
                
                # OLD CODE (REMOVED):
                # try:
                #     if ops.current_view is None:
                #         try:
                #             from binaryninjaui import UIContext
                #             act_ctx = UIContext.activeContext()
                #             act_bv = None
                #             if act_ctx:
                #                 vf = act_ctx.getCurrentViewFrame()
                #                 if vf and hasattr(vf, "getCurrentBinaryView"):
                #                     act_bv = vf.getCurrentBinaryView()
                #             ops.current_view = act_bv
                #             if act_bv:
                #                 ops.register_view(act_bv)
                #         except Exception:
                #             pass
                # except Exception:
                #     pass
                
            except Exception:
                # Never raise out of the timer
                pass

        _bv_monitor_timer = QTimer()
        _bv_monitor_timer.setInterval(1000)  # 1s; light periodic sync
        _bv_monitor_timer.timeout.connect(_tick)

        def _start():
            try:
                _tick()
                _bv_monitor_timer.start()
            except Exception:
                pass

        try:
            ui.execute_on_main_thread(_start)
        except Exception:
            _start()
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
            # PATCHED: Removed _try_autostart_for_bv call that was causing view resets
            # on every UI interaction. The server should only auto-start once on initial
            # file open, not on every view change.
            try:
                bv = self._get_active_bv()
                # Ensure the status indicator exists and reflects current state
                _ensure_status_indicator()
                _set_status_indicator(bool(plugin.server and plugin.server.server))
                _start_indicator_watcher()
                _start_bv_monitor()
                if bv:
                    # Track the BinaryView for multi-binary support
                    try:
                        plugin.server.binary_ops.register_view(bv)
                    except Exception:
                        pass
                    # PATCHED: Removed _try_autostart_for_bv(bv) call
                    # This was causing the server to constantly reset the view
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
                _start_bv_monitor()
                if bv:
                    try:
                        plugin.server.binary_ops.register_view(bv)
                    except Exception:
                        pass
                    # Keep autostart here - this is the RIGHT place for it (new file opened)
                    _try_autostart_for_bv(bv)
            except Exception as e:
                bn.log_error(f"MCP Max OnAfterOpenFile error: {e}")

        # Best-effort close notifications (may not be called on all versions)
        def OnBeforeCloseFile(self, *args):  # type: ignore[override]
            try:
                bv = self._get_active_bv()
                if bv and plugin.server and plugin.server.binary_ops:
                    try:
                        fn = getattr(bv.file, "filename", None)
                    except Exception:
                        fn = None
                    if fn:
                        plugin.server.binary_ops.unregister_by_filename(fn)
            except Exception:
                pass

        def OnAfterCloseFile(self, *args):  # type: ignore[override]
            try:
                # Force a prune after close
                if plugin.server and plugin.server.binary_ops:
                    _ = plugin.server.binary_ops.list_open_binaries()
            except Exception:
                pass

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
    _start_bv_monitor()
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

# Register global handler to discover and track all opened BinaryViews
try:
    from binaryninja.binaryview import BinaryViewType

    def _on_bv_initial_analysis(bv):
        try:
            # Ensure server exists; even if not running, register the view for listing later
            if plugin.server and plugin.server.binary_ops:
                plugin.server.binary_ops.register_view(bv)
        except Exception:
            pass

    try:
        BinaryViewType.add_binaryview_initial_analysis_completion_event(_on_bv_initial_analysis)
        bn.log_info("Registered BinaryView initial analysis completion event for MCP Max")
    except Exception as e:
        bn.log_debug(f"Unable to register BV analysis completion event: {e}")
    # Also register finalized event to catch newly created/opened views early
    try:
        BinaryViewType.add_binaryview_finalized_event(_on_bv_initial_analysis)
        bn.log_info("Registered BinaryView finalized event for MCP Max")
    except Exception as e:
        bn.log_debug(f"Unable to register BV finalized event: {e}")
except Exception:
    pass