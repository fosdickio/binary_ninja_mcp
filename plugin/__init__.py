import binaryninja as bn
from .core.config import Config
from .server.http_server import MCPServer


class BinaryNinjaMCP:
    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)

    def start_server(self, bv):
        try:
            self.server.binary_ops.current_view = bv
            self.server.start()
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
        except Exception as e:
            bn.log_error(f"Failed to start MCP server: {str(e)}")

    def stop_server(self, bv):
        try:
            self.server.binary_ops.current_view = None
            self.server.stop()
            bn.log_info("Binary Ninja MCP Max plugin stopped successfully")
        except Exception as e:
            bn.log_error(f"Failed to stop server: {str(e)}")


plugin = BinaryNinjaMCP()

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
