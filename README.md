# Binary Ninja MCP <img src="images/binja.png" height="24" style="margin-left: 5px; vertical-align: middle;">

This repository contains a Binary Ninja plugin, MCP server, and bridge that enables seamless integration of Binary Ninja's capabilities with your favorite LLM client.

## Features

- Seamless, real-time integration between Binary Ninja and MCP clients
- Enhanced reverse engineering workflow with AI assistance
- Primary support for Claude Desktop as the MCP client, but extensible for other integrations

## Examples

### Generating a Binary Analysis Report

![Binary Analysis Report Generation](images/mcp-demo-report.png)

### Renaming Functions

![Rename Function Demo](images/mcp-demo-rename.gif)

## Components

This repository contains two separate components:

1. A Binary Ninja plugin that provides an MCP server that exposes Binary Ninja's capabilities through HTTP endpoints.  This can be used with any client that implements the MCP protocol.
2. A separate MCP bridge component that connects your favorite MCP client to the Binary Ninja MCP server.  While Claude Desktop is the primary integration path, the MCP server can be used with other clients.

## Supported Integrations

The following table details which integrations with Binary Ninja are currently supported.

| Function | Description |
|----------|-------------|
| `get_binary_status` | Get the current status of the loaded binary. |
| `list_classes` | List all namespace/class names in the program. |
| `list_data_items` | List defined data labels and their values. |
| `list_exports` | List exported functions/symbols. |
| `list_imports` | List imported symbols in the program. |
| `list_methods` | List all function names in the program. |
| `list_namespaces` | List all non-global namespaces in the program. |
| `list_segments` | List all memory segments in the program. |
| `rename_data` | Rename a data label at the specified address. |
| `rename_function` | Rename a function by its current name to a new user-defined name. |
| `search_functions_by_name` | Search for functions whose name contains the given substring. |
| `decompile_function` | Decompile a specific function by name and return the decompiled C code. |
| `set_comment` | Set a comment at a specific address. |
| `set_function_comment` | Set a comment for a function. |
| `get_comment` | Get the comment at a specific address. |
| `get_function_comment` | Get the comment for a function. |
| `delete_comment` | Delete the comment at a specific address. |
| `delete_function_comment` | Delete the comment for a function. |
| `get_assembly_function` | Get the assembly representation of a function by name or address. |
| `function_at` | Retrive the name of the function the address belongs to. |
| `code_references` | Retrive names and addresses of functions that call the given function. |
| `get_user_defined_type` | Retrive definition of a user defined type (struct, enumeration, typedef, union). |

## Prerequisites

- [Binary Ninja](https://binary.ninja/)
- Python 3.12+
- [Claude Desktop](https://claude.ai/download) (or your preferred integration)

## Installation

### Binary Ninja Plugin

You may install the plugin through Binary Ninja's Plugin Manager (`Plugins > Manage Plugins`).

![Plugin Manager Listing](images/plugin-manager-listing.png)

To manually configure the plugin, this repository can be copied into the Binary Ninja plugins folder.

### Claude Desktop Bridge (Optional)

This is only needed if you want to use Claude Desktop as your MCP client.  Make sure that you have your virtual environment configured first:

```bash
git clone git@github.com:fosdickio/binary_ninja_mcp.git
cd binary_ninja_mcp

python3 -m venv .venv
source .venv/bin/activate   # On macOS/Linux

pip install -r bridge/requirements.txt
```

#### Automated Configuration (Mac)

On a Mac, you can automate the setup by running:

```bash
./scripts/setup_claude_desktop.py
```

#### Manual Configuration

On other operating systems or to manually configure the Claude Desktop integration:

1. Navigate to `Settings > Developer > Edit Config`
2. Add the following configuration:

```json
{
  "mcpServers": {
    "binary_ninja_mcp": {
      "command": "/ABSOLUTE/PATH/TO/binary_ninja_mcp/.venv/bin/python",
      "args": [
        "/ABSOLUTE/PATH/TO/binary_ninja_mcp/bridge/binja_mcp_bridge.py"
      ]
    }
  }
}
```

Note: Replace `/ABSOLUTE/PATH/TO` with the actual absolute path to your project directory. The virtual environment's Python interpreter must be used to access the installed dependencies.

## Usage

### Claude Desktop

1. Open Binary Ninja and install the `Binary Ninja MCP` plugin
2. Restart Binary Ninja and then open a binary
3. Start the MCP server (`Plugins > MCP Server > Start MCP Server`)
4. Launch Claude Desktop

The integration will be automatically available after you open Claude Desktop.

![Claude Integration](images/claude-desktop-integration.png)

You may now start prompting Claude about the currently open binary.  Example prompts:

- "Generate a binary analysis report for the current binary."
- "Rename function X to Y in the current binary."
- "List all functions in the current binary."
- "What is the status of the loaded binary?"

### Other MCP Client Integrations

The bridge can be used with other MCP clients by implementing the appropriate integration layer.

## Development

The project structure is organized as follows:

```
binary_ninja_mcp/
├── bridge/                      # MCP client integration
├── plugin/                      # Binary Ninja plugin
├── scripts/
│   └── setup_claude_desktop.py  # Setup script for Claude Desktop
```
## Contributing

Contributions are welcome. Please feel free to submit a pull request.

