# Binary Ninja MCP <img src="images/binja.png" height="24" style="margin-left: 5px; vertical-align: middle;">

This repository contains a Binary Ninja plugin, MCP server, and bridge that enables seamless integration of Binary Ninja's capabilities with your favorite LLM client.

## Features

- Seamless, real-time integration between Binary Ninja and MCP clients
- Enhanced reverse engineering workflow with AI assistance
- Support for every MCP client (Cline, Claude desktop, Roo Code, etc)

## Examples

### Solving a CTF Challenge

https://github.com/user-attachments/assets/67b76a53-ea21-4bef-86d2-f751b891c604

You can also watch the demo video on [YouTube](https://www.youtube.com/watch?v=0ffMHH39L_M)

## Components

This repository contains two separate components:

1. A Binary Ninja plugin that provides an MCP server that exposes Binary Ninja's capabilities through HTTP endpoints. This can be used with any client that implements the MCP protocol.
2. A separate MCP bridge component that connects your favorite MCP client to the Binary Ninja MCP server. While Claude Desktop is the primary integration path, the MCP server can be used with other clients.

## Supported Integrations

The following table lists available MCP tools. Sorted alphabetically by function name.

| Function                                      | Description                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `convert_number(text, size)`                  | Convert a number/string to multiple representations (LE/BE, bases).                         |
| `decompile_function`                          | Decompile a specific function by name and return the decompiled C code.                     |
| `define_types`                                | Add type definitions from a C string type definition.                                       |
| `delete_comment`                              | Delete the comment at a specific address.                                                   |
| `delete_function_comment`                     | Delete the comment for a function.                                                          |
| `edit_function_signature`                     | Edit signature of a given function, given as a type string.                                 |
| `format_value(address, text, size)`           | Convert a value and annotate it at an address in BN (adds a comment).                       |
| `function_at`                                 | Retrieve the name of the function the address belongs to.                                   |
| `get_assembly_function`                       | Get the assembly representation of a function by name or address.                           |
| `get_binary_status`                           | Get the current status of the loaded binary.                                                |
| `get_comment`                                 | Get the comment at a specific address.                                                      |
| `get_function_comment`                        | Get the comment for a function.                                                             |
| `get_user_defined_type`                       | Retrieve definition of a user-defined type (struct, enumeration, typedef, union).           |
| `get_xrefs_to(address)`                       | Get all cross references (code and data) to an address.                                     |
| `get_data_decl(name_or_address, length)`      | Return a C-like declaration and a hexdump for a data symbol or address.                     |
| `hexdump_address(address, length)`            | Text hexdump at address. `length < 0` reads exact defined size if available.                |
| `hexdump_data(name_or_address, length)`       | Hexdump by data symbol name or address. `length < 0` reads exact defined size if available. |
| `get_xrefs_to_enum(enum_name)`                | Get usages related to an enum (matches member constants in code).                           |
| `get_xrefs_to_field(struct_name, field_name)` | Get all cross references to a named struct field.                                           |
| `get_xrefs_to_struct(struct_name)`            | Get xrefs/usages related to a struct (members, globals, code refs).                         |
| `get_xrefs_to_type(type_name)`                | Get xrefs/usages related to a struct/type (globals, refs, HLIL matches).                    |
| `get_xrefs_to_union(union_name)`              | Get xrefs/usages related to a union (members, globals, code refs).                          |
| `get_type_info(type_name)`                    | Resolve a type and return declaration, kind, and members.                                   |
| `list_all_strings()`                          | List all strings (no pagination; aggregates all pages).                                     |
| `list_classes`                                | List all namespace/class names in the program.                                              |
| `list_data_items`                             | List defined data labels and their values.                                                  |
| `list_exports`                                | List exported functions/symbols.                                                            |
| `list_imports`                                | List imported symbols in the program.                                                       |
| `list_local_types(offset, count)`             | List local Types in the current database (name/kind/decl).                                  |
| `list_methods`                                | List all function names in the program.                                                     |
| `list_namespaces`                             | List all non-global namespaces in the program.                                              |
| `list_segments`                               | List all memory segments in the program.                                                    |
| `list_strings(offset, count)`                 | List all strings in the database (paginated).                                               |
| `list_strings_filter(offset, count, filter)`  | List matching strings (paginated, filtered by substring).                                   |
| `rename_data`                                 | Rename a data label at the specified address.                                               |
| `rename_function`                             | Rename a function by its current name to a new user-defined name.                           |
| `rename_variable`                             | Rename variable inside a given function.                                                    |
| `retype_variable`                             | Retype variable inside a given function.                                                    |
| `search_functions_by_name`                    | Search for functions whose name contains the given substring.                               |
| `search_types(query, offset, count)`          | Search local Types by substring (name/decl).                                                |
| `set_comment`                                 | Set a comment at a specific address.                                                        |
| `set_function_comment`                        | Set a comment for a function.                                                               |

HTTP endpoints

- `/allStrings`: All strings in one response.
- `/convertNumber?text=<value>&size=<n>`: Convert number/string to hex/dec/bin and LE/BE.
- `/formatValue?address=<addr>&text=<value>&size=<n>`: Convert and set a comment at an address.
- `/getXrefsTo?address=<addr>`: Xrefs to address (code+data).
- `/getDataDecl?name=<symbol>|address=<addr>&length=<n>`: JSON with declaration-style string and a hexdump for a data symbol or address. Keys: `address`, `name`, `size`, `type`, `decl`, `hexdump`. `length < 0` reads exact defined size if available.
- `/hexdump?address=<addr>&length=<n>`: Text hexdump aligned at address; `length < 0` reads exact defined size if available.
- `/hexdumpByName?name=<symbol>&length=<n>`: Text hexdump by symbol name. Recognizes BN auto-labels like `data_<hex>`, `byte_<hex>`, `word_<hex>`, `dword_<hex>`, `qword_<hex>`, `off_<hex>`, `unk_<hex>`, and plain hex addresses.
- `/data?offset=<n>&limit=<m>&length=<n>`: Defined data items with previews. `length` controls bytes read per item (capped at defined size). Default behavior reads exact defined size when available; `length=-1` forces exact-size.
- `/getXrefsToEnum?name=<enum>`: Enum usages by matching member constants.
- `/getXrefsToField?struct=<name>&field=<name>`: Xrefs to struct field.
- `/getXrefsToType?name=<type>`: Xrefs/usages related to a struct/type name.
- `/getTypeInfo?name=<type>`: Resolve a type and return declaration and details.
- `/getXrefsToUnion?name=<union>`: Union xrefs/usages (members, globals, refs).
- `/localTypes?offset=<n>&limit=<m>`: List local types.
- `/strings?offset=<n>&limit=<m>`: Paginated strings.
- `/strings/filter?offset=<n>&limit=<m>&filter=<substr>`: Filtered strings.
- `/searchTypes?query=<substr>&offset=<n>&limit=<m>`: Search local types by substring.

## Prerequisites

- [Binary Ninja](https://binary.ninja/)
- Python 3.12+
- [Claude Desktop](https://claude.ai/download) (or your preferred integration)

## Installation

### Binary Ninja Plugin Manager

You may install the plugin through Binary Ninja's Plugin Manager (`Plugins > Manage Plugins`). When installed via the Plugin Manager, the plugin resides under:

- macOS: `~/Library/Application Support/Binary Ninja/plugins/repositories/community/plugins/CX330Blake_binary_ninja_mcp_max`
- Linux: `~/.binaryninja/plugins/repositories/community/plugins/CX330Blake_binary_ninja_mcp_max`
- Windows: `%APPDATA%\Binary Ninja\plugins\repositories\community\plugins\CX330Blake_binary_ninja_mcp_max`

To manually configure the plugin, this repository can be copied into the Binary Ninja plugins folder.

#### Automatic MCP Client Setup

The plugin includes an automatic installer that wires up supported MCP clients to this server using the key `binary_ninja_mcp_max`.

- First run: When Binary Ninja loads the plugin, it will:
  - Create a local venv under this plugin at `.venv/` (if missing) and install `bridge/requirements.txt`.
  - Add an entry for `binary_ninja_mcp_max` to known MCP client configs (Cline, Roo Code, Claude Desktop, Cursor, Windsurf, Claude Code, LM Studio) when their config files are present.
  - Write `.mcp_auto_setup_done` at the plugin root to avoid repeating on every launch.

- Re-run auto-setup: Delete the `.mcp_auto_setup_done` file or run the uninstall command below; then restart Binary Ninja or run the installer again.

#### CLI Installer (all platforms)

You can also manage MCP client entries from the command line:

```bash
python scripts/mcp_client_installer.py --install    # add/update entries
python scripts/mcp_client_installer.py --uninstall  # remove entries and delete .mcp_auto_setup_done
python scripts/mcp_client_installer.py --config     # print a generic JSON config snippet
```

- Use `--quiet` to reduce output. The installer preserves any existing `env` overrides for this server key.

### Manual Configuration

For other MCP clients:

```json
{
    "mcpServers": {
        "binary_ninja_mcp_max": {
            "command": "/ABSOLUTE/PATH/TO/Binary\ Ninja/plugins/repositories/community/plugins/CX330Blake_binary_ninja_mcp_max/.venv/bin/python",
            "args": [
                "/ABSOLUTE/PATH/TO/Binary\ Ninja/plugins/repositories/community/plugins/CX330Blake_binary_ninja_mcp_max/bridge/binja_mcp_bridge.py"
            ]
        }
    }
}
```

Note: Replace `/ABSOLUTE/PATH/TO` with the actual absolute path to your project directory. The virtual environment's Python interpreter must be used to access the installed dependencies.

## Usage

1. Open Binary Ninja and install the `Binary Ninja MCP` plugin
2. Restart Binary Ninja and then open a binary
3. Click the button shown at left bottom corner
4. Start using it through your MCP client

You may now start prompting Claude about the currently open binary. Example prompts:

- "Generate a binary analysis report for the current binary."
- "Rename function X to Y in the current binary."
- "List all functions in the current binary."
- "What is the status of the loaded binary?"

### Other MCP Client Integrations

The bridge can be used with other MCP clients by implementing the appropriate integration layer.

## Development

### Quick Start

```bash
git clone <this-repo>
cd binary_ninja_mcp_max

# Create a local venv and install bridge deps
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
pip install -r bridge/requirements.txt

# Optional: register the MCP server with supported clients
python scripts/mcp_client_installer.py --install
```

Then open Binary Ninja, load a binary, and start the server if it’s not already running:

- Binary Ninja menu: Plugins > MCP Server > Start MCP Server

The server listens on `http://localhost:9009` and exposes HTTP endpoints consumed by the bridge.

### Test Locally (HTTP)

After the server is running in Binary Ninja, you can sanity-check endpoints from a terminal:

```bash
curl http://localhost:9009/status
curl "http://localhost:9009/functions?offset=0&limit=10"
```

### Working on the Bridge

- Entry point: `bridge/binja_mcp_bridge.py` (run by your MCP client).
- The CLI installer configures MCP clients to use:
  - `command`: the plugin’s `.venv` Python
  - `args`: `[bridge/binja_mcp_bridge.py]`
- Edit tools in `bridge/binja_mcp_bridge.py` and re-run from your MCP client (e.g., Claude Desktop, Cline) to pick up changes.

### Working on the Binary Ninja Plugin

- Core server: `plugin/server/http_server.py` (served inside Binary Ninja).
- Capabilities and endpoints live under `plugin/core/` and `plugin/api/`.
- Logs appear in Binary Ninja’s Log window; use them to debug requests and responses.

### Reset or Reconfigure MCP Clients

```bash
# Remove entries and delete the auto-setup marker (.mcp_auto_setup_done)
python scripts/mcp_client_installer.py --uninstall

# Re-install entries
python scripts/mcp_client_installer.py --install
```

Deleting the `.mcp_auto_setup_done` file at the repo root also forces the plugin’s one-time auto-setup to run again on next load.

### Project Layout

```
binary_ninja_mcp_max/
├── bridge/                      # MCP tools (client side)
├── plugin/                      # Binary Ninja plugin + HTTP server (server side)
├── scripts/                     # Installers and helpers
│   └── mcp_client_installer.py
└── README.md
```

## Contributing

Contributions are welcome. Please feel free to submit a pull request.
