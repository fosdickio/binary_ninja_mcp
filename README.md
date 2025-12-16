# Binary Ninja MCP

This repository contains a Binary Ninja plugin, MCP server, and bridge that enables seamless integration of Binary Ninja's capabilities with your favorite LLM client.

![Binary Ninja MCP Logo](images/logo-small.png)

## Features

- Seamless, real-time integration between Binary Ninja and MCP clients
- Enhanced reverse engineering workflow with AI assistance
- Support for every MCP client (Cline, Claude desktop, Roo Code, etc.)
- Open multiple binaries and switch the active target automatically

## Examples

### Solving a CTF Challenge

Check out [this demo video on YouTube](https://www.youtube.com/watch?v=0ffMHH39L_M) that uses the extension to solve a CTF challenge.

## Components

This repository contains two separate components:

1. A Binary Ninja plugin that provides an MCP server that exposes Binary Ninja's capabilities through HTTP endpoints. This can be used with any client that implements the MCP protocol.
2. A separate MCP bridge component that connects your favorite MCP client to the Binary Ninja MCP server.

## Prerequisites

- [Binary Ninja](https://binary.ninja/)
- Python 3.12+
- MCP client (those with auto-setup support are listed below)

## Installation

### MCP Client

Please install the MCP client before you install Binary Ninja MCP so that the MCP clients can be auto-setup. We currently support auto-setup for these MCP clients:

    1. Cline (recommended)
    2. Roo Code
    3. Claude Desktop (recommended)
    4. Cursor
    5. Windsurf
    6. Claude Code
    7. LM Studio

### Extension Installation

After the MCP client is installed, you can install the MCP server using the Binary Ninja Plugin Manager or manually. Both methods support auto-setup of MCP clients.

If your MCP client is not set, you should install it first then try to reinstall the extension.

#### Binary Ninja Plugin Manager

You may install the extension through Binary Ninja's Plugin Manager (`Plugins > Manage Plugins`).

![Plugin Manager](images/plugin-manager-listing.png)

#### Manual Install

To manually install the extension, this repository can be copied into the [Binary Ninja plugins folder](https://docs.binary.ninja/guide/plugins.html).

### [Optional] Manual Setup of the MCP Client

*You do NOT need to set this up manually if you use a supported MCP client and follow the installation steps before.*

You can also manage MCP client entries from the command line:

```bash
python scripts/mcp_client_installer.py --install    # auto setup supported MCP clients
python scripts/mcp_client_installer.py --uninstall  # remove entries and delete `.mcp_auto_setup_done`
python scripts/mcp_client_installer.py --config     # print a generic JSON config snippet
```

For other MCP clients, this is an example config:

```json
{
    "mcpServers": {
        "binary_ninja_mcp": {
            "command": "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/.venv/bin/python",
            "args": [
                "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/bridge/binja_mcp_bridge.py"
            ]
        }
    }
}
```

Note: Replace `/ABSOLUTE/PATH/TO` with the actual absolute path to your project directory. The virtual environment's Python interpreter must be used to access the installed dependencies.

## Usage

1. Open Binary Ninja and load a binary
2. Click the button shown at left bottom corner
3. Start using it through your MCP client

You may now start prompting LLMs about the currently open binary (or binaries). Example prompts:

### CTF Challenges

```txt
You're the best CTF player in the world. Please solve this reversing CTF challenge in the <folder_name> folder using Binary Ninja. Rename ALL the function and the variables during your analyzation process (except for main function) so I can better read the code. Write a python solve script if you need. Also, if you need to create struct or anything, please go ahead. Reverse the code like a human reverser so that I can read the decompiled code that analyzed by you.
```

### Malware Analysis

```txt
Your task is to analyze an unknown file which is currently open in Binary Ninja. You can use the existing MCP server called "binary_ninja_mcp" to interact with the Binary Ninja instance and retrieve information, using the tools made available by this server. In general use the following strategy:

- Start from the entry point of the code
- If this function call others, make sure to follow through the calls and analyze these functions as well to understand their context
- If more details are necessary, disassemble or decompile the function and add comments with your findings
- Inspect the decompilation and add comments with your findings to important areas of code
- Add a comment to each function with a brief summary of what it does
- Rename variables and function parameters to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive, using vibe_ as prefix.
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- When you finish your analysis, report how long the analysis took
- At the end, create a report with your findings.
- Based only on these findings, make an assessment on whether the file is malicious or not.
```

## Supported Capabilities

The following table lists the available MCP functions for use:

| Function                                                             | Description                                                                                                  |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `decompile_function`                                                 | Decompile a specific function by name and return HLIL-like code with addresses.                              |
| `get_il(name_or_address, view, ssa)`                                 | Get IL for a function in `hlil`, `mlil`, or `llil` (SSA supported for MLIL/LLIL).                            |
| `define_types`                                                       | Add type definitions from a C string type definition.                                                        |
| `delete_comment`                                                     | Delete the comment at a specific address.                                                                    |
| `delete_function_comment`                                            | Delete the comment for a function.                                                                           |
| `declare_c_type(c_declaration)`                                      | Create/update a local type from a single C declaration.                                                      |
| `format_value(address, text, size)`                                  | Convert a value and annotate it at an address in BN (adds a comment).                                        |
| `function_at`                                                        | Retrieve the name of the function the address belongs to.                                                    |
| `get_assembly_function`                                              | Get the assembly representation of a function by name or address.                                            |
| `get_entry_points()`                                                 | List entry point(s) of the loaded binary.                                                                    |
| `get_binary_status`                                                  | Get the current status of the loaded binary.                                                                 |
| `get_comment`                                                        | Get the comment at a specific address.                                                                       |
| `get_function_comment`                                               | Get the comment for a function.                                                                              |
| `get_user_defined_type`                                              | Retrieve definition of a user-defined type (struct, enumeration, typedef, union).                            |
| `get_xrefs_to(address)`                                              | Get all cross references (code and data) to an address.                                                      |
| `get_data_decl(name_or_address, length)`                             | Return a C-like declaration and a hexdump for a data symbol or address.                                      |
| `hexdump_address(address, length)`                                   | Text hexdump at address. `length < 0` reads exact defined size if available.                                 |
| `hexdump_data(name_or_address, length)`                              | Hexdump by data symbol name or address. `length < 0` reads exact defined size if available.                  |
| `get_xrefs_to_enum(enum_name)`                                       | Get usages related to an enum (matches member constants in code).                                            |
| `get_xrefs_to_field(struct_name, field_name)`                        | Get all cross references to a named struct field.                                                            |
| `get_xrefs_to_struct(struct_name)`                                   | Get xrefs/usages related to a struct (members, globals, code refs).                                          |
| `get_xrefs_to_type(type_name)`                                       | Get xrefs/usages related to a struct/type (globals, refs, HLIL matches).                                     |
| `get_xrefs_to_union(union_name)`                                     | Get xrefs/usages related to a union (members, globals, code refs).                                           |
| `get_type_info(type_name)`                                           | Resolve a type and return declaration, kind, and members.                                                    |
| `make_function_at(address, platform)`                                | Create a function at an address. `platform` optional; use `default` to pick the BinaryView/platform default. |
| `list_platforms()`                                                   | List all available platform names.                                                                           |
| `list_binaries()`                                                    | List managed/open binaries with ids and active flag.                                                         |
| `select_binary(view)`                                                | Select active binary by id or filename.                                                                      |
| `list_all_strings()`                                                 | List all strings (no pagination; aggregates all pages).                                                      |
| `list_classes`                                                       | List all namespace/class names in the program.                                                               |
| `list_data_items`                                                    | List defined data labels and their values.                                                                   |
| `list_exports`                                                       | List exported functions/symbols.                                                                             |
| `list_imports`                                                       | List imported symbols in the program.                                                                        |
| `list_local_types(offset, count)`                                    | List local Types in the current database (name/kind/decl).                                                   |
| `list_methods`                                                       | List all function names in the program.                                                                      |
| `list_namespaces`                                                    | List all non-global namespaces in the program.                                                               |
| `list_segments`                                                      | List all memory segments in the program.                                                                     |
| `list_strings(offset, count)`                                        | List all strings in the database (paginated).                                                                |
| `list_strings_filter(offset, count, filter)`                         | List matching strings (paginated, filtered by substring).                                                    |
| `rename_data`                                                        | Rename a data label at the specified address.                                                                |
| `rename_function`                                                    | Rename a function by its current name to a new user-defined name.                                            |
| `rename_single_variable`                                             | Rename a single local variable inside a function.                                                            |
| `rename_multi_variables`                                             | Batch rename multiple local variables in a function (mapping or pairs).                                      |
| `set_local_variable_type(function_address, variable_name, new_type)` | Set a local variable's type.                                                                                 |
| `retype_variable`                                                    | Retype variable inside a given function.                                                                     |
| `search_functions_by_name`                                           | Search for functions whose name contains the given substring.                                                |
| `search_types(query, offset, count)`                                 | Search local Types by substring (name/decl).                                                                 |
| `set_comment`                                                        | Set a comment at a specific address.                                                                         |
| `set_function_comment`                                               | Set a comment for a function.                                                                                |
| `set_function_prototype(name_or_address, prototype)`                 | Set a function's prototype by name or address.                                                               |
| `patch_bytes(address, data, save_to_file)`                           | Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS. |

These are the list of HTTP endpoints that can be called:

- `/allStrings`: All strings in one response.
- `/formatValue?address=<addr>&text=<value>&size=<n>`: Convert and set a comment at an address.
- `/getXrefsTo?address=<addr>`: Xrefs to address (code+data).
- `/getDataDecl?name=<symbol>|address=<addr>&length=<n>`: JSON with declaration-style string and a hexdump for a data symbol or address. Keys: `address`, `name`, `size`, `type`, `decl`, `hexdump`. `length < 0` reads exact defined size if available.
- `/hexdump?address=<addr>&length=<n>`: Text hexdump aligned at address; `length < 0` reads exact defined size if available.
- `/hexdumpByName?name=<symbol>&length=<n>`: Text hexdump by symbol name. Recognizes BN auto-labels like `data_<hex>`, `byte_<hex>`, `word_<hex>`, `dword_<hex>`, `qword_<hex>`, `off_<hex>`, `unk_<hex>`, and plain hex addresses.
- `/makeFunctionAt?address=<addr>&platform=<name|default>`: Create a function at an address (idempotent if already exists). `platform=default` uses the BinaryView/platform default.
- `/platforms`: List all available platform names.
- `/binaries` or `/views`: List managed/open binaries with ids and active flag.
- `/selectBinary?view=<id|filename>`: Select active binary for subsequent operations.
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
- `/patch` or `/patchBytes?address=<addr>&data=<hex>&save_to_file=<bool>`: Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS.
- `/renameVariables`: Batch rename locals in a function. Parameters:
  - Function: one of `functionAddress`, `address`, `function`, `functionName`, or `name`.
  - Provide renames via one of:
    - `renames`: JSON array of `{old, new}` objects
    - `mapping`: JSON object of `old->new`
    - `pairs`: compact string `old1:new1,old2:new2`
          Returns per-item results plus totals. Order is respected; later pairs can refer to earlier new names.

## Contributing

Contributions are welcome. Please feel free to submit a pull request.
