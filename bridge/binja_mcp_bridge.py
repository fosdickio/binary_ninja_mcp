import os as _os
import sys as _sys
import traceback as _tb

# Install a very-early excepthook so any ImportError at module import time is captured.
def _bridge_excepthook(exc_type, exc, tb):
    # Print to stderr for interactive runs
    _tb.print_exception(exc_type, exc, tb, file=_sys.stderr)

_sys.excepthook = _bridge_excepthook

from mcp.server.fastmcp import FastMCP
import requests


binja_server_url = "http://localhost:9009"
mcp = FastMCP("binja-mcp")

def _active_filename() -> str:
    """Return the currently active filename as known by the server."""
    try:
        st = get_json("status")
        if isinstance(st, dict) and st.get("filename"):
            return str(st.get("filename"))
    except Exception:
        pass
    return "(none)"


def safe_get(endpoint: str, params: dict = None, timeout: float | None = 5) -> list:
    """
    Perform a GET request. If 'params' is given, we convert it to a query string.
    """
    if params is None:
        params = {}
    qs = [f"{k}={v}" for k, v in params.items()]
    query_string = "&".join(qs)
    url = f"{binja_server_url}/{endpoint}"
    if query_string:
        url += "?" + query_string

    try:
        if timeout is None:
            response = requests.get(url)
        else:
            response = requests.get(url, timeout=timeout)
        response.encoding = "utf-8"
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def get_json(endpoint: str, params: dict = None, timeout: float | None = 5):
    """
    Perform a GET and return parsed JSON.
    - On 2xx: returns parsed JSON.
    - On 4xx/5xx: attempts to parse JSON body and return it; if not JSON, returns {'error': 'Error <code>: <text>'}.
    Returns None only on transport errors.
    """
    if params is None:
        params = {}
    qs = [f"{k}={v}" for k, v in params.items()]
    query_string = "&".join(qs)
    url = f"{binja_server_url}/{endpoint}"
    if query_string:
        url += "?" + query_string
    try:
        if timeout is None:
            response = requests.get(url)
        else:
            response = requests.get(url, timeout=timeout)
        response.encoding = "utf-8"
        # Try to parse JSON regardless of status
        try:
            data = response.json()
        except Exception:
            data = None
        if response.ok:
            return data
        # Non-OK: return parsed error object if available; otherwise synthesize one
        if isinstance(data, dict):
            # Ensure at least an error field for LLMs
            if "error" not in data:
                data = {"error": str(data)}
            data.setdefault("status", response.status_code)
            return data
        text = (response.text or "").strip()
        return {"error": f"Error {response.status_code}: {text}"}
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}


def get_text(endpoint: str, params: dict = None, timeout: float | None = 5) -> str:
    """Perform a GET and return raw text (or an error string)."""
    if params is None:
        params = {}
    qs = [f"{k}={v}" for k, v in params.items()]
    query_string = "&".join(qs)
    url = f"{binja_server_url}/{endpoint}"
    if query_string:
        url += "?" + query_string
    try:
        if timeout is None:
            response = requests.get(url)
        else:
            response = requests.get(url, timeout=timeout)
        response.encoding = "utf-8"
        if response.ok:
            return response.text
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        if isinstance(data, dict):
            response = requests.post(
                f"{binja_server_url}/{endpoint}", data=data, timeout=5
            )
        else:
            response = requests.post(
                f"{binja_server_url}/{endpoint}", data=data.encode("utf-8"), timeout=5
            )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    header = f"File: {_active_filename()}"
    body = safe_get("methods", {"offset": offset, "limit": limit})
    return [header] + (body or [])

@mcp.tool()
def get_entry_points() -> list:
    """
    List entry point(s) of the loaded binary.
    """
    data = get_json("entryPoints")
    if not data or "entry_points" not in data:
        return ["Error: no response"]
    out: list[str] = []
    for ep in data.get("entry_points", []) or []:
        addr = ep.get("address")
        name = ep.get("name") or "(unknown)"
        out.append(f"{addr}\t{name}")
    return out

@mcp.tool()
def retype_variable(function_name: str, variable_name: str, type_str: str) -> str:
    """
    Retype a variable in a function.
    """
    data = get_json("retypeVariable", {"functionName": function_name, "variableName": variable_name, "type": type_str})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return data["status"]
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)

@mcp.tool()
def rename_single_variable(function_name: str, variable_name: str, new_name: str) -> str:
    """
    Rename a variable in a function.
    """
    data = get_json("renameVariable", {"functionName": function_name, "variableName": variable_name, "newName": new_name})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return data["status"]
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)

@mcp.tool()
def rename_multi_variables(function_identifier: str, mapping_json: str = "", pairs: str = "", renames_json: str = "") -> str:
    """
    Rename multiple local variables in one call.
    - function_identifier: function name or address (hex)
    - Provide either mapping_json (JSON object old->new), renames_json (JSON array of {old,new}), or pairs ("old1:new1,old2:new2").
    Returns per-item results and totals.
    """
    params: dict[str, object] = {}
    ident = (function_identifier or "").strip()
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["functionName"] = ident

    payload = None
    import json as _json
    if renames_json:
        try:
            payload = _json.loads(renames_json)
        except Exception:
            return "Error: renames_json is not valid JSON"
        params["renames"] = payload
    elif mapping_json:
        try:
            payload = _json.loads(mapping_json)
        except Exception:
            return "Error: mapping_json is not valid JSON"
        params["mapping"] = payload
    elif pairs:
        params["pairs"] = pairs
    else:
        return "Error: provide mapping_json, renames_json, or pairs"

    data = get_json("renameVariables", params)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return f"Error: {data['error']}"
    try:
        total = data.get("total")
        renamed = data.get("renamed")
        return f"Batch rename: {renamed}/{total} applied"
    except Exception:
        return str(data)

@mcp.tool()
def define_types(c_code: str) -> str:
    """
    Define types from a C code string.
    """
    data = get_json("defineTypes", {"cCode": c_code})
    if not data:
        return "Error: no response"
    # Expect a list of defined type names or a dict; normalize to string
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    if isinstance(data, (list, tuple)):
        return "Defined types: " + ", ".join(map(str, data))
    return str(data)

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})


@mcp.tool()
def hexdump_address(address: str, length: int = -1) -> str:
    """
    Hexdump data starting at an address. When length < 0, reads the exact defined size if available.
    """
    params = {"address": address}
    if length is not None:
        params["length"] = length
    return get_text("hexdump", params, timeout=None)


@mcp.tool()
def hexdump_data(name_or_address: str, length: int = -1) -> str:
    """
    Hexdump a data symbol by name or address. When length < 0, reads the exact defined size if available.
    """
    ident = (name_or_address or "").strip()
    if ident.startswith("0x"):
        return hexdump_address(ident, length)
    return get_text("hexdumpByName", {"name": ident, "length": length}, timeout=None)


@mcp.tool()
def get_data_decl(name_or_address: str, length: int = -1) -> str:
    """
    Return a declaration-like string and a hexdump for a data symbol by name or address.
    LLM-friendly: includes both a C-like declaration (when possible) and text hexdump.
    """
    ident = (name_or_address or "").strip()
    params = {"name": ident} if not ident.startswith("0x") else {"address": ident}
    if length is not None:
        params["length"] = length
    data = get_json("getDataDecl", params, timeout=None)
    if not data:
        return "Error: no response"
    if "error" in data:
        return f"Error: {data.get('error')}"
    decl = data.get("decl") or "(no declaration)"
    hexdump = data.get("hexdump") or ""
    addr = data.get("address", "")
    name = data.get("name", ident)
    return f"Declaration ({addr} {name}):\n{decl}\n\nHexdump:\n{hexdump}"


@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("decompile", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "decompiled" in data:
        return file_line + data["decompiled"]
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    return file_line + str(data)

@mcp.tool()
def get_il(name_or_address: str, view: str = "hlil", ssa: bool = False) -> str:
    """
    Get IL for a function in the selected view.
    - view: one of hlil, mlil, llil
    - ssa: set True to request SSA form (MLIL/LLIL only)
    """
    file_line = f"File: {_active_filename()}\n\n"
    ident = (name_or_address or "").strip()
    params = {"view": view, "ssa": int(bool(ssa))}
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = get_json("il", params, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "il" in data:
        return file_line + data["il"]
    if "error" in data:
        import json as _json
        return file_line + _json.dumps(data, indent=2, ensure_ascii=False)
    return file_line + str(data)

@mcp.tool()
def fetch_disassembly(name: str) -> str:
    """
    Retrive the disassembled code of a function with a given name as assemby mnemonic instructions.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("assembly", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "assembly" in data:
        return file_line + data["assembly"]
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    return file_line + str(data)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@mcp.tool()
def set_comment(address: str, comment: str) -> str:
    """
    Set a comment at a specific address.
    """
    return safe_post("comment", {"address": address, "comment": comment})


@mcp.tool()
def set_function_comment(function_name: str, comment: str) -> str:
    """
    Set a comment for a function.
    """
    return safe_post("comment/function", {"name": function_name, "comment": comment})


@mcp.tool()
def get_comment(address: str) -> str:
    """
    Get the comment at a specific address.
    """
    return safe_get("comment", {"address": address})[0]


@mcp.tool()
def get_function_comment(function_name: str) -> str:
    """
    Get the comment for a function.
    """
    return safe_get("comment/function", {"name": function_name})[0]


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})


@mcp.tool()
def list_sections(offset: int = 0, limit: int = 100) -> list:
    """
    List sections in the program with pagination.

    Returns one line per section with: start-end, size, name, and any semantics/type if available.
    """
    data = get_json("sections", {"offset": offset, "limit": limit})
    if not data or not isinstance(data, dict):
        return ["Error: no response"]
    if data.get("error"):
        return [f"Error: {data.get('error')}"]
    sections = data.get("sections", []) or []
    out: list[str] = [f"File: {_active_filename()}"]
    for s in sections:
        try:
            start = s.get("start") or ""
            end = s.get("end") or ""
            size = s.get("size")
            name = s.get("name") or "(unnamed)"
            sem = s.get("semantics") or s.get("type") or ""
            tail = f"\t{sem}" if sem else ""
            out.append(f"{start}-{end}\t{size}\t{name}{tail}")
        except Exception:
            continue
    return out

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_strings(offset: int = 0, count: int = 100) -> list:
    """
    List all strings in the database (paginated).
    """
    return safe_get("strings", {"offset": offset, "limit": count}, timeout=None)

@mcp.tool()
def list_strings_filter(offset: int = 0, count: int = 100, filter: str = "") -> list:
    """
    List matching strings in the database (paginated, filtered).
    """
    return safe_get("strings/filter", {"offset": offset, "limit": count, "filter": filter}, timeout=None)

@mcp.tool()
def list_local_types(offset: int = 0, count: int = 200, include_libraries: bool = False) -> list:
    """
    List all local types in the database (paginated).
    """
    return safe_get("localTypes", {"offset": offset, "limit": count, "includeLibraries": int(bool(include_libraries))}, timeout=None)

@mcp.tool()
def search_types(query: str, offset: int = 0, count: int = 200, include_libraries: bool = False) -> list:
    """
    Search local types whose name or declaration contains the substring.
    """
    return safe_get("searchTypes", {"query": query, "offset": offset, "limit": count, "includeLibraries": int(bool(include_libraries))}, timeout=None)

@mcp.tool()
def list_all_strings(batch_size: int = 500) -> list:
    """
    List all strings in the database (aggregated across pages).
    """
    results: list[str] = []
    offset = 0
    while True:
        data = get_json("strings", {"offset": offset, "limit": batch_size}, timeout=None)
        if not data or "strings" not in data:
            break
        items = data.get("strings", [])
        if not items:
            break
        for s in items:
            addr = s.get("address")
            length = s.get("length")
            stype = s.get("type")
            value = s.get("value")
            results.append(f"{addr}\t{length}\t{stype}\t{value}")
        if len(items) < batch_size:
            break
        offset += batch_size
    return results

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(
        "searchFunctions", {"query": query, "offset": offset, "limit": limit}
    )


@mcp.tool()
def get_binary_status() -> str:
    """
    Get the current status of the loaded binary.
    """
    return safe_get("status")[0]


@mcp.tool()
def list_binaries() -> list:
    """
    List managed/open binaries known to the server with ids and active flag.
    """
    data = get_json("binaries")
    if not data:
        return ["Error: no response"]
    if isinstance(data, dict) and data.get("error"):
        return [data.get("error")]
    items = data.get("binaries", [])
    out = []
    for it in items:
        vid = it.get("id")
        view_id = it.get("view_id")
        fn = it.get("filename")
        basename = it.get("basename") or ""
        selectors = it.get("selectors") or []
        active = it.get("active")
        label = basename or fn or "(unknown)"
        full = fn or "(no filename)"
        selector_text = ", ".join(str(s) for s in selectors if s)
        mark = " *active*" if active else ""
        view_part = f" view={view_id}" if view_id else ""
        out.append(f"{vid}. {label}{view_part}{mark}\n    path: {full}\n    selectors: {selector_text}")
    return out

@mcp.tool()
def select_binary(view: str) -> str:
    """
    Select which binary to analyze by ordinal, internal view id, full path, or basename.
    Call this after listing binaries whenever you need to switch analysis targets.
    """
    data = get_json("selectBinary", {"view": view})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json
        return _json.dumps(data, indent=2, ensure_ascii=False)
    sel = data.get("selected") if isinstance(data, dict) else None
    if sel:
        ordinal = sel.get("id") or "?"
        view_id = sel.get("view_id") or ""
        fn = sel.get("filename") or ""
        basename = sel.get("basename") or ""
        selectors = sel.get("selectors") or []
        selector_text = ", ".join(str(s) for s in selectors if s)
        display_name = basename or fn or "(unknown)"
        view_part = f" (view {view_id})" if view_id else ""
        path_part = f"\nFull path: {fn}" if fn else ""
        return f"Selected {ordinal}: {display_name}{view_part}{path_part}\nSelectors: {selector_text}"
    return str(data)


@mcp.tool()
def delete_comment(address: str) -> str:
    """
    Delete the comment at a specific address.
    """
    return safe_post("comment", {"address": address, "_method": "DELETE"})


@mcp.tool()
def delete_function_comment(function_name: str) -> str:
    """
    Delete the comment for a function.
    """
    return safe_post("comment/function", {"name": function_name, "_method": "DELETE"})

@mcp.tool()
def function_at(address: str) -> str:
    """
    Retrive the name of the function the address belongs to. Address must be in hexadecimal format 0x00001
    """
    return safe_get("functionAt", {"address": address})

@mcp.tool()
def get_user_defined_type(type_name: str) -> str:
    """
    Retrive definition of a user defined type (struct, enumeration, typedef, union)
    """
    return safe_get("getUserDefinedType", {"name": type_name})
    
@mcp.tool()
def get_xrefs_to(address: str) -> list:
    """
    Get all cross references (code and data) to the given address.
    Address can be hex (e.g., 0x401000) or decimal.
    """
    return safe_get("getXrefsTo", {"address": address})

@mcp.tool()
def get_xrefs_to_field(struct_name: str, field_name: str) -> list:
    """
    Get all cross references to a named struct field (member).
    """
    return safe_get("getXrefsToField", {"struct": struct_name, "field": field_name})

@mcp.tool()
def get_xrefs_to_struct(struct_name: str) -> list:
    """
    Get cross references/usages related to a struct name.
    """
    return safe_get("getXrefsToStruct", {"name": struct_name})

@mcp.tool()
def get_xrefs_to_type(type_name: str) -> list:
    """
    Get xrefs/usages related to a struct or type name.
    Includes global instances, code refs to those, HLIL matches, and functions whose signature mentions the type.
    """
    return safe_get("getXrefsToType", {"name": type_name})

@mcp.tool()
def get_xrefs_to_enum(enum_name: str) -> list:
    """
    Get usages/xrefs of an enum by scanning for member values and matches.
    """
    return safe_get("getXrefsToEnum", {"name": enum_name})

@mcp.tool()
def get_xrefs_to_union(union_name: str) -> list:
    """
    Get cross references/usages related to a union type by name.
    """
    return safe_get("getXrefsToUnion", {"name": union_name})


@mcp.tool()
def format_value(address: str, text: str, size: int = 0) -> list:
    """
    Convert and annotate a value at an address in Binary Ninja.
    Adds a comment with hex/dec and C literal/string so you can see the change.
    """
    return safe_get("formatValue", {"address": address, "text": text, "size": size}, timeout=None)

@mcp.tool()
def convert_number(text: str, size: int = 0) -> str:
    """
    Convert a number or string to multiple representations (hex/dec/bin, LE/BE, C char/string literals).
    Accepts decimal (e.g., 123), hex (0x7b or 7Bh), binary (0b1111011), octal (0o173),
    char ('A'), or string ("ABC" with escapes like \x41).
    """
    data = get_json("convertNumber", {"text": text, "size": size}, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return f"Error: {data['error']}"
    import json as _json
    return _json.dumps(data, indent=2, ensure_ascii=False)

@mcp.tool()
def get_type_info(type_name: str) -> str:
    """
    Resolve a type name and return its declaration and details (kind, members, enum values).
    """
    data = get_json("getTypeInfo", {"name": type_name}, timeout=None)
    if not data:
        return "Error: no response"
    if "error" in data:
        return f"Error: {data.get('error')}"
    import json as _json
    return _json.dumps(data, indent=2, ensure_ascii=False)

@mcp.tool()
def set_function_prototype(name_or_address: str, prototype: str) -> str:
    """
    Set a function's prototype by name or address.
    """
    # Use GET like other endpoints (server accepts complex prototypes)
    ident = (name_or_address or "").strip()
    params = {"prototype": prototype}
    # Choose param name based on identifier format
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = get_json("setFunctionPrototype", params)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return f"Applied prototype at {data.get('address')}: {data.get('applied_type')}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)

@mcp.tool()
def make_function_at(address: str, platform: str = "") -> str:
    """
    Create a function at the given address. Platform is optional (e.g., "linux-x86_64").
    Use "default" to explicitly select the BinaryView/platform default.
    Returns status and function info; no-op if the function already exists.
    """
    params = {"address": address}
    if platform:
        params["platform"] = platform
    data = get_json("makeFunctionAt", params)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json
        return _json.dumps(data, indent=2, ensure_ascii=False)
    if isinstance(data, dict) and data.get("status") == "exists":
        return f"Function already exists at {data.get('address')}: {data.get('name')}"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Created function at {data.get('address')}: {data.get('name')}"
    return str(data)

@mcp.tool()
def list_platforms() -> str:
    """
    List all available platform names from Binary Ninja.
    """
    data = get_json("platforms")
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json
        return _json.dumps(data, indent=2, ensure_ascii=False)
    plats = data.get("platforms") if isinstance(data, dict) else None
    if not plats:
        return "(no platforms)"
    return "\n".join(plats)

@mcp.tool()
def declare_c_type(c_declaration: str) -> str:
    """
    Create or update a local type from a C declaration.
    """
    data = get_json("declareCType", {"declaration": c_declaration})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("defined_types"):
        names = ", ".join(data["defined_types"].keys())
        return f"Declared types ({data.get('count', 0)}): {names}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    data = get_json(
        "setLocalVariableType",
        {"functionAddress": function_address, "variableName": variable_name, "newType": new_type},
    )
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Retyped {data.get('variable')} in {data.get('function')} to {data.get('applied_type')}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)

@mcp.tool()
def patch_bytes(address: str, data: str, save_to_file: bool = True) -> str:
    """
    Patch bytes at a given address in the binary.
    - address: Address to patch (hex string like "0x401000" or decimal)
    - data: Hex string of bytes to write (e.g., "90 90" or "9090" or "0x90 0x90")
    - save_to_file: If True (default), save patched binary to disk and re-sign on macOS.
                    If False, only modify in memory without affecting the original file.
    
    Returns status with original and patched bytes.
    On macOS, automatically re-signs the binary after patching to avoid execution errors.
    """
    # Handle boolean type conversion (MCP may pass as string)
    if isinstance(save_to_file, str):
        save_to_file = save_to_file.lower() not in ("false", "0", "no")
    
    params = {"address": address, "data": data, "save_to_file": save_to_file}
    result = get_json("patch", params)
    if not result:
        return "Error: no response"
    
    status = result.get("status") if isinstance(result, dict) else None
    if status in ("ok", "partial"):
        orig = result.get("original_bytes", "")
        patched = result.get("patched_bytes", "")
        written = result.get("bytes_written", 0)
        requested = result.get("bytes_requested", 0)
        addr = result.get("address", address)
        saved = result.get("saved_to_file", False)
        saved_path = result.get("saved_path", "")
        save_error = result.get("save_error", "")
        codesign = result.get("codesign", {})
        warning = result.get("warning", "")
        
        msg = f"Patched {written}/{requested} bytes at {addr}"
        if status == "partial":
            msg += " (PARTIAL WRITE)"
        if warning:
            msg += f"\nWarning: {warning}"
        if orig:
            msg += f"\nOriginal: {orig}"
        if patched:
            msg += f"\nPatched:  {patched}"
        if saved:
            msg += f"\nSaved to file: {saved_path}"
        elif save_error:
            msg += f"\nWarning: File not saved - {save_error}"
        
        # Show codesign status for macOS
        if codesign:
            if codesign.get("success"):
                msg += f"\nCode signing: {codesign.get('message', 'Re-signed successfully')}"
            elif codesign.get("attempted"):
                msg += f"\nCode signing: Failed - {codesign.get('error', 'Unknown error')}"
        
        return msg
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return str(result)
    
# ==================== NEW WINDOWS RE TOOLS ====================

@mcp.tool()
def get_function_callers(name: str) -> str:
    """
    Get all functions that call a specific function (callers/incoming references).
    Useful for understanding how a function is used throughout the binary.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("functionCallers", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    callers = data.get("callers", [])
    if not callers:
        return file_line + f"No callers found for function '{name}'"
    lines = [f"Callers of {name} ({len(callers)} found):"]
    for c in callers:
        lines.append(f"  {c.get('address', '?')}  {c.get('caller_name', '?')}  call_site: {c.get('call_site', '?')}")
    return file_line + "\n".join(lines)


@mcp.tool()
def get_function_callees(name: str) -> str:
    """
    Get all functions called by a specific function (callees/outgoing references).
    Useful for understanding what a function does and its dependencies.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("functionCallees", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    callees = data.get("callees", [])
    if not callees:
        return file_line + f"No callees found for function '{name}'"
    lines = [f"Callees of {name} ({len(callees)} found):"]
    for c in callees:
        lines.append(f"  {c.get('call_site', '?')}  -> {c.get('callee_name', '?')} ({c.get('callee_address', '?')})")
    return file_line + "\n".join(lines)


@mcp.tool()
def get_function_vars(name: str) -> str:
    """
    Get all local variables and parameters of a function with their types.
    Essential for understanding function internals and data flow.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("functionVars", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Variables in {data.get('function', name)}:"]
    
    params = data.get("parameters", [])
    if params:
        lines.append("\nParameters:")
        for p in params:
            lines.append(f"  {p.get('type', '?'):20} {p.get('name', '?')}")
    
    locals_ = data.get("locals", [])
    if locals_:
        lines.append("\nLocal Variables:")
        for v in locals_:
            storage = v.get('storage', '')
            lines.append(f"  {v.get('type', '?'):20} {v.get('name', '?'):15} {storage}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_basic_blocks(name: str) -> str:
    """
    Get basic block information for a function including addresses and edges.
    Useful for understanding control flow and identifying loops/branches.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("basicBlocks", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    blocks = data.get("blocks", [])
    if not blocks:
        return file_line + f"No basic blocks found for function '{name}'"
    
    lines = [f"Basic blocks in {data.get('function', name)} ({len(blocks)} blocks):"]
    for b in blocks:
        edges = b.get('outgoing_edges', [])
        edge_str = ", ".join([f"{e.get('type', '?')}->{e.get('target', '?')}" for e in edges]) if edges else "(no outgoing)"
        lines.append(f"  {b.get('start', '?')}-{b.get('end', '?')}  edges: {edge_str}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_stack_layout(name: str) -> str:
    """
    Get the stack frame layout for a function showing all stack variables and their offsets.
    Critical for understanding local variable organization and potential buffer overflows.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("stackLayout", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Stack layout for {data.get('function', name)}:"]
    lines.append(f"  Frame size: {data.get('frame_size', 'unknown')} bytes")
    
    vars_ = data.get("stack_vars", [])
    if vars_:
        lines.append("\n  Offset    Size  Type                 Name")
        lines.append("  " + "-" * 55)
        for v in vars_:
            off = v.get('offset', 0)
            off_str = f"{off:+d}" if isinstance(off, int) else str(off)
            lines.append(f"  {off_str:8}  {v.get('size', '?'):4}  {v.get('type', '?'):20} {v.get('name', '?')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def find_strings_containing(pattern: str, offset: int = 0, limit: int = 100) -> str:
    """
    Search for strings containing a pattern (case-insensitive substring match).
    Useful for finding interesting strings like URLs, registry keys, API names, error messages.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("strings/filter", {"filter": pattern, "offset": offset, "limit": limit}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    strings = data.get("strings", [])
    total = data.get("total", len(strings))
    
    if not strings:
        return file_line + f"No strings found matching '{pattern}'"
    
    lines = [f"Strings matching '{pattern}' ({len(strings)} shown, {total} total):"]
    for s in strings:
        lines.append(f"  {s.get('address', '?'):12} {s.get('value', '')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_binary_info() -> str:
    """
    Get comprehensive information about the loaded binary including architecture,
    platform, entry point, sections, and PE-specific metadata.
    Essential first step when analyzing any binary.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("binaryInfo", timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = ["Binary Information:"]
    for key in ["filename", "architecture", "platform", "address_size", "endianness", 
                "entry_point", "image_base", "is_executable", "is_relocatable"]:
        if key in data:
            lines.append(f"  {key}: {data[key]}")
    
    sections = data.get("sections", [])
    if sections:
        lines.append("\nSections:")
        for s in sections:
            lines.append(f"  {s.get('name', '?'):15} {s.get('start', '?')}-{s.get('end', '?')}  size: {s.get('size', '?')}")
    
    pe_info = data.get("pe_info", {})
    if pe_info:
        lines.append("\nPE Information:")
        for k, v in pe_info.items():
            lines.append(f"  {k}: {v}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def find_functions_by_pattern(pattern: str, offset: int = 0, limit: int = 100) -> str:
    """
    Search for functions matching a regex pattern in their name.
    Useful for finding related functions (e.g., all 'Crypt*' or '*Handler*' functions).
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("searchFunctionsRegex", {"pattern": pattern, "offset": offset, "limit": limit}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    matches = data.get("matches", [])
    if not matches:
        return file_line + f"No functions found matching pattern '{pattern}'"
    
    lines = [f"Functions matching '{pattern}' ({len(matches)} found):"]
    for m in matches:
        lines.append(f"  {m.get('address', '?'):12} {m.get('name', '?')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_import_by_name(name: str) -> str:
    """
    Get detailed information about a specific imported function including
    all cross-references to it. Essential for tracking Windows API usage.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("importByName", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Import: {data.get('name', name)}"]
    lines.append(f"  Address: {data.get('address', '?')}")
    lines.append(f"  Module: {data.get('module', '?')}")
    
    xrefs = data.get("xrefs", [])
    if xrefs:
        lines.append(f"\nCross-references ({len(xrefs)}):")
        for x in xrefs:
            lines.append(f"  {x.get('address', '?'):12} in {x.get('function', '?')}")
    else:
        lines.append("\nNo cross-references found")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_constants_in_function(name: str) -> str:
    """
    Get all constant values used in a function (immediate values, addresses, etc.).
    Useful for identifying magic numbers, flags, sizes, and hardcoded values.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("functionConstants", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    constants = data.get("constants", [])
    if not constants:
        return file_line + f"No constants found in function '{name}'"
    
    lines = [f"Constants in {data.get('function', name)} ({len(constants)} found):"]
    for c in constants:
        val = c.get('value', 0)
        # Show both hex and decimal for clarity
        if isinstance(val, int):
            val_str = f"{val:#x} ({val})"
        else:
            val_str = str(val)
        lines.append(f"  {c.get('address', '?'):12} {val_str:24} {c.get('context', '')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_high_level_overview(name: str) -> str:
    """
    Get a high-level summary of a function including calls made, strings used,
    and key characteristics. Great for quickly understanding what a function does.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("functionOverview", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Overview of {data.get('name', name)}:"]
    lines.append(f"  Address: {data.get('address', '?')}")
    lines.append(f"  Size: {data.get('size', '?')} bytes")
    lines.append(f"  Basic blocks: {data.get('block_count', '?')}")
    lines.append(f"  Cyclomatic complexity: {data.get('complexity', '?')}")
    
    # Calls
    calls = data.get("calls", [])
    if calls:
        lines.append(f"\nFunctions called ({len(calls)}):")
        for c in calls[:20]:  # Limit display
            lines.append(f"    {c}")
        if len(calls) > 20:
            lines.append(f"    ... and {len(calls) - 20} more")
    
    # Strings used
    strings = data.get("strings_used", [])
    if strings:
        lines.append(f"\nStrings used ({len(strings)}):")
        for s in strings[:10]:  # Limit display
            lines.append(f"    \"{s[:60]}{'...' if len(s) > 60 else ''}\"")
        if len(strings) > 10:
            lines.append(f"    ... and {len(strings) - 10} more")
    
    # API calls (imports)
    apis = data.get("api_calls", [])
    if apis:
        lines.append(f"\nAPI/Import calls ({len(apis)}):")
        for a in apis:
            lines.append(f"    {a}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_possible_values(function_name: str, address: str, variable: str) -> str:
    """
    Get possible values for a variable at a specific address using dataflow analysis.
    Useful for understanding what values a variable can hold at a point in code.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("possibleValues", {
        "function": function_name,
        "address": address,
        "variable": variable
    }, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Possible values for '{variable}' at {address} in {function_name}:"]
    
    value_type = data.get("value_type", "unknown")
    lines.append(f"  Type: {value_type}")
    
    if "value" in data:
        lines.append(f"  Value: {data['value']}")
    if "range" in data:
        r = data["range"]
        lines.append(f"  Range: [{r.get('min', '?')}, {r.get('max', '?')}]")
    if "possible_values" in data:
        pv = data["possible_values"]
        lines.append(f"  Possible values: {pv}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def analyze_switch_statement(function_name: str, address: str) -> str:
    """
    Analyze a switch/jump table at a specific address.
    Useful for understanding complex control flow with multiple cases.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("analyzeSwitch", {
        "function": function_name,
        "address": address
    }, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Switch analysis at {address}:"]
    
    cases = data.get("cases", [])
    if cases:
        lines.append(f"\nCases ({len(cases)}):")
        for c in cases:
            lines.append(f"  case {c.get('value', '?')}: -> {c.get('target', '?')}")
    
    default = data.get("default")
    if default:
        lines.append(f"  default: -> {default}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def trace_data_flow(function_name: str, from_address: str, variable: str) -> str:
    """
    Trace the data flow of a variable from a specific point.
    Shows where the value comes from and where it flows to.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("traceDataFlow", {
        "function": function_name,
        "address": from_address,
        "variable": variable
    }, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Data flow trace for '{variable}' from {from_address}:"]
    
    definitions = data.get("definitions", [])
    if definitions:
        lines.append("\nDefined at:")
        for d in definitions:
            lines.append(f"  {d.get('address', '?')}: {d.get('instruction', '?')}")
    
    uses = data.get("uses", [])
    if uses:
        lines.append("\nUsed at:")
        for u in uses:
            lines.append(f"  {u.get('address', '?')}: {u.get('instruction', '?')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def find_interesting_functions() -> str:
    """
    Find potentially interesting functions based on heuristics:
    - Functions with 'crypt', 'password', 'key', 'auth', 'license' in name
    - Functions that call crypto APIs
    - Functions with high complexity
    - Entry points and exports
    Great starting point for security analysis.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("interestingFunctions", timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = ["Interesting Functions Found:"]
    
    categories = [
        ("crypto_related", "Crypto-related functions"),
        ("auth_related", "Authentication-related"),
        ("network_related", "Network-related"),
        ("file_related", "File operations"),
        ("registry_related", "Registry operations"),
        ("high_complexity", "High complexity functions"),
        ("exports", "Exported functions"),
    ]
    
    for key, label in categories:
        funcs = data.get(key, [])
        if funcs:
            lines.append(f"\n{label} ({len(funcs)}):")
            for f in funcs[:15]:
                if isinstance(f, dict):
                    lines.append(f"  {f.get('address', '?'):12} {f.get('name', '?')}")
                else:
                    lines.append(f"  {f}")
            if len(funcs) > 15:
                lines.append(f"  ... and {len(funcs) - 15} more")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def get_call_graph(name: str, depth: int = 2, direction: str = "both") -> str:
    """
    Get the call graph centered on a function.
    - depth: How many levels of calls to include (default 2)
    - direction: 'callers', 'callees', or 'both'
    Useful for understanding function relationships.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("callGraph", {
        "name": name,
        "depth": depth,
        "direction": direction
    }, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Call graph for {name} (depth={depth}, direction={direction}):"]
    
    def format_tree(node, indent=0):
        result = []
        prefix = "  " * indent + ("└─ " if indent > 0 else "")
        result.append(f"{prefix}{node.get('name', '?')} ({node.get('address', '?')})")
        for child in node.get("children", []):
            result.extend(format_tree(child, indent + 1))
        return result
    
    if "callers" in data and data["callers"]:
        lines.append("\nCallers (who calls this):")
        for c in data["callers"]:
            lines.extend(format_tree(c, 1))
    
    if "center" in data:
        lines.append(f"\n→ {data['center'].get('name', name)} ←")
    
    if "callees" in data and data["callees"]:
        lines.append("\nCallees (what this calls):")
        for c in data["callees"]:
            lines.extend(format_tree(c, 1))
    
    return file_line + "\n".join(lines)


@mcp.tool()
def tag_function(name: str, tag_type: str, comment: str = "") -> str:
    """
    Add a tag/bookmark to a function for later reference.
    tag_type examples: 'interesting', 'vulnerable', 'needs-review', 'crypto', 'auth'
    """
    data = get_json("tagFunction", {
        "name": name,
        "tag_type": tag_type,
        "comment": comment
    })
    if not data:
        return "Error: no response"
    if "error" in data:
        return f"Error: {data.get('error')}"
    return f"Tagged function '{name}' with '{tag_type}'"


@mcp.tool()
def list_tags(tag_type: str = "") -> str:
    """
    List all tagged functions, optionally filtered by tag type.
    """
    file_line = f"File: {_active_filename()}\n\n"
    params = {"tag_type": tag_type} if tag_type else {}
    data = get_json("listTags", params)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    tags = data.get("tags", [])
    if not tags:
        return file_line + "No tags found"
    
    lines = ["Tagged items:"]
    for t in tags:
        lines.append(f"  [{t.get('tag_type', '?')}] {t.get('address', '?')} {t.get('name', '?')}")
        if t.get('comment'):
            lines.append(f"      Comment: {t.get('comment')}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def compare_functions(func1: str, func2: str) -> str:
    """
    Compare two functions and show similarities/differences.
    Useful for identifying code reuse, variations, or copied code.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("compareFunctions", {"func1": func1, "func2": func2}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    lines = [f"Comparison: {func1} vs {func2}"]
    lines.append(f"\nSimilarity: {data.get('similarity', '?')}%")
    
    lines.append(f"\n{'Metric':<25} {func1:<20} {func2:<20}")
    lines.append("-" * 65)
    
    for metric in ["size", "block_count", "instruction_count", "callee_count", "complexity"]:
        v1 = data.get(f"{metric}_1", "?")
        v2 = data.get(f"{metric}_2", "?")
        lines.append(f"{metric:<25} {str(v1):<20} {str(v2):<20}")
    
    common_calls = data.get("common_calls", [])
    if common_calls:
        lines.append(f"\nCommon function calls ({len(common_calls)}):")
        for c in common_calls[:10]:
            lines.append(f"  {c}")
    
    return file_line + "\n".join(lines)


@mcp.tool()
def find_crypto_constants() -> str:
    """
    Search for known cryptographic constants in the binary.
    Identifies potential use of AES, DES, MD5, SHA, RSA, and other crypto algorithms.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("findCryptoConstants", timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    
    findings = data.get("findings", [])
    if not findings:
        return file_line + "No known cryptographic constants found"
    
    lines = [f"Cryptographic constants found ({len(findings)}):"]
    for f in findings:
        lines.append(f"  {f.get('address', '?'):12} {f.get('algorithm', '?'):15} {f.get('description', '')}")
        if f.get('function'):
            lines.append(f"      In function: {f.get('function')}")
    
    return file_line + "\n".join(lines)


if __name__ == "__main__":
    # Important: write any logs to stderr to avoid corrupting MCP stdio JSON-RPC
    print("Starting MCP bridge service...", file=_sys.stderr)
    try:
        mcp.run()
    except Exception as _e:
        # Ensure any runtime exception is captured in the log file
        _bridge_excepthook(type(_e), _e, _e.__traceback__)
        raise
