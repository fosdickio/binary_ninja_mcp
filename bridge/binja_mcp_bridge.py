from mcp.server.fastmcp import FastMCP
import requests


binja_server_url = "http://localhost:9009"
mcp = FastMCP("binja-mcp")


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
    Perform a GET and return parsed JSON. Returns None on error.
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
            return response.json()
        return None
    except Exception:
        return None


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
    return safe_get("methods", {"offset": offset, "limit": limit})

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
def rename_variable(function_name: str, variable_name: str, new_name: str) -> str:
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
def edit_function_signature(function_name: str, signature: str) -> str:
    """
    Edit the signature of a function.
    """
    data = get_json("editFunctionSignature", {"functionName": function_name, "signature": signature})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return data["status"]
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
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
    data = get_json("decompile", {"name": name}, timeout=None)
    if not data:
        return "Error: no response"
    if "decompiled" in data:
        return data["decompiled"]
    if "error" in data:
        return f"Error: {data.get('error')}"
    return str(data)

@mcp.tool()
def fetch_disassembly(name: str) -> str:
    """
    Retrive the disassembled code of a function with a given name as assemby mnemonic instructions.
    """
    data = get_json("assembly", {"name": name}, timeout=None)
    if not data:
        return "Error: no response"
    if "assembly" in data:
        return data["assembly"]
    if "error" in data:
        return f"Error: {data.get('error')}"
    return str(data)

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
def convert_number(text: str, size: int = 0) -> list:
    """
    Convert a number (decimal, hexadecimal, char, or ASCII string) to multiple representations.
    """
    return safe_get("convertNumber", {"text": text, "size": size}, timeout=None)

@mcp.tool()
def format_value(address: str, text: str, size: int = 0) -> list:
    """
    Convert and annotate a value at an address in Binary Ninja.
    Adds a comment with hex/dec and C literal/string so you can see the change.
    """
    return safe_get("formatValue", {"address": address, "text": text, "size": size}, timeout=None)

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

    
if __name__ == "__main__":
    print("Starting MCP bridge service...")
    mcp.run()
