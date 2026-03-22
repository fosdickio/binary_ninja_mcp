/**
 * MCP Tool definitions for Binary Ninja integration.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BinjaHttpClient } from "./client.js";

export function registerTools(server: McpServer, client: BinjaHttpClient): void {
  // Helper function to get active filename
  async function getActiveFilename(): Promise<string> {
    const data = await client.getJson<{ filename?: string }>("status");
    if (data && typeof data === "object" && "filename" in data) {
      return (data as { filename: string }).filename || "(none)";
    }
    return "(none)";
  }

  // ===== Function Analysis Tools =====

  server.tool(
    "list_methods",
    "List all function names in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const filename = await getActiveFilename();
      const lines = await client.getLines("methods", { offset, limit });
      return {
        content: [{ type: "text", text: `File: ${filename}\n${lines.join("\n")}` }],
      };
    }
  );

  server.tool(
    "get_entry_points",
    "List entry point(s) of the loaded binary.",
    {},
    async () => {
      const data = await client.getJson<{ entry_points?: Array<{ address: string; name?: string }> }>("entryPoints");
      if (!data || "error" in data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      const entryPoints = (data as { entry_points?: Array<{ address: string; name?: string }> }).entry_points || [];
      const lines = entryPoints.map((ep) => {
        const addr = ep.address;
        const name = ep.name || "(unknown)";
        return `${addr}\t${name}`;
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "search_functions_by_name",
    "Search for functions whose name contains the given substring.",
    {
      query: z.string().describe("Search query string"),
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ query, offset = 0, limit = 100 }) => {
      if (!query) {
        return { content: [{ type: "text", text: "Error: query string is required" }] };
      }
      const lines = await client.getLines("searchFunctions", { query, offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "decompile_function",
    "Decompile a specific function by name and return the decompiled C code.",
    {
      name: z.string().describe("Function name or address"),
    },
    async ({ name }) => {
      const filename = await getActiveFilename();
      const data = await client.getJson<{ decompiled?: string; error?: string }>("decompile", { name });
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${data.error}` }] };
      }
      const decompiled = (data as { decompiled?: string }).decompiled;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${decompiled || ""}` }] };
    }
  );

  server.tool(
    "get_il",
    "Get IL for a function in the selected view (hlil, mlil, llil).",
    {
      name_or_address: z.string().describe("Function name or address (hex like 0x401000)"),
      view: z.enum(["hlil", "mlil", "llil"]).default("hlil").describe("IL view: hlil, mlil, or llil"),
      ssa: z.boolean().default(false).describe("Request SSA form (MLIL/LLIL only)"),
    },
    async ({ name_or_address, view = "hlil", ssa = false }) => {
      const filename = await getActiveFilename();
      const ident = name_or_address.trim();
      const params: Record<string, string | number> = { view, ssa: ssa ? 1 : 0 };
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.name = ident;
      }
      const data = await client.getJson<{ il?: string; error?: unknown }>("il", params);
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${JSON.stringify(data.error)}` }] };
      }
      const il = (data as { il?: string }).il;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${il || ""}` }] };
    }
  );

  server.tool(
    "fetch_disassembly",
    "Retrieve the disassembled code of a function as assembly mnemonic instructions.",
    {
      name: z.string().describe("Function name"),
    },
    async ({ name }) => {
      const filename = await getActiveFilename();
      const data = await client.getJson<{ assembly?: string; error?: string }>("assembly", { name });
      if (!data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: no response` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `File: ${filename}\n\nError: ${(data as { error: string }).error}` }] };
      }
      const assembly = (data as { assembly?: string }).assembly;
      return { content: [{ type: "text", text: `File: ${filename}\n\n${assembly || ""}` }] };
    }
  );

  // ===== Rename Tools =====

  server.tool(
    "rename_function",
    "Rename a function by its current name. The configured prefix will be automatically prepended if not present.",
    {
      old_name: z.string().describe("Current function name"),
      new_name: z.string().describe("New function name"),
    },
    async ({ old_name, new_name }) => {
      const result = await client.post("renameFunction", { oldName: old_name, newName: new_name });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "rename_single_variable",
    "Rename a variable in a function.",
    {
      function_name: z.string().describe("Function name"),
      variable_name: z.string().describe("Current variable name"),
      new_name: z.string().describe("New variable name"),
    },
    async ({ function_name, variable_name, new_name }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("renameVariable", {
        functionName: function_name,
        variableName: variable_name,
        newName: new_name,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: (data as { status: string }).status }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "rename_multi_variables",
    "Rename multiple local variables in one call.",
    {
      function_identifier: z.string().describe("Function name or address (hex)"),
      mapping_json: z.string().optional().describe("JSON object old->new"),
      pairs: z.string().optional().describe("Comma-separated old:new pairs"),
      renames_json: z.string().optional().describe("JSON array of {old,new} objects"),
    },
    async ({ function_identifier, mapping_json, pairs, renames_json }) => {
      const ident = function_identifier.trim();
      const params: Record<string, string> = {};
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.functionName = ident;
      }

      if (renames_json) {
        try {
          JSON.parse(renames_json);
          params.renames = renames_json;
        } catch {
          return { content: [{ type: "text", text: "Error: renames_json is not valid JSON" }] };
        }
      } else if (mapping_json) {
        try {
          JSON.parse(mapping_json);
          params.mapping = mapping_json;
        } catch {
          return { content: [{ type: "text", text: "Error: mapping_json is not valid JSON" }] };
        }
      } else if (pairs) {
        params.pairs = pairs;
      } else {
        return { content: [{ type: "text", text: "Error: provide mapping_json, renames_json, or pairs" }] };
      }

      const data = await client.getJson<{ error?: string; total?: number; renamed?: number }>("renameVariables", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      const total = (data as { total?: number }).total;
      const renamed = (data as { renamed?: number }).renamed;
      return { content: [{ type: "text", text: `Batch rename: ${renamed}/${total} applied` }] };
    }
  );

  server.tool(
    "rename_data",
    "Rename a data label at the specified address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      new_name: z.string().describe("New name for the data label"),
    },
    async ({ address, new_name }) => {
      const result = await client.post("renameData", { address, newName: new_name });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // ===== Comment Tools =====

  server.tool(
    "set_comment",
    "Set a comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      comment: z.string().describe("Comment text"),
    },
    async ({ address, comment }) => {
      const result = await client.post("comment", { address, comment });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "get_comment",
    "Get the comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("comment", { address });
      return { content: [{ type: "text", text: lines[0] ?? "" }] };
    }
  );

  server.tool(
    "delete_comment",
    "Delete the comment at a specific address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
    },
    async ({ address }) => {
      const result = await client.post("comment", { address, _method: "DELETE" });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "set_function_comment",
    "Set a comment for a function.",
    {
      function_name: z.string().describe("Function name"),
      comment: z.string().describe("Comment text"),
    },
    async ({ function_name, comment }) => {
      const result = await client.post("comment/function", { name: function_name, comment });
      return { content: [{ type: "text", text: result }] };
    }
  );

  server.tool(
    "get_function_comment",
    "Get the comment for a function.",
    {
      function_name: z.string().describe("Function name"),
    },
    async ({ function_name }) => {
      const lines = await client.getLines("comment/function", { name: function_name });
      return { content: [{ type: "text", text: lines[0] || "" }] };
    }
  );

  server.tool(
    "delete_function_comment",
    "Delete the comment for a function.",
    {
      function_name: z.string().describe("Function name"),
    },
    async ({ function_name }) => {
      const result = await client.post("comment/function", { name: function_name, _method: "DELETE" });
      return { content: [{ type: "text", text: result }] };
    }
  );

  // ===== Type Tools =====

  server.tool(
    "define_types",
    "Define types from a C code string.",
    {
      c_code: z.string().describe("C code containing type definitions"),
    },
    async ({ c_code }) => {
      const data = await client.getJson<{ error?: string } | unknown[]>("defineTypes", { cCode: c_code });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if (Array.isArray(data)) {
        return { content: [{ type: "text", text: `Defined types: ${data.join(", ")}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "list_local_types",
    "List all local types in the database (paginated).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(200).describe("Number of results to return"),
      include_libraries: z.boolean().default(false).describe("Include library types"),
    },
    async ({ offset = 0, count = 200, include_libraries = false }) => {
      const lines = await client.getLines("localTypes", {
        offset,
        limit: count,
        includeLibraries: include_libraries ? 1 : 0,
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "search_types",
    "Search local types whose name or declaration contains the substring.",
    {
      query: z.string().describe("Search query"),
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(200).describe("Number of results to return"),
      include_libraries: z.boolean().default(false).describe("Include library types"),
    },
    async ({ query, offset = 0, count = 200, include_libraries = false }) => {
      const lines = await client.getLines("searchTypes", {
        query,
        offset,
        limit: count,
        includeLibraries: include_libraries ? 1 : 0,
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_user_defined_type",
    "Retrieve definition of a user defined type (struct, enumeration, typedef, union).",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const lines = await client.getLines("getUserDefinedType", { name: type_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_type_info",
    "Resolve a type name and return its declaration and details (kind, members, enum values).",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const data = await client.getJson<Record<string, unknown>>("getTypeInfo", { name: type_name });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${String(data.error)}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    "declare_c_type",
    "Create or update a local type from a C declaration.",
    {
      c_declaration: z.string().describe("C type declaration"),
    },
    async ({ c_declaration }) => {
      const data = await client.getJson<{ error?: string; defined_types?: Record<string, unknown>; count?: number }>("declareCType", { declaration: c_declaration });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      if ((data as { defined_types?: Record<string, unknown> }).defined_types) {
        const names = Object.keys((data as { defined_types: Record<string, unknown> }).defined_types).join(", ");
        const count = (data as { count?: number }).count || 0;
        return { content: [{ type: "text", text: `Declared types (${count}): ${names}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "retype_variable",
    "Retype a variable in a function.",
    {
      function_name: z.string().describe("Function name"),
      variable_name: z.string().describe("Variable name"),
      type_str: z.string().describe("New type for the variable"),
    },
    async ({ function_name, variable_name, type_str }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("retypeVariable", {
        functionName: function_name,
        variableName: variable_name,
        type: type_str,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: (data as { status: string }).status }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "set_local_variable_type",
    "Set a local variable's type.",
    {
      function_address: z.string().describe("Function address or name"),
      variable_name: z.string().describe("Variable name"),
      new_type: z.string().describe("New type"),
    },
    async ({ function_address, variable_name, new_type }) => {
      const data = await client.getJson<{ status?: string; error?: string }>("setLocalVariableType", {
        functionAddress: function_address,
        variableName: variable_name,
        newType: new_type,
      });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ((data as { status?: string }).status === "ok") {
        const d = data as { variable?: string; function?: string; applied_type?: string };
        return { content: [{ type: "text", text: `Retyped ${d.variable} in ${d.function} to ${d.applied_type}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // ===== Data Tools =====

  server.tool(
    "list_data_items",
    "List defined data labels and their values with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("data", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "hexdump_address",
    "Hexdump data starting at an address.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      length: z.number().default(-1).describe("Number of bytes (use -1 for defined size)"),
    },
    async ({ address, length = -1 }) => {
      const params: Record<string, string | number> = { address };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const text = await client.getText("hexdump", params);
      return { content: [{ type: "text", text }] };
    }
  );

  server.tool(
    "hexdump_data",
    "Hexdump a data symbol by name or address.",
    {
      name_or_address: z.string().describe("Symbol name or address (hex)"),
      length: z.number().default(-1).describe("Number of bytes (use -1 for defined size)"),
    },
    async ({ name_or_address, length = -1 }) => {
      const ident = name_or_address.trim();
      if (ident.startsWith("0x")) {
        const params: Record<string, string | number> = { address: ident };
        if (length !== undefined && length !== -1) {
          params.length = length;
        }
        const text = await client.getText("hexdump", params);
        return { content: [{ type: "text", text }] };
      }
      const params: Record<string, string | number> = { name: ident };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const text = await client.getText("hexdumpByName", params);
      return { content: [{ type: "text", text }] };
    }
  );

  server.tool(
    "get_data_decl",
    "Return a declaration-like string and hexdump for a data symbol.",
    {
      name_or_address: z.string().describe("Symbol name or address (hex)"),
      length: z.number().default(-1).describe("Number of bytes"),
    },
    async ({ name_or_address, length = -1 }) => {
      const ident = name_or_address.trim();
      const params: Record<string, string | number> = ident.startsWith("0x")
        ? { address: ident }
        : { name: ident };
      if (length !== undefined && length !== -1) {
        params.length = length;
      }
      const data = await client.getJson<{
        error?: string;
        decl?: string;
        hexdump?: string;
        address?: string;
        name?: string;
      }>("getDataDecl", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      const decl = (data as { decl?: string }).decl || "(no declaration)";
      const hexdump = (data as { hexdump?: string }).hexdump || "";
      const addr = (data as { address?: string }).address || "";
      const name = (data as { name?: string }).name || ident;
      return {
        content: [{ type: "text", text: `Declaration (${addr} ${name}):\n${decl}\n\nHexdump:\n${hexdump}` }],
      };
    }
  );

  // ===== Cross-Reference Tools =====

  server.tool(
    "get_xrefs_to",
    "Get all cross references (code and data) to the given address.",
    {
      address: z.string().describe("Address (hex or decimal)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("getXrefsTo", { address });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_field",
    "Get all cross references to a named struct field (member).",
    {
      struct_name: z.string().describe("Struct name"),
      field_name: z.string().describe("Field name"),
    },
    async ({ struct_name, field_name }) => {
      const lines = await client.getLines("getXrefsToField", { struct: struct_name, field: field_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_struct",
    "Get cross references/usages related to a struct name.",
    {
      struct_name: z.string().describe("Struct name"),
    },
    async ({ struct_name }) => {
      const lines = await client.getLines("getXrefsToStruct", { name: struct_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_type",
    "Get xrefs/usages related to a struct or type name.",
    {
      type_name: z.string().describe("Type name"),
    },
    async ({ type_name }) => {
      const lines = await client.getLines("getXrefsToType", { name: type_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_enum",
    "Get usages/xrefs of an enum by scanning for member values and matches.",
    {
      enum_name: z.string().describe("Enum name"),
    },
    async ({ enum_name }) => {
      const lines = await client.getLines("getXrefsToEnum", { name: enum_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_xrefs_to_union",
    "Get cross references/usages related to a union type by name.",
    {
      union_name: z.string().describe("Union name"),
    },
    async ({ union_name }) => {
      const lines = await client.getLines("getXrefsToUnion", { name: union_name });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  // ===== Utility Tools =====

  server.tool(
    "function_at",
    "Retrieve the name of the function the address belongs to.",
    {
      address: z.string().describe("Address (hex format 0x00001)"),
    },
    async ({ address }) => {
      const lines = await client.getLines("functionAt", { address });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "get_stack_frame_vars",
    "Get stack frame variable information for a function (names, offsets, sizes, types).",
    {
      function_identifier: z.string().describe("Function name or address (hex)"),
    },
    async ({ function_identifier }) => {
      const ident = function_identifier.trim();
      const params: Record<string, string> = ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)
        ? { address: ident }
        : { name: ident };
      const data = await client.getJson<{ error?: string; stack_frame_vars?: string[] }>("getStackFrameVars", params);
      if (!data) {
        return { content: [{ type: "text", text: "" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: "" }] };
      }
      const vars = (data as { stack_frame_vars?: string[] }).stack_frame_vars;
      return { content: [{ type: "text", text: (vars || []).join("\n") }] };
    }
  );

  server.tool(
    "list_classes",
    "List all namespace/class names in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("classes", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_namespaces",
    "List all non-global namespaces in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("namespaces", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_segments",
    "List all memory segments in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("segments", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_sections",
    "List sections in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const data = await client.getJson<{ error?: string; sections?: Array<Record<string, unknown>> }>("sections", { offset, limit });
      if (!data || "error" in data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      const filename = await getActiveFilename();
      const sections = (data as { sections?: Array<Record<string, unknown>> }).sections || [];
      const lines = [`File: ${filename}`];
      for (const s of sections) {
        const start = (s as { start?: string }).start || "";
        const end = (s as { end?: string }).end || "";
        const size = (s as { size?: number }).size;
        const name = (s as { name?: string }).name || "(unnamed)";
        const sem = ((s as { semantics?: string }).semantics || (s as { type?: string }).type) || "";
        const tail = sem ? `\t${sem}` : "";
        lines.push(`${start}-${end}\t${size}\t${name}${tail}`);
      }
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_imports",
    "List imported symbols in the program with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("imports", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_exports",
    "List exported functions/symbols with pagination.",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      limit: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, limit = 100 }) => {
      const lines = await client.getLines("exports", { offset, limit });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_strings",
    "List all strings in the database (paginated).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(100).describe("Number of results to return"),
    },
    async ({ offset = 0, count = 100 }) => {
      const lines = await client.getLines("strings", { offset, limit: count });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_strings_filter",
    "List matching strings in the database (paginated, filtered).",
    {
      offset: z.number().default(0).describe("Offset for pagination"),
      count: z.number().default(100).describe("Number of results to return"),
      filter: z.string().optional().describe("Filter string"),
    },
    async ({ offset = 0, count = 100, filter = "" }) => {
      const lines = await client.getLines("strings/filter", { offset, limit: count, filter });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_all_strings",
    "List all strings in the database (aggregated across pages).",
    {
      batch_size: z.number().default(500).describe("Batch size for aggregation"),
    },
    async ({ batch_size = 500 }) => {
      const results: string[] = [];
      let offset = 0;
      while (true) {
        const data = await client.getJson<Record<string, unknown>>("strings", { offset, limit: batch_size });
        if (!data || !("strings" in data)) {
          break;
        }
        const stringsData = data.strings as Array<{ address?: string; length?: number; type?: string; value?: string }>;
        const items = Array.isArray(stringsData) ? stringsData : [];
        if (!items.length) {
          break;
        }
        for (const s of items) {
          const addr = s.address || "";
          const length = s.length;
          const stype = s.type || "";
          const value = s.value || "";
          results.push(`${addr}\t${length}\t${stype}\t${value}`);
        }
        if (items.length < batch_size) {
          break;
        }
        offset += batch_size;
      }
      return { content: [{ type: "text", text: results.join("\n") }] };
    }
  );

  server.tool(
    "get_binary_status",
    "Get the current status of the loaded binary.",
    {},
    async () => {
      const lines = await client.getLines("status");
      return { content: [{ type: "text", text: lines[0] || "" }] };
    }
  );

  server.tool(
    "list_binaries",
    "List managed/open binaries known to the server with ids and active flag.",
    {},
    async () => {
      const data = await client.getJson<{ error?: string; binaries?: Array<Record<string, unknown>> }>("binaries");
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: (data as { error: string }).error }] };
      }
      const binaries = (data as { binaries?: Array<Record<string, unknown>> }).binaries || [];
      const lines = binaries.map((it) => {
        const vid = (it as { id?: number }).id;
        const view_id = (it as { view_id?: number }).view_id;
        const fn = (it as { filename?: string }).filename;
        const basename = (it as { basename?: string }).basename || "";
        const selectors = (it as { selectors?: number[] }).selectors || [];
        const active = (it as { active?: boolean }).active;
        const label = basename || fn || "(unknown)";
        const full = fn || "(no filename)";
        const selectorText = selectors.map(String).join(", ");
        const mark = active ? " *active*" : "";
        const viewPart = view_id ? ` view=${view_id}` : "";
        return `${vid}. ${label}${viewPart}${mark}\n    path: ${full}\n    selectors: ${selectorText}`;
      });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "select_binary",
    "Select which binary to analyze by ordinal, internal view id, full path, or basename.",
    {
      view: z.string().describe("Ordinal, view id, full path, or basename"),
    },
    async ({ view }) => {
      const data = await client.getJson<{ error?: string; selected?: Record<string, unknown> }>("selectBinary", { view });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      const sel = (data as { selected?: Record<string, unknown> }).selected;
      if (sel) {
        const ordinal = (sel as { id?: number }).id || "?";
        const view_id = (sel as { view_id?: number }).view_id;
        const fn = (sel as { filename?: string }).filename || "";
        const basename = (sel as { basename?: string }).basename || "";
        const selectors = (sel as { selectors?: number[] }).selectors || [];
        const selectorText = selectors.map(String).join(", ");
        const displayName = basename || fn || "(unknown)";
        const viewPart = view_id ? ` (view ${view_id})` : "";
        const pathPart = fn ? `\nFull path: ${fn}` : "";
        return { content: [{ type: "text", text: `Selected ${ordinal}: ${displayName}${viewPart}${pathPart}\nSelectors: ${selectorText}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // ===== Binary Modification Tools =====

  server.tool(
    "set_function_prototype",
    "Set a function's prototype by name or address.",
    {
      name_or_address: z.string().describe("Function name or address"),
      prototype: z.string().describe("New function prototype"),
    },
    async ({ name_or_address, prototype }) => {
      const ident = name_or_address.trim();
      const params: Record<string, string> = { prototype };
      if (ident.toLowerCase().startsWith("0x") || /^\d+$/.test(ident)) {
        params.address = ident;
      } else {
        params.name = ident;
      }
      const data = await client.getJson<{ status?: string; error?: string; address?: string; applied_type?: string }>("setFunctionPrototype", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("status" in data) {
        return { content: [{ type: "text", text: `Applied prototype at ${(data as { address?: string }).address}: ${(data as { applied_type?: string }).applied_type}` }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${(data as { error: string }).error}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "make_function_at",
    "Create a function at the given address.",
    {
      address: z.string().describe("Address (hex like 0x401000 or decimal)"),
      platform: z.string().optional().describe("Platform (e.g., linux-x86_64)"),
    },
    async ({ address, platform }) => {
      const params: Record<string, string> = { address };
      if (platform) {
        params.platform = platform;
      }
      const data = await client.getJson<{ error?: string; status?: string; address?: string; name?: string }>("makeFunctionAt", params);
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      if ((data as { status?: string }).status === "exists") {
        return { content: [{ type: "text", text: `Function already exists at ${(data as { address?: string }).address}: ${(data as { name?: string }).name}` }] };
      }
      if ((data as { status?: string }).status === "ok") {
        return { content: [{ type: "text", text: `Created function at ${(data as { address?: string }).address}: ${(data as { name?: string }).name}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  server.tool(
    "list_platforms",
    "List all available platform names from Binary Ninja.",
    {},
    async () => {
      const data = await client.getJson<{ error?: string; platforms?: string[] }>("platforms");
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }
      const plats = (data as { platforms?: string[] }).platforms;
      if (!plats) {
        return { content: [{ type: "text", text: "(no platforms)" }] };
      }
      return { content: [{ type: "text", text: plats.join("\n") }] };
    }
  );

  server.tool(
    "patch_bytes",
    "Patch bytes at a given address in the binary.",
    {
      address: z.string().describe("Address (hex like 0x401000 or decimal)"),
      data: z.string().describe("Hex string of bytes to write (e.g., '90 90' or '9090')"),
      save_to_file: z.boolean().default(true).describe("Save patched binary to disk"),
    },
    async ({ address, data, save_to_file = true }) => {
      const result = await client.getJson<{
        error?: string;
        status?: string;
        original_bytes?: string;
        patched_bytes?: string;
        bytes_written?: number;
        bytes_requested?: number;
        saved_to_file?: boolean;
        saved_path?: string;
        warning?: string;
      }>("patch", { address, data, save_to_file: save_to_file ? 1 : 0 });
      if (!result) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in result) {
        return { content: [{ type: "text", text: `Error: ${(result as { error: string }).error}` }] };
      }
      const status = (result as { status?: string }).status;
      if (status === "ok" || status === "partial") {
        const orig = (result as { original_bytes?: string }).original_bytes || "";
        const patched = (result as { patched_bytes?: string }).patched_bytes || "";
        const written = (result as { bytes_written?: number }).bytes_written || 0;
        const requested = (result as { bytes_requested?: number }).bytes_requested || 0;
        const saved = (result as { saved_to_file?: boolean }).saved_to_file || false;
        const savedPath = (result as { saved_path?: string }).saved_path || "";
        const warning = (result as { warning?: string }).warning || "";

        let msg = `Patched ${written}/${requested} bytes at ${address}`;
        if (status === "partial") {
          msg += " (PARTIAL WRITE)";
        }
        if (warning) {
          msg += `\nWarning: ${warning}`;
        }
        if (orig) {
          msg += `\nOriginal: ${orig}`;
        }
        if (patched) {
          msg += `\nPatched:  ${patched}`;
        }
        if (saved) {
          msg += `\nSaved to file: ${savedPath}`;
        }
        return { content: [{ type: "text", text: msg }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "format_value",
    "Convert and annotate a value at an address in Binary Ninja.",
    {
      address: z.string().describe("Address (hex like 0x401000)"),
      text: z.string().describe("Text to convert"),
      size: z.number().default(0).describe("Size in bytes"),
    },
    async ({ address, text, size = 0 }) => {
      const lines = await client.getLines("formatValue", { address, text, size });
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "convert_number",
    "Convert a number or string to multiple representations (hex/dec/bin, C literals).",
    {
      text: z.string().describe("Number or string to convert (decimal, hex 0x7b, binary 0b1111011, char 'A', or string)"),
      size: z.number().default(0).describe("Size in bytes (0 for auto)"),
    },
    async ({ text, size = 0 }) => {
      const data = await client.getJson<Record<string, unknown>>("convertNumber", { text, size });
      if (!data) {
        return { content: [{ type: "text", text: "Error: no response" }] };
      }
      if ("error" in data) {
        return { content: [{ type: "text", text: `Error: ${String(data.error)}` }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );
}
