from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from typing import Dict, Any
import binaryninja as bn
import threading
from ..core.binary_operations import BinaryOperations
from ..core.config import Config
from ..api.endpoints import BinaryNinjaEndpoints
from ..utils.string_utils import parse_int_or_default
from ..utils.number_utils import convert_number as util_convert_number


class MCPRequestHandler(BaseHTTPRequestHandler):
    binary_ops = None  # Will be set by the server

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def endpoints(self):
        # Create endpoints on demand to ensure binary_ops is set
        if not hasattr(self, "_endpoints"):
            if not self.binary_ops:
                raise RuntimeError("binary_ops not initialized")
            self._endpoints = BinaryNinjaEndpoints(self.binary_ops)
        return self._endpoints

    def log_message(self, format, *args):
        bn.log_info(format % args)

    def _set_headers(self, content_type="application/json", status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        self._set_headers(status_code=status_code)
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _parse_query_params(self) -> Dict[str, str]:
        parsed_path = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed_path.query))

    def _parse_post_params(self) -> Dict[str, Any]:
        """Parse POST request parameters from various formats.

        Supports:
        - JSON data (application/json)
        - Form data (application/x-www-form-urlencoded)
        - Raw text (text/plain)

        Returns:
            Dictionary containing the parsed parameters
        """
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}

        content_type = self.headers.get("Content-Type", "")
        post_data = self.rfile.read(content_length).decode("utf-8")

        bn.log_info(f"Received POST data: {post_data}")
        bn.log_info(f"Content-Type: {content_type}")

        # Handle JSON data
        if "application/json" in content_type.lower():
            try:
                return json.loads(post_data)
            except json.JSONDecodeError as e:
                bn.log_error(f"Failed to parse JSON: {e}")
                return {"error": "Invalid JSON format"}

        # Handle form data
        if "application/x-www-form-urlencoded" in content_type.lower():
            try:
                return dict(urllib.parse.parse_qsl(post_data))
            except Exception as e:
                bn.log_error(f"Failed to parse form data: {e}")
                return {"error": "Invalid form data format"}

        # Handle raw text
        if "text/plain" in content_type.lower() or not content_type:
            return {"name": post_data.strip()}

        # Try all formats as fallback
        try:
            return json.loads(post_data)
        except json.JSONDecodeError:
            try:
                parsed = dict(urllib.parse.parse_qsl(post_data))
                if parsed:
                    return parsed
            except (ValueError, TypeError):
                pass

            return {"name": post_data.strip()}

    def _check_binary_loaded(self):
        """Check if a binary is loaded and return appropriate error response if not"""
        if not self.binary_ops or not self.binary_ops.current_view:
            self._send_json_response({"error": "No binary loaded"}, 400)
            return False
        return True

    def do_GET(self):
        try:
            # For all endpoints except /status, check if binary is loaded
            if not self.path.startswith("/status") and not self._check_binary_loaded():
                return

            params = self._parse_query_params()
            path = urllib.parse.urlparse(self.path).path
            offset = parse_int_or_default(params.get("offset"), 0)
            # Support both `limit` and `count` (alias) for pagination
            if params.get("count") is not None:
                limit = parse_int_or_default(params.get("count"), 100)
            else:
                limit = parse_int_or_default(params.get("limit"), 100)

            if path == "/status":
                status = {
                    "loaded": self.binary_ops
                    and self.binary_ops.current_view is not None,
                    "filename": self.binary_ops.current_view.file.filename
                    if self.binary_ops and self.binary_ops.current_view
                    else None,
                }
                self._send_json_response(status)

            elif path == "/functions" or path == "/methods":
                functions = self.binary_ops.get_function_names(offset, limit)
                bn.log_info(f"Found {len(functions)} functions")
                self._send_json_response({"functions": functions})

            elif path == "/classes":
                classes = self.binary_ops.get_class_names(offset, limit)
                self._send_json_response({"classes": classes})

            elif path == "/segments":
                segments = self.binary_ops.get_segments(offset, limit)
                self._send_json_response({"segments": segments})

            elif path == "/imports":
                imports = self.endpoints.get_imports(offset, limit)
                self._send_json_response({"imports": imports})

            elif path == "/exports":
                exports = self.endpoints.get_exports(offset, limit)
                self._send_json_response({"exports": exports})

            elif path == "/namespaces":
                namespaces = self.endpoints.get_namespaces(offset, limit)
                self._send_json_response({"namespaces": namespaces})

            elif path == "/data":
                try:
                    data_items = self.binary_ops.get_defined_data(offset, limit)
                    self._send_json_response({"data": data_items})
                except Exception as e:
                    bn.log_error(f"Error getting data items: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/localTypes":
                try:
                    types = self.binary_ops.list_local_types(offset, limit)
                    bn.log_info(f"/localTypes returned {len(types)} entries (offset={offset}, limit={limit})")
                    self._send_json_response({"types": types})
                except Exception as e:
                    bn.log_error(f"Error listing local types: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/strings":
                try:
                    bn.log_info(f"/strings request: offset={offset}, limit={limit}, raw_params={params}")
                    strings = self.binary_ops.get_strings(offset, limit)
                    self._send_json_response({"strings": strings})
                except Exception as e:
                    bn.log_error(f"Error getting strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/allStrings":
                try:
                    # Return all strings without pagination
                    bn.log_info("/allStrings request received")
                    strings = self.binary_ops.get_strings(0, 2147483647)
                    self._send_json_response({"strings": strings})
                except Exception as e:
                    bn.log_error(f"Error getting all strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/strings/filter":
                try:
                    pattern = params.get("filter", "")
                    bn.log_info(f"/strings/filter request: offset={offset}, limit={limit}, pattern={pattern}")
                    # Get all strings first, then filter and paginate
                    all_strings = self.binary_ops.get_strings(0, 2147483647)
                    if pattern:
                        pl = pattern.lower()
                        filtered = [s for s in all_strings if isinstance(s.get("value"), str) and pl in s.get("value", "").lower()]
                    else:
                        filtered = all_strings
                    page = filtered[offset : offset + limit]
                    self._send_json_response({"strings": page, "total": len(filtered)})
                except Exception as e:
                    bn.log_error(f"Error filtering strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/searchFunctions":
                search_term = params.get("query", "")
                matches = self.endpoints.search_functions(search_term, offset, limit)
                self._send_json_response({"matches": matches})

            elif path == "/decompile":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                self._handle_decompile(function_name)

            elif path == "/assembly":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                try:
                    func_info = self.binary_ops.get_function_info(function_name)
                    if not func_info:
                        bn.log_error(f"Function not found: {function_name}")
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested_name": function_name,
                                "available_functions": self.binary_ops.get_function_names(
                                    0, 10
                                ),
                            },
                            404,
                        )
                        return

                    bn.log_info(f"Found function for assembly: {func_info}")
                    assembly = self.binary_ops.get_assembly_function(function_name)

                    if assembly is None:
                        self._send_json_response(
                            {
                                "error": "Assembly retrieval failed",
                                "function": func_info,
                                "reason": "Function assembly could not be retrieved. Check the Binary Ninja log for detailed error information.",
                            },
                            500,
                        )
                    else:
                        self._send_json_response(
                            {"assembly": assembly, "function": func_info}
                        )
                except Exception as e:
                    bn.log_error(f"Error handling assembly request: {str(e)}")
                    import traceback
                    bn.log_error(traceback.format_exc())
                    self._send_json_response(
                        {
                            "error": "Assembly retrieval failed",
                            "requested_name": function_name,
                            "exception": str(e),
                        },
                        500,
                    )

            elif path == "/functionAt":
                address_str = params.get("address")
                if not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address (in hex format, e.g., 0x41d100) the address of an insruction",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Convert hex string to integer
                    if isinstance(address_str, str) and address_str.startswith("0x"):
                        offset = int(address_str, 16)
                    else:
                        offset = int(address_str)
                        
                    # Add function to binary_operations.py
                    function_names = self.binary_ops.get_functions_containing_address(offset)
                    
                    self._send_json_response(
                        {
                            "address": hex(offset),
                            "functions": function_names
                        }
                    )
                except ValueError:
                    self._send_json_response(
                        {
                            "error": "Invalid address format",
                            "help": "Address must be a valid hexadecimal (0x...) or decimal number",
                            "received": address_str,
                        },
                        400,
                    )
                except Exception as e:
                    bn.log_error(f"Error handling function_at request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "address": address_str,
                        },
                        500,
                    )
                    
            elif path == "/codeReferences":
                function_name = params.get("function")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function parameter",
                            "help": "Required parameter: function (name of the function to find references to)",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Get function information first to confirm it exists
                    func_info = self.binary_ops.get_function_info(function_name)
                    if not func_info:
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested_function": function_name
                            },
                            404,
                        )
                        return
                        
                    # Get all code references to this function
                    code_refs = self.binary_ops.get_function_code_references(function_name)
                    
                    self._send_json_response(
                        {
                            "function": function_name,
                            "code_references": code_refs
                        }
                    )
                except Exception as e:
                    bn.log_error(f"Error handling code_references request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "function": function_name,
                        },
                        500,
                    )
                    
            elif path == "/getUserDefinedType":
                type_name = params.get("name")
                if not type_name:
                    self._send_json_response(
                        {
                            "error": "Missing name parameter",
                            "help": "Required parameter: name (name of the user-defined type to retrieve)",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Get the user-defined type definition
                    type_info = self.binary_ops.get_user_defined_type(type_name)
                    
                    if type_info:
                        self._send_json_response(type_info)
                    else:
                        # If type not found, list available types for reference
                        available_types = {}
                        
                        try:
                            if (hasattr(self.binary_ops._current_view, "user_type_container") and 
                                self.binary_ops._current_view.user_type_container):
                                for type_id in self.binary_ops._current_view.user_type_container.types.keys():
                                    current_type = self.binary_ops._current_view.user_type_container.types[type_id]
                                    available_types[current_type[0]] = str(current_type[1].type) if hasattr(current_type[1], "type") else "unknown"
                        except Exception as e:
                            bn.log_error(f"Error listing available types: {e}")
                            
                        self._send_json_response(
                            {
                                "error": "Type not found",
                                "requested_type": type_name,
                                "available_types": available_types
                            },
                            404,
                        )
                except Exception as e:
                    bn.log_error(f"Error handling getUserDefinedType request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "type_name": type_name,
                        },
                        500,
                    )
                    
            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )
            elif path == "/editFunctionSignature":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                signature = params.get("signature")
                if not signature:
                    self._send_json_response(
                        {"error": "Missing signature parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.edit_function_signature(function_name, signature))
                except Exception as e:
                    bn.log_error(f"Error handling editFunctionSignature request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/retypeVariable":
                function_name =  params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                type_str = params.get("type")
                if not type_str:
                    self._send_json_response(
                        {"error": "Missing type parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.retype_variable(function_name, variable_name, type_str))
                except Exception as e:
                    bn.log_error(f"Error handling retypeVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/renameVariable":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                new_name = params.get("newName")
                if not new_name:
                    self._send_json_response(
                        {"error": "Missing new name parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.rename_variable(function_name, variable_name, new_name))
                except Exception as e:
                    bn.log_error(f"Error handling renameVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
                    
            elif path == "/getXrefsTo":
                address_str = params.get("address")
                if not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address (hex like 0x401000 or decimal)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    result = self.binary_ops.get_xrefs_to_address(address_str)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsTo request: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToField":
                struct_name = params.get("struct") or params.get("structName")
                field_name = params.get("field") or params.get("fieldName")
                if not struct_name or not field_name:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: struct (or structName), field (or fieldName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_field(struct_name, field_name)
                    self._send_json_response({
                        "struct": struct_name,
                        "field": field_name,
                        "references": refs
                    })
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToField: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToStruct":
                struct_name = params.get("name") or params.get("struct") or params.get("structName")
                if not struct_name:
                    self._send_json_response(
                        {
                            "error": "Missing struct name parameter",
                            "help": "Required: name (or struct/structName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_struct(struct_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToStruct: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToType":
                type_name = params.get("name") or params.get("type") or params.get("typeName")
                if not type_name:
                    self._send_json_response(
                        {
                            "error": "Missing type name parameter",
                            "help": "Required: name (or type/typeName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_type(type_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToType: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            

            elif path == "/getXrefsToEnum":
                enum_name = params.get("name") or params.get("enum") or params.get("enumName")
                if not enum_name:
                    self._send_json_response(
                        {
                            "error": "Missing enum name parameter",
                            "help": "Required: name (or enum/enumName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_enum(enum_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToEnum: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/convertNumber":
                text = params.get("text")
                size_param = params.get("size")
                if text is None:
                    self._send_json_response(
                        {"error": "Missing text parameter", "help": "Required: text (number or string)"},
                        400,
                    )
                    return
                try:
                    result = util_convert_number(text, size_param)
                    self._send_json_response(result)
                except Exception as e:
                    bn.log_error(f"Error handling convertNumber: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/formatValue":
                # Compute representations and annotate BN at an address
                text = params.get("text")
                size_param = params.get("size")
                address_str = params.get("address")
                if not text or not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: address, text. Optional: size",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    # Parse address
                    if isinstance(address_str, str) and address_str.startswith("0x"):
                        addr = int(address_str, 16)
                    else:
                        addr = int(address_str)
                except Exception:
                    self._send_json_response({"error": "Invalid address format"}, 400)
                    return

                try:
                    conv = util_convert_number(text, size_param)
                    # Create a concise annotation
                    bases = conv.get("bases", {})
                    c_lit = conv.get("c_literal")
                    c_str = conv.get("c_string")
                    parts = []
                    if "hex" in bases:
                        parts.append(f"hex={bases['hex']}")
                    if "dec" in bases:
                        parts.append(f"dec={bases['dec']}")
                    if c_lit:
                        parts.append(f"char={c_lit}")
                    if c_str:
                        # Trim long strings for comments
                        s = c_str
                        if len(s) > 64:
                            s = s[:61] + '"…'
                        parts.append(f"str={s}")
                    annot = "Converted: " + ", ".join(parts) if parts else f"Converted: {conv}"

                    applied = self.binary_ops.set_comment(addr, annot)
                    self._send_json_response({
                        "address": hex(addr),
                        "converted": conv,
                        "applied_comment": bool(applied),
                        "comment": annot,
                    })
                except Exception as e:
                    bn.log_error(f"Error handling formatValue: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToUnion":
                union_name = params.get("name") or params.get("union") or params.get("unionName")
                if not union_name:
                    self._send_json_response(
                        {
                            "error": "Missing union name parameter",
                            "help": "Required: name (or union/unionName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_union(union_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToUnion: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/defineTypes":
                c_code = params.get("cCode")
                if not c_code:
                    self._send_json_response(
                        {"error": "Missing cCode parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.define_types(c_code))
                except Exception as e:
                    bn.log_error(f"Error handling defineTypes request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            else:
                self._send_json_response({"error": "Not found"}, 404)

        except Exception as e:
            bn.log_error(f"Error handling GET request: {e}")
            self._send_json_response({"error": str(e)}, 500)

    def _handle_decompile(self, function_name: str):
        """Handle function decompilation requests.

        Args:
            function_name: Name or address of the function to decompile

        Sends JSON response with either:
        - Decompiled function code and metadata
        - Error message with available functions list
        """
        try:
            func_info = self.binary_ops.get_function_info(function_name)
            if not func_info:
                bn.log_error(f"Function not found: {function_name}")
                self._send_json_response(
                    {
                        "error": "Function not found",
                        "requested_name": function_name,
                        "available_functions": self.binary_ops.get_function_names(
                            0, 10
                        ),
                    },
                    404,
                )
                return

            bn.log_info(f"Found function for decompilation: {func_info}")
            decompiled = self.binary_ops.decompile_function(function_name)

            if decompiled is None:
                self._send_json_response(
                    {
                        "error": "Decompilation failed",
                        "function": func_info,
                        "reason": "Function could not be decompiled. This might be due to missing debug information or unsupported function type.",
                    },
                    500,
                )
            else:
                self._send_json_response(
                    {"decompiled": decompiled, "function": func_info}
                )
        except Exception as e:
            bn.log_error(f"Error during decompilation: {e}")
            self._send_json_response(
                {
                    "error": f"Decompilation error: {str(e)}",
                    "requested_name": function_name,
                },
                500,
            )

    def do_POST(self):
        try:
            if not self._check_binary_loaded():
                return

            params = self._parse_post_params()
            path = urllib.parse.urlparse(self.path).path

            bn.log_info(f"POST {path} with params: {params}")

            if path == "/load":
                filepath = params.get("filepath")
                if not filepath:
                    self._send_json_response(
                        {"error": "Missing filepath parameter"}, 400
                    )
                    return

                try:
                    self.binary_ops.load_binary(filepath)
                    self._send_json_response(
                        {"success": True, "message": f"Binary loaded: {filepath}"}
                    )
                except Exception as e:
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/rename/function" or path == "/renameFunction":
                old_name = params.get("oldName") or params.get("old_name")
                new_name = params.get("newName") or params.get("new_name")

                bn.log_info(
                    f"Rename request - old_name: {old_name}, new_name: {new_name}, params: {params}"
                )

                if not old_name or not new_name:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required parameters: oldName (or old_name) and newName (or new_name)",
                            "received": params,
                        },
                        400,
                    )
                    return

                # Handle address format (both 0x... and plain number)
                if isinstance(old_name, str):
                    if old_name.startswith("0x"):
                        try:
                            old_name = int(old_name, 16)
                        except ValueError:
                            pass
                    elif old_name.isdigit():
                        old_name = int(old_name)

                bn.log_info(f"Attempting to rename function: {old_name} -> {new_name}")

                # Get function info for validation
                func_info = self.binary_ops.get_function_info(old_name)
                if func_info:
                    bn.log_info(f"Found function: {func_info}")
                    success = self.binary_ops.rename_function(old_name, new_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully renamed function from {old_name} to {new_name}",
                                "function": func_info,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to rename function",
                                "message": "The function was found but could not be renamed. This might be due to permissions or binary restrictions.",
                                "function": func_info,
                            },
                            500,
                        )
                else:
                    available_funcs = self.binary_ops.get_function_names(0, 10)
                    bn.log_error(f"Function not found: {old_name}")
                    self._send_json_response(
                        {
                            "error": "Function not found",
                            "requested": old_name,
                            "help": "Make sure the function exists. You can use either the function name or its address.",
                            "available_functions": available_funcs,
                        },
                        404,
                    )

            elif path == "/rename/data" or path == "/renameData":
                address = params.get("address")
                new_name = params.get("newName") or params.get("new_name")
                if not address or not new_name:
                    self._send_json_response({"error": "Missing parameters"}, 400)
                    return

                try:
                    address_int = (
                        int(address, 16) if isinstance(address, str) else int(address)
                    )
                    success = self.binary_ops.rename_data(address_int, new_name)
                    self._send_json_response({"success": success})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("functionName") or params.get("name")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )

            else:
                self._send_json_response({"error": "Not found"}, 404)
        except Exception as e:
            bn.log_error(f"Error handling POST request: {e}")
            self._send_json_response({"error": str(e)}, 500)


class MCPServer:
    """HTTP server for Binary Ninja MCP plugin.

    Provides REST API endpoints for:
    - Binary analysis and manipulation
    - Function decompilation
    - Symbol renaming
    - Data inspection
    """

    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.thread = None
        self.binary_ops = BinaryOperations(config.binary_ninja)

    def start(self):
        """Start the HTTP server in a background thread."""
        server_address = (self.config.server.host, self.config.server.port)

        # Create handler with access to binary operations
        handler_class = type(
            "MCPRequestHandlerWithOps",
            (MCPRequestHandler,),
            {"binary_ops": self.binary_ops},
        )

        self.server = HTTPServer(server_address, handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        bn.log_info(
            f"Server started on {self.config.server.host}:{self.config.server.port}"
        )

    def stop(self):
        """Stop the HTTP server and clean up resources."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join()
            bn.log_info("Server stopped")
