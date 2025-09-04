from typing import Dict, Any, List, Optional
import binaryninja as bn
from ..core.binary_operations import BinaryOperations


class BinaryNinjaEndpoints:
    def __init__(self, binary_ops: BinaryOperations):
        self.binary_ops = binary_ops

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the binary view"""
        return {
            "loaded": self.binary_ops.current_view is not None,
            "filename": self.binary_ops.current_view.file.filename
            if self.binary_ops.current_view
            else None,
        }

    def get_function_info(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a function"""
        try:
            return self.binary_ops.get_function_info(identifier)
        except Exception as e:
            bn.log_error(f"Error getting function info: {e}")
            return None

    def get_imports(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of imported functions"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        imports = []
        for sym in self.binary_ops.current_view.get_symbols_of_type(
            bn.SymbolType.ImportedFunctionSymbol
        ):
            imports.append(
                {
                    "name": sym.name,
                    "address": hex(sym.address),
                    "raw_name": sym.raw_name if hasattr(sym, "raw_name") else sym.name,
                    "full_name": sym.full_name
                    if hasattr(sym, "full_name")
                    else sym.name,
                }
            )
        return imports[offset : offset + limit]

    def get_exports(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of exported symbols"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        exports = []
        for sym in self.binary_ops.current_view.get_symbols():
            if sym.type not in [
                bn.SymbolType.ImportedFunctionSymbol,
                bn.SymbolType.ExternalSymbol,
            ]:
                exports.append(
                    {
                        "name": sym.name,
                        "address": hex(sym.address),
                        "raw_name": sym.raw_name
                        if hasattr(sym, "raw_name")
                        else sym.name,
                        "full_name": sym.full_name
                        if hasattr(sym, "full_name")
                        else sym.name,
                        "type": str(sym.type),
                    }
                )
        return exports[offset : offset + limit]

    def get_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """Get list of C++ namespaces"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        namespaces = set()
        for sym in self.binary_ops.current_view.get_symbols():
            if "::" in sym.name:
                parts = sym.name.split("::")
                if len(parts) > 1:
                    namespace = "::".join(parts[:-1])
                    namespaces.add(namespace)

        sorted_namespaces = sorted(list(namespaces))
        return sorted_namespaces[offset : offset + limit]

    def get_defined_data(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self.binary_ops.current_view.data_vars:
            data_type = self.binary_ops.current_view.get_type_at(var)
            value = None

            try:
                if data_type and data_type.width <= 8:
                    value = str(
                        self.binary_ops.current_view.read_int(var, data_type.width)
                    )
                else:
                    value = "(complex data)"
            except (ValueError, TypeError):
                value = "(unreadable)"

            sym = self.binary_ops.current_view.get_symbol_at(var)
            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name
                    if sym and hasattr(sym, "raw_name")
                    else None,
                    "value": value,
                    "type": str(data_type) if data_type else None,
                }
            )

        return data_items[offset : offset + limit]

    def search_functions(
        self, search_term: str, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search functions by name"""
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        if not search_term:
            return []

        matches = []
        for func in self.binary_ops.current_view.functions:
            if search_term.lower() in func.name.lower():
                matches.append(
                    {
                        "name": func.name,
                        "address": hex(func.start),
                        "raw_name": func.raw_name
                        if hasattr(func, "raw_name")
                        else func.name,
                        "symbol": {
                            "type": str(func.symbol.type) if func.symbol else None,
                            "full_name": func.symbol.full_name if func.symbol else None,
                        }
                        if func.symbol
                        else None,
                    }
                )

        matches.sort(key=lambda x: x["name"])
        return matches[offset : offset + limit]

    def decompile_function(self, identifier: str) -> Optional[str]:
        """Decompile a function by name or address"""
        try:
            return self.binary_ops.decompile_function(identifier)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {e}")
            return None

    def get_assembly_function(self, identifier: str) -> Optional[str]:
        """Get the assembly representation of a function by name or address"""
        try:
            return self.binary_ops.get_assembly_function(identifier)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function: {e}")
            return None

    def define_types(self, c_code: str) -> Dict[str, str]:
        """Define types from C code string
        
        Args:
            c_code: C code string containing type definitions
            
        Returns:
            Dictionary mapping type names to their string representations
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing the types fails
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Parse the C code string to get type objects
            parse_result = self.binary_ops.current_view.parse_types_from_string(c_code)
            
            # Define each type in the binary view
            defined_types = {}
            for name, type_obj in parse_result.types.items():
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined_types[str(name)] = str(type_obj)
                
            return defined_types
        except Exception as e:
            raise ValueError(f"Failed to define types: {str(e)}")

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> Dict[str, str]:
        """Rename a variable inside a function
        
        Args:
            function_name: Name of the function containing the variable
            old_name: Current name of the variable
            new_name: New name for the variable
            
        Returns:
            Dictionary with status message
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be renamed
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        # Find the function by name
        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")
            
        # Try to rename the variable
        try:
            # Get the variable by name and rename it
            variable = function.get_variable_by_name(old_name)
            if not variable:
                raise ValueError(f"Variable '{old_name}' not found in function '{function_name}'")
                
            variable.name = new_name
            return {"status": f"Successfully renamed variable '{old_name}' to '{new_name}' in function '{function_name}'"}
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {str(e)}")


    def retype_variable(self, function_name: str, name: str, type_str: str) -> Dict[str, str]:
        """Retype a variable inside a function
        
        Args:
            function_name: Name of the function containing the variable
            name: Current name of the variable
            type: C type for the variable
            
        Returns:
            Dictionary with status message
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be retyped
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        # Find the function by name
        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")
            
        # Try to rename the variable
        try:
            # Get the variable by name and rename it
            variable = function.get_variable_by_name(name)
            if not variable:
                raise ValueError(f"Variable '{name}' not found in function '{function_name}'")
                
            variable.type = type_str
            return {"status": f"Successfully retyped variable '{name}' to '{type_str}' in function '{function_name}'"}
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {str(e)}")


    def edit_function_signature(self, function_name: str, signature: str) -> Dict[str, str]:
        """Rename a variable inside a function
        
        Args:
            function_name: Name of the function to edit the signature of
            signature: new signature to apply
            
        Returns:
            Dictionary with status message
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If the function is not found or variable cannot be renamed
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")
            
        # Find the function by name
        function = self.binary_ops.get_function_by_name_or_address(function_name)
        if not function:
            raise ValueError(f"Function '{function_name}' not found")
            
        function.type = self.binary_ops.current_view.parse_type_string(signature)[0]

        function.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
            
        try:
            return {"status": f"Successfully"}
        except Exception as e:
            raise ValueError(f"Failed to rename variable: {str(e)}")

    def set_function_prototype(self, function_address: str | int, prototype: str) -> Dict[str, str]:
        """Set a function's prototype by address.

        Args:
            function_address: Function address (hex string like 0x401000 or integer)
            prototype: C-style function prototype/type string (e.g., "int __cdecl f(int a)", or "int(int)" )

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded.
            ValueError: If the function or prototype is invalid.
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        # Resolve function
        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            # If an address was provided and no function exists, try to create one
            addr_int = None
            try:
                if isinstance(function_address, str) and function_address.lower().startswith("0x"):
                    addr_int = int(function_address, 16)
                elif isinstance(function_address, (int, str)):
                    addr_int = int(function_address)
            except Exception:
                addr_int = None

            if addr_int is not None:
                try:
                    bv = self.binary_ops.current_view
                    # Prefer create_user_function; fallback to add_function
                    if hasattr(bv, "create_user_function"):
                        bv.create_user_function(addr_int)
                    elif hasattr(bv, "add_function"):
                        bv.add_function(addr_int)
                    # Fetch again
                    func = self.binary_ops.get_function_by_name_or_address(addr_int)
                    # As a fallback, find the function containing the address
                    if not func and hasattr(bv, "get_functions_containing"):
                        try:
                            containing = bv.get_functions_containing(addr_int)
                            if containing:
                                func = containing[0]
                        except Exception:
                            pass
                except Exception:
                    func = None

        if not func:
            raise ValueError(f"Function not found at/address '{function_address}'")

        try:
            # Normalize prototype (strip stray trailing semicolon)
            proto = (prototype or "").strip()
            if proto.endswith(";"):
                proto = proto[:-1].strip()

            # Parse the prototype into a Binary Ninja Type
            t, _ = self.binary_ops.current_view.parse_type_string(proto)
            if not t:
                raise ValueError("Failed to parse prototype")

            # Apply and reanalyze
            func.type = t
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
            return {
                "status": "ok",
                "function": func.name,
                "address": hex(func.start),
                "applied_type": str(t),
            }
        except Exception as e:
            raise ValueError(f"Failed to set function prototype: {str(e)}")

    def declare_c_type(self, c_declaration: str) -> Dict[str, Any]:
        """Create or update a local type from a single C declaration.

        Accepts any C type declaration (struct/union/enum/typedef/function type) and defines
        the resulting named types in the current BinaryView's user types. If multiple types
        are declared, all are applied.

        Args:
            c_declaration: C declaration string (e.g., "typedef struct { int a; } Foo;")

        Returns:
            Dictionary with keys:
              - defined_types: map of type name -> declaration string
              - count: number of types defined/updated

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If parsing fails or no types are found
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        decl = (c_declaration or "").strip()
        if not decl:
            raise ValueError("Empty C declaration")

        try:
            result = self.binary_ops.current_view.parse_types_from_string(decl)
        except Exception as e:
            raise ValueError(f"Failed to parse declaration: {str(e)}")

        if not result or not getattr(result, "types", {}):
            raise ValueError("No named types found in declaration")

        defined: Dict[str, str] = {}
        for name, type_obj in result.types.items():
            try:
                self.binary_ops.current_view.define_user_type(name, type_obj)
                defined[str(name)] = str(type_obj)
            except Exception as e:
                raise ValueError(f"Failed to define type '{name}': {str(e)}")

        return {"defined_types": defined, "count": len(defined)}

    def set_local_variable_type(self, function_address: str | int, variable_name: str, new_type: str) -> Dict[str, str]:
        """Set a local variable's type in a function.

        Args:
            function_address: Function identifier (address in hex or int, or name)
            variable_name: Local variable name to retype
            new_type: C type string (e.g., "int *", "const char*", "struct Foo*")

        Returns:
            Dictionary with status message.

        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If function/variable/type are invalid
        """
        if not self.binary_ops.current_view:
            raise RuntimeError("No binary loaded")

        func = self.binary_ops.get_function_by_name_or_address(function_address)
        if not func:
            raise ValueError(f"Function '{function_address}' not found")

        if not variable_name:
            raise ValueError("Missing variable name")

        # Resolve the variable by name
        var = None
        try:
            if hasattr(func, "get_variable_by_name"):
                var = func.get_variable_by_name(variable_name)
        except Exception:
            var = None

        if not var:
            raise ValueError(f"Variable '{variable_name}' not found in function '{func.name}'")

        # Parse type string
        try:
            t, _ = self.binary_ops.current_view.parse_type_string((new_type or "").strip())
        except Exception:
            t = None
        if t is None:
            # Fall back to assigning the string if BN API supports it; otherwise fail
            try:
                var.type = new_type
                applied = str(new_type)
            except Exception:
                raise ValueError(f"Failed to parse type: '{new_type}'")
        else:
            # Apply via variable object or function API
            applied = str(t)
            try:
                var.type = t
            except Exception:
                # Try create_user_var if direct assignment fails
                try:
                    if hasattr(func, "create_user_var") and hasattr(var, "storage"):
                        func.create_user_var(var, t, variable_name)
                    else:
                        raise ValueError("Retyping not supported by this Binary Ninja API version")
                except Exception as e:
                    raise ValueError(f"Failed to set variable type: {str(e)}")

        # Trigger reanalysis for consistency
        try:
            func.reanalyze(bn.FunctionUpdateType.UserFunctionUpdate)
        except Exception:
            pass

        return {
            "status": "ok",
            "function": func.name,
            "address": hex(func.start),
            "variable": variable_name,
            "applied_type": applied,
        }
