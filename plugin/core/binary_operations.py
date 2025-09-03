import binaryninja as bn
from typing import Optional, List, Dict, Any, Union
from .config import BinaryNinjaConfig
from binaryninja.enums import TypeClass, StructureVariant
from ..utils.string_utils import escape_non_ascii



class BinaryOperations:
    def __init__(self, config: BinaryNinjaConfig):
        self.config = config
        self._current_view: Optional[bn.BinaryView] = None

    @property
    def current_view(self) -> Optional[bn.BinaryView]:
        return self._current_view

    @current_view.setter
    def current_view(self, bv: Optional[bn.BinaryView]):
        self._current_view = bv
        if bv:
            bn.log_info(f"Set current binary view: {bv.file.filename}")
        else:
            bn.log_info("Cleared current binary view")

    def load_binary(self, filepath: str) -> bn.BinaryView:
        """Load a binary file using the appropriate method based on the Binary Ninja API version"""
        try:
            if hasattr(bn, "open_view"):
                bn.log_info("Using bn.open_view method")
                self._current_view = bn.open_view(filepath)
            elif hasattr(bn, "BinaryViewType") and hasattr(
                bn.BinaryViewType, "get_view_of_file"
            ):
                bn.log_info("Using BinaryViewType.get_view_of_file method")
                file_metadata = bn.FileMetadata()
                try:
                    if hasattr(bn.BinaryViewType, "get_default_options"):
                        options = bn.BinaryViewType.get_default_options()
                        self._current_view = bn.BinaryViewType.get_view_of_file(
                            filepath, file_metadata, options
                        )
                    else:
                        self._current_view = bn.BinaryViewType.get_view_of_file(
                            filepath, file_metadata
                        )
                except TypeError:
                    self._current_view = bn.BinaryViewType.get_view_of_file(filepath)
            else:
                bn.log_info("Using legacy method")
                file_metadata = bn.FileMetadata()
                binary_view_type = bn.BinaryViewType.get_view_of_file_with_options(
                    filepath, file_metadata
                )
                if binary_view_type:
                    self._current_view = binary_view_type.open()
                else:
                    raise Exception("No view type available for this file")

            return self._current_view
        except Exception as e:
            bn.log_error(f"Failed to load binary: {e}")
            raise

    def get_function_by_name_or_address(
        self, identifier: Union[str, int]
    ) -> Optional[bn.Function]:
        """Get a function by either its name or address.

        Args:
            identifier: Function name or address (can be int, hex string, or decimal string)

        Returns:
            Function object if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Handle address-based lookup
        try:
            if isinstance(identifier, str) and identifier.startswith("0x"):
                addr = int(identifier, 16)
            elif isinstance(identifier, (int, str)):
                addr = int(identifier) if isinstance(identifier, str) else identifier

            func = self._current_view.get_function_at(addr)
            if func:
                bn.log_info(f"Found function at address {hex(addr)}: {func.name}")
                return func
        except ValueError:
            pass

        # Handle name-based lookup with case sensitivity
        for func in self._current_view.functions:
            if func.name == identifier:
                bn.log_info(f"Found function by name: {func.name}")
                return func

        # Try case-insensitive match as fallback
        for func in self._current_view.functions:
            if func.name.lower() == str(identifier).lower():
                bn.log_info(f"Found function by case-insensitive name: {func.name}")
                return func

        # Try symbol table lookup as last resort
        symbol = self._current_view.get_symbol_by_raw_name(str(identifier))
        if symbol and symbol.address:
            func = self._current_view.get_function_at(symbol.address)
            if func:
                bn.log_info(f"Found function through symbol lookup: {func.name}")
                return func

        bn.log_error(f"Could not find function: {identifier}")
        return None

    def get_function_names(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, str]]:
        """Get list of function names with addresses"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        functions = []
        for func in self._current_view.functions:
            functions.append(
                {
                    "name": func.name,
                    "address": hex(func.start),
                    "raw_name": func.raw_name
                    if hasattr(func, "raw_name")
                    else func.name,
                }
            )

        return functions[offset : offset + limit]

    def get_class_names(self, offset: int = 0, limit: int = 100) -> List[str]:
        """Get list of class names with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        class_names = set()

        try:
            # Try different methods to identify classes
            for type_obj in self._current_view.types.values():
                try:
                    # Skip None or invalid types
                    if not type_obj or not hasattr(type_obj, "name"):
                        continue

                    # Method 1: Check type_class attribute
                    if hasattr(type_obj, "type_class"):
                        class_names.add(type_obj.name)
                        continue

                    # Method 2: Check structure attribute
                    if hasattr(type_obj, "structure") and type_obj.structure:
                        structure = type_obj.structure

                        # Check various attributes that indicate a class
                        if any(
                            hasattr(structure, attr)
                            for attr in [
                                "vtable",
                                "base_structures",
                                "members",
                                "functions",
                            ]
                        ):
                            class_names.add(type_obj.name)
                            continue

                        # Check type attribute if available
                        if hasattr(structure, "type"):
                            type_str = str(structure.type).lower()
                            if "class" in type_str or "struct" in type_str:
                                class_names.add(type_obj.name)
                                continue

                except Exception as e:
                    bn.log_debug(
                        f"Error processing type {getattr(type_obj, 'name', '<unknown>')}: {e}"
                    )
                    continue

            bn.log_info(f"Found {len(class_names)} classes")
            sorted_names = sorted(list(class_names))
            return sorted_names[offset : offset + limit]

        except Exception as e:
            bn.log_error(f"Error getting class names: {e}")
            return []

    def get_segments(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of segments with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        segments = []
        for segment in self._current_view.segments:
            segment_info = {
                "start": hex(segment.start),
                "end": hex(segment.end),
                "name": "",
                "flags": [],
            }

            # Try to get segment name if available
            if hasattr(segment, "name"):
                segment_info["name"] = segment.name
            elif hasattr(segment, "data_name"):
                segment_info["name"] = segment.data_name

            # Try to get segment flags safely
            if hasattr(segment, "flags"):
                try:
                    if isinstance(segment.flags, (list, tuple)):
                        segment_info["flags"] = list(segment.flags)
                    else:
                        segment_info["flags"] = [str(segment.flags)]
                except (AttributeError, TypeError, ValueError):
                    pass

            # Add segment permissions if available
            if hasattr(segment, "readable"):
                segment_info["readable"] = bool(segment.readable)
            if hasattr(segment, "writable"):
                segment_info["writable"] = bool(segment.writable)
            if hasattr(segment, "executable"):
                segment_info["executable"] = bool(segment.executable)

            segments.append(segment_info)

        return segments[offset : offset + limit]

    def rename_function(self, old_name: str, new_name: str) -> bool:
        """Rename a function using multiple fallback methods.

        Args:
            old_name: Current function name or address
            new_name: New name for the function

        Returns:
            True if rename succeeded, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(old_name)
            if not func:
                bn.log_error(f"Function not found: {old_name}")
                return False

            bn.log_info(f"Found function to rename: {func.name} at {hex(func.start)}")

            if not new_name or not isinstance(new_name, str):
                bn.log_error(f"Invalid new name: {new_name}")
                return False

            if not hasattr(func, "name") or not hasattr(func, "__setattr__"):
                bn.log_error(f"Function {func.name} cannot be renamed (read-only)")
                return False

            try:
                # Try direct name assignment first
                old_name = func.name
                func.name = new_name

                if func.name == new_name:
                    bn.log_info(
                        f"Successfully renamed function from {old_name} to {new_name}"
                    )
                    return True

                # Try symbol-based renaming if direct assignment fails
                if hasattr(func, "symbol") and func.symbol:
                    try:
                        new_symbol = bn.Symbol(
                            func.symbol.type,
                            func.start,
                            new_name,
                            namespace=func.symbol.namespace
                            if hasattr(func.symbol, "namespace")
                            else None,
                        )
                        self._current_view.define_user_symbol(new_symbol)
                        bn.log_info("Successfully renamed function using symbol table")
                        return True
                    except Exception as e:
                        bn.log_error(f"Symbol-based rename failed: {e}")

                # Try function update method as last resort
                if hasattr(self._current_view, "update_function"):
                    try:
                        func_copy = func
                        func_copy.name = new_name
                        self._current_view.update_function(func)
                        bn.log_info("Successfully renamed function using update method")
                        return True
                    except Exception as e:
                        bn.log_error(f"Function update rename failed: {e}")

                bn.log_error(
                    f"All rename methods failed - function name unchanged: {func.name}"
                )
                return False

            except Exception as e:
                bn.log_error(f"Error during rename operation: {e}")
                return False

        except Exception as e:
            bn.log_error(f"Error in rename_function: {e}")
            return False

    def get_function_info(
        self, identifier: Union[str, int]
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information about a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        bn.log_info(f"Found function: {func.name} at {hex(func.start)}")

        info = {
            "name": func.name,
            "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
            "address": hex(func.start),
            "symbol": None,
        }

        if func.symbol:
            info["symbol"] = {
                "type": str(func.symbol.type),
                "full_name": func.symbol.full_name
                if hasattr(func.symbol, "full_name")
                else func.symbol.name,
            }

        return info

    def decompile_function(self, identifier: Union[str, int]) -> Optional[str]:
        """Decompile a function to its high-level representation.

        Args:
            identifier: Function name or address

        Returns:
            Decompiled function code as string, or None if decompilation fails
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # analyze func in case it was skipped
        func.analysis_skipped = False
        self._current_view.update_analysis_and_wait()

        try:
            # Try high-level IL first for best readability
            if hasattr(func, "hlil"):
                return str(func.hlil)
            # Fall back to medium-level IL if available
            elif hasattr(func, "mlil"):
                return str(func.mlil)
            # Use basic function representation as last resort
            else:
                return str(func)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {str(e)}")
            return None

    def rename_data(self, address: int, new_name: str) -> bool:
        """Rename data at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.define_user_symbol(
                    bn.Symbol(bn.SymbolType.DataSymbol, address, new_name)
                )
                return True
        except Exception as e:
            bn.log_error(f"Failed to rename data: {e}")
        return False

    def get_defined_data(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self._current_view.data_vars:
            data_type = None
            value = None

            try:
                # Try to get data type safely
                if hasattr(self._current_view, "get_type_at"):
                    data_type = self._current_view.get_type_at(var)
                elif hasattr(self._current_view, "get_data_var_at"):
                    data_type = self._current_view.get_data_var_at(var)

                # Try to read value if type is available and small enough
                if data_type and hasattr(data_type, "width") and data_type.width <= 8:
                    try:
                        value = str(self._current_view.read_int(var, data_type.width))
                    except (ValueError, RuntimeError):
                        value = "(unreadable)"
                else:
                    value = "(complex data)"
            except (AttributeError, TypeError, ValueError, RuntimeError):
                value = "(unknown)"
                data_type = None

            # Get symbol information
            sym = self._current_view.get_symbol_at(var)
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

    def list_local_types(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """List local types (Types view) in the current database.

        Returns a list of dictionaries with:
        - name: type name
        - kind: struct/union/class/enum/typedef/unknown
        - decl: string form of the type (when available)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []
        seen_names = set()
        try:
            def add_type_entry(name, tobj):
                # Normalize name to string to avoid BN QualifiedName in JSON
                try:
                    name_str = str(name) if name is not None else None
                except Exception:
                    name_str = None
                if not name_str or name_str in seen_names:
                    return
                tc = getattr(tobj, "type_class", None)
                kind = "unknown"
                if tc == TypeClass.VoidTypeClass:
                    kind = "void"
                elif tc == TypeClass.BoolTypeClass:
                    kind = "bool"
                elif tc == TypeClass.IntegerTypeClass:
                    kind = "int"
                elif tc == TypeClass.FloatTypeClass:
                    kind = "float"
                elif tc == TypeClass.StructureTypeClass:
                    try:
                        if getattr(tobj, "type", None) == StructureVariant.StructStructureType:
                            kind = "struct"
                        elif getattr(tobj, "type", None) == StructureVariant.UnionStructureType:
                            kind = "union"
                        elif getattr(tobj, "type", None) == StructureVariant.ClassStructureType:
                            kind = "class"
                        else:
                            kind = "struct"
                    except Exception:
                        kind = "struct"
                elif tc == TypeClass.EnumerationTypeClass:
                    kind = "enum"
                elif tc == TypeClass.NamedTypeReferenceClass:
                    kind = "typedef"
                elif tc == TypeClass.FunctionTypeClass:
                    kind = "function"
                elif tc == TypeClass.WideCharTypeClass:
                    kind = "wchar"
                elif tc == TypeClass.PointerTypeClass:
                    kind = "pointer"
                elif tc == TypeClass.ArrayTypeClass:
                    kind = "array"

                decl = None
                try:
                    decl = str(tobj)
                except Exception:
                    try:
                        decl = str(getattr(tobj, "type", None))
                    except Exception:
                        decl = None

                results.append({
                    "name": name_str,
                    "kind": kind,
                    "type_class": str(tc) if tc is not None else None,
                    "decl": decl,
                })
                seen_names.add(name_str)

            # Source 1: user_type_container (explicit local/user types)
            try:
                utc = getattr(self._current_view, "user_type_container", None)
                if utc and getattr(utc, "types", None):
                    for type_id in list(utc.types.keys()):
                        try:
                            entry = utc.types[type_id]
                            name = entry[0] if isinstance(entry, (tuple, list)) else getattr(entry, "name", None)
                            tobj = entry[1] if isinstance(entry, (tuple, list)) else getattr(entry, "type", entry)
                            add_type_entry(name, tobj)
                        except Exception:
                            continue
            except Exception:
                pass

            # Source 2: view.types (BN view-local types)
            for k, v in self._current_view.types.items():
                try:
                    if isinstance(v, (tuple, list)) and len(v) >= 2:
                        name = str(v[0])
                        tobj = v[1]
                    else:
                        tobj = v
                        name = getattr(v, "name", None)
                        if not name:
                            name = str(k)
                    add_type_entry(name, tobj)
                except Exception:
                    continue
        except Exception as e:
            bn.log_error(f"Error listing local types: {e}")
        return results[offset : offset + limit]

    def get_strings(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of strings in the current binary view with pagination.

        Returns a list of dictionaries containing:
        - address: start address of the string (hex)
        - length: length in bytes (int if available)
        - type: Binary Ninja string type (str if available)
        - value: best-effort decoded and escaped string value
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []

        try:
            # Prefer modern API if available
            strings_iter = None
            if hasattr(self._current_view, "get_strings"):
                try:
                    strings_iter = self._current_view.get_strings()
                except TypeError:
                    strings_iter = None

            if strings_iter is None and hasattr(self._current_view, "strings"):
                try:
                    strings_iter = list(self._current_view.strings)
                except Exception:
                    strings_iter = []

            if strings_iter is None:
                strings_iter = []

            for s in strings_iter:
                try:
                    addr = None
                    length = None
                    stype = None
                    value = None

                    # Common attributes on StringReference
                    addr = getattr(s, "start", getattr(s, "address", None))
                    length = getattr(s, "length", None)
                    stype = getattr(s, "type", None)
                    if stype is not None:
                        try:
                            stype = str(stype)
                        except Exception:
                            stype = str(stype)

                    value = getattr(s, "value", None)

                    # Best-effort read/decode if value is not present
                    if value is None and addr is not None and length is not None:
                        try:
                            raw = self._current_view.read(addr, length)
                            # Stop at first null byte if present
                            nul = raw.find(b"\x00")
                            if nul != -1:
                                raw = raw[:nul]
                            try:
                                value = raw.decode("utf-8", errors="ignore")
                            except Exception:
                                value = raw.decode("latin-1", errors="ignore")
                        except Exception:
                            value = None

                    # Ensure value is a string and escape non-ASCII
                    if value is None:
                        value = ""
                    value = escape_non_ascii(str(value))

                    results.append(
                        {
                            "address": hex(addr) if isinstance(addr, int) else (str(addr) if addr is not None else None),
                            "length": int(length) if isinstance(length, (int,)) else (None if length is None else int(length)),
                            "type": stype,
                            "value": value,
                        }
                    )
                except Exception as e:
                    # Keep collecting even if one entry fails
                    bn.log_debug(f"Error processing string entry: {e}")
                    continue

            return results[offset : offset + limit]
        except Exception as e:
            bn.log_error(f"Error getting strings: {e}")
            return []

    def set_comment(self, address: int, comment: str) -> bool:
        """Set a comment at a specific address.

        Args:
            address: The address to set the comment at
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return False

            self._current_view.set_comment_at(address, comment)
            bn.log_info(f"Set comment at {hex(address)}: {comment}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set comment: {e}")
            return False

    def set_function_comment(self, identifier: Union[str, int], comment: str) -> bool:
        """Set a comment for a function.

        Args:
            identifier: Function name or address
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return False

            self._current_view.set_comment_at(func.start, comment)
            bn.log_info(f"Set comment for function {func.name} at {hex(func.start)}: {comment}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set function comment: {e}")
            return False

    def get_comment(self, address: int) -> Optional[str]:
        """Get the comment at a specific address.

        Args:
            address: The address to get the comment from

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return None

            comment = self._current_view.get_comment_at(address)
            return comment if comment else None
        except Exception as e:
            bn.log_error(f"Failed to get comment: {e}")
            return None

    def get_function_comment(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the comment for a function.

        Args:
            identifier: Function name or address

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None

            comment = self._current_view.get_comment_at(func.start)
            return comment if comment else None
        except Exception as e:
            bn.log_error(f"Failed to get function comment: {e}")
            return None

    def delete_comment(self, address: int) -> bool:
        """Delete a comment at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.set_comment_at(address, None)
                return True
        except Exception as e:
            bn.log_error(f"Failed to delete comment: {e}")
        return False

    def delete_function_comment(self, identifier: Union[str, int]) -> bool:
        """Delete a comment for a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                return False
                
            func.comment = None
            return True
        except Exception as e:
            bn.log_error(f"Failed to delete function comment: {e}")
        return False
        

    def get_assembly_function(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the assembly representation of a function with practical annotations.

        Args:
            identifier: Function name or address

        Returns:
            Assembly code as string, or None if the function cannot be found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None
                
            bn.log_info(f"Found function: {func.name} at {hex(func.start)}")
            
            var_map = {}    # TODO: Implement this functionality (issues with var.storage not returning the correst sp offset)
            assembly_blocks = {}
            
            if not hasattr(func, "basic_blocks") or not func.basic_blocks:
                bn.log_error(f"Function {func.name} has no basic blocks")
                # Try alternate approach with linear disassembly
                start_addr = func.start
                try:
                    func_length = func.total_bytes
                    if func_length <= 0:
                        func_length = 1024  # Use a reasonable default if length not available
                except:
                    func_length = 1024  # Use a reasonable default if error
                    
                try:
                    # Create one big block for the entire function
                    block_lines = []
                    current_addr = start_addr
                    end_addr = start_addr + func_length
                    
                    while current_addr < end_addr:
                        try:
                            # Get instruction length
                            instr_len = self._current_view.get_instruction_length(current_addr)
                            if instr_len <= 0:
                                instr_len = 4  # Default to a reasonable instruction length
                                
                            # Get disassembly for this instruction
                            line = self._get_instruction_with_annotations(current_addr, instr_len, var_map)
                            if line:
                                block_lines.append(line)
                                
                            current_addr += instr_len
                        except Exception as e:
                            bn.log_error(f"Error processing address {hex(current_addr)}: {str(e)}")
                            block_lines.append(f"# Error at {hex(current_addr)}: {str(e)}")
                            current_addr += 1  # Skip to next byte
                    
                    assembly_blocks[start_addr] = [f"# Block at {hex(start_addr)}"] + block_lines + [""]
                    
                except Exception as e:
                    bn.log_error(f"Linear disassembly failed: {str(e)}")
                    return None
            else:
                for i, block in enumerate(func.basic_blocks):
                    try:
                        block_lines = []
                        
                        # Process each address in the block
                        addr = block.start
                        while addr < block.end:
                            try:
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    instr_len = 4  # Default to a reasonable instruction length
                                
                                # Get disassembly for this instruction
                                line = self._get_instruction_with_annotations(addr, instr_len, var_map)
                                if line:
                                    block_lines.append(line)
                                    
                                addr += instr_len
                            except Exception as e:
                                bn.log_error(f"Error processing address {hex(addr)}: {str(e)}")
                                block_lines.append(f"# Error at {hex(addr)}: {str(e)}")
                                addr += 1  # Skip to next byte
                        
                        # Store block with its starting address as key
                        assembly_blocks[block.start] = [f"# Block {i+1} at {hex(block.start)}"] + block_lines + [""]
                        
                    except Exception as e:
                        bn.log_error(f"Error processing block {i+1} at {hex(block.start)}: {str(e)}")
                        assembly_blocks[block.start] = [f"# Error processing block {i+1} at {hex(block.start)}: {str(e)}", ""]
            
            # Sort blocks by address and concatenate them
            sorted_blocks = []
            for addr in sorted(assembly_blocks.keys()):
                sorted_blocks.extend(assembly_blocks[addr])
            
            return "\n".join(sorted_blocks)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function {identifier}: {str(e)}")
            import traceback
            bn.log_error(traceback.format_exc())
            return None

    def _get_instruction_with_annotations(self, addr: int, instr_len: int, var_map: Dict[int, str]) -> Optional[str]:
        """Get a single instruction with practical annotations.
        
        Args:
            addr: Address of the instruction
            instr_len: Length of the instruction
            var_map: Dictionary mapping offsets to variable names
            
        Returns:
            Formatted instruction string with annotations
        """
        if not self._current_view:
            return None
            
        try:
            # Get raw bytes for fallback
            try:
                raw_bytes = self._current_view.read(addr, instr_len)
                hex_bytes = ' '.join(f'{b:02x}' for b in raw_bytes)
            except:
                hex_bytes = "??"
                
            # Get basic disassembly
            disasm_text = ""
            try:
                if hasattr(self._current_view, "get_disassembly"):
                    disasm = self._current_view.get_disassembly(addr)
                    if disasm:
                        disasm_text = disasm
            except:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            if not disasm_text:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            # Check if this is a call instruction and try to get target function name
            if "call" in disasm_text.lower():
                try:
                    # Extract the address from the call instruction
                    import re
                    addr_pattern = r'0x[0-9a-fA-F]+'
                    match = re.search(addr_pattern, disasm_text)
                    if match:
                        call_addr_str = match.group(0)
                        call_addr = int(call_addr_str, 16)
                        
                        # Look up the target function name
                        sym = self._current_view.get_symbol_at(call_addr)
                        if sym and hasattr(sym, "name"):
                            # Replace the address with the function name
                            disasm_text = disasm_text.replace(call_addr_str, sym.name)
                except:
                    pass
                    
            # Try to annotate memory references with variable names
            try:
                # Look for memory references like [reg+offset]
                import re
                mem_ref_pattern = r'\[([^\]]+)\]'
                mem_refs = re.findall(mem_ref_pattern, disasm_text)
                
                # For each memory reference, check if it's a known variable
                for mem_ref in mem_refs:
                    # Parse for ebp relative references
                    offset_pattern = r'(ebp|rbp)(([+-]0x[0-9a-fA-F]+)|([+-]\d+))'
                    offset_match = re.search(offset_pattern, mem_ref)
                    if offset_match:
                        # Extract base register and offset
                        base_reg = offset_match.group(1)
                        offset_str = offset_match.group(2)
                        
                        # Convert offset to integer
                        try:
                            offset = int(offset_str, 16) if offset_str.startswith('0x') or offset_str.startswith('-0x') else int(offset_str)      
                            
                            # Try to find variable name
                            var_name = var_map.get(offset)
                            
                            # If found, add it to the memory reference
                            if var_name:
                                old_ref = f"[{mem_ref}]"
                                new_ref = f"[{mem_ref} {{{var_name}}}]"
                                disasm_text = disasm_text.replace(old_ref, new_ref)
                        except:
                            pass
            except:
                pass
                
            # Get comment if any
            comment = None
            try:
                comment = self._current_view.get_comment_at(addr)
            except:
                pass
                
            # Format the final line
            addr_str = f"{addr:08x}"
            line = f"0x{addr_str}  {disasm_text}"
            
            # Add comment at the end if any
            if comment:
                line += f"  ; {comment}"
                
            return line
        except Exception as e:
            bn.log_error(f"Error annotating instruction at {hex(addr)}: {str(e)}")
            return f"0x{addr:08x}  {hex_bytes} ; [Error: {str(e)}]"
            
    def get_functions_containing_address(self, address: int) -> list:
        """Get functions containing a specific address.
        
        Args:
            address: The instruction address to find containing functions for
            
        Returns:
            List of function names containing the address
        """
        if not self.current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            functions = list(self.current_view.get_functions_containing(address))
            return [func.name for func in functions]
        except Exception as e:
            bn.log_error(f"Error getting functions containing address {hex(address)}: {e}")
            return []
            
    def get_function_code_references(self, function_name: str) -> list:
        """Get all code references to a function.
        
        Args:
            function_name: Name of the function to find references to
            
        Returns:
            List of dictionaries containing function names and addresses that reference the target function
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # First, get the function by name
            func = self.get_function_by_name_or_address(function_name)
            if not func:
                bn.log_error(f"Function not found: {function_name}")
                return []
                
            # Get all code references to the function's start address
            code_refs = []
            for ref in list(self._current_view.get_code_refs(func.start)):
                try:
                    # For each reference, get the containing function and address
                    if ref.function:
                        code_refs.append({
                            "function": ref.function.name,
                            "address": hex(ref.address)
                        })
                except Exception as e:
                    bn.log_error(f"Error processing reference at {hex(ref.address)}: {e}")
                    
            return code_refs
        except Exception as e:
            bn.log_error(f"Error getting code references for function {function_name}: {e}")
            return []
            
    def get_user_defined_type(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Get the definition of a user-defined type (struct, enum, etc.)
        
        Args:
            type_name: Name of the user-defined type to retrieve
            
        Returns:
            Dictionary with type information and definition, or None if not found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if we have a user type container
            if not hasattr(self._current_view, "user_type_container") or not self._current_view.user_type_container:
                bn.log_info(f"No user type container available")
                return None
                
            # Search for the requested type by name
            found_type = None
            found_type_id = None
            
            for type_id in self._current_view.user_type_container.types.keys():
                current_type = self._current_view.user_type_container.types[type_id]
                type_name_from_container = current_type[0]
                
                if type_name_from_container == type_name:
                    found_type = current_type
                    found_type_id = type_id
                    break
                    
            if not found_type or not found_type_id:
                bn.log_info(f"Type not found: {type_name}")
                return None
                
            # Determine the type category (struct, enum, etc.)
            type_category = "unknown"
            type_object = found_type[1]
            bn.log_info(f"Stage1")
            bn.log_info(f"Stage1.5 {type_object.type_class} {StructureVariant.StructStructureType}")
            if type_object.type_class == TypeClass.EnumerationTypeClass:
                type_category = "enum"
            elif type_object.type_class == TypeClass.StructureTypeClass:
                if type_object.type == StructureVariant.StructStructureType:
                    type_category = "struct"
                elif type_object.type == StructureVariant.UnionStructureType:
                    type_category = "union"
                elif type_object.type == StructureVariant.ClassStructureType:
                    type_category = "class"
            elif type_object.type_class == TypeClass.NamedTypeReferenceClass:
                type_category = "typedef"

            # Generate the C++ style definition
            definition_lines = []
            
            try:
                if type_category == "struct" or type_category == "class" or type_category == "union":
                    definition_lines.append(f"{type_category} {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "type"):
                            definition_lines.append(f"    {member.type} {member.name};")
                    definition_lines.append("};")
                elif type_category == "enum":
                    definition_lines.append(f"enum {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "value"):
                            definition_lines.append(f"    {member.name} = {member.value},")
                    definition_lines.append("};")
                elif type_category == "typedef":
                    str_type_object = str(type_object)
                    definition_lines.append(f"typedef {str_type_object};")
            except Exception as e:
                bn.log_error(f"Error getting type lines: {e}")

            # Construct the final definition string
            definition = "\n".join(definition_lines)
            
            return {
                "name": type_name,
                "type": type_category,
                "definition": definition
            }
        except Exception as e:
            bn.log_error(f"Error getting user-defined type {type_name}: {e}")
            return None

    def get_xrefs_to_address(self, address: Union[int, str]) -> Dict[str, Any]:
        """Get all cross references (code and data) to a given address.

        Args:
            address: Address as int, hex string (e.g., "0x401000"), or decimal string

        Returns:
            Dictionary with address, code_references, and data_references lists
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Normalize address to int
        try:
            if isinstance(address, str):
                addr = int(address, 16) if address.startswith("0x") else int(address)
            else:
                addr = int(address)
        except (TypeError, ValueError):
            raise ValueError("Invalid address format; use hex (0x...) or decimal")

        result: Dict[str, Any] = {
            "address": hex(addr),
            "code_references": [],
            "data_references": [],
        }

        # Code references
        try:
            if hasattr(self._current_view, "get_code_refs"):
                for ref in list(self._current_view.get_code_refs(addr)):
                    try:
                        fn_name = ref.function.name if getattr(ref, "function", None) else None
                        entry = {"function": fn_name, "address": hex(ref.address)}

                        # Heuristic: only attach a following call if the referenced data
                        # is carried in a parameter register up to that call (likely passed as an arg)
                        try:
                            func = ref.function if getattr(ref, "function", None) else self._current_view.get_function_at(ref.address)
                            if func is not None:
                                import re as _re
                                # identify destination register at xref instruction
                                def _canon_reg(r: str) -> str:
                                    r = (r or "").strip().lower()
                                    mp = {
                                        'rcx':'rcx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
                                        'rdx':'rdx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
                                        'r8':'r8','r8d':'r8','r8w':'r8','r8b':'r8',
                                        'r9':'r9','r9d':'r9','r9w':'r9','r9b':'r9',
                                        'rdi':'rdi','edi':'rdi','di':'rdi','dil':'rdi',
                                        'rsi':'rsi','esi':'rsi','si':'rsi','sil':'rsi',
                                    }
                                    return mp.get(r, r)
                                def _first_op_reg(d: str) -> str:
                                    try:
                                        parts = d.strip().split(None, 1)
                                        if len(parts) < 2:
                                            return ""
                                        ops = parts[1].split(';',1)[0]
                                        first = ops.split(',',1)[0].strip()
                                        if '[' in first:
                                            return ""
                                        for kw in ("byte","word","dword","qword","ptr"):
                                            if first.startswith(kw):
                                                first = first[len(kw):].strip()
                                        return first.split()[0]
                                    except Exception:
                                        return ""
                                try:
                                    xdis = self._current_view.get_disassembly(ref.address) or ""
                                except Exception:
                                    xdis = ""
                                dest = _canon_reg(_first_op_reg(xdis))
                                arg_regs = {"rcx","rdx","r8","r9","rdi","rsi"}
                                if dest in arg_regs:
                                    steps = 16
                                    curr = ref.address
                                    overwritten = False
                                    while steps > 0 and curr < getattr(func, 'highest_address', curr + 1024):
                                        ilen = self._current_view.get_instruction_length(curr) or 1
                                        try:
                                            dis = self._current_view.get_disassembly(curr) or ""
                                        except Exception:
                                            dis = ""
                                        # detect clobber of the arg register
                                        if curr != ref.address and _canon_reg(_first_op_reg(dis)) == dest:
                                            overwritten = True
                                        if ("call" in dis.lower()) and not overwritten:
                                            entry["following_call_address"] = hex(curr)
                                            m = _re.search(r"0x[0-9a-fA-F]+", dis)
                                            tgt = None
                                            if m:
                                                try:
                                                    tgt = int(m.group(0), 16)
                                                except Exception:
                                                    tgt = None
                                            if tgt is not None:
                                                sym = self._current_view.get_symbol_at(tgt)
                                                if sym and hasattr(sym,'name'):
                                                    entry["following_call_target"] = sym.name
                                                else:
                                                    tfn = self._current_view.get_function_at(tgt)
                                                    entry["following_call_target"] = tfn.name if (tfn and hasattr(tfn,'name')) else hex(tgt)
                                            break
                                        curr += max(1, ilen)
                                        steps -= 1
                        except Exception:
                            pass

                        result["code_references"].append(entry)
                    except Exception:
                        continue
        except Exception as e:
            bn.log_error(f"Error getting code references to {hex(addr)}: {e}")

        # Data references
        try:
            if hasattr(self._current_view, "get_data_refs"):
                for ref_addr in list(self._current_view.get_data_refs(addr)):
                    try:
                        fn = self._current_view.get_function_at(ref_addr)
                        fn_name = fn.name if fn else None
                        result["data_references"].append(
                            {"function": fn_name, "address": hex(ref_addr)}
                        )
                    except Exception:
                        continue
        except Exception as e:
            bn.log_error(f"Error getting data references to {hex(addr)}: {e}")

        return result

    def get_xrefs_to_field(self, struct_name: str, field_name: str) -> List[Dict[str, Any]]:
        """Get all cross references to a named struct field (member).

        This uses a best-effort heuristic:
        - Scans HLIL for occurrences of the field name (e.g., ".field" or "->field")
        - If a global instance of the struct is found, computes the field's absolute
          address (base + offset) and includes code refs to that address
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        struct_name = str(struct_name).strip()
        field_name = str(field_name).strip()
        results: List[Dict[str, Any]] = []

        # Try to resolve struct member offset
        member_offset = None
        try:
            if hasattr(self._current_view, "types") and self._current_view.types:
                for t in self._current_view.types.values():
                    try:
                        if getattr(t, "name", None) == struct_name and hasattr(t, "structure") and t.structure:
                            for m in getattr(t, "members", getattr(t.structure, "members", [])):
                                if getattr(m, "name", None) == field_name and hasattr(m, "offset"):
                                    member_offset = int(m.offset)
                                    break
                            if member_offset is not None:
                                break
                    except Exception:
                        continue
        except Exception:
            pass

        # HLIL scan for textual member access
        import re
        pattern = re.compile(rf"(\.|->)\s*{re.escape(field_name)}(\b|\W)")
        for func in list(self._current_view.functions):
            try:
                if not hasattr(func, "hlil") or not func.hlil:
                    continue
                for ins in func.hlil.instructions:
                    try:
                        text = str(ins)
                        if pattern.search(text):
                            results.append({
                                "kind": "hlil-match",
                                "function": func.name,
                                "address": hex(getattr(ins, "address", func.start)),
                                "text": text
                            })
                    except Exception:
                        continue
            except Exception:
                continue

        # If we know the member offset, try to find global instances and code-refs
        if member_offset is not None:
            try:
                for var_addr in list(self._current_view.data_vars):
                    try:
                        t = None
                        if hasattr(self._current_view, "get_type_at"):
                            t = self._current_view.get_type_at(var_addr)
                        t_str = str(t) if t is not None else ""
                        # crude match for exact or pointer to struct
                        if t_str == struct_name or t_str.endswith(f"* {struct_name}") or struct_name in t_str:
                            field_addr = var_addr + member_offset
                            # code refs to this absolute address
                            try:
                                for ref in list(self._current_view.get_code_refs(field_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    results.append({
                                        "kind": "global-field-ref",
                                        "function": fn_name,
                                        "address": hex(ref.address),
                                        "field_address": hex(field_addr),
                                    })
                            except Exception:
                                pass
                    except Exception:
                        continue
            except Exception:
                pass

        return results

    def get_xrefs_to_type(self, type_name: str) -> Dict[str, Any]:
        """Get cross references/usages related to a struct/type name.

        Best-effort heuristics:
        - Finds global data variables whose type string mentions the type name; includes code refs to those globals
        - Scans HLIL text for instructions mentioning the type (casts/annotations)
        - Marks functions whose signature mentions the type
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        type_name = str(type_name).strip()
        tnl = type_name.lower()

        result: Dict[str, Any] = {
            "type": type_name,
            "data_instances": [],   # [{address, type, name?}]
            "data_code_references": [],  # [{function, address, target}]
            "code_references": [],  # HLIL matches [{function, address, text}]
            "functions_with_type": [],  # function names
        }

        # 1) Global data variables whose type matches the type name
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str and tnl in t_str.lower():
                        sym = self._current_view.get_symbol_at(var_addr)
                        result["data_instances"].append(
                            {
                                "address": hex(var_addr),
                                "type": t_str,
                                "name": sym.name if sym else None,
                            }
                        )
                        # Also add code refs to this global
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    result["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # 2) HLIL textual matches for the type (casts/annotations)
        try:
            import re
            # Look for the type name as a word or part of a cast/annotation
            pat = re.compile(re.escape(type_name), re.IGNORECASE)
            for func in list(self._current_view.functions):
                try:
                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                if pat.search(text):
                                    result["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                            except Exception:
                                continue
                    # 3) Functions whose signature mentions the type
                    try:
                        sig_text = str(func.type)
                        if sig_text and tnl in sig_text.lower():
                            result["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Deduplicate function list
        try:
            result["functions_with_type"] = sorted(list(set(result["functions_with_type"])) )
        except Exception:
            pass

        return result

    def get_xrefs_to_enum(self, enum_name: str) -> Dict[str, Any]:
        """Find usages of an enum by matching its member values in code and variables.

        Notes:
        - Enums are values, not addresses; there are no traditional "data references" to enums.
        - This scans for immediate constants equal to enum members and common bitmask checks.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        enum_name_str = str(enum_name).strip()
        en_lower = enum_name_str.lower()

        result: Dict[str, Any] = {
            "enum": enum_name_str,
            "members": [],  # [{name, value}]
            "usages": [],   # [{function, address, text, member, value}]
        }

        # Locate the enum type and collect members
        enum_type = None
        try:
            for t in self._current_view.types.values():
                try:
                    # Match by exact name or case-insensitive
                    if getattr(t, "type_class", None) == TypeClass.EnumerationTypeClass:
                        tname = getattr(t, "name", None)
                        if tname and tname.lower() == en_lower:
                            enum_type = t
                            break
                except Exception:
                    continue
        except Exception:
            pass

        # If not found by exact name, try substring match
        if enum_type is None:
            try:
                for t in self._current_view.types.values():
                    try:
                        if getattr(t, "type_class", None) == TypeClass.EnumerationTypeClass:
                            tname = getattr(t, "name", "")
                            if tname and en_lower in tname.lower():
                                enum_type = t
                                break
                    except Exception:
                        continue
            except Exception:
                pass

        members: List[Dict[str, Any]] = []
        values: List[int] = []
        if enum_type is not None:
            try:
                for m in getattr(enum_type, "members", []):
                    try:
                        name = getattr(m, "name", None)
                        val = getattr(m, "value", None)
                        if name is not None and isinstance(val, int):
                            members.append({"name": name, "value": val})
                            values.append(val)
                    except Exception:
                        continue
            except Exception:
                pass

        result["members"] = members

        # Build simple patterns for HLIL text matching of constants (hex)
        import re
        hex_patterns = []
        for v in values:
            hex_patterns.append(re.compile(rf"0x{v:x}\b", re.IGNORECASE))
        # Also a single combined pattern to speed up
        combined_hex = None
        if values:
            combined_hex = re.compile(r"(" + "|".join([rf"0x{v:x}\b" for v in values]) + ")", re.IGNORECASE)

        # Scan functions for matches
        for func in list(self._current_view.functions):
            try:
                if hasattr(func, "hlil") and func.hlil:
                    for ins in func.hlil.instructions:
                        try:
                            text = str(ins)
                            matched_val = None
                            if combined_hex is not None:
                                m = combined_hex.search(text)
                                if m:
                                    # parse the matched hex back to int to map member name
                                    try:
                                        matched_val = int(m.group(0), 16)
                                    except Exception:
                                        matched_val = None
                            if matched_val is not None:
                                member_name = None
                                for mem in members:
                                    if mem["value"] == matched_val:
                                        member_name = mem["name"]
                                        break
                                result["usages"].append(
                                    {
                                        "function": func.name,
                                        "address": hex(getattr(ins, "address", func.start)),
                                        "text": text,
                                        "member": member_name,
                                        "value": matched_val,
                                    }
                                )
                        except Exception:
                            continue
            except Exception:
                continue

        return result

    def get_xrefs_to_struct(self, struct_name: str) -> Dict[str, Any]:
        """Get cross references/usages related specifically to a struct name.

        Includes:
        - members: list of struct members with offsets and types
        - data_instances: globals whose type mentions the struct
        - data_code_references: code refs to those globals
        - field_code_references: code refs to addresses of global_instance + member offset
        - code_references: HLIL lines with member access (".field"/"->field")
        - functions_with_type: functions whose signatures mention the struct
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        name = str(struct_name).strip()
        name_l = name.lower()
        # Build candidate names to handle common PE struct aliases
        candidate_names = {name}
        # Remove leading underscore variant
        if name.startswith("_"):
            candidate_names.add(name[1:])
        else:
            candidate_names.add("_" + name)
        # PE-specific heuristics
        nl = name_l
        if "coff" in nl and "header" in nl:
            candidate_names.update({"IMAGE_FILE_HEADER", "_IMAGE_FILE_HEADER"})
        if ("pe64" in nl or "optional_header64" in nl or "optional" in nl) and "header" in nl:
            candidate_names.update({"IMAGE_OPTIONAL_HEADER64", "_IMAGE_OPTIONAL_HEADER64"})
        if ("pe32" in nl or "optional_header32" in nl or ("optional" in nl and "64" not in nl)) and "header" in nl:
            candidate_names.update({"IMAGE_OPTIONAL_HEADER32", "_IMAGE_OPTIONAL_HEADER32"})
        if "dos" in nl and "header" in nl:
            candidate_names.update({"IMAGE_DOS_HEADER", "_IMAGE_DOS_HEADER"})
        candidate_names_l = {c.lower() for c in candidate_names}

        out: Dict[str, Any] = {
            "struct": name,
            "members": [],
            "data_instances": [],
            "data_code_references": [],
            "field_code_references": [],
            "code_references": [],
            "functions_with_type": [],
            "vars_with_type": [],
            "code_references_by_cast": [],
        }

        # Resolve the struct type and members
        members = []
        try:
            for t in self._current_view.types.values():
                try:
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        if tl == name_l or name_l in tl or tl in candidate_names_l:
                            for m in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                                try:
                                    members.append(
                                        {
                                            "name": getattr(m, "name", None),
                                            "offset": int(getattr(m, "offset", 0))
                                            if hasattr(m, "offset")
                                            else None,
                                            "type": str(getattr(m, "type", ""))
                                            if hasattr(m, "type")
                                            else None,
                                        }
                                    )
                                except Exception:
                                    continue
                            break
                except Exception:
                    continue
        except Exception:
            pass
        out["members"] = members

        # Gather globals with this struct in their type string
        global_instances: List[int] = []
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str:
                        tl = t_str.lower()
                        if name_l in tl or any(cn in tl for cn in candidate_names_l):
                            sym = self._current_view.get_symbol_at(var_addr)
                            out["data_instances"].append(
                                {
                                    "address": hex(var_addr),
                                    "type": t_str,
                                    "name": sym.name if sym else None,
                                }
                            )
                            global_instances.append(var_addr)
                            # Code refs to the variable itself
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = (
                                        ref.function.name
                                        if getattr(ref, "function", None)
                                        else None
                                    )
                                    out["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # Also gather symbol-based instances whose name mentions the struct alias
        symbol_instances: List[int] = []
        try:
            for sym in list(self._current_view.get_symbols()):
                try:
                    sname = getattr(sym, "name", "") or ""
                    sfull = getattr(sym, "full_name", "") or ""
                    sl = (sname + " " + sfull).lower()
                    if any(cn in sl for cn in candidate_names_l):
                        addr = getattr(sym, "address", None)
                        if isinstance(addr, int):
                            # capture as data instance if not already present
                            out["data_instances"].append(
                                {
                                    "address": hex(addr),
                                    "type": None,
                                    "name": sname,
                                }
                            )
                            symbol_instances.append(addr)
                            # code refs to this symbol
                            try:
                                if hasattr(self._current_view, "get_code_refs"):
                                    for ref in list(self._current_view.get_code_refs(addr)):
                                        fn_name = (
                                            ref.function.name
                                            if getattr(ref, "function", None)
                                            else None
                                        )
                                        out["data_code_references"].append(
                                            {
                                                "function": fn_name,
                                                "address": hex(ref.address),
                                                "target": hex(addr),
                                            }
                                        )
                            except Exception:
                                pass
                except Exception:
                    continue
        except Exception:
            pass

        # Code refs to computed field addresses for each global instance
        if members and (global_instances or symbol_instances):
            try:
                for base in list(set(global_instances + symbol_instances)):
                    for m in members:
                        try:
                            off = m.get("offset")
                            if off is None:
                                continue
                            field_addr = base + int(off)
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(field_addr)):
                                    fn_name = (
                                        ref.function.name
                                        if getattr(ref, "function", None)
                                        else None
                                    )
                                    out["field_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "field_address": hex(field_addr),
                                            "member": m.get("name"),
                                        }
                                    )
                        except Exception:
                            continue
            except Exception:
                pass

        # If the struct is contained as a field of another struct, try deriving field addresses from parent instances
        try:
            parent_offsets: List[Dict[str, Any]] = []
            for t in self._current_view.types.values():
                try:
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        # scan members for types that mention our struct aliases
                        for mem in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                            try:
                                mtype = getattr(mem, "type", None)
                                mtype_str = str(mtype) if mtype is not None else ""
                                ml = mtype_str.lower()
                                if ml and (name_l in ml or any(cn in ml for cn in candidate_names_l)):
                                    parent_offsets.append(
                                        {
                                            "parent": tname,
                                            "offset": int(getattr(mem, "offset", 0)) if hasattr(mem, "offset") else None,
                                            "member": getattr(mem, "name", None),
                                        }
                                    )
                            except Exception:
                                continue
                except Exception:
                    continue

            # For each parent type, find instances and compute field address
            for po in parent_offsets:
                poff = po.get("offset")
                if poff is None:
                    continue
                parent_name = po.get("parent")
                try:
                    # scan data variables
                    for var_addr in list(self._current_view.data_vars):
                        try:
                            t = None
                            if hasattr(self._current_view, "get_type_at"):
                                t = self._current_view.get_type_at(var_addr)
                            t_str = str(t) if t is not None else ""
                            if t_str and parent_name and parent_name.lower() in t_str.lower():
                                field_addr = var_addr + poff
                                if hasattr(self._current_view, "get_code_refs"):
                                    for ref in list(self._current_view.get_code_refs(field_addr)):
                                        fn_name = (
                                            ref.function.name
                                            if getattr(ref, "function", None)
                                            else None
                                        )
                                        out["field_code_references"].append(
                                            {
                                                "function": fn_name,
                                                "address": hex(ref.address),
                                                "field_address": hex(field_addr),
                                                "member": po.get("member"),
                                            }
                                        )
                        except Exception:
                            continue
                    # scan symbols with parent type in name
                    for sym in list(self._current_view.get_symbols()):
                        try:
                            sname = getattr(sym, "name", "") or ""
                            sfull = getattr(sym, "full_name", "") or ""
                            sl = (sname + " " + sfull).lower()
                            if parent_name and parent_name.lower() in sl:
                                addr = getattr(sym, "address", None)
                                if isinstance(addr, int):
                                    field_addr = addr + poff
                                    if hasattr(self._current_view, "get_code_refs"):
                                        for ref in list(self._current_view.get_code_refs(field_addr)):
                                            fn_name = (
                                                ref.function.name
                                                if getattr(ref, "function", None)
                                                else None
                                            )
                                            out["field_code_references"].append(
                                                {
                                                    "function": fn_name,
                                                    "address": hex(ref.address),
                                                    "field_address": hex(field_addr),
                                                    "member": po.get("member"),
                                                }
                                            )
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

        # HLIL matches for member access text
        
        try:
            import re
            patterns = []
            for m in members:
                nm = m.get("name")
                if not nm:
                    continue
                patterns.append(re.compile(rf"(\.|->)\s*{re.escape(str(nm))}(\b|\W)", re.IGNORECASE))

            for func in list(self._current_view.functions):
                try:
                    # Capture variables whose type mentions the struct
                    try:
                        for v in getattr(func, "vars", []):
                            try:
                                vtype = getattr(v, "type", None)
                                vname = getattr(v, "name", None)
                                vtype_str = str(vtype) if vtype is not None else ""
                                if vtype_str and name_l in vtype_str.lower():
                                    out["vars_with_type"].append({
                                        "function": func.name,
                                        "var": vname,
                                        "type": vtype_str,
                                    })
                            except Exception:
                                continue
                    except Exception:
                        pass

                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                if any(p.search(text) for p in patterns):
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                                # Also capture casts/annotations explicitly mentioning the struct name
                                tl = text.lower()
                                if name_l in tl or any(cn in tl for cn in candidate_names_l):
                                    # Heuristic: detect patterns like '(COFF_Header*)' or '(struct COFF_Header*)'
                                    cast_pat = r"\(.*(" + "|".join(re.escape(c) for c in candidate_names) + r").*\)"
                                    if re.search(cast_pat, text, re.IGNORECASE):
                                        out["code_references_by_cast"].append(
                                            {
                                                "function": func.name,
                                                "address": hex(getattr(ins, "address", func.start)),
                                                "text": text,
                                            }
                                        )
                            except Exception:
                                continue
                    # Functions whose signature mentions the struct
                    try:
                        sig_text = str(func.type)
                        if sig_text:
                            sl = sig_text.lower()
                            if name_l in sl or any(cn in sl for cn in candidate_names_l):
                                out["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Dedup functions list
        try:
            out["functions_with_type"] = sorted(list(set(out["functions_with_type"])) )
        except Exception:
            pass

        return out

    def get_xrefs_to_union(self, union_name: str) -> Dict[str, Any]:
        """Get cross references/usages related to a union type by name.

        Includes:
        - members: list of union members with offsets/types (offsets may be 0/overlapping)
        - data_instances: globals whose type mentions the union
        - data_code_references: code refs to those globals
        - code_references: HLIL lines with member access (".field"/"->field")
        - functions_with_type: functions whose signatures mention the union
        - vars_with_type: function-local variables typed as the union
        - code_references_by_cast: HLIL lines with explicit casts mentioning the union
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        name = str(union_name).strip()
        name_l = name.lower()

        out: Dict[str, Any] = {
            "union": name,
            "members": [],
            "data_instances": [],
            "data_code_references": [],
            "code_references": [],
            "functions_with_type": [],
            "vars_with_type": [],
            "code_references_by_cast": [],
        }

        # Resolve union members
        members: List[Dict[str, Any]] = []
        try:
            for t in self._current_view.types.values():
                try:
                    # Union types are presented via StructureTypeClass with UnionStructureType variant
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        if tl == name_l or name_l in tl:
                            # If the BN type exposes a variant, prefer checking for union
                            try:
                                if getattr(t, "type", None) == StructureVariant.UnionStructureType:
                                    pass
                            except Exception:
                                pass
                            for m in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                                try:
                                    members.append(
                                        {
                                            "name": getattr(m, "name", None),
                                            "offset": int(getattr(m, "offset", 0)) if hasattr(m, "offset") else None,
                                            "type": str(getattr(m, "type", "")) if hasattr(m, "type") else None,
                                        }
                                    )
                                except Exception:
                                    continue
                            break
                except Exception:
                    continue
        except Exception:
            pass
        out["members"] = members

        # Gather globals with this union in their type string
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str and name_l in t_str.lower():
                        sym = self._current_view.get_symbol_at(var_addr)
                        out["data_instances"].append(
                            {
                                "address": hex(var_addr),
                                "type": t_str,
                                "name": sym.name if sym else None,
                            }
                        )
                        # Code refs to that variable
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    out["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # HLIL member access and casts; function variables/signatures
        try:
            import re
            patterns = []
            for m in members:
                nm = m.get("name")
                if not nm:
                    continue
                patterns.append(re.compile(rf"(\.|->)\s*{re.escape(str(nm))}(\b|\W)", re.IGNORECASE))

            for func in list(self._current_view.functions):
                try:
                    # variables typed as this union
                    try:
                        for v in getattr(func, "vars", []):
                            try:
                                vtype = getattr(v, "type", None)
                                vname = getattr(v, "name", None)
                                vtype_str = str(vtype) if vtype is not None else ""
                                if vtype_str and name_l in vtype_str.lower():
                                    out["vars_with_type"].append(
                                        {
                                            "function": func.name,
                                            "var": vname,
                                            "type": vtype_str,
                                        }
                                    )
                            except Exception:
                                continue
                    except Exception:
                        pass

                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                tl = text.lower()
                                matched_member = any(p.search(text) for p in patterns) if patterns else False
                                if matched_member:
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                                # Capture casts mentioning the union
                                cast_matched = False
                                if name_l in tl:
                                    if re.search(rf"\(.*{re.escape(name)}.*\)", text, re.IGNORECASE):
                                        out["code_references_by_cast"].append(
                                            {
                                                "function": func.name,
                                                "address": hex(getattr(ins, "address", func.start)),
                                                "text": text,
                                            }
                                        )
                                        cast_matched = True
                                # Fallback: any HLIL mention of the union name counts as a code reference
                                if (not matched_member) and (not cast_matched) and (name_l in tl):
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                            except Exception:
                                continue
                    # function signature mentions
                    try:
                        sig_text = str(func.type)
                        if sig_text and name_l in sig_text.lower():
                            out["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Dedup functions list
        try:
            out["functions_with_type"] = sorted(list(set(out["functions_with_type"])) )
        except Exception:
            pass

        return out
    
