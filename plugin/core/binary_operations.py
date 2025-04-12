import binaryninja as bn
from typing import Optional, List, Dict, Any, Union
from .config import BinaryNinjaConfig
from binaryninja.enums import TypeClass, StructureVariant



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
