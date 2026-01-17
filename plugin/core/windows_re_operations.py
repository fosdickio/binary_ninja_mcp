"""
Windows Reverse Engineering Operations for Binary Ninja MCP.

This module provides additional operations specifically useful for 
Windows binary reverse engineering, including:
- Function callers/callees analysis
- Stack layout analysis  
- Basic block information
- Crypto constant detection
- Interesting function discovery
- Call graph generation
"""

import binaryninja as bn
from typing import List, Dict, Any, Optional, Union
import re


# Known cryptographic constants for detection
CRYPTO_CONSTANTS = {
    # AES S-box (first 16 bytes)
    bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]): ("AES", "S-box"),
    # AES inverse S-box (first 16 bytes)
    bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]): ("AES", "Inverse S-box"),
    # MD5 initialization constants
    bytes([0x01, 0x23, 0x45, 0x67]): ("MD5", "Init constant A"),
    bytes([0x89, 0xab, 0xcd, 0xef]): ("MD5", "Init constant B"),
    # SHA-1 initialization constants
    bytes([0x67, 0x45, 0x23, 0x01]): ("SHA-1", "Init constant H0"),
    bytes([0xef, 0xcd, 0xab, 0x89]): ("SHA-1", "Init constant H1"),
    # DES initial permutation (first 8 bytes)
    bytes([0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02]): ("DES", "Initial permutation"),
    # RSA public exponent
    bytes([0x01, 0x00, 0x01]): ("RSA", "Common public exponent 65537"),
    # RC4 identity permutation marker
    bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]): ("RC4", "Identity permutation start"),
    # Blowfish P-array (first 8 bytes, big-endian)
    bytes([0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3]): ("Blowfish", "P-array"),
    # CRC32 polynomial
    bytes([0xdb, 0x71, 0x08, 0x41]): ("CRC32", "Polynomial (reflected)"),
}

# Interesting function name patterns for Windows RE
INTERESTING_PATTERNS = {
    "crypto_related": [
        r"(?i)crypt", r"(?i)encrypt", r"(?i)decrypt", r"(?i)aes", r"(?i)des",
        r"(?i)rsa", r"(?i)sha", r"(?i)md5", r"(?i)hash", r"(?i)cipher",
        r"(?i)key", r"(?i)iv", r"(?i)salt", r"(?i)hmac", r"(?i)pbkdf",
    ],
    "auth_related": [
        r"(?i)auth", r"(?i)login", r"(?i)logon", r"(?i)password", r"(?i)credential",
        r"(?i)token", r"(?i)session", r"(?i)license", r"(?i)valid", r"(?i)check",
    ],
    "network_related": [
        r"(?i)socket", r"(?i)connect", r"(?i)send", r"(?i)recv", r"(?i)http",
        r"(?i)url", r"(?i)download", r"(?i)upload", r"(?i)network", r"(?i)internet",
    ],
    "file_related": [
        r"(?i)file", r"(?i)read", r"(?i)write", r"(?i)open", r"(?i)close",
        r"(?i)create", r"(?i)delete", r"(?i)path", r"(?i)directory",
    ],
    "registry_related": [
        r"(?i)reg", r"(?i)registry", r"(?i)hkey", r"(?i)regopen", r"(?i)regset",
    ],
}


class WindowsREOperations:
    """Additional operations for Windows reverse engineering."""
    
    def __init__(self, binary_ops):
        self.binary_ops = binary_ops
    
    @property
    def bv(self):
        return self.binary_ops.current_view
    
    def get_function_callers(self, identifier: str) -> Dict[str, Any]:
        """Get all functions that call a specific function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        callers = []
        try:
            # Get caller sites
            for ref in func.caller_sites:
                try:
                    caller_func = ref.function if hasattr(ref, 'function') else None
                    callers.append({
                        "caller_name": caller_func.name if caller_func else "(unknown)",
                        "address": hex(caller_func.start) if caller_func else None,
                        "call_site": hex(ref.address) if hasattr(ref, 'address') else None,
                    })
                except Exception:
                    continue
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "function": func.name,
            "address": hex(func.start),
            "callers": callers
        }
    
    def get_function_callees(self, identifier: str) -> Dict[str, Any]:
        """Get all functions called by a specific function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        callees = []
        try:
            # Get callees via call_sites
            for site in func.call_sites:
                try:
                    # Get the target of the call
                    target_addr = None
                    target_name = None
                    
                    # Try to get callee from the call site
                    if hasattr(site, 'hlil') and site.hlil:
                        hlil = site.hlil
                        if hasattr(hlil, 'dest') and hasattr(hlil.dest, 'constant'):
                            target_addr = hlil.dest.constant
                    
                    if target_addr is None:
                        # Try disassembly-based approach
                        try:
                            dis = self.bv.get_disassembly(site.address)
                            if dis:
                                match = re.search(r'0x[0-9a-fA-F]+', dis)
                                if match:
                                    target_addr = int(match.group(0), 16)
                        except Exception:
                            pass
                    
                    if target_addr:
                        # Get function or symbol at target
                        target_func = self.bv.get_function_at(target_addr)
                        if target_func:
                            target_name = target_func.name
                        else:
                            sym = self.bv.get_symbol_at(target_addr)
                            if sym:
                                target_name = sym.name
                            else:
                                target_name = hex(target_addr)
                    
                    callees.append({
                        "call_site": hex(site.address),
                        "callee_name": target_name or "(indirect)",
                        "callee_address": hex(target_addr) if target_addr else None,
                    })
                except Exception:
                    continue
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "function": func.name,
            "address": hex(func.start),
            "callees": callees
        }
    
    def get_function_vars(self, identifier: str) -> Dict[str, Any]:
        """Get all local variables and parameters of a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        parameters = []
        locals_ = []
        
        try:
            # Get parameter variables
            for var in func.parameter_vars:
                try:
                    parameters.append({
                        "name": var.name,
                        "type": str(var.type) if var.type else "unknown",
                    })
                except Exception:
                    continue
            
            # Get local variables
            for var in func.vars:
                try:
                    # Skip parameters (already captured)
                    if var in func.parameter_vars:
                        continue
                    
                    storage = ""
                    if hasattr(var, 'storage'):
                        storage = f"[{var.storage}]"
                    elif hasattr(var, 'source_type'):
                        storage = f"[{var.source_type}]"
                    
                    locals_.append({
                        "name": var.name,
                        "type": str(var.type) if var.type else "unknown",
                        "storage": storage,
                    })
                except Exception:
                    continue
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "function": func.name,
            "address": hex(func.start),
            "parameters": parameters,
            "locals": locals_
        }
    
    def get_basic_blocks(self, identifier: str) -> Dict[str, Any]:
        """Get basic block information for a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        blocks = []
        try:
            for bb in func.basic_blocks:
                edges = []
                for edge in bb.outgoing_edges:
                    edge_type = str(edge.type) if hasattr(edge, 'type') else "unknown"
                    target = hex(edge.target.start) if hasattr(edge, 'target') and edge.target else "?"
                    edges.append({
                        "type": edge_type,
                        "target": target,
                    })
                
                blocks.append({
                    "start": hex(bb.start),
                    "end": hex(bb.end),
                    "instruction_count": bb.instruction_count if hasattr(bb, 'instruction_count') else None,
                    "outgoing_edges": edges,
                })
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "function": func.name,
            "address": hex(func.start),
            "blocks": blocks
        }
    
    def get_stack_layout(self, identifier: str) -> Dict[str, Any]:
        """Get stack frame layout for a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        stack_vars = []
        frame_size = 0
        
        try:
            # Get stack layout
            if hasattr(func, 'stack_layout'):
                for var in func.stack_layout:
                    try:
                        # Get storage offset safely
                        offset = 0
                        if hasattr(var, 'storage'):
                            try:
                                offset = int(var.storage)
                            except (ValueError, TypeError):
                                offset = 0
                        
                        # Get size safely
                        size = None
                        if var.type and hasattr(var.type, 'width'):
                            try:
                                size = int(var.type.width)
                            except (ValueError, TypeError):
                                size = None
                        
                        stack_vars.append({
                            "offset": offset,
                            "name": var.name if hasattr(var, 'name') else "unknown",
                            "type": str(var.type) if var.type else "unknown",
                            "size": size,
                        })
                    except Exception:
                        continue
            
            # Calculate frame size from highest/lowest offsets
            if stack_vars:
                offsets = [v.get('offset', 0) for v in stack_vars if isinstance(v.get('offset'), (int, float))]
                if offsets:
                    frame_size = max(offsets) - min(offsets)
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "function": func.name,
            "address": hex(func.start),
            "frame_size": frame_size,
            "stack_vars": sorted(stack_vars, key=lambda x: x.get('offset', 0) if isinstance(x.get('offset'), (int, float)) else 0)
        }
    
    def get_binary_info(self) -> Dict[str, Any]:
        """Get comprehensive information about the loaded binary."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        info = {
            "filename": self.bv.file.filename,
            "architecture": str(self.bv.arch) if self.bv.arch else None,
            "platform": str(self.bv.platform) if self.bv.platform else None,
            "address_size": self.bv.address_size,
            "endianness": "little" if self.bv.endianness == bn.Endianness.LittleEndian else "big",
            "entry_point": hex(self.bv.entry_point) if self.bv.entry_point else None,
            "image_base": hex(self.bv.start) if hasattr(self.bv, 'start') else None,
            "is_executable": self.bv.executable if hasattr(self.bv, 'executable') else None,
            "is_relocatable": self.bv.relocatable if hasattr(self.bv, 'relocatable') else None,
        }
        
        # Get sections
        sections = []
        try:
            for name, section in self.bv.sections.items():
                sections.append({
                    "name": name,
                    "start": hex(section.start),
                    "end": hex(section.end),
                    "size": section.end - section.start,
                })
        except Exception:
            pass
        info["sections"] = sections
        
        # PE-specific info
        pe_info = {}
        try:
            # Try to get PE headers if available
            if hasattr(self.bv, 'get_metadata'):
                # Check for PE format
                pass  # PE info extraction would go here
        except Exception:
            pass
        if pe_info:
            info["pe_info"] = pe_info
        
        return info
    
    def search_functions_regex(self, pattern: str, offset: int = 0, limit: int = 100) -> Dict[str, Any]:
        """Search for functions matching a regex pattern."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"error": f"Invalid regex pattern: {e}"}
        
        matches = []
        for func in self.bv.functions:
            try:
                if regex.search(func.name):
                    matches.append({
                        "name": func.name,
                        "address": hex(func.start),
                    })
            except Exception:
                continue
        
        return {
            "pattern": pattern,
            "matches": matches[offset:offset + limit],
            "total": len(matches)
        }
    
    def get_import_by_name(self, name: str) -> Dict[str, Any]:
        """Get detailed information about a specific imported function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        # Find the import
        found = None
        module = None
        address = None
        
        try:
            for sym in self.bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol):
                if name.lower() in sym.name.lower():
                    found = sym
                    address = sym.address
                    # Try to extract module name
                    if hasattr(sym, 'namespace') and sym.namespace:
                        module = str(sym.namespace)
                    break
        except Exception:
            pass
        
        if not found:
            return {"error": f"Import not found: {name}"}
        
        # Get cross-references
        xrefs = []
        try:
            for ref in self.bv.get_code_refs(address):
                func = ref.function if hasattr(ref, 'function') else self.bv.get_function_at(ref.address)
                xrefs.append({
                    "address": hex(ref.address),
                    "function": func.name if func else "(unknown)",
                })
        except Exception:
            pass
        
        return {
            "name": found.name,
            "address": hex(address) if address else None,
            "module": module,
            "xrefs": xrefs
        }
    
    def get_function_constants(self, identifier: str) -> Dict[str, Any]:
        """Get all constant values used in a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        constants = []
        try:
            # Use HLIL for better constant extraction
            if hasattr(func, 'hlil') and func.hlil:
                for ins in func.hlil.instructions:
                    try:
                        text = str(ins)
                        # Find hex constants
                        for match in re.finditer(r'0x[0-9a-fA-F]+', text):
                            val = int(match.group(0), 16)
                            constants.append({
                                "address": hex(getattr(ins, 'address', func.start)),
                                "value": val,
                                "context": text[:80],
                            })
                        # Find decimal constants (larger than typical small numbers)
                        for match in re.finditer(r'\b(\d{4,})\b', text):
                            if '0x' not in text[max(0, match.start()-2):match.start()]:
                                val = int(match.group(1))
                                constants.append({
                                    "address": hex(getattr(ins, 'address', func.start)),
                                    "value": val,
                                    "context": text[:80],
                                })
                    except Exception:
                        continue
        except Exception as e:
            return {"error": str(e)}
        
        # Deduplicate by value
        seen = set()
        unique_constants = []
        for c in constants:
            if c['value'] not in seen:
                seen.add(c['value'])
                unique_constants.append(c)
        
        return {
            "function": func.name,
            "constants": unique_constants
        }
    
    def get_function_overview(self, identifier: str) -> Dict[str, Any]:
        """Get a high-level summary of a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        overview = {
            "name": func.name,
            "address": hex(func.start),
            "size": func.total_bytes if hasattr(func, 'total_bytes') else None,
            "block_count": len(list(func.basic_blocks)) if func.basic_blocks else 0,
            "complexity": None,
            "calls": [],
            "strings_used": [],
            "api_calls": [],
        }
        
        try:
            # Calculate cyclomatic complexity (edges - nodes + 2)
            nodes = overview["block_count"]
            edges = 0
            for bb in func.basic_blocks:
                edges += len(list(bb.outgoing_edges))
            overview["complexity"] = edges - nodes + 2 if nodes > 0 else 0
        except Exception:
            pass
        
        try:
            # Get called functions
            callees = set()
            api_calls = set()
            for site in func.call_sites:
                try:
                    dis = self.bv.get_disassembly(site.address) or ""
                    match = re.search(r'0x[0-9a-fA-F]+', dis)
                    if match:
                        target = int(match.group(0), 16)
                        target_func = self.bv.get_function_at(target)
                        if target_func:
                            callees.add(target_func.name)
                        else:
                            sym = self.bv.get_symbol_at(target)
                            if sym:
                                name = sym.name
                                # Check if it's an import (API call)
                                if sym.type == bn.SymbolType.ImportedFunctionSymbol:
                                    api_calls.add(name)
                                else:
                                    callees.add(name)
                except Exception:
                    continue
            overview["calls"] = sorted(list(callees))
            overview["api_calls"] = sorted(list(api_calls))
        except Exception:
            pass
        
        try:
            # Get strings referenced by this function
            strings_used = []
            if hasattr(func, 'hlil') and func.hlil:
                for ins in func.hlil.instructions:
                    try:
                        text = str(ins)
                        # Look for string references
                        for match in re.finditer(r'0x[0-9a-fA-F]+', text):
                            addr = int(match.group(0), 16)
                            # Check if this is a string
                            for s in self.bv.strings:
                                if s.start == addr:
                                    strings_used.append(s.value if hasattr(s, 'value') else str(s))
                                    break
                    except Exception:
                        continue
            overview["strings_used"] = strings_used[:50]  # Limit
        except Exception:
            pass
        
        return overview
    
    def find_interesting_functions(self) -> Dict[str, Any]:
        """Find potentially interesting functions based on heuristics."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        results = {cat: [] for cat in INTERESTING_PATTERNS.keys()}
        results["high_complexity"] = []
        results["exports"] = []
        
        try:
            for func in self.bv.functions:
                name = func.name
                
                # Check against patterns
                for category, patterns in INTERESTING_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, name):
                            results[category].append({
                                "name": name,
                                "address": hex(func.start),
                            })
                            break
                
                # Check complexity
                try:
                    nodes = len(list(func.basic_blocks))
                    edges = sum(len(list(bb.outgoing_edges)) for bb in func.basic_blocks)
                    complexity = edges - nodes + 2 if nodes > 0 else 0
                    if complexity > 20:  # High complexity threshold
                        results["high_complexity"].append({
                            "name": name,
                            "address": hex(func.start),
                            "complexity": complexity,
                        })
                except Exception:
                    pass
            
            # Get exports
            for sym in self.bv.get_symbols_of_type(bn.SymbolType.FunctionSymbol):
                if hasattr(sym, 'binding') and sym.binding == bn.SymbolBinding.GlobalBinding:
                    results["exports"].append({
                        "name": sym.name,
                        "address": hex(sym.address),
                    })
        except Exception as e:
            return {"error": str(e)}
        
        # Sort high complexity by complexity value
        results["high_complexity"].sort(key=lambda x: x.get("complexity", 0), reverse=True)
        
        return results
    
    def get_call_graph(self, identifier: str, depth: int = 2, direction: str = "both") -> Dict[str, Any]:
        """Get call graph centered on a function."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        def get_callers_recursive(f, current_depth, visited):
            if current_depth <= 0 or f.start in visited:
                return []
            visited.add(f.start)
            
            callers = []
            try:
                for ref in f.caller_sites:
                    caller_func = ref.function if hasattr(ref, 'function') else None
                    if caller_func and caller_func.start not in visited:
                        node = {
                            "name": caller_func.name,
                            "address": hex(caller_func.start),
                            "children": get_callers_recursive(caller_func, current_depth - 1, visited)
                        }
                        callers.append(node)
            except Exception:
                pass
            return callers
        
        def get_callees_recursive(f, current_depth, visited):
            if current_depth <= 0 or f.start in visited:
                return []
            visited.add(f.start)
            
            callees = []
            try:
                for site in f.call_sites:
                    try:
                        dis = self.bv.get_disassembly(site.address) or ""
                        match = re.search(r'0x[0-9a-fA-F]+', dis)
                        if match:
                            target = int(match.group(0), 16)
                            target_func = self.bv.get_function_at(target)
                            if target_func and target_func.start not in visited:
                                node = {
                                    "name": target_func.name,
                                    "address": hex(target_func.start),
                                    "children": get_callees_recursive(target_func, current_depth - 1, visited)
                                }
                                callees.append(node)
                    except Exception:
                        continue
            except Exception:
                pass
            return callees
        
        result = {
            "center": {
                "name": func.name,
                "address": hex(func.start),
            }
        }
        
        if direction in ("callers", "both"):
            result["callers"] = get_callers_recursive(func, depth, set())
        
        if direction in ("callees", "both"):
            result["callees"] = get_callees_recursive(func, depth, set())
        
        return result
    
    def find_crypto_constants(self) -> Dict[str, Any]:
        """Search for known cryptographic constants in the binary."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        findings = []
        
        try:
            # Search for each known constant
            for const_bytes, (algorithm, description) in CRYPTO_CONSTANTS.items():
                # Search in data sections
                for section_name, section in self.bv.sections.items():
                    try:
                        data = self.bv.read(section.start, section.end - section.start)
                        offset = data.find(const_bytes)
                        while offset != -1:
                            addr = section.start + offset
                            # Find containing function if any
                            func = self.bv.get_function_at(addr)
                            findings.append({
                                "address": hex(addr),
                                "algorithm": algorithm,
                                "description": description,
                                "function": func.name if func else None,
                                "section": section_name,
                            })
                            offset = data.find(const_bytes, offset + 1)
                    except Exception:
                        continue
        except Exception as e:
            return {"error": str(e)}
        
        return {"findings": findings}
    
    def compare_functions(self, func1_id: str, func2_id: str) -> Dict[str, Any]:
        """Compare two functions and show similarities/differences."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func1 = self.binary_ops.get_function_by_name_or_address(func1_id)
        func2 = self.binary_ops.get_function_by_name_or_address(func2_id)
        
        if not func1:
            return {"error": f"Function not found: {func1_id}"}
        if not func2:
            return {"error": f"Function not found: {func2_id}"}
        
        def get_metrics(f):
            metrics = {
                "size": f.total_bytes if hasattr(f, 'total_bytes') else 0,
                "block_count": len(list(f.basic_blocks)) if f.basic_blocks else 0,
                "instruction_count": sum(bb.instruction_count for bb in f.basic_blocks) if f.basic_blocks else 0,
            }
            
            # Get callees
            callees = set()
            try:
                for site in f.call_sites:
                    dis = self.bv.get_disassembly(site.address) or ""
                    match = re.search(r'0x[0-9a-fA-F]+', dis)
                    if match:
                        target = int(match.group(0), 16)
                        target_func = self.bv.get_function_at(target)
                        if target_func:
                            callees.add(target_func.name)
                        else:
                            sym = self.bv.get_symbol_at(target)
                            if sym:
                                callees.add(sym.name)
            except Exception:
                pass
            metrics["callees"] = callees
            metrics["callee_count"] = len(callees)
            
            # Complexity
            nodes = metrics["block_count"]
            edges = sum(len(list(bb.outgoing_edges)) for bb in f.basic_blocks) if f.basic_blocks else 0
            metrics["complexity"] = edges - nodes + 2 if nodes > 0 else 0
            
            return metrics
        
        m1 = get_metrics(func1)
        m2 = get_metrics(func2)
        
        # Calculate similarity
        common_calls = m1["callees"] & m2["callees"]
        all_calls = m1["callees"] | m2["callees"]
        call_similarity = len(common_calls) / len(all_calls) * 100 if all_calls else 100
        
        size_similarity = min(m1["size"], m2["size"]) / max(m1["size"], m2["size"]) * 100 if max(m1["size"], m2["size"]) > 0 else 100
        
        overall_similarity = (call_similarity + size_similarity) / 2
        
        return {
            "similarity": round(overall_similarity, 1),
            "size_1": m1["size"],
            "size_2": m2["size"],
            "block_count_1": m1["block_count"],
            "block_count_2": m2["block_count"],
            "instruction_count_1": m1["instruction_count"],
            "instruction_count_2": m2["instruction_count"],
            "callee_count_1": m1["callee_count"],
            "callee_count_2": m2["callee_count"],
            "complexity_1": m1["complexity"],
            "complexity_2": m2["complexity"],
            "common_calls": sorted(list(common_calls)),
        }
    
    def tag_function(self, identifier: str, tag_type: str, comment: str = "") -> Dict[str, Any]:
        """Add a tag to a function (uses function comment as fallback)."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(identifier)
        if not func:
            return {"error": f"Function not found: {identifier}"}
        
        try:
            # Try the proper tagging API first
            try:
                # Create or get tag type
                tag_type_obj = self.bv.get_tag_type(tag_type)
                if not tag_type_obj:
                    tag_type_obj = self.bv.create_tag_type(tag_type, "⭐")
                
                # Try different ways to add the tag
                if hasattr(func, 'add_user_function_tag'):
                    func.add_user_function_tag(tag_type_obj, comment or tag_type)
                elif hasattr(func, 'create_user_function_tag'):
                    func.create_user_function_tag(tag_type_obj, comment or tag_type)
                elif hasattr(func, 'create_tag'):
                    func.create_tag(tag_type_obj, comment or tag_type)
                else:
                    raise AttributeError("No tagging method available")
                
                return {
                    "success": True,
                    "function": func.name,
                    "tag_type": tag_type,
                    "comment": comment,
                }
            except (AttributeError, TypeError):
                # Fallback: use function comment to "tag" the function
                existing_comment = func.comment or ""
                tag_marker = f"[TAG:{tag_type}]"
                if tag_marker not in existing_comment:
                    new_comment = f"{tag_marker} {comment}\n{existing_comment}" if existing_comment else f"{tag_marker} {comment}"
                    func.comment = new_comment.strip()
                
                return {
                    "success": True,
                    "function": func.name,
                    "tag_type": tag_type,
                    "comment": comment,
                    "method": "comment_fallback",
                }
        except Exception as e:
            return {"error": str(e)}
    
    def list_tags(self, tag_type: str = "") -> Dict[str, Any]:
        """List all tagged functions (checks both proper tags and comment-based tags)."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        tags = []
        try:
            for func in self.bv.functions:
                # Check proper function tags first
                if hasattr(func, 'function_tags'):
                    try:
                        for tag in func.function_tags:
                            if tag_type and tag.type.name != tag_type:
                                continue
                            tags.append({
                                "name": func.name,
                                "address": hex(func.start),
                                "tag_type": tag.type.name,
                                "comment": tag.data if hasattr(tag, 'data') else "",
                            })
                    except Exception:
                        pass
                
                # Also check for comment-based tags (fallback method)
                if func.comment:
                    import re
                    for match in re.finditer(r'\[TAG:([^\]]+)\]\s*([^\n]*)', func.comment):
                        found_tag_type = match.group(1)
                        found_comment = match.group(2).strip()
                        if tag_type and found_tag_type != tag_type:
                            continue
                        tags.append({
                            "name": func.name,
                            "address": hex(func.start),
                            "tag_type": found_tag_type,
                            "comment": found_comment,
                            "method": "comment_fallback",
                        })
        except Exception as e:
            return {"error": str(e)}
        
        return {"tags": tags}
    
    def get_possible_values(self, function_name: str, address: str, variable: str) -> Dict[str, Any]:
        """Get possible values for a variable at a specific address using dataflow analysis."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(function_name)
        if not func:
            return {"error": f"Function not found: {function_name}"}
        
        # Parse address
        try:
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    addr = int(address)
            else:
                addr = int(address)
        except (ValueError, TypeError):
            return {"error": f"Invalid address format: {address}"}
        
        result = {
            "function": func.name,
            "address": hex(addr),
            "variable": variable,
            "possible_values": [],
            "value_set": None,
        }
        
        try:
            # Try to use HLIL for dataflow analysis
            if hasattr(func, 'hlil') and func.hlil:
                hlil = func.hlil
                
                # Find the instruction at or near the address
                for ins in hlil.instructions:
                    if hasattr(ins, 'address') and ins.address == addr:
                        # Found the instruction - look for variable uses
                        ins_str = str(ins)
                        if variable in ins_str:
                            # Try to get value set if available
                            if hasattr(ins, 'get_possible_values'):
                                try:
                                    pv = ins.get_possible_values()
                                    result["value_set"] = str(pv)
                                except Exception:
                                    pass
                            
                            # Look for constants in the instruction that might relate to the variable
                            for match in re.finditer(r'0x[0-9a-fA-F]+|\b\d+\b', ins_str):
                                try:
                                    val = int(match.group(0), 16 if match.group(0).startswith('0x') else 10)
                                    result["possible_values"].append({
                                        "value": val,
                                        "hex": hex(val),
                                        "context": ins_str[:100],
                                    })
                                except ValueError:
                                    continue
                            break
                
                # If no exact match, try to find variable definitions
                for ins in hlil.instructions:
                    ins_str = str(ins)
                    # Look for assignments to the variable
                    if f"{variable} = " in ins_str or f"{variable}:" in ins_str:
                        result["possible_values"].append({
                            "definition_at": hex(getattr(ins, 'address', 0)),
                            "instruction": ins_str[:100],
                        })
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def analyze_switch_statement(self, function_name: str, address: str) -> Dict[str, Any]:
        """Analyze a switch/jump table at a specific address."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(function_name)
        if not func:
            return {"error": f"Function not found: {function_name}"}
        
        # Parse address
        try:
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    addr = int(address)
            else:
                addr = int(address)
        except (ValueError, TypeError):
            return {"error": f"Invalid address format: {address}"}
        
        result = {
            "function": func.name,
            "address": hex(addr),
            "switch_found": False,
            "cases": [],
            "default_case": None,
        }
        
        try:
            # Look for indirect jumps or switch-like patterns
            if hasattr(func, 'mlil') and func.mlil:
                mlil = func.mlil
                
                for ins in mlil.instructions:
                    if hasattr(ins, 'address') and ins.address == addr:
                        ins_str = str(ins)
                        
                        # Check if this looks like a switch
                        if 'jump' in ins_str.lower() or 'switch' in ins_str.lower():
                            result["switch_found"] = True
                            result["instruction"] = ins_str
                            
                            # Try to extract targets
                            if hasattr(ins, 'dest'):
                                result["destination"] = str(ins.dest)
                        break
            
            # Also check HLIL for switch statements
            if hasattr(func, 'hlil') and func.hlil:
                hlil = func.hlil
                
                for ins in hlil.instructions:
                    ins_str = str(ins)
                    # HLIL shows switch statements more clearly
                    if 'switch' in ins_str.lower():
                        result["switch_found"] = True
                        result["hlil_instruction"] = ins_str[:200]
                        
                        # Extract case values if visible
                        for match in re.finditer(r'case\s+(0x[0-9a-fA-F]+|\d+)', ins_str):
                            try:
                                case_val = match.group(1)
                                if case_val.startswith('0x'):
                                    case_num = int(case_val, 16)
                                else:
                                    case_num = int(case_val)
                                result["cases"].append({
                                    "value": case_num,
                                    "hex": hex(case_num),
                                })
                            except ValueError:
                                continue
            
            # Look at basic blocks for indirect jumps
            for bb in func.basic_blocks:
                if bb.start <= addr < bb.end:
                    result["basic_block"] = {
                        "start": hex(bb.start),
                        "end": hex(bb.end),
                    }
                    
                    # Check outgoing edges for multiple targets (switch pattern)
                    edges = list(bb.outgoing_edges)
                    if len(edges) > 2:  # More than just true/false suggests switch
                        result["switch_found"] = True
                        result["num_cases"] = len(edges)
                        for edge in edges:
                            if hasattr(edge, 'target') and edge.target:
                                result["cases"].append({
                                    "target": hex(edge.target.start),
                                    "type": str(edge.type) if hasattr(edge, 'type') else "unknown",
                                })
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def trace_data_flow(self, function_name: str, variable: str, from_address: str) -> Dict[str, Any]:
        """Trace the data flow of a variable from a specific point."""
        if not self.bv:
            return {"error": "No binary loaded"}
        
        func = self.binary_ops.get_function_by_name_or_address(function_name)
        if not func:
            return {"error": f"Function not found: {function_name}"}
        
        # Parse address
        try:
            if isinstance(from_address, str):
                if from_address.startswith("0x"):
                    addr = int(from_address, 16)
                else:
                    addr = int(from_address)
            else:
                addr = int(from_address)
        except (ValueError, TypeError):
            return {"error": f"Invalid address format: {from_address}"}
        
        result = {
            "function": func.name,
            "variable": variable,
            "from_address": hex(addr),
            "definitions": [],  # Where the variable is defined
            "uses": [],  # Where the variable is used
            "flow": [],  # Sequence of operations
        }
        
        try:
            # Use HLIL for better dataflow visibility
            if hasattr(func, 'hlil') and func.hlil:
                hlil = func.hlil
                
                for ins in hlil.instructions:
                    ins_str = str(ins)
                    ins_addr = getattr(ins, 'address', 0)
                    
                    # Check if variable is involved in this instruction
                    if variable in ins_str:
                        entry = {
                            "address": hex(ins_addr),
                            "instruction": ins_str[:150],
                        }
                        
                        # Determine if this is a definition or use
                        if f"{variable} = " in ins_str:
                            entry["type"] = "definition"
                            result["definitions"].append(entry)
                        elif f"= {variable}" in ins_str or f"({variable}" in ins_str or f", {variable}" in ins_str:
                            entry["type"] = "use"
                            result["uses"].append(entry)
                        else:
                            entry["type"] = "reference"
                        
                        result["flow"].append(entry)
            
            # Also try MLIL SSA for more precise dataflow
            if hasattr(func, 'mlil') and func.mlil:
                mlil = func.mlil
                if hasattr(mlil, 'ssa_form'):
                    try:
                        ssa = mlil.ssa_form
                        for ins in ssa.instructions:
                            ins_str = str(ins)
                            if variable in ins_str:
                                # Look for SSA versions
                                ssa_match = re.search(rf'{variable}#(\d+)', ins_str)
                                if ssa_match:
                                    version = ssa_match.group(1)
                                    result["flow"].append({
                                        "address": hex(getattr(ins, 'address', 0)),
                                        "instruction": ins_str[:150],
                                        "ssa_version": version,
                                        "type": "ssa_reference",
                                    })
                    except Exception:
                        pass
                        
        except Exception as e:
            result["error"] = str(e)
        
        # Sort flow by address
        result["flow"].sort(key=lambda x: int(x.get("address", "0x0"), 16))
        
        return result
