import binaryninja as bn
from typing import Optional, List, Dict, Any, Union
import weakref
import subprocess
import platform
from .config import BinaryNinjaConfig
from binaryninja.enums import TypeClass, StructureVariant
from ..utils.string_utils import escape_non_ascii
from ..utils.number_utils import convert_number as util_convert_number
import re



class BinaryOperations:
    def __init__(self, config: BinaryNinjaConfig):
        self.config = config
        self._current_view: Optional[bn.BinaryView] = None
        # Multi-binary support
        # Store weak references so closed views are auto-pruned
        self._views_by_id: dict[str, weakref.ReferenceType] = {}
        self._next_view_id: int = 1
        self._id_by_filename: dict[str, str] = {}

    @property
    def current_view(self) -> Optional[bn.BinaryView]:
        return self._current_view

    @current_view.setter
    def current_view(self, bv: Optional[bn.BinaryView]):
        self._current_view = bv
        if bv:
            bn.log_info(f"Set current binary view: {bv.file.filename}")
            try:
                self._register_view(bv)
            except Exception:
                pass
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

            try:
                if self._current_view is not None:
                    self._register_view(self._current_view)
            except Exception:
                pass
            return self._current_view
        except Exception as e:
            bn.log_error(f"Failed to load binary: {e}")
            raise

    # ---------------- Multi-binary helpers ----------------
    def _prune_views(self) -> None:
        """Remove entries for BinaryViews that no longer exist and rebuild filename map."""
        alive: dict[str, weakref.ReferenceType] = {}
        new_fn_map: dict[str, str] = {}
        alive_objs: list[object] = []
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            alive[vid] = w
            alive_objs.append(vb)
            try:
                fn = str(getattr(vb.file, 'filename', None)) if getattr(vb, 'file', None) else None
            except Exception:
                fn = None
            if fn and fn not in new_fn_map:
                new_fn_map[fn] = vid
        self._views_by_id = alive
        self._id_by_filename = new_fn_map
        
        # If current_view no longer exists among alive views, clear it
        # BUT: only do this if alive_objs is non-empty - if all weakrefs are dead,
        # we should NOT clear current_view since it holds a strong reference and
        # might be the only valid view left.
        # Also, if current_view is valid, we should re-add it to the registry.
        try:
            if self._current_view is not None:
                # Check if current_view is still valid (can access its filename)
                try:
                    _ = self._current_view.file.filename
                    cv_valid = True
                except Exception:
                    cv_valid = False
                
                if cv_valid:
                    # current_view is valid - if it's not in alive_objs, re-register it
                    if not any(obj is self._current_view for obj in alive_objs):
                        # Re-register the current view since it holds a strong reference
                        vid = str(self._next_view_id)
                        self._next_view_id += 1
                        self._views_by_id[vid] = weakref.ref(self._current_view)
                        try:
                            fn = self._current_view.file.filename
                            if fn:
                                self._id_by_filename[fn] = vid
                        except Exception:
                            pass
                else:
                    # current_view is invalid - clear it
                    self._current_view = None
        except Exception:
            pass  # Don't clear current_view on exception - leave it as is

    def _register_view(self, bv: bn.BinaryView) -> str:
        """Add a view to the managed list if not present, return its id."""
        self._prune_views()
        # Reuse existing id if the exact object is already tracked
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is bv:
                return vid
        # Prefer deduplication by canonical filename
        fn = None
        try:
            fn = str(getattr(bv.file, 'filename', None)) if getattr(bv, 'file', None) else None
        except Exception:
            fn = None
        if fn:
            # If a view for this filename already exists, reuse its id and update the view
            existing_id = self._id_by_filename.get(fn)
            if existing_id and existing_id in self._views_by_id:
                # Always store weak references so closed views can be pruned
                self._views_by_id[existing_id] = weakref.ref(bv)
                return existing_id
        # Assign a new id
        vid = str(self._next_view_id)
        self._next_view_id += 1
        self._views_by_id[vid] = weakref.ref(bv)
        if fn:
            self._id_by_filename[fn] = vid
        return vid

    def register_view(self, bv: bn.BinaryView) -> str:
        """Public wrapper to register a BinaryView and return its id."""
        return self._register_view(bv)

    def unregister_by_filename(self, filename: str) -> int:
        """Remove all tracked views that match the given absolute filename.

        Returns number of entries removed.
        """
        if not filename:
            return 0
        self._prune_views()
        to_delete: list[str] = []
        for vid, w in list(self._views_by_id.items()):
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            try:
                fn = getattr(vb.file, 'filename', None)
            except Exception:
                fn = None
            if fn == filename:
                to_delete.append(vid)
        for vid in to_delete:
            self._views_by_id.pop(vid, None)
        # Rebuild filename map and clear current_view if it matched
        try:
            cur_fn = None
            if self._current_view and getattr(self._current_view, 'file', None):
                cur_fn = getattr(self._current_view.file, 'filename', None)
            if cur_fn == filename:
                self._current_view = None
        except Exception:
            self._current_view = None
        self._prune_views()
        return len(to_delete)

    def list_open_binaries(self) -> list[dict[str, str]]:
        """Return a list of managed/open binaries with ids.

        Note: Tracks binaries opened via this plugin or explicitly registered as current_view.
        """
        items: list[dict[str, str]] = []
        
        # Cleanup and ensure current_view is registered
        # _prune_views now handles re-registering current_view if it's valid
        self._prune_views()
        
        # Deduplicate by canonical filename; prefer the id mapped in _id_by_filename
        entries: list[tuple[str, str, bool]] = []  # (id, filename, active)
        seen: set[str] = set()
        for vid, w in self._views_by_id.items():
            try:
                vb = w()
            except Exception:
                vb = None
            if vb is None:
                continue
            try:
                fn = vb.file.filename
            except Exception:
                fn = "(unknown)"
            key = fn
            if key in seen:
                continue
            seen.add(key)
            # Resolve canonical id for this filename when available
            canonical_id = self._id_by_filename.get(fn, vid)
            try:
                vb_canon_ref = self._views_by_id.get(canonical_id)
                vb_canon = vb_canon_ref() if vb_canon_ref else vb
            except Exception:
                vb_canon = vb
            entries.append((canonical_id, fn, bool(vb_canon is self._current_view)))
        # Sort by filename for stable ordering
        entries.sort(key=lambda t: (t[1] or ""))
        for cid, fn, active in entries:
            items.append({"id": cid, "filename": fn, "active": active})
        return items

    def select_view(self, ident: str) -> dict[str, str] | None:
        """Select active BinaryView by id or filename/basename.

        Returns selection info on success, None on failure.
        """
        s = (ident or "").strip()
        if not s:
            return None
        self._prune_views()
        # Try id
        w = self._views_by_id.get(s)
        vb = None
        if w is not None:
            try:
                vb = w()
            except Exception:
                vb = None
        # If user passed a 1-based ordinal (from /binaries), map it to filename
        if vb is None and s.isdigit():
            try:
                idx = int(s)
                if idx >= 1:
                    lst = self.list_open_binaries()  # sorted order
                    if 1 <= idx <= len(lst):
                        fname = lst[idx - 1].get("filename")
                        if fname:
                            map_id = self._id_by_filename.get(fname)
                            if map_id:
                                wmap = self._views_by_id.get(map_id)
                                vb = wmap() if wmap else None
            except Exception:
                vb = None
        # Try direct filename mapping
        if vb is None:
            try:
                # Exact filename
                map_id = self._id_by_filename.get(s)
                if map_id:
                    wmap = self._views_by_id.get(map_id)
                    vb = wmap() if wmap else None
            except Exception:
                vb = None
        if vb is None:
            # Try match by full filename or basename
            for vid, w2 in self._views_by_id.items():
                try:
                    v = w2()
                except Exception:
                    v = None
                if v is None:
                    continue
                try:
                    fn = v.file.filename
                except Exception:
                    fn = None
                if not fn:
                    continue
                import os as _os
                if s == fn or s == _os.path.basename(fn):
                    vb = v
                    break
        if vb is None:
            return None
        self.current_view = vb
        vid = None
        for k, wv in self._views_by_id.items():
            try:
                vv = wv()
            except Exception:
                vv = None
            if vv is vb:
                vid = k
                break
        return {"id": vid or "", "filename": getattr(vb.file, 'filename', '(unknown)')}

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

    def get_sections(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of sections with pagination.

        Returns per-section fields when available:
        - name: section name
        - start/end: hex strings
        - size: integer number of bytes (end - start)
        - type: stringified section type (if exposed by BN)
        - semantics: stringified semantics (if exposed by BN)
        - linked_section: related/paired section name if exposed
        - alignment: alignment in bytes if exposed
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []

        # Binary Ninja has exposed sections across versions either as an
        # iterable of Section objects or a dict-like object. Handle both.
        try:
            sec_container = getattr(self._current_view, "sections", None)
        except Exception:
            sec_container = None
        if not sec_container:
            return []

        def _iter_sections(container):
            try:
                # If it's a dict-like {name: Section}
                if hasattr(container, "items"):
                    for _name, _sec in list(container.items()):
                        yield _sec
                    return
            except Exception:
                pass
            # Otherwise assume it's iterable of Section objects
            try:
                for _sec in list(container):
                    yield _sec
            except Exception:
                return

        for sec in _iter_sections(sec_container):
            try:
                start = getattr(sec, "start", None)
                end = getattr(sec, "end", None)
                if start is None or end is None:
                    continue
                name = None
                try:
                    name = getattr(sec, "name", None)
                except Exception:
                    name = None
                try:
                    size = int(end) - int(start)
                except Exception:
                    size = None

                entry: Dict[str, Any] = {
                    "name": name or "",
                    "start": hex(int(start)),
                    "end": hex(int(end)),
                    "size": size,
                }

                # Optional attributes: type, semantics, linked_section, alignment
                for attr, key in (
                    ("type", "type"),
                    ("semantics", "semantics"),
                    ("linked_section", "linked_section"),
                    ("align", "alignment"),
                    ("alignment", "alignment"),
                ):
                    try:
                        val = getattr(sec, attr, None)
                        if val is not None:
                            entry[key] = str(val)
                    except Exception:
                        pass

                results.append(entry)
            except Exception:
                continue

        return results[offset : offset + limit]

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
        """Decompile a function and include addresses per statement.

        Args:
            identifier: Function name or address

        Returns:
            Decompiled HLIL-like code with address prefixes per line
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
            il = getattr(func, "hlil", None)
            if il and hasattr(il, "instructions"):
                lines: list[str] = []
                last_addr: Optional[int] = None
                for ins in il.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Fall back to MLIL with addresses
            mil = getattr(func, "mlil", None)
            if mil and hasattr(mil, "instructions"):
                lines: list[str] = []
                last_addr: Optional[int] = None
                for ins in mil.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Last resort
            return str(func)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {str(e)}")
            return None

    def get_function_il(self, identifier: Union[str, int], view: str = "hlil", ssa: bool = False) -> Optional[str]:
        """Return IL for a function with selectable view and optional SSA form.

        Args:
            identifier: Function name or address
            view: One of 'hlil', 'mlil', 'llil' (case-insensitive). Aliases: 'il' -> 'llil'.
            ssa: When True, use SSA form if available (MLIL/LLIL only)

        Returns:
            Concatenated string with one instruction per line prefixed by address.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # Ensure analysis has run for this function
        try:
            func.analysis_skipped = False
            self._current_view.update_analysis_and_wait()
        except Exception:
            pass

        v = (view or "").strip().lower()
        if v in ("il", "llil", "low", "lowlevel", "low-level", "low_level"):
            prop = "llil"
        elif v in ("mlil", "medium", "mediumlevel", "medium-level", "medium_level"):
            prop = "mlil"
        else:
            # Default to HLIL when unknown
            prop = "hlil"

        try:
            il_func = getattr(func, prop, None)
            if il_func is None:
                return None

            # Only MLIL/LLIL support SSA form in practice
            if ssa and hasattr(il_func, "ssa_form") and il_func.ssa_form is not None:
                il_func = il_func.ssa_form

            if not hasattr(il_func, "instructions"):
                # As a last resort, stringify the object
                return str(il_func)

            lines: list[str] = []
            last_addr: Optional[int] = None
            for ins in il_func.instructions:
                try:
                    addr = getattr(ins, "address", None)
                except Exception:
                    addr = None
                if addr is None:
                    addr = last_addr if last_addr is not None else func.start
                last_addr = addr
                addr_str = f"{int(addr):08x}"
                text = str(ins)
                lines.append(f"{addr_str}        {text}")
            return "\n".join(lines)
        except Exception as e:
            bn.log_error(f"Error getting {prop}{' SSA' if ssa else ''} for function {identifier}: {str(e)}")
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

    def make_function_at(self, address: str | int, architecture: str | None = None) -> Dict[str, Any]:
        """Create a function at the given address (no-op if it already exists).

        Args:
            address: Hex string (e.g., 0x401000) or integer address.
            architecture: Optional architecture name (e.g., "x86_64", "x86", "armv7").

        Returns:
            Dict with keys: status (ok|exists), address, name (if found), architecture (if resolved).

        Raises:
            RuntimeError if no binary is loaded.
            ValueError on invalid address or creation failure.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Parse address
        try:
            if isinstance(address, str) and address.lower().startswith("0x"):
                addr = int(address, 16)
            else:
                addr = int(address)
        except Exception:
            raise ValueError(f"Invalid address: {address}")

        bv = self._current_view

        # If a function already exists, return info
        try:
            existing = bv.get_function_at(addr)
            if existing:
                return {
                    "status": "exists",
                    "address": hex(addr),
                    "name": existing.name,
                    "architecture": str(getattr(existing, "arch", getattr(bv, "arch", ""))) or None,
                }
        except Exception:
            pass

        # Resolve platform if provided; otherwise use view/platform default.
        # Note: BinaryView.create_user_function expects a Platform, not an Architecture.
        plat_obj = None
        arch_token = None
        if isinstance(architecture, str):
            arch_token = architecture.strip().lower()
        if architecture and arch_token not in (None, "", "default", "auto", "platform"):
            try:
                P = getattr(__import__('binaryninja', fromlist=['Platform']), 'Platform', None)
            except Exception:
                P = None
            if P is not None:
                try:
                    plat_obj = P[architecture]
                except Exception:
                    try:
                        getp = getattr(P, 'get_by_name', None)
                        if callable(getp):
                            plat_obj = getp(architecture)
                    except Exception:
                        plat_obj = None
            # If user explicitly provided an architecture/platform name and we couldn't resolve it,
            # return an error with suggestions instead of silently using the default.
            if plat_obj is None:
                import re as _re
                from difflib import get_close_matches as _gcm
                suggestions: list[str] = []
                names: list[str] = []
                # Prefer dynamic enumeration via binaryninja.Platform
                try:
                    import binaryninja as _bn  # type: ignore
                    try:
                        names = [str(getattr(p, 'name', str(p))) for p in list(getattr(_bn, 'Platform'))]
                    except Exception:
                        names = []
                except Exception:
                    names = []
                # Fallback: try iterating via imported P if available
                if not names and P is not None:
                    try:
                        names = [str(getattr(p, 'name', str(p))) for p in list(P)]
                    except Exception:
                        names = []
                # Last resort: static catalog (kept up-to-date best-effort)
                if not names:
                    names = [
                        'decree-x86','efi-x86','efi-windows-x86','efi-x86_64','efi-windows-x86_64','efi-aarch64','efi-windows-aarch64','efi-armv7','efi-thumb2',
                        'freebsd-x86','freebsd-x86_64','freebsd-aarch64','freebsd-armv7','freebsd-thumb2',
                        'ios-aarch64','ios-armv7','ios-thumb2','ios-kernel-aarch64','ios-kernel-armv7','ios-kernel-thumb2',
                        'linux-ppc32','linux-ppcvle32','linux-ppc64','linux-ppc32_le','linux-ppc64_le','linux-rv32gc','linux-rv64gc',
                        'linux-x86','linux-x86_64','linux-x32','linux-aarch64','linux-armv7','linux-thumb2','linux-armv7eb','linux-thumb2eb',
                        'linux-mipsel','linux-mips','linux-mips3','linux-mipsel3','linux-mips64','linux-cnmips64','linux-mipsel64',
                        'mac-x86','mac-x86_64','mac-aarch64','mac-armv7','mac-thumb2','mac-kernel-x86','mac-kernel-x86_64','mac-kernel-aarch64','mac-kernel-armv7','mac-kernel-thumb2',
                        'windows-x86','windows-x86_64','windows-aarch64','windows-armv7','windows-thumb2','windows-kernel-x86','windows-kernel-x86_64','windows-kernel-windows-aarch64',
                    ]
                # Build ranked suggestions
                tl = (arch_token or "").lower()
                def _score(n: str) -> float:
                    nl = n.lower()
                    s = 0.0
                    if tl and tl in nl:
                        s += 2.0
                    # remove non-alnum for loose matching
                    tlr = _re.sub(r"[^a-z0-9]", "", tl)
                    nlr = _re.sub(r"[^a-z0-9]", "", nl)
                    if tlr and tlr in nlr:
                        s += 1.0
                    return s
                base = sorted(names)
                # Start with substring matches, then extend with close matches
                substr = [n for n in base if tl in n.lower()]
                # Use difflib for additional candidates if needed
                extra = _gcm(tl, base, n=10, cutoff=0.3) if tl else []
                cand = []
                seen = set()
                for n in substr + extra:
                    if n not in seen:
                        seen.add(n)
                        cand.append(n)
                cand.sort(key=_score, reverse=True)
                suggestions = cand[:10]
                raise ValueError(f"Unknown platform/architecture '{architecture}'")
        # Default/platform fallback when no explicit architecture provided
        if plat_obj is None:
            try:
                plat_obj = getattr(bv, 'platform', None)
            except Exception:
                plat_obj = None

        # Create the function
        try:
            if hasattr(bv, 'create_user_function'):
                if plat_obj is not None:
                    bv.create_user_function(addr, plat_obj)
                else:
                    bv.create_user_function(addr)
            elif hasattr(bv, 'add_function'):
                if plat_obj is not None:
                    bv.add_function(addr, plat_obj)
                else:
                    bv.add_function(addr)
            else:
                raise ValueError('BinaryView does not support function creation')
        except Exception as e:
            raise ValueError(f"Failed to create function: {str(e)}")

        # Fetch created function info
        try:
            fn = bv.get_function_at(addr)
        except Exception:
            fn = None
        return {
            "status": "ok",
            "address": hex(addr),
            "name": fn.name if fn else None,
            "platform": str(plat_obj) if plat_obj is not None else None,
            "architecture": str(getattr(plat_obj, 'arch', None)) if plat_obj is not None else (str(getattr(bv, 'arch', None)) if getattr(bv, 'arch', None) is not None else None),
        }

    def get_defined_data(
        self, offset: int = 0, limit: int = 100, read_len: int = 32
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables with lightweight previews and sizes.

        Returns per-item fields:
        - address: hex string
        - name/raw_name: label info if available
        - type: string if available
        - size: exact defined size in bytes if known (from BN type)
        - width: alias of size for backward compatibility
        - value: small integer value when width<=8 and readable; otherwise None
        - bytes_hex: hex string of up to preview_len bytes
        - ascii_preview: printable ASCII representation for the same bytes
        - repr: concise, human-friendly summary for LLMs (value/ASCII/hex)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self._current_view.data_vars:
            data_type = None  # may be a BN Type or a DataVariable
            value = None
            width = None
            bytes_hex = None
            ascii_preview = None
            typ_obj = None

            try:
                # Prefer DataVariable (carries underlying Type)
                dv = None
                if hasattr(self._current_view, "get_data_var_at"):
                    try:
                        dv = self._current_view.get_data_var_at(var)
                    except Exception:
                        dv = None
                if dv is not None and hasattr(dv, "type") and dv.type is not None:
                    typ_obj = dv.type
                    data_type = dv  # keep for fallback string formatting
                else:
                    # Fall back to direct type lookup
                    if hasattr(self._current_view, "get_type_at"):
                        try:
                            typ_obj = self._current_view.get_type_at(var)
                            data_type = typ_obj
                        except Exception:
                            typ_obj = None

                # Exact defined size if available
                if typ_obj is not None and hasattr(typ_obj, "width"):
                    try:
                        width = int(typ_obj.width)
                    except Exception:
                        width = None

                # Best-effort numeric read for small integers (<= 8 bytes)
                if width is not None and width <= 8:
                    try:
                        value = str(self._current_view.read_int(var, width))
                    except (ValueError, RuntimeError):
                        value = None

                # Provide bytes + ASCII preview for all cases
                # Determine effective read length
                try:
                    requested = int(read_len)
                except Exception:
                    requested = 32
                # If requested < 0 and width known, treat as "read exact size"
                if requested < 0 and width is not None:
                    eff_len = max(0, int(width))
                else:
                    eff_len = max(0, requested if requested >= 0 else 32)
                if width is not None:
                    eff_len = min(eff_len, int(width))

                try:
                    raw = self._current_view.read(var, eff_len)
                    if raw is not None:
                        try:
                            bytes_hex = raw.hex()
                        except Exception:
                            bytes_hex = None
                        try:
                            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
                        except Exception:
                            ascii_preview = None
                except (ValueError, RuntimeError, TypeError):
                    pass
            except (AttributeError, TypeError, ValueError, RuntimeError):
                value = None
                data_type = None
                typ_obj = None

            # If BN doesn't expose a width, try to infer size from call sites
            if width is None:
                try:
                    inferred = self.infer_data_size(int(var))
                    if isinstance(inferred, int) and inferred > 0:
                        width = inferred
                except Exception:
                    pass

            # Get symbol information
            sym = self._current_view.get_symbol_at(var)
            # Choose a concise repr for LLMs
            if value is not None:
                short_repr = f"int:{value}"
            elif ascii_preview:
                short_repr = f"ascii:\"{ascii_preview}\""
            elif bytes_hex:
                short_repr = f"hex:{bytes_hex}"
            else:
                short_repr = None

            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name if sym and hasattr(sym, "raw_name") else None,
                    # Prefer clean type string (avoid "<var ...>" envelope when possible)
                    "type": (str(typ_obj) if typ_obj is not None else (str(data_type) if data_type else None)),
                    "size": width,
                    "width": width,
                    "value": value,
                    "bytes_hex": bytes_hex,
                    "ascii_preview": ascii_preview,
                    "bytes_read": len(bytes_hex)//2 if bytes_hex else 0,
                    "repr": short_repr,
                }
            )

        return data_items[offset : offset + limit]

    def infer_data_size(self, address: int) -> Optional[int]:
        """Infer size for data at address when BN hasn't defined a type width.

        Strategy:
        - Prefer BN's DataVariable.type.width or get_type_at().width if available.
        - Otherwise scan HLIL for calls like memcmp/strncmp/memcpy/strncpy where
          an argument equals this address and extract the last numeric argument
          as a best-effort length. Returns the maximum constant seen.
        """
        if not self._current_view:
            return None

        # 1) BN-provided width if available
        try:
            dv = None
            if hasattr(self._current_view, "get_data_var_at"):
                dv = self._current_view.get_data_var_at(address)
            t = None
            if dv is not None and hasattr(dv, "type"):
                t = dv.type
            elif hasattr(self._current_view, "get_type_at"):
                t = self._current_view.get_type_at(address)
            if t is not None and hasattr(t, "width") and t.width:
                return int(t.width)
        except Exception:
            pass

        # 2) HLIL heuristic
        try:
            addr_hex = hex(address)
            candidates: List[int] = []
            names = ("memcmp", "strncmp", "memcpy", "strncpy")
            for func in list(self._current_view.functions):
                try:
                    il = getattr(func, "hlil", None)
                    if not il:
                        continue
                    for ins in il.instructions:
                        try:
                            text = str(ins)
                            if addr_hex not in text:
                                continue
                            if not any(n in text for n in names):
                                continue
                            # Extract all numeric constants
                            nums = re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", text)
                            vals: List[int] = []
                            for n in nums:
                                try:
                                    v = int(n, 16) if n.startswith("0x") else int(n)
                                    vals.append(v)
                                except Exception:
                                    continue
                            if vals:
                                # Heuristic: last constant in call string is likely the size
                                candidates.append(vals[-1])
                        except Exception:
                            continue
                except Exception:
                    continue
            if candidates:
                # Use the maximum plausible size
                best = max(c for c in candidates if c > 0)
                if best > 0:
                    return best
        except Exception:
            pass
        return None

    def list_local_types(self, offset: int = 0, limit: int = 100, include_libraries: bool = False) -> List[Dict[str, Any]]:
        """List local types (Types view) in the current database.

        Returns a list of dictionaries with:
        - name: type name
        - kind: struct/union/class/enum/typedef/unknown
        - decl: string form of the type (when available)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []
        seen_keys = set()
        try:
            def add_type_entry(name, tobj):
                # Normalize name to string to avoid BN QualifiedName in JSON
                try:
                    name_str = str(name) if name is not None else None
                except Exception:
                    name_str = None
                if not name_str:
                    return
                # Fallback: try to resolve missing type object by querying BV / libraries
                if tobj is None:
                    try:
                        if hasattr(self._current_view, "get_type_by_name"):
                            t2 = self._current_view.get_type_by_name(name_str)
                            if t2 is not None:
                                tobj = t2
                    except Exception:
                        pass
                    if tobj is None:
                        try:
                            plat = getattr(self._current_view, "platform", None)
                            libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                            for lib in libs:
                                get_t = getattr(lib, "get_type_by_name", None)
                                if not callable(get_t):
                                    continue
                                t3 = None
                                try:
                                    # Try QualifiedName if available
                                    try:
                                        t3 = get_t(bn.QualifiedName(name_str))
                                    except Exception:
                                        t3 = get_t(name_str)
                                except Exception:
                                    t3 = None
                                if t3 is not None:
                                    tobj = t3
                                    break
                        except Exception:
                            pass

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

                # If kind is unknown or a named typedef, try to infer underlying from declaration text
                try:
                    dlow = (decl or "").strip().lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            kind = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            kind = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            kind = "enum"
                except Exception:
                    pass

                key = (name_str, decl or "")
                if key in seen_keys:
                    return
                results.append({
                    "name": name_str,
                    "kind": kind,
                    "type_class": str(tc) if tc is not None else None,
                    "decl": decl,
                })
                seen_keys.add(key)

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

            # Source 3: platform type libraries (optional; can be heavy)
            if include_libraries:
                try:
                    plat = getattr(self._current_view, "platform", None)
                    libs = []
                    try:
                        libs = list(getattr(plat, "type_libraries", []) or [])
                    except Exception:
                        libs = []
                    for lib in libs:
                        # Try multiple ways to enumerate names in this library
                        names = []
                        try:
                            nt = getattr(lib, "named_types", None)
                            if isinstance(nt, dict):
                                names = list(nt.keys())
                        except Exception:
                            pass
                        if not names:
                            try:
                                tmap = getattr(lib, "types", None)
                                if isinstance(tmap, dict):
                                    names = list(tmap.keys())
                            except Exception:
                                pass
                        if not names:
                            try:
                                get_names = getattr(lib, "get_type_names", None)
                                if callable(get_names):
                                    names = list(get_names())
                            except Exception:
                                pass
                        # Fetch each type object if possible
                        for nm in names:
                            try:
                                tobj = None
                                try:
                                    g = getattr(lib, "get_type_by_name", None)
                                    if callable(g):
                                        tobj = g(nm)
                                except Exception:
                                    tobj = None
                                add_type_entry(nm, tobj)
                            except Exception:
                                continue
                except Exception:
                    pass
        except Exception as e:
            bn.log_error(f"Error listing local types: {e}")
        return results[offset : offset + limit]

    def search_local_types(self, query: str, offset: int = 0, limit: int = 100, include_libraries: bool = False) -> List[Dict[str, Any]]:
        """Search local/view types whose name or declaration contains the substring.

        Returns entries with {name, kind, type_class, decl}.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
        if not query:
            return []
        ql = str(query).lower()
        # Only local types by default (fast). Optionally include libraries.
        all_types = self.list_local_types(0, 1_000_000, include_libraries=include_libraries)
        matches: List[Dict[str, Any]] = []
        for t in all_types:
            try:
                name = t.get("name") or ""
                decl = t.get("decl") or ""
                if (ql in str(name).lower()) or (ql in str(decl).lower()):
                    matches.append(t)
            except Exception:
                continue
        if isinstance(limit, int) and limit < 0:
            return matches[offset:]
        return matches[offset : offset + limit]

    def get_type_info(self, name: str) -> Dict[str, Any]:
        """Resolve a type by name and return detailed information.

        Returns a dictionary with:
        - name: type name
        - kind: struct/union/class/enum/typedef/... (best-effort)
        - decl: declaration string
        - members: for struct/union [{name, type, offset}]
        - enum_members: for enums [{name, value}]
        - underlying: for typedefs, best-effort underlying declaration
        - source: local | library | unknown
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        type_name = str(name)
        tobj = None
        source = "unknown"

        # 1) Try view local resolution first
        try:
            if hasattr(self._current_view, "get_type_by_name"):
                t = self._current_view.get_type_by_name(type_name)
                if t is not None:
                    tobj = t
                    source = "local"
        except Exception:
            pass

        # 2) Fall back to platform type libraries
        if tobj is None:
            try:
                plat = getattr(self._current_view, "platform", None)
                libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                for lib in libs:
                    get_t = getattr(lib, "get_type_by_name", None)
                    if not callable(get_t):
                        continue
                    try:
                        # Try with QualifiedName if available
                        try:
                            t = get_t(bn.QualifiedName(type_name))
                        except Exception:
                            t = get_t(type_name)
                    except Exception:
                        t = None
                    if t is not None:
                        tobj = t
                        source = "library"
                        break
            except Exception:
                pass

        # Prepare defaults
        kind = "unknown"
        decl = None
        members: List[Dict[str, Any]] = []
        enum_members: List[Dict[str, Any]] = []
        underlying = None

        # Extract details from type object
        if tobj is not None:
            try:
                decl = str(tobj)
            except Exception:
                try:
                    decl = str(getattr(tobj, "type", None))
                except Exception:
                    decl = None

            tc = getattr(tobj, "type_class", None)
            if tc == TypeClass.StructureTypeClass:
                # structure variant
                try:
                    v = getattr(tobj, "type", None)
                    if v == StructureVariant.UnionStructureType:
                        kind = "union"
                    elif v == StructureVariant.ClassStructureType:
                        kind = "class"
                    else:
                        kind = "struct"
                except Exception:
                    kind = "struct"

                # collect members
                try:
                    for m in getattr(tobj, "members", getattr(getattr(tobj, "structure", None), "members", [])):
                        try:
                            members.append({
                                "name": getattr(m, "name", None),
                                "type": str(getattr(m, "type", "")) if hasattr(m, "type") else None,
                                "offset": int(getattr(m, "offset", 0)) if hasattr(m, "offset") else None,
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.EnumerationTypeClass:
                kind = "enum"
                try:
                    for em in getattr(tobj, "members", []):
                        try:
                            enum_members.append({
                                "name": getattr(em, "name", None),
                                "value": getattr(em, "value", None),
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.NamedTypeReferenceClass:
                kind = "typedef"
                # best-effort underlying from decl text
                try:
                    dlow = (decl or "").lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            underlying = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            underlying = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            underlying = "enum"
                except Exception:
                    pass

            elif tc == TypeClass.IntegerTypeClass:
                kind = "int"
            elif tc == TypeClass.FloatTypeClass:
                kind = "float"
            elif tc == TypeClass.BoolTypeClass:
                kind = "bool"
            elif tc == TypeClass.VoidTypeClass:
                kind = "void"
            elif tc == TypeClass.PointerTypeClass:
                kind = "pointer"
            elif tc == TypeClass.ArrayTypeClass:
                kind = "array"
            elif tc == TypeClass.FunctionTypeClass:
                kind = "function"

            # Infer kind from decl if still unknown
            if kind == "unknown" and decl:
                try:
                    dl = decl.lower()
                    if dl.startswith("struct ") or " struct " in dl:
                        kind = "struct"
                    elif dl.startswith("union ") or " union " in dl:
                        kind = "union"
                    elif dl.startswith("enum ") or " enum " in dl:
                        kind = "enum"
                except Exception:
                    pass

        return {
            "name": type_name,
            "kind": kind,
            "decl": decl,
            "members": members if members else None,
            "enum_members": enum_members if enum_members else None,
            "underlying": underlying,
            "source": source,
        }

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
        

    # set_integer_display removed per request


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
            # Include hex bytes column padded for readability
            bytes_col = f"{hex_bytes}".ljust(16)
            line = f"{addr_str}  {bytes_col} {disasm_text}"
            
            # Add comment at the end if any
            if comment:
                line += f"  ; {comment}"
                
            return line
        except Exception as e:
            bn.log_error(f"Error annotating instruction at {hex(addr)}: {str(e)}")
            return f"{addr:08x}  {hex_bytes} ; [Error: {str(e)}]"
            
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

    def get_entry_points(self) -> List[Dict[str, Any]]:
        """Return entry point(s) for the current binary view.

        Primarily uses `bv.entry_point`. Also includes common startup symbols like
        `_start` when resolvable.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        bv = self._current_view
        results: List[Dict[str, Any]] = []

        def _append(addr: int):
            try:
                if addr is None:
                    return
                name = None
                try:
                    sym = bv.get_symbol_at(addr)
                    if sym and getattr(sym, "name", None):
                        name = sym.name
                except Exception:
                    pass
                if name is None:
                    try:
                        func = bv.get_function_at(addr)
                        if func and getattr(func, "name", None):
                            name = func.name
                    except Exception:
                        pass
                results.append({
                    "address": hex(int(addr)),
                    "name": name,
                })
            except Exception:
                pass

        # Primary entry point
        try:
            ep = getattr(bv, "entry_point", None)
            if isinstance(ep, int) and ep >= 0:
                _append(ep)
        except Exception:
            pass

        # Common startup symbol fallback
        for sname in ("_start", "entry", "start", "WinMain", "mainCRTStartup"):
            try:
                sym = bv.get_symbol_by_name(sname) if hasattr(bv, "get_symbol_by_name") else None
                if sym and hasattr(sym, "address"):
                    addr = int(sym.address)
                    if not any(r.get("address") == hex(addr) for r in results):
                        _append(addr)
            except Exception:
                continue

        return results
            
    # Removed: get_function_code_references() in favor of address-based get_xrefs_to_* helpers
            
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

    def patch_bytes(self, address: Union[str, int], data: Union[str, bytes, List[int]], save_to_file: bool = True) -> Dict[str, Any]:
        """Patch bytes at a given address in the binary.
        
        Args:
            address: Address to patch (hex string like "0x401000" or integer)
            data: Bytes to write. Can be:
                - Hex string: "90 90" or "9090" or "0x90 0x90"
                - List of integers: [0x90, 0x90]
                - Bytes object: b"\x90\x90"
            save_to_file: If True (default), save the patched binary to disk
                
        Returns:
            Dictionary with status, address, original bytes, and patched bytes
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If address or data format is invalid
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
        
        # Parse address
        # Only treat as hex if it has "0x" prefix or contains a-f/A-F characters
        # This avoids ambiguity where "123" would be treated as hex instead of decimal
        if isinstance(address, str):
            address = address.strip()
            if address.startswith("0x") or address.startswith("0X"):
                addr = int(address, 16)
            elif any(c in "abcdefABCDEF" for c in address):
                # Contains hex letters, treat as hex
                addr = int(address, 16)
            else:
                # Pure digits, treat as decimal
                addr = int(address, 10)
        else:
            addr = int(address)
        
        # Parse data into bytes
        patch_bytes = None
        if isinstance(data, bytes):
            patch_bytes = data
        elif isinstance(data, str):
            # Try to parse as hex string
            data_str = data.strip()
            # Remove "0x" prefix if present
            if data_str.startswith("0x"):
                data_str = data_str[2:]
            # Remove spaces
            data_str = data_str.replace(" ", "").replace("\n", "").replace("\t", "")
            # Convert hex string to bytes
            try:
                patch_bytes = bytes.fromhex(data_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        elif isinstance(data, list):
            # List of integers
            try:
                patch_bytes = bytes(data)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid byte list: {e}")
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
        
        if not patch_bytes:
            raise ValueError("Empty patch data")
        
        # Read original bytes for comparison
        try:
            original_bytes = self._current_view.read(addr, len(patch_bytes))
            if original_bytes is None:
                original_bytes = b""
        except Exception as e:
            bn.log_warn(f"Could not read original bytes at {hex(addr)}: {e}")
            original_bytes = b""
        
        # Write the patch
        try:
            written = self._current_view.write(addr, patch_bytes)
            
            # Determine status based on whether all bytes were written
            if written != len(patch_bytes):
                bn.log_warn(f"Only wrote {written} of {len(patch_bytes)} bytes at {hex(addr)}")
                status = "partial"
            else:
                status = "ok"
            
            result = {
                "status": status,
                "address": hex(addr),
                "original_bytes": original_bytes.hex() if original_bytes else "",
                "patched_bytes": patch_bytes.hex(),
                "bytes_written": written,
                "bytes_requested": len(patch_bytes),
                "saved_to_file": False,
            }
            
            # Add warning message if partial write
            if status == "partial":
                result["warning"] = f"Only wrote {written} of {len(patch_bytes)} bytes"
            
            # Save to file if requested
            if save_to_file:
                try:
                    # Get the original file path
                    original_file = self._current_view.file.filename
                    if original_file:
                        # Save the patched binary back to the original file
                        if self._current_view.save(original_file):
                            result["saved_to_file"] = True
                            result["saved_path"] = original_file
                            bn.log_info(f"Patched binary saved to: {original_file}")
                            
                            # On macOS, re-sign the binary to avoid "killed" error
                            if platform.system() == "Darwin":
                                result["codesign"] = self._codesign_binary(original_file)
                        else:
                            bn.log_warn(f"Failed to save patched binary to: {original_file}")
                            result["save_error"] = "save() returned False"
                    else:
                        bn.log_warn("No original file path available for saving")
                        result["save_error"] = "No original file path"
                except Exception as save_e:
                    bn.log_warn(f"Failed to save patched binary: {save_e}")
                    result["save_error"] = str(save_e)
            
            return result
        except Exception as e:
            raise ValueError(f"Failed to patch bytes at {hex(addr)}: {str(e)}")

    def _codesign_binary(self, file_path: str) -> Dict[str, Any]:
        """Re-sign a binary on macOS after patching.
        
        On macOS, modifying a binary invalidates its code signature, causing the
        system to kill the process when executed. This method removes the old
        signature and applies an ad-hoc signature to make the binary executable.
        
        Args:
            file_path: Path to the binary file to sign
            
        Returns:
            Dictionary with codesign status and any error messages
        """
        result = {
            "attempted": True,
            "success": False,
            "platform": "macOS",
        }
        
        try:
            # Step 1: Remove existing signature (optional, codesign -f will overwrite anyway)
            remove_result = subprocess.run(
                ["codesign", "--remove-signature", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if remove_result.returncode != 0:
                # It's okay if removal fails (binary might not have been signed)
                bn.log_info(f"codesign --remove-signature returned {remove_result.returncode}: {remove_result.stderr}")
            
            # Step 2: Apply ad-hoc signature with force flag
            sign_result = subprocess.run(
                ["codesign", "-f", "-s", "-", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if sign_result.returncode == 0:
                result["success"] = True
                result["message"] = "Binary re-signed with ad-hoc signature"
                bn.log_info(f"Successfully re-signed binary: {file_path}")
            else:
                result["error"] = sign_result.stderr or f"codesign failed with code {sign_result.returncode}"
                bn.log_warn(f"Failed to re-sign binary: {result['error']}")
                
        except FileNotFoundError:
            result["error"] = "codesign command not found"
            bn.log_warn("codesign command not found - is Xcode Command Line Tools installed?")
        except subprocess.TimeoutExpired:
            result["error"] = "codesign command timed out"
            bn.log_warn("codesign command timed out")
        except Exception as e:
            result["error"] = str(e)
            bn.log_warn(f"Error during codesign: {e}")
        
        return result
    
