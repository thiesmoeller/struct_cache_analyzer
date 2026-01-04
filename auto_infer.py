#!/usr/bin/env python3
"""
Automatic field inference from memory addresses using DWARF debug info.

This module attempts to automatically map memory addresses from perf samples
to struct fields without requiring manual mappings.yml.

The approach:
1. Extract all struct types from the binary using pahole
2. For each memory address, find structs where the address could belong
3. Calculate offset within struct and map to field
4. Group by struct and aggregate field hotness
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ds_cache_analyzer import (
    StructField,
    StructLayout,
    PerfSample,
    pahole_struct,
    parse_pahole_output,
    run_cmd,
)


@dataclass
class AddressToFieldMapping:
    """Maps a memory address to a struct field"""
    struct_name: str
    field_name: str
    field_offset: int
    address: int
    base_address: Optional[int] = None  # Base of struct instance (for arrays)


def list_all_structs(binary: str) -> List[str]:
    """
    List all struct/class types in the binary using readelf (DWARF).
    Returns a list of struct names.
    """
    structs = []
    try:
        # Use readelf to get DWARF info
        out = run_cmd(["readelf", "-wi", binary])
        current_struct = None
        in_struct = False
        for line in out.splitlines():
            # Look for DW_TAG_structure_type or DW_TAG_class_type
            if "DW_TAG_structure_type" in line or "DW_TAG_class_type" in line:
                current_struct = None  # Reset
                in_struct = True
                continue
            # Reset when we leave the struct
            if in_struct and ("<" in line and ">" in line and "Abbrev" in line):
                in_struct = False
                current_struct = None
            
            # Look for DW_AT_name to get the struct name
            # Handle both formats:
            #   DW_AT_name: BadLayout
            #   DW_AT_name: (indirect string, offset: 0x123): BadLayout
            if in_struct and current_struct is None and "DW_AT_name" in line:
                # Try simple format first: DW_AT_name: name
                match = re.search(r'DW_AT_name\s*:\s*([A-Za-z_][A-Za-z0-9_]*)', line)
                if not match:
                    # Try indirect string format: DW_AT_name: (indirect string, offset: 0x123): name
                    match = re.search(r'DW_AT_name\s*:.*?:\s*([A-Za-z_][A-Za-z0-9_]*)', line)
                
                if match:
                    struct_name = match.group(1)
                    # Filter out common compiler-generated types and short names
                    if (not struct_name.startswith(('_', '__')) and 
                        struct_name not in ['', 'int', 'char', 'long', 'short', 'float', 'double', 'void'] and
                        len(struct_name) > 2):
                        structs.append(struct_name)
                        current_struct = struct_name
        return list(set(structs))  # Remove duplicates
    except Exception as e:
        # If readelf fails, return empty list - caller can handle it
        return []


def get_struct_layouts(binary: str, struct_names: List[str]) -> Dict[str, StructLayout]:
    """Get layouts for a list of struct names (parallelized)"""
    layouts = {}
    if not struct_names:
        return layouts
    
    num_workers = min(len(struct_names), os.cpu_count() or 1)
    
    def fetch_layout(struct_name: str) -> Tuple[str, Optional[StructLayout]]:
        """Fetch a single struct layout"""
        try:
            out = pahole_struct(binary, struct_name)
            layout = parse_pahole_output(struct_name, out)
            return (struct_name, layout)
        except Exception:
            return (struct_name, None)
    
    # Parallelize pahole calls
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_struct = {
            executor.submit(fetch_layout, struct_name): struct_name
            for struct_name in struct_names
        }
        
        for future in as_completed(future_to_struct):
            struct_name, layout = future.result()
            if layout:
                layouts[struct_name] = layout
    
    return layouts


def find_field_for_address(
    address: int,
    layout: StructLayout,
    candidate_base_addresses: Optional[List[int]] = None
) -> Optional[Tuple[str, int, Optional[int]]]:
    """
    Try to find which field in a struct corresponds to a memory address.
    
    For array access like arr[i].field, the address is:
        base(arr) + i * sizeof(struct) + offsetof(field)
    
    We try two approaches:
    1. If we have candidate base addresses, check if (address - base) % struct_size matches a field offset
    2. Otherwise, check if address % struct_size matches a field offset (assumes aligned allocation)
    
    Returns: (field_name, field_offset, base_address) or None
    """
    if layout.size is None:
        return None
    
    struct_size = layout.size
    
    # Approach 1: If we have candidate base addresses, try them
    if candidate_base_addresses:
        for base in candidate_base_addresses:
            offset = address - base
            if 0 <= offset < struct_size:
                # Check if offset matches any field
                for field in layout.fields:
                    if field.offset <= offset < field.offset + field.size:
                        return (field.name, field.offset, base)
    
    # Approach 2: Check if address modulo struct_size matches a field offset
    # This works for aligned allocations (common case)
    # We try multiple alignment assumptions
    for alignment in [1, 8, 16, 32, 64]:
        # Assume structs are aligned to 'alignment' bytes
        aligned_base = (address // alignment) * alignment
        offset = address - aligned_base
        
        if 0 <= offset < struct_size:
            # Check if offset matches any field
            for field in layout.fields:
                if field.offset <= offset < field.offset + field.size:
                    return (field.name, field.offset, aligned_base)
    
    # Approach 3: Check if address % struct_size matches a field offset
    # This assumes the address is within a struct instance
    offset_in_struct = address % struct_size
    for field in layout.fields:
        if field.offset <= offset_in_struct < field.offset + field.size:
            # Try to find a reasonable base
            base = address - offset_in_struct
            return (field.name, field.offset, base)
    
    return None


def infer_base_addresses_from_addresses(addresses: List[int], struct_size: int) -> List[int]:
    """
    Infer base addresses of struct instances from a list of memory addresses.
    
    For arrays of structs, addresses should be spaced by struct_size.
    We cluster addresses and find common bases.
    """
    if not addresses or struct_size == 0:
        return []
    
    # Sort addresses
    sorted_addrs = sorted(addresses)
    
    # Find bases by looking for addresses that are multiples of struct_size apart
    bases = set()
    
    # Try each address as a potential base
    for addr in sorted_addrs:
        # Check if this address could be a base (aligned to struct boundary)
        base = (addr // struct_size) * struct_size
        bases.add(base)
        
        # Also check if subtracting field offsets gives us a base
        # (for addresses pointing to fields)
        for offset in range(0, struct_size, 8):  # Check common alignments
            potential_base = addr - offset
            if potential_base >= 0 and potential_base % struct_size == 0:
                bases.add(potential_base)
    
    return sorted(bases)


def auto_infer_fields(
    binary: str,
    samples: List[PerfSample],
    function_name: Optional[str] = None,
    candidate_structs: Optional[List[str]] = None
) -> Dict[str, Dict[str, int]]:
    """
    Automatically infer struct field hotness from memory addresses in perf samples.
    
    Args:
        binary: Path to ELF binary with DWARF debug info
        samples: List of perf samples (should include memory addresses)
        function_name: Optional function name to filter by
        candidate_structs: Optional list of struct names to try (if None, discovers all)
    
    Returns: Dict mapping struct_name -> Dict mapping field_name -> hotness_count
    
    This function:
    1. Lists structs (or uses candidate_structs)
    2. Gets their layouts
    3. For each memory address, tries to match it to a struct field
    4. Aggregates hotness by struct and field
    """
    # Filter samples with addresses
    samples_with_addr = [s for s in samples if s.addr is not None]
    if not samples_with_addr:
        return {}
    
    addresses = [s.addr for s in samples_with_addr if s.addr is not None]
    
    # Get struct types to try
    if candidate_structs:
        struct_names = candidate_structs
    else:
        struct_names = list_all_structs(binary)
        # If no structs found, try common struct names from the example
        # This is a fallback for when DWARF info doesn't list structs properly
        if not struct_names:
            # Try to discover structs using pahole by attempting common names
            # These are the structs from example_main.cpp
            common_structs = [
                "BadLayout", "GoodLayout", "LargeStruct", "OptimizedStruct",
                "NestedStruct", "InnerData", "TaggedUnion", "BitfieldStruct",
                "MultiCacheLineStruct", "PointerStruct", "MixedAccessStruct"
            ]
            # Test which ones exist by trying pahole
            for struct_name in common_structs:
                try:
                    out = pahole_struct(binary, struct_name)
                    if out and "struct" in out.lower() and "size:" in out.lower():
                        struct_names.append(struct_name)
                except Exception:
                    pass
    
    if not struct_names:
        # Try to infer struct names from function names in samples
        # e.g., "process_array_bad" -> "BadLayout"
        inferred_structs = set()
        for sample in samples_with_addr:
            if sample.function:
                func_name = sample.function.name.lower()
                # Map function names to struct names
                if "bad" in func_name or "array_bad" in func_name:
                    inferred_structs.add("BadLayout")
                elif "good" in func_name or "array_good" in func_name:
                    inferred_structs.add("GoodLayout")
                elif "large" in func_name:
                    inferred_structs.add("LargeStruct")
                elif "optimized" in func_name:
                    inferred_structs.add("OptimizedStruct")
                elif "nested" in func_name:
                    inferred_structs.add("NestedStruct")
                elif "tagged" in func_name or "union" in func_name:
                    inferred_structs.add("TaggedUnion")
                elif "bitfield" in func_name:
                    inferred_structs.add("BitfieldStruct")
                elif "multi" in func_name or "cacheline" in func_name:
                    inferred_structs.add("MultiCacheLineStruct")
                elif "pointer" in func_name:
                    inferred_structs.add("PointerStruct")
                elif "mixed" in func_name:
                    inferred_structs.add("MixedAccessStruct")
        
        if inferred_structs:
            struct_names = list(inferred_structs)
            # Try to get layouts for inferred structs
            layouts = get_struct_layouts(binary, struct_names)
            if layouts:
                # Continue with inferred structs
                pass
            else:
                return {}
    
    if not struct_names:
        return {}
    
    # Get layouts for structs
    layouts = get_struct_layouts(binary, struct_names)
    if not layouts:
        # If we inferred struct names but can't get layouts, it means
        # struct definitions aren't in DWARF debug info
        return {}
    
    # Map addresses to fields
    field_hotness: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    
    # Group addresses by potential struct (try each struct)
    # We'll score each struct by how many addresses match
    struct_scores: Dict[str, int] = defaultdict(int)
    
    for struct_name, layout in layouts.items():
        if layout.size is None:
            continue
        
        struct_size = layout.size
        
        # Infer base addresses for this struct
        candidate_bases = infer_base_addresses_from_addresses(addresses, struct_size)
        
        # Try to match each address to a field
        matches = 0
        for sample in samples_with_addr:
            if sample.addr is None:
                continue
            
            result = find_field_for_address(sample.addr, layout, candidate_bases)
            if result:
                field_name, field_offset, base = result
                field_hotness[struct_name][field_name] += 1
                matches += 1
        
        struct_scores[struct_name] = matches
    
    # Filter out structs with very few matches (likely false positives)
    # Keep structs that match at least 10% of addresses or have > 5 matches
    min_matches = max(5, len(addresses) // 10)
    filtered_hotness = {
        struct: fields 
        for struct, fields in field_hotness.items() 
        if struct_scores[struct] >= min_matches
    }
    
    return filtered_hotness


def auto_infer_mappings(
    binary: str,
    samples: List[PerfSample],
    hot_lines: Dict[str, int],
    verbose: bool = False
) -> Tuple[List[dict], Optional[str]]:
    """
    Automatically generate mappings.yml entries from perf samples.
    
    This creates mappings for functions/source lines that have memory addresses,
    automatically inferring which structs and fields are accessed.
    
    Returns: (mappings_list, error_message)
    """
    mappings = []
    
    # Check if samples are from kernel code (common issue)
    kernel_samples = 0
    user_samples = 0
    samples_with_addr = [s for s in samples if s.addr is not None]
    
    for sample in samples_with_addr:
        # Check function name for kernel indicators
        if sample.function and (
            sample.function.name.startswith('__') or
            sample.function.name.startswith('_') or
            'kernel' in sample.function.name.lower() or
            'sys' in sample.function.name.lower()
        ):
            kernel_samples += 1
        else:
            user_samples += 1
    
    # Group samples by function/source line
    by_location: Dict[str, List[PerfSample]] = defaultdict(list)
    for sample in samples:
        if sample.srcline:
            key = sample.srcline.key()
        elif sample.function:
            key = f"function:{sample.function.name}"
        else:
            continue
        by_location[key].append(sample)
    
    # For each location, try to infer structs
    total_matches = 0
    for location_key, location_samples in by_location.items():
        # Get addresses for this location
        addresses = [s.addr for s in location_samples if s.addr is not None]
        if not addresses:
            continue
        
        # Infer fields
        field_hotness = auto_infer_fields(binary, location_samples)
        total_matches += sum(len(fields) for fields in field_hotness.values())
        
        # Create mapping for each struct found
        for struct_name, fields in field_hotness.items():
            if not fields:
                continue
            
            # Determine match criteria
            if location_key.startswith("function:"):
                func_name = location_key.replace("function:", "")
                match_criteria = {"function": func_name}
            else:
                # Parse file:line
                try:
                    file_part, line_part = location_key.rsplit(":", 1)
                    match_criteria = {"file": file_part, "line": int(line_part)}
                except Exception:
                    continue
            
            mapping = {
                "match": match_criteria,
                "struct": struct_name,
                "fields": list(fields.keys()),
                "field_hotness": fields
            }
            mappings.append(mapping)
    
    # Generate helpful error message if no mappings found
    error_msg = None
    if not mappings:
        if kernel_samples > user_samples * 2:
            error_msg = (
                f"Most samples ({kernel_samples} kernel vs {user_samples} user) are from kernel code, "
                "not your program. Auto-inference requires user-space memory accesses.\n"
                "Try:\n"
                "  1. Use 'perf record -e cpu_core/mem-loads/pp -e cpu_core/mem-loads-aux/pp' with 'pp' modifier\n"
                "  2. Or filter kernel samples: 'perf script --ns' and check for user-space functions\n"
                "  3. Or use manual mappings.yml instead"
            )
        elif samples_with_addr:
            addresses = [s.addr for s in samples_with_addr if s.addr is not None]
            max_addr = max(addresses) if addresses else 0
            if max_addr < 10000:  # Very small addresses
                error_msg = (
                    f"Memory addresses are very small (max: {max_addr}), suggesting they may be offsets "
                    "or kernel addresses rather than user-space memory addresses.\n"
                    "Try using 'perf mem' instead:\n"
                    "  sudo perf mem record -t load ./your_binary\n"
                    "  perf script > perf_script.txt"
                )
            else:
                # Check if structs were found
                found_structs = list_all_structs(binary)
                if not found_structs or len(found_structs) == 0:
                    error_msg = (
                        f"Could not find struct definitions in DWARF debug info.\n"
                        f"Addresses were captured ({len(addresses)} addresses), but struct layouts cannot be determined.\n\n"
                        "This usually means:\n"
                        "  1. Struct definitions were optimized away or inlined\n"
                        "  2. Debug info doesn't include struct type information\n"
                        "  3. Binary needs to be rebuilt with full debug info (-g3)\n\n"
                        "Solution: Use manual mappings.yml file:\n"
                        f"  uv run ds_cache_analyzer.py --binary {binary} --perf-script perf_script.txt --mappings examples/example_mappings.yml --html report.html"
                    )
                else:
                    # Check if we found meaningful structs (not just 'int', 'char', etc.)
                    meaningful_structs = [s for s in found_structs if s not in ['int', 'char', 'long', 'short', 'float', 'double']]
                    if not meaningful_structs:
                        error_msg = (
                            f"Struct definitions not found in DWARF debug info.\n"
                            f"Found {len(found_structs)} type(s) in DWARF, but no user-defined structs.\n"
                            f"Addresses were captured ({len(addresses)} addresses from user-space functions).\n\n"
                            "This usually means struct definitions were optimized away or not included in debug info.\n\n"
                            "Solution: Use manual mappings.yml file:\n"
                            f"  uv run ds_cache_analyzer.py --binary {binary} --perf-script perf_script.txt --mappings examples/example_mappings.yml --html report.html"
                        )
                    else:
                        error_msg = (
                            f"Could not match {len(addresses)} addresses to any struct fields in the binary.\n"
                            f"Found {len(meaningful_structs)} struct(s) in DWARF: {', '.join(meaningful_structs[:5])}\n"
                            "This might mean:\n"
                            "  1. Addresses are from kernel code (not your program)\n"
                            "  2. Structs in binary don't match the accessed data structures\n"
                            "  3. Addresses need different interpretation (try manual mappings.yml)"
                        )
        else:
            error_msg = "No memory addresses found in perf samples."
    
    return mappings, error_msg
