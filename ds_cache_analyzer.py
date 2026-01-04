#!/usr/bin/env python3
"""
ds_cache_analyzer.py - Enhanced "data structure cache misuse analyzer"

What it does:
- Parses `perf script` output that includes `srcline` and `addr`
- Aggregates hot source lines by sample count (proxy for "problematic")
- Uses `pahole` (DWARF) to extract struct member layout (offset/size)
- Optionally uses automatic field inference from memory addresses (--auto-infer)
- Or uses a user-provided YAML mapping from hot lines -> struct + fields accessed
- Visualizes cache-line layout with heat maps showing field hotness
- Analyzes Array of Structures (AoS) alignment issues
- Suggests field reordering to minimize cache misses

Automatic inference:
When using --auto-infer and perf events that capture memory addresses (mem-loads with aux),
the tool can automatically map memory addresses to struct fields using DWARF debug info.
This eliminates the need for manual mappings.yml in many cases.

For pointer-based access (common case), the tool:
1. Extracts struct layouts from DWARF using pahole
2. Matches memory addresses to struct fields by calculating offsets
3. Groups addresses by struct and aggregates field hotness
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

try:
    from rich import print as rprint  # type: ignore
    from rich.console import Console  # type: ignore
    from rich.table import Table  # type: ignore
    from rich.panel import Panel  # type: ignore
    console = Console()
except Exception:
    rprint = print
    console = None

try:
    import jinja2
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    jinja2 = None


CACHELINE = 64


@dataclasses.dataclass(frozen=True)
class SrcLine:
    file: str
    line: int

    def key(self) -> str:
        return f"{self.file}:{self.line}"


@dataclasses.dataclass(frozen=True)
class FunctionInfo:
    name: str
    addr: Optional[int] = None
    offset: Optional[int] = None

    def key(self) -> str:
        return self.name


@dataclasses.dataclass
class PerfSample:
    srcline: Optional[SrcLine]
    addr: Optional[int]
    event: Optional[str]
    function: Optional[FunctionInfo] = None


@dataclasses.dataclass
class StructField:
    name: str
    offset: int
    size: int
    hotness: int = 0  # Sample count for this field


@dataclasses.dataclass
class StructLayout:
    name: str
    size: Optional[int]
    fields: List[StructField]
    alignment: Optional[int] = None  # For AoS analysis


@dataclasses.dataclass
class AoSAlignmentIssue:
    """Represents an alignment issue in an array of structures"""
    struct_name: str
    struct_size: int
    cache_lines_per_struct: int
    misalignment_bytes: int
    description: str


def run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n\n{e.output}") from e


def parse_perf_script(path: str) -> List[PerfSample]:
    """
    Expected perf script format includes: event ... srcline ... addr ... function

    For example lines often contain:
      ... mem-loads ... /path/file.cpp:123 ... addr 0x7f... function_name+0xoffset
      ... cache-misses ... 0x401223 function_name(args)+0x5d
      ... TIMESTAMP: MEMORY_ADDRESS cpu_core/mem-loads-aux/: INSTRUCTION_ADDRESS function+offset

    We accept many variants by regex searching:
    - srcline: something.cpp:123
    - addr: 0xdeadbeef (hex) or decimal number before mem-loads-aux event
    - function: function_name(...)+0xoffset or function_name+0xoffset
    - event: token like mem-loads or cpu/mem-loads/... depending on config
    """
    samples: List[PerfSample] = []
    # srcline usually looks like: /path/file.cpp:123 or file.cpp:123
    srcline_re = re.compile(r"(?P<file>[^ \t:]+?\.(?:c|cc|cpp|cxx|h|hpp|hh)):(?P<line>\d+)")
    addr_re = re.compile(r"\b0x(?P<hex>[0-9a-fA-F]+)\b")
    # Pattern for mem-loads-aux: TIMESTAMP: DECIMAL_ADDRESS event_name
    # Format: "TIMESTAMP: ADDRESS cpu_core/mem-loads-aux/:" or "TIMESTAMP: ADDRESS mem-loads-aux"
    mem_loads_aux_re = re.compile(r":\s+(?P<addr>\d+)\s+[^:]*mem-loads-aux")
    # Pattern for perf mem output: EVENT_NAME/: HEX_ADDRESS
    # Format: "cpu_core/mem-loads,ldlat=30/:     7ff7129c7738 ..."
    perf_mem_addr_re = re.compile(r"(?:mem-loads|mem-stores)[^:]*/:\s+(?P<addr>[0-9a-fA-F]{8,})\b")
    # Function pattern: function_name(...)+0xoffset or function_name+0xoffset
    function_re = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\+\s*0x(?P<offset>[0-9a-fA-F]+)")
    function_simple_re = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*0x(?P<offset>[0-9a-fA-F]+)")
    # event token often appears near start after timestamp, but we search for cache/memory keywords
    event_re = re.compile(r"\b(mem-loads|mem-stores|cpu/mem-loads[^ ]*|mem-loads-aux|cpu_core/mem-loads[^ ]*|cache-misses|L1-dcache-load-misses|cpu_[a-z]+/cache-misses[^ ]*|cpu_[a-z]+/L1-dcache-load-misses[^ ]*)\b")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue

            msrc = srcline_re.search(ln)
            srcline = None
            if msrc:
                srcline = SrcLine(file=msrc.group("file"), line=int(msrc.group("line")))

            mevt = event_re.search(ln)
            evt = mevt.group(1) if mevt else None

            # Extract memory address
            addr = None
            # For perf mem output: mem-loads,ldlat=30/: HEX_ADDRESS
            if evt and ("mem-loads" in evt or "mem-stores" in evt):
                mperf = perf_mem_addr_re.search(ln)
                if mperf:
                    try:
                        addr = int(mperf.group("addr"), 16)
                    except (ValueError, AttributeError):
                        pass
            # For mem-loads-aux events, address is decimal before the event name
            if addr is None and evt and "mem-loads-aux" in evt:
                maux = mem_loads_aux_re.search(ln)
                if maux:
                    try:
                        addr = int(maux.group("addr"))
                    except (ValueError, AttributeError):
                        pass
            # Fallback to hex address pattern (0x...)
            if addr is None:
                maddr = addr_re.search(ln)
                if maddr:
                    try:
                        addr = int(maddr.group("hex"), 16)
                    except (ValueError, AttributeError):
                        pass

            # Extract function name
            func_info = None
            mfunc = function_re.search(ln)
            if not mfunc:
                mfunc = function_simple_re.search(ln)
            if mfunc:
                func_name = mfunc.group("name")
                func_offset = int(mfunc.group("offset"), 16) if mfunc else None
                func_info = FunctionInfo(name=func_name, addr=addr, offset=func_offset)

            # Keep lines that have at least srcline, addr, or function info
            if srcline or addr or func_info:
                samples.append(PerfSample(srcline=srcline, addr=addr, event=evt, function=func_info))
    return samples


def aggregate_hot_lines(samples: List[PerfSample]) -> Counter:
    """Aggregate hot source lines and functions"""
    c = Counter()
    for s in samples:
        if s.srcline:
            c[s.srcline.key()] += 1
        elif s.function:
            # Use function name as fallback when source lines aren't available
            c[f"function:{s.function.name}"] += 1
    return c


def load_mappings(path: str) -> List[dict]:
    if yaml is None:
        raise RuntimeError("pyyaml not installed. Install: python3 -m pip install --user pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "mappings" not in data:
        raise ValueError("mappings.yml must be a dict with top-level key 'mappings'")
    if not isinstance(data["mappings"], list):
        raise ValueError("'mappings' must be a list")
    return data["mappings"]


def normalize_path(p: str) -> str:
    # Keep as-is but strip common prefixes; user can match either relative or basename
    return p.replace("\\", "/")


def mapping_match(mapping: dict, srcline_key: str) -> bool:
    """
    mapping:
      match:
        file: "src/foo.cpp"  (can be basename or suffix)
        line: 123
        # OR
        function: "function_name"  (for function-based matching)
    """
    m = mapping.get("match", {})
    
    # Check for function-based matching
    want_function = m.get("function")
    if want_function:
        if srcline_key.startswith("function:"):
            got_function = srcline_key.replace("function:", "")
            return got_function == want_function or got_function.startswith(want_function)
        return False
    
    # Source line-based matching
    want_file = normalize_path(str(m.get("file", "")))
    want_line = int(m.get("line", -1))

    try:
        file_part, line_part = srcline_key.rsplit(":", 1)
        got_file = normalize_path(file_part)
        got_line = int(line_part)
    except Exception:
        return False

    if want_line != got_line:
        return False

    # allow suffix match or basename match
    if got_file.endswith(want_file) or os.path.basename(got_file) == os.path.basename(want_file):
        return True
    return False


def pahole_struct(binary: str, struct_name: str) -> str:
    # -C selects struct/class; -I prints includes sometimes; keep minimal
    return run_cmd(["pahole", "-C", struct_name, binary])


def fetch_struct_layout(binary: str, struct_name: str) -> Tuple[str, Optional[StructLayout], Optional[str]]:
    """
    Fetch struct layout using pahole. Returns (struct_name, layout, error_message).
    This function is designed to be called in parallel.
    """
    try:
        out = pahole_struct(binary, struct_name)
        layout = parse_pahole_output(struct_name, out)
        source_file = get_struct_source_file(binary, struct_name)
        return (struct_name, layout, None)
    except RuntimeError as e:
        return (struct_name, None, str(e))
    except Exception as e:
        return (struct_name, None, f"Unexpected error: {e}")


def get_struct_source_file(binary: str, struct_name: str) -> Optional[str]:
    """Try to get the source file where a struct is defined using readelf/DWARF"""
    try:
        # Use readelf to get DWARF info and find the source file
        out = run_cmd(["readelf", "-wi", binary])
        in_struct = False
        current_struct = None
        source_file = None
        
        for line in out.splitlines():
            # Look for struct definition
            if "DW_TAG_structure_type" in line or "DW_TAG_class_type" in line:
                in_struct = True
                current_struct = None
                source_file = None
                continue
            
            # Check if we're in the right struct
            if in_struct and "DW_AT_name" in line:
                match = re.search(r'DW_AT_name\s*:.*?:\s*([A-Za-z_][A-Za-z0-9_]*)', line)
                if match and match.group(1) == struct_name:
                    current_struct = struct_name
                    continue
            
            # Look for source file (DW_AT_decl_file)
            if in_struct and current_struct == struct_name and "DW_AT_decl_file" in line:
                # Extract file index
                file_match = re.search(r'DW_AT_decl_file\s*:\s*(\d+)', line)
                if file_match:
                    file_idx = int(file_match.group(1))
                    # Now find the file name in the .debug_line section or file table
                    # This is a simplified approach - we'd need to parse the full DWARF
                    # For now, try to find it in the output
                    pass
            
            # Look for source file directly in some DWARF formats
            if in_struct and current_struct == struct_name:
                # Try to find file path patterns
                file_match = re.search(r'\[(\d+)\]\s+(.+\.(?:cpp|cc|cxx|c|hpp|hh|h))', line)
                if file_match:
                    source_file = file_match.group(2)
                    break
            
            # Reset when we leave the struct
            if in_struct and ("<" in line and ">" in line and "Abbrev" in line):
                if current_struct == struct_name and source_file:
                    return source_file
                in_struct = False
                current_struct = None
        
        return source_file
    except Exception:
        return None


def is_kernel_struct(struct_name: str, source_file: Optional[str] = None) -> bool:
    """Detect if a struct is from kernel/system code"""
    # Check struct name patterns
    kernel_patterns = [
        r'^__',  # Double underscore prefix (common in kernel)
        r'^_sys_',  # System structs
        r'^sys_',  # System structs
        r'^kern_',  # Kernel structs
        r'^kernel_',  # Kernel structs
        r'^timespec$',  # Common system types
        r'^lconv$',  # Locale structs
        r'^exception_ptr$',  # Standard library types
    ]
    
    for pattern in kernel_patterns:
        if re.match(pattern, struct_name):
            return True
    
    # Check source file paths
    if source_file:
        kernel_paths = [
            '/usr/include',
            '/usr/src',
            '/lib',
            '/sys',
            '/kernel',
            'linux/',
            'sys/',
            'bits/',
            'gnu/',
        ]
        for path in kernel_paths:
            if path in source_file:
                return True
    
    return False


def parse_pahole_output(struct_name: str, out: str) -> StructLayout:
    """
    Parse typical pahole output:

    struct Foo {
        int a; /*     0     4 */
        char b; /*     4     1 */
        ...
    }; /* size: 64, cachelines: 1, members: 2 */

    We'll extract:
    - field name
    - offset
    - size
    - total size if present
    - alignment info if present
    """
    fields: List[StructField] = []
    size: Optional[int] = None
    alignment: Optional[int] = None

    # member line: "type name; /*  16  8 */"
    mem_re = re.compile(
        r"^\s*(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*/\*\s*(?P<off>\d+)\s+(?P<size>\d+)\s*\*/"
    )
    # end line: "}; /* size: 64, cachelines: 1, members: 2 */"
    size_re = re.compile(r"size:\s*(?P<size>\d+)")
    align_re = re.compile(r"aligned:\s*(?P<align>\d+)")

    for ln in out.splitlines():
        m = mem_re.match(ln)
        if m:
            fields.append(
                StructField(
                    name=m.group("name"),
                    offset=int(m.group("off")),
                    size=int(m.group("size")),
                )
            )
        ms = size_re.search(ln)
        if ms:
            try:
                size = int(ms.group("size"))
            except Exception:
                pass
        ma = align_re.search(ln)
        if ma:
            try:
                alignment = int(ma.group("align"))
            except Exception:
                pass

    if not fields:
        # pahole sometimes prints class/struct with slightly different format; show raw if failed
        raise RuntimeError(f"Failed to parse pahole output for {struct_name}. Raw output:\n\n{out}")

    return StructLayout(name=struct_name, size=size, fields=fields, alignment=alignment)


def calculate_field_hotness(layout: StructLayout, field_hotness_map: Dict[str, int]) -> None:
    """Update field hotness values from the mapping"""
    for field in layout.fields:
        field.hotness = field_hotness_map.get(field.name, 0)


def analyze_aos_alignment(layout: StructLayout) -> Optional[AoSAlignmentIssue]:
    """
    Analyze if this structure has AoS alignment issues.
    Returns an issue if the struct size doesn't align well with cache lines.
    """
    if layout.size is None:
        return None
    
    struct_size = layout.size
    cache_lines_per_struct = (struct_size + CACHELINE - 1) // CACHELINE
    
    # Check if struct size is a multiple of cache line size
    if struct_size % CACHELINE == 0:
        return None  # Perfect alignment
    
    # Calculate misalignment
    misalignment = struct_size % CACHELINE
    
    # If struct spans multiple cache lines but doesn't align, it's problematic
    if cache_lines_per_struct > 1:
        description = (
            f"Struct spans {cache_lines_per_struct} cache lines. "
            f"Each array element requires {cache_lines_per_struct} cache line loads. "
            f"Consider padding to {((struct_size // CACHELINE) + 1) * CACHELINE} bytes "
            f"or restructuring to fit in {CACHELINE} bytes."
        )
    else:
        # Single cache line but might have padding issues
        if misalignment > 0:
            description = (
                f"Struct fits in 1 cache line but has {misalignment} bytes of padding. "
                f"Consider reorganizing fields to reduce padding."
            )
        else:
            return None
    
    return AoSAlignmentIssue(
        struct_name=layout.name,
        struct_size=struct_size,
        cache_lines_per_struct=cache_lines_per_struct,
        misalignment_bytes=misalignment,
        description=description
    )


def suggest_field_reordering(layout: StructLayout) -> List[StructField]:
    """
    Suggest a field reordering that groups hot fields together in the first cache line.
    Returns a list of fields sorted by suggested order.
    """
    # Separate hot and cold fields
    hot_fields = [f for f in layout.fields if f.hotness > 0]
    cold_fields = [f for f in layout.fields if f.hotness == 0]
    
    # Sort hot fields by hotness (descending), then by size (descending for better packing)
    hot_fields.sort(key=lambda f: (-f.hotness, -f.size))
    
    # Sort cold fields by size (descending) for better packing
    cold_fields.sort(key=lambda f: -f.size)
    
    # Pack hot fields first, then cold fields
    suggested_order = hot_fields + cold_fields
    
    return suggested_order


def render_struct_cachelines(layout: StructLayout, highlight_fields: List[str], 
                             show_heatmap: bool = True) -> str:
    """
    Produce an enhanced ASCII visualization:
    - cacheline segments of 64 bytes
    - fields shown as ranges with heat map visualization
    - highlight fields with hotness indicators
    """
    total_size = layout.size if layout.size is not None else max(f.offset + f.size for f in layout.fields)
    n_lines = (total_size + CACHELINE - 1) // CACHELINE

    # build per-cacheline representation
    lines: List[str] = []
    highlight_set = set(highlight_fields)
    
    # Find max hotness for normalization
    max_hotness = max((f.hotness for f in layout.fields), default=1)

    # Precompute fields per cacheline
    per_cl: Dict[int, List[StructField]] = defaultdict(list)
    for f in layout.fields:
        start_cl = f.offset // CACHELINE
        end_cl = (f.offset + max(1, f.size) - 1) // CACHELINE
        for cl in range(start_cl, end_cl + 1):
            per_cl[cl].append(f)

    for cl in range(n_lines):
        cl_start = cl * CACHELINE
        cl_end = min(total_size, cl_start + CACHELINE)
        
        # Calculate cache line hotness (sum of field hotness in this line)
        cl_hotness = sum(f.hotness for f in per_cl.get(cl, []))
        hotness_bar = ""
        if show_heatmap and max_hotness > 0:
            intensity = min(10, int((cl_hotness / max_hotness) * 10)) if max_hotness > 0 else 0
            hotness_bar = "█" * intensity + "░" * (10 - intensity)
        
        header = f"CL{cl:02d} [{cl_start:4d}..{cl_end:4d})"
        if hotness_bar:
            header += f" [{hotness_bar}] hotness={cl_hotness}"
        lines.append(header)

        fields = sorted(per_cl.get(cl, []), key=lambda x: x.offset)
        if not fields:
            lines.append("  (no members)")
            continue

        for f in fields:
            f_start = f.offset
            f_end = f.offset + f.size
            is_hot = f.name in highlight_set or f.hotness > 0
            hotness_indicator = ""
            if f.hotness > 0:
                hotness_indicator = f"🔥{f.hotness}"
            tag = "HOT " if is_hot else "    "
            # show overlap segment within this cacheline
            seg_start = max(f_start, cl_start)
            seg_end = min(f_end, cl_start + CACHELINE)
            lines.append(
                f"  {tag}{f.name:20s} off={f_start:4d} size={f.size:4d} "
                f"{hotness_indicator:>8s}  (covers {seg_start}-{seg_end})"
            )
    return "\n".join(lines)


def sanitize_filename(name: str) -> str:
    """Sanitize a struct name for use as a filename"""
    return "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in name) + ".html"


def get_template_env():
    """Get Jinja2 template environment with custom filters"""
    if jinja2 is None:
        return None
    
    # Get the directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(script_dir, 'templates')
    
    if not os.path.exists(template_dir):
        return None
    
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Add custom filters
    def basename_filter(path: str) -> str:
        """Extract basename from a file path"""
        return os.path.basename(path) if path else ""
    
    env.filters['basename'] = basename_filter
    
    return env


def render_struct_html_page(layout: StructLayout, highlight_fields: List[str], 
                           aos_issue: Optional[AoSAlignmentIssue],
                           reordered_fields: List[StructField],
                           total_hotness: int,
                           source_file: Optional[str] = None) -> str:
    """Generate a modern HTML page for a single struct using Jinja2"""
    env = get_template_env()
    if env is None:
        raise RuntimeError("Jinja2 templates not found. Ensure templates/ directory exists with struct_detail.html")
    
    template = env.get_template('struct_detail.html')
    
    total_size = layout.size if layout.size is not None else max(f.offset + f.size for f in layout.fields)
    n_lines = (total_size + CACHELINE - 1) // CACHELINE
    max_hotness = max((f.hotness for f in layout.fields), default=1)
    
    # Calculate cache line hotness and deduplicate fields per cache line
    per_cl: Dict[int, List[StructField]] = defaultdict(list)
    per_cl_unique: Dict[int, Dict[str, StructField]] = defaultdict(dict)
    for f in layout.fields:
        start_cl = f.offset // CACHELINE
        end_cl = (f.offset + max(1, f.size) - 1) // CACHELINE
        for cl in range(start_cl, end_cl + 1):
            per_cl[cl].append(f)
            # Store unique fields by name for each cache line
            if f.name not in per_cl_unique[cl]:
                per_cl_unique[cl][f.name] = f
    
    # Convert dict to list for template
    per_cl_unique_list: Dict[int, List[StructField]] = {
        cl: sorted(fields_dict.values(), key=lambda x: x.offset)
        for cl, fields_dict in per_cl_unique.items()
    }
    
    return template.render(
        layout=layout,
        highlight_fields=highlight_fields,
        aos_issue=aos_issue,
        reordered_fields=reordered_fields,
        total_hotness=total_hotness,
        source_file=source_file,
        n_lines=n_lines,
        total_size=total_size,
        max_hotness=max_hotness,
        per_cl=per_cl_unique_list,
        CACHELINE=CACHELINE
    )


def render_index_page(structs_data: List[Tuple[str, StructLayout, int, Optional[AoSAlignmentIssue], str, Optional[str], bool]]) -> str:
    """Generate the main index page with struct listing and filtering using Jinja2"""
    env = get_template_env()
    if env is None:
        raise RuntimeError("Jinja2 templates not found. Ensure templates/ directory exists with index.html")
    
    template = env.get_template('index.html')
    
    # Sort by total hotness (descending)
    structs_data_sorted = sorted(structs_data, key=lambda x: x[2], reverse=True)
    
    return template.render(structs=structs_data_sorted, CACHELINE=CACHELINE)


def main() -> int:
    ap = argparse.ArgumentParser(description="Enhanced data-structure cache misuse analyzer")
    ap.add_argument("--binary", required=True, help="Path to ELF binary built with -g")
    ap.add_argument("--perf-script", required=True, help="Path to perf script text file")
    ap.add_argument("--mappings", help="Path to mappings.yml (optional if --auto-infer is used)")
    ap.add_argument("--auto-infer", action="store_true", 
                    help="Automatically infer struct fields from memory addresses using DWARF")
    ap.add_argument("--top", type=int, default=15, help="Top hot source lines to show")
    ap.add_argument("--html", help="Output HTML report directory (or .html file for legacy single-file mode)")
    ap.add_argument("--no-heatmap", action="store_true", help="Disable heat map visualization")
    args = ap.parse_args()

    samples = parse_perf_script(args.perf_script)
    hot = aggregate_hot_lines(samples)

    rprint(f"\nParsed {len(samples)} perf-script samples.")
    rprint(f"Found {len(hot)} unique source lines.\n")
    
    # Count samples with addresses
    samples_with_addr = [s for s in samples if s.addr is not None]
    rprint(f"Samples with memory addresses: {len(samples_with_addr)}/{len(samples)}")
    if samples_with_addr:
        rprint(f"  Address range: 0x{min(s.addr for s in samples_with_addr if s.addr):x} - 0x{max(s.addr for s in samples_with_addr if s.addr):x}")
    rprint("")

    # Print hot lines
    rprint(f"Top {args.top} hot lines (sample counts):")
    for k, v in hot.most_common(args.top):
        rprint(f"  {v:8d}  {k}")
    rprint("")

    # Load mappings or auto-infer
    mappings = []
    if args.auto_infer or not args.mappings:
        if args.auto_infer or len(samples_with_addr) > 0:
            rprint("[bold cyan]Attempting automatic field inference from memory addresses...[/bold cyan]")
            try:
                from auto_infer import auto_infer_mappings
                auto_mappings, error_msg = auto_infer_mappings(args.binary, samples, dict(hot))
                if auto_mappings:
                    rprint(f"[green]✓ Auto-inferred {len(auto_mappings)} mapping(s)[/green]\n")
                    mappings = auto_mappings
                else:
                    rprint("[yellow]⚠ Could not auto-infer mappings.[/yellow]")
                    if error_msg:
                        rprint(f"[yellow]{error_msg}[/yellow]\n")
                    else:
                        rprint("[yellow]   Tip: Use 'perf record -e cpu_core/mem-loads/ -e cpu_core/mem-loads-aux/' to capture addresses.[/yellow]\n")
                    if args.mappings:
                        mappings = load_mappings(args.mappings)
                    else:
                        rprint("[red]Error: No mappings provided and auto-inference failed.[/red]")
                        rprint("[red]   Provide --mappings or use --auto-infer with perf events that capture addresses.[/red]")
                        return 1
            except ImportError as e:
                rprint(f"[yellow]Warning: Could not import auto_infer module: {e}[/yellow]")
                if args.mappings:
                    mappings = load_mappings(args.mappings)
                else:
                    rprint("[red]Error: No mappings provided and auto-inference unavailable.[/red]")
                    return 1
        else:
            if args.mappings:
                mappings = load_mappings(args.mappings)
            else:
                rprint("[red]Error: No mappings provided and no memory addresses found.[/red]")
                rprint("[red]   Provide --mappings or use perf events that capture addresses (mem-loads with aux).[/red]")
                return 1
    else:
        mappings = load_mappings(args.mappings)

    # For each mapping, find matching hot line counts and show struct layout
    any_match = False
    html_reports = []
    
    # First pass: collect structs that need pahole calls (parallelize these)
    structs_to_fetch = []
    mapping_data = []
    
    for mp in mappings:
        # Extract source file information from mapping
        match_info = mp.get("match", {})
        source_file = match_info.get("file")
        if not source_file and match_info.get("function"):
            # For function-based matches, try to find source file from samples
            func_name = match_info.get("function")
            # Look for samples with this function to get source file
            for sample in samples:
                if sample.function and sample.function.name == func_name and sample.srcline:
                    source_file = sample.srcline.file
                    break
        struct = mp.get("struct")
        fields = mp.get("fields", [])
        field_hotness = mp.get("field_hotness", {})  # Optional: explicit hotness per field
        
        if not struct or not isinstance(fields, list):
            rprint("[warning] Skipping invalid mapping entry (needs struct + fields list).")
            continue

        matched_keys = [k for k in hot.keys() if mapping_match(mp, k)]
        if not matched_keys:
            continue

        any_match = True
        total = sum(hot[k] for k in matched_keys)
        
        manual_layout = mp.get("struct_layout")
        
        # Store mapping data for processing after parallel fetch
        mapping_data.append({
            "mapping": mp,
            "struct": struct,
            "fields": fields,
            "field_hotness": field_hotness,
            "matched_keys": matched_keys,
            "total": total,
            "source_file": source_file,
            "manual_layout": manual_layout
        })
        
        # Collect structs that need pahole calls
        if not manual_layout:
            if struct not in structs_to_fetch:
                structs_to_fetch.append(struct)
    
    # Parallel fetch struct layouts using pahole
    struct_layouts_cache: Dict[str, Tuple[Optional[StructLayout], Optional[str]]] = {}
    if structs_to_fetch:
        num_workers = min(len(structs_to_fetch), os.cpu_count() or 1)
        rprint(f"[dim]Fetching {len(structs_to_fetch)} struct layout(s) using {num_workers} worker(s)...[/dim]\n")
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_to_struct = {
                executor.submit(fetch_struct_layout, args.binary, struct_name): struct_name
                for struct_name in structs_to_fetch
            }
            
            for future in as_completed(future_to_struct):
                struct_name, layout, error = future.result()
                struct_layouts_cache[struct_name] = (layout, error)
    
    # Second pass: process mappings using fetched layouts
    for md in mapping_data:
        mp = md["mapping"]
        struct = md["struct"]
        fields = md["fields"]
        field_hotness = md["field_hotness"]
        matched_keys = md["matched_keys"]
        total = md["total"]
        source_file = md["source_file"]
        manual_layout = md["manual_layout"]
        
        rprint("=" * 80)
        rprint(f"Mapping -> struct [bold]{struct}[/bold], fields={fields}")
        rprint("Matched hot lines:")
        for k in matched_keys:
            rprint(f"  {hot[k]:8d}  {k}")
        rprint(f"Total samples for these lines: {total}\n")

        # Extract layout - try pahole first, fall back to manual specification
        layout = None
        
        if manual_layout:
            # Use manually specified layout
            fields = []
            for field_spec in manual_layout.get("fields", []):
                if isinstance(field_spec, dict):
                    fields.append(StructField(
                        name=field_spec.get("name", ""),
                        offset=int(field_spec.get("offset", 0)),
                        size=int(field_spec.get("size", 0))
                    ))
            layout = StructLayout(
                name=struct,
                size=manual_layout.get("size"),
                fields=fields,
                alignment=manual_layout.get("alignment")
            )
        else:
            # Use cached layout from parallel fetch
            cached_layout, error = struct_layouts_cache.get(struct, (None, None))
            if cached_layout:
                layout = cached_layout
                # Try to get source file from DWARF if not already found
                if not source_file:
                    source_file = get_struct_source_file(args.binary, struct)
            else:
                if error:
                    rprint(f"[yellow]Warning: Could not extract struct layout for {struct} using pahole.[/yellow]")
                    rprint(f"[yellow]Error: {error}[/yellow]")
                    rprint(f"[yellow]Tip: Add 'struct_layout' to your mapping entry to manually specify the layout.[/yellow]")
                continue
        
        # Detect if this is a kernel/system struct
        is_kernel = is_kernel_struct(struct, source_file)

        # Calculate field hotness
        # Use explicit field_hotness if provided, otherwise distribute total samples evenly
        field_hotness_map: Dict[str, int] = {}
        if isinstance(field_hotness, dict):
            field_hotness_map = {k: int(v) for k, v in field_hotness.items()}
        else:
            # Distribute total samples among fields (simple heuristic)
            per_field = total // len(fields) if fields else 0
            field_hotness_map = {str(f): per_field for f in fields}
        
        calculate_field_hotness(layout, field_hotness_map)

        rprint(f"Struct layout: {layout.name} (size={layout.size if layout.size is not None else 'unknown'})")
        if layout.alignment:
            rprint(f"Alignment: {layout.alignment} bytes")
        
        # AoS alignment analysis
        aos_issue = analyze_aos_alignment(layout)
        if aos_issue:
            rprint("\n[bold red]⚠️  Array of Structures Alignment Issue:[/bold red]")
            rprint(f"  {aos_issue.description}")
            rprint(f"  Struct size: {aos_issue.struct_size} bytes")
            rprint(f"  Cache lines per element: {aos_issue.cache_lines_per_struct}")
            rprint(f"  Misalignment: {aos_issue.misalignment_bytes} bytes\n")
        
        # Render visualization
        viz = render_struct_cachelines(
            layout, 
            highlight_fields=[str(x) for x in fields],
            show_heatmap=not args.no_heatmap
        )
        rprint(viz)
        rprint("")
        
        # Field reordering suggestion
        reordered = suggest_field_reordering(layout)
        if any(f.hotness > 0 for f in layout.fields):
            rprint("[bold cyan]💡 Suggested field reordering (hot fields first):[/bold cyan]")
            cumulative = 0
            for i, f in enumerate(reordered):
                cache_line = cumulative // CACHELINE
                hot_indicator = f"🔥{f.hotness}" if f.hotness > 0 else ""
                rprint(f"  {i+1:2d}. {f.name:20s} size={f.size:3d} {hot_indicator:>8s} -> CL{cache_line}")
                cumulative += f.size
            rprint("")
        
        # Generate HTML if requested
        if args.html:
            total_field_hotness = sum(f.hotness for f in layout.fields)
            html_reports.append((struct, layout, total_field_hotness, aos_issue, reordered, [str(x) for x in fields], source_file, is_kernel))
    
    # Write HTML report directory
    if args.html and html_reports:
        # Determine output directory
        if args.html.endswith('.html'):
            # Legacy: single file mode - extract directory name
            output_dir = os.path.dirname(args.html) or '.'
            if output_dir == '.':
                output_dir = args.html.replace('.html', '_report')
        else:
            output_dir = args.html
        
        # Create directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate individual struct pages
        structs_data_for_index = []
        for struct_name, layout, total_hotness, aos_issue, reordered_fields, highlight_fields, source_file, is_kernel in html_reports:
            # Sanitize filename
            safe_filename = sanitize_filename(struct_name)
            struct_path = os.path.join(output_dir, safe_filename)
            
            # Generate individual struct page
            struct_html = render_struct_html_page(
                layout, 
                highlight_fields, 
                aos_issue, 
                reordered_fields,
                total_hotness,
                source_file
            )
            
            with open(struct_path, "w", encoding="utf-8") as f:
                f.write(struct_html)
            
            # Collect data for index page (include safe_filename, source_file, is_kernel)
            structs_data_for_index.append((struct_name, layout, total_hotness, aos_issue, safe_filename, source_file, is_kernel))
        
        # Generate index page
        index_html = render_index_page(structs_data_for_index)
        index_path = os.path.join(output_dir, "index.html")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(index_html)
        
        rprint(f"[green]HTML report directory created: {output_dir}/[/green]")
        rprint(f"[green]  - index.html (overview with {len(html_reports)} structs)[/green]")
        rprint(f"[green]  - Individual struct pages generated[/green]\n")

    if not any_match:
        rprint("No mappings matched any hot source lines.")
        rprint("Tip: confirm perf script emits file:line that matches your mappings.yml (suffix/basename match).")

    rprint("\nNotes:")
    rprint("- Field hotness is calculated from matched perf samples.")
    rprint("- Use 'field_hotness' in mappings.yml to override per-field hotness values.")
    rprint("- AoS alignment issues indicate structures that span multiple cache lines.")
    rprint("- Suggested reordering groups hot fields together to minimize cache misses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
