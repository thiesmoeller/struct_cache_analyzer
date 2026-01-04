# Cache Structure Analyzer

A tool to analyze C++ structure layouts for cache performance issues. It helps identify:
- Hot fields that cause cache misses due to poor layout
- Array of Structures (AoS) alignment issues
- Opportunities to reorganize fields to minimize cache line loads

## Features

- **Hotness Visualization**: Shows which fields are accessed most frequently in hot paths
- **Cache Line Heat Maps**: Visual representation of cache line usage with hotness indicators
- **AoS Alignment Analysis**: Detects when array elements span multiple cache lines
- **Field Reordering Suggestions**: Recommends field order to group hot fields together
- **HTML Reports**: Generate interactive HTML visualizations
- **Automatic Field Inference**: Automatically maps memory addresses to struct fields (when using Intel PT)

## Requirements

- Python 3.7+
- `uv` - Python package manager (recommended) or `pip`
- `pahole` (from `dwarves` package) - for extracting struct layouts from binaries
- CMake 3.15+ (for building C++ examples)
- `perf` (Linux perf tool) - for performance profiling

## Installation

### Python Setup

**Using uv (recommended):**
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Setup environment
uv sync

# Activate environment (optional)
source .venv/bin/activate
```

**Using pip:**
```bash
pip install -r requirements.txt
```

### System Dependencies

```bash
# On Debian/Ubuntu
sudo apt-get install dwarves cmake build-essential

# On Fedora/RHEL
sudo dnf install dwarves cmake gcc-c++

# On macOS
brew install dwarves cmake
```

### Build C++ Examples

```bash
# Quick build
./build.sh

# Or manually
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
```

## Quick Start

### 1. Build Your Binary with Debug Symbols

```bash
# Ensure debug symbols are included
g++ -g -O2 -o my_program my_program.cpp

# Or with CMake (already configured)
cd build && cmake --build .
```

### 2. Record Performance Data

Choose the appropriate perf event for your system:

**Option 1: Memory Loads with Addresses (Recommended for Automatic Inference)**
```bash
# Use perf mem (simplest, recommended for automatic inference)
sudo perf mem record -t load ./build/bin/example

# Alternative: Direct mem-loads events (requires Intel Processor Trace support)
sudo perf record -e '{cpu_core/mem-loads-aux/,cpu_core/mem-loads/}' \
    -g --call-graph dwarf ./build/bin/example
```

**Option 2: L1 Cache Load Misses (For Manual Mappings)**
```bash
# For Intel hybrid CPUs (i7-14700K, etc.)
perf record -e cpu_core/L1-dcache-load-misses/ -g --call-graph dwarf ./build/bin/example

# Generic (works everywhere)
perf record -e L1-dcache-load-misses -g --call-graph dwarf ./build/bin/example
```

**Option 3: Generic Cache Misses (Universal, Requires Manual Mappings)**
```bash
perf record -e cache-misses -g --call-graph dwarf ./build/bin/example
```

**Generate script output:**
```bash
perf script > perf_script.txt
```

### 3. Run the Analyzer

**Option A: Automatic Inference (When memory addresses are available)**

If you used `mem-loads` events or `perf mem`, you can use automatic inference:

```bash
uv run python ds_cache_analyzer.py \
    --binary ./build/bin/example \
    --perf-script perf_script.txt \
    --auto-infer \
    --html report.html
```

**Option B: Manual Mappings**

Create a `mappings.yml` file:

```yaml
mappings:
  # Match by function name
  - match:
      function: "process_array_bad"
    struct: "MyStruct"
    fields:
      - "hot_field"
      - "another_field"
    field_hotness:
      hot_field: 1000
      another_field: 500

  # Match by source line
  - match:
      file: "example_main.cpp"
      line: 42
    struct: "MyStruct"
    fields:
      - "hot_field"
```

Then run:
```bash
uv run python ds_cache_analyzer.py \
    --binary ./build/bin/example \
    --perf-script perf_script.txt \
    --mappings mappings.yml \
    --html report.html
```

## Understanding the Output

### Terminal Output

```
CL00 [   0..  64) [████████░░] hotness=1500
    HOT field1              off=   0 size=   8 🔥1000  (covers 0-8)
    HOT field2              off=   8 size=   4 🔥500  (covers 8-12)
    field3                  off=  12 size=   4        (covers 12-16)
```

- **CL00, CL01**: Cache line numbers (each is 64 bytes)
- **🔥N**: Hotness indicator showing N samples
- **HOT**: Marks frequently accessed fields
- **Heat bars**: Visual representation of cache line hotness

### HTML Report

Open `report.html` in your browser for:
- Interactive cache line visualization
- Color-coded hot/cold fields
- AoS alignment warnings
- Field reordering suggestions

## Perf Events Guide

### Intel i7-14700K (Alder Lake) Specific

Your CPU is a hybrid architecture:
- **P-cores (Performance cores)**: `cpu_core` PMU
- **E-cores (Efficiency cores)**: `cpu_atom` PMU

For cache analysis, focus on P-cores where hot paths typically execute:

```bash
# Best for cache analysis
perf record -e cpu_core/L1-dcache-load-misses/ -g --call-graph dwarf ./your_binary

# For detailed memory access (requires Intel PT)
perf record -e '{cpu_core/mem-loads-aux/,cpu_core/mem-loads/}' \
    -g --call-graph dwarf ./your_binary
```

### Event Comparison

| Event | Specificity | CPU Load | Best For |
|-------|-------------|----------|----------|
| `perf mem record -t load` | Very High | Medium | **Automatic inference (recommended)** |
| `cpu_core/L1-dcache-load-misses/` | High | Low | Cache analysis with manual mappings |
| `cpu_core/mem-loads/` + aux | Very High | Medium | Detailed memory access patterns |
| `cpu_core/cache-misses/` | Medium | Low | General cache analysis |
| `cache-misses` | Low | Very Low | Universal compatibility |

### Troubleshooting Perf Events

**If events are not available:**
```bash
# Check available events
perf list | grep cpu_core

# Try without PMU specification (falls back to generic)
perf record -e L1-dcache-load-misses -g --call-graph dwarf ./your_binary
```

**If you get "event not found":**
- Ensure you're running on the correct CPU (not in a VM without PMU passthrough)
- Try the generic `cache-misses` event as fallback
- Check kernel version (needs recent kernel for hybrid CPU support)

## Automatic Field Inference

The tool supports **automatic field inference** from memory addresses, eliminating the need for manual `mappings.yml` files in many cases.

### How It Works

When you use `perf` events that capture memory addresses (like `mem-loads` with `mem-loads-aux`), the analyzer can automatically:

1. Extract struct layouts from DWARF debug info using `pahole`
2. Match memory addresses to struct fields by calculating offsets
3. Group addresses by struct and aggregate field hotness
4. Generate mappings automatically without manual YAML configuration

### Requirements

1. **Binary must have DWARF debug info**: Build with `-g3` flag
2. **Perf must capture memory addresses**: Use events that provide addresses
3. **Intel Processor Trace (PT) support**: Required for `mem-loads-aux` events

### Usage

```bash
# Option 1: Using perf mem (recommended if available)
sudo perf mem record -t load ./build/bin/example
perf script > perf_script.txt

# Option 2: Using mem-loads events (requires Intel PT support)
sudo perf record -e '{cpu_core/mem-loads-aux/,cpu_core/mem-loads/}' \
    -g --call-graph dwarf ./build/bin/example
perf script > perf_script.txt

# Run analyzer with --auto-infer
uv run python ds_cache_analyzer.py \
    --binary ./your_binary \
    --perf-script perf_script.txt \
    --auto-infer \
    --html report.html
```

### Limitations

- Requires memory addresses (events like `cache-misses` don't provide addresses)
- Intel PT support required for `mem-loads-aux` events
- May have false positives when multiple structs match
- Local structs may not be discoverable automatically

## Intel Processor Trace (PT) Support

Intel Processor Trace (PT) is required for capturing memory addresses, which enables automatic field inference. The simplest way to use it is with `perf mem record -t load`, which handles Intel PT automatically.

### Quick Check

```bash
# Check if Intel PT is available in the kernel
ls -l /sys/bus/event_source/devices/intel_pt/type

# Check CPU support
grep intel_pt /proc/cpuinfo
```

### Enablement Steps

1. **Verify Hardware Support**: Check if your CPU supports Intel PT
2. **Check Kernel Support**: Modern Linux kernels (4.1+) include Intel PT support
3. **Enable in BIOS/UEFI** (may be required):
   - Reboot and enter BIOS/UEFI
   - Navigate to CPU Configuration or Advanced CPU Settings
   - Look for "Intel Processor Trace" or "Processor Trace"
   - Enable the option
4. **Verify Intel PT Works**:
   ```bash
   # Test basic Intel PT
   sudo perf record -e intel_pt// -a sleep 1
   
   # Test memory address capture (what you'll actually use)
   sudo perf mem record -t load ./build/bin/example
   ```

### Troubleshooting Intel PT

**Error: "Cannot collect data source with the load latency event alone"**
- Check BIOS settings - Intel PT might be disabled
- Check kernel version (needs 4.1+)
- Some operations require root privileges

**Error: "Operation not permitted"**
- Use `sudo` for recording: `sudo perf record ...`
- Or adjust `perf_event_paranoid` temporarily (not recommended for security)

**Alternative: Use Manual Mappings**

If Intel PT cannot be enabled, the analyzer works perfectly fine with manual mappings (no Intel PT required).

## Mappings Format

The tool supports two matching modes:

### Function-based Matching

```yaml
mappings:
  - match:
      function: "process_array_bad"  # Function name from perf output
    struct: "BadLayout"
    fields:
      - "hot_field"
    field_hotness:
      hot_field: 1000
    # Optional: Manual struct layout if pahole can't find struct
    struct_layout:
      size: 68
      fields:
        - name: "hot_field"
          offset: 64
          size: 4
```

### Source Line-based Matching

```yaml
mappings:
  - match:
      file: "example_main.cpp"
      line: 42
    struct: "BadLayout"
    fields:
      - "hot_field"
```

## Example: Optimizing a Hot Structure

### Before (Poor Layout)

```cpp
struct BadLayout {
    int64_t rarely_used_field;  // 8 bytes
    char padding[56];            // 56 bytes padding
    int hot_field;              // 4 bytes - spans cache line!
};
```

This structure spans 2 cache lines. Accessing `hot_field` requires loading 2 cache lines.

### After (Optimized Layout)

```cpp
struct GoodLayout {
    int hot_field;              // 4 bytes - first cache line
    int64_t rarely_used_field;  // 8 bytes
    char padding[52];           // 52 bytes padding
};
```

Now `hot_field` is in the first cache line, reducing cache misses.

## Tips for Best Results

1. **Profile realistic workloads**: Use actual input data that represents production usage
2. **Multiple mappings**: Create mappings for all hot paths accessing structures
3. **Field hotness**: Use explicit `field_hotness` in mappings.yml for more accurate analysis
4. **Iterate**: Make changes, recompile, and re-analyze to verify improvements
5. **Use appropriate perf events**: Choose events that match your analysis goals

## Troubleshooting

### "No mappings matched any hot source lines"
- Check that file paths in `mappings.yml` match those in `perf_script.txt`
- Use basename matching (e.g., `file: "my_program.cpp"` instead of full path)
- Verify line numbers match actual source lines

### "Failed to parse pahole output"
- Ensure binary was compiled with `-g` flag
- Check that struct name matches exactly (case-sensitive)
- Verify `pahole` is installed: `pahole --version`

### "Command failed: pahole"
- Install `dwarves` package (contains `pahole`)
- Ensure binary has DWARF debug information

### "Struct definitions not found in DWARF"
- Rebuild with `-g3` flag for maximum debug info
- Check that structs aren't optimized away
- Use manual `struct_layout` specification in mappings.yml

## Examples

See the `examples/` directory for:
- Example C++ code demonstrating various cache layout scenarios
- Example mappings file (`example_mappings.yml`)
- Complete workflow examples

## Limitations

- Automatic inference requires perf events that capture memory addresses
- Manual mappings still needed when addresses aren't available
- Field hotness is estimated from function/source line samples
- Does not account for compiler optimizations that may reorder fields
- Local structs may not be found by pahole

## Future Enhancements

- Enhanced DWARF location expression evaluation for better address-to-field mapping
- Support for Structure of Arrays (SoA) analysis
- Integration with compiler-specific layout analysis
- Cache simulation for more accurate predictions
- Better handling of nested structs and unions
