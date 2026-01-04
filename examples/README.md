# Examples

This directory contains example files demonstrating cache structure analysis.

## Files

- **example_main.cpp**: Main example program demonstrating various cache layout scenarios
- **example.cpp**: Additional example code (if used)
- **example_mappings.yml**: Example mappings file showing how to map hot functions/source lines to struct fields

## Building the Example

```bash
# From the project root
mkdir -p build && cd build
cmake ..
cmake --build .

# Run the example
./bin/example
```

## Using the Example with the Analyzer

```bash
# Record performance data
perf record -e cpu_core/L1-dcache-load-misses/ -g --call-graph dwarf ./build/bin/example
perf script > perf_script.txt

# Analyze with the tool
uv run python ds_cache_analyzer.py \
  --binary ./build/bin/example \
  --perf-script perf_script.txt \
  --mappings examples/example_mappings.yml \
  --html report.html
```

## Example Structures

The example program demonstrates various cache layout scenarios:

1. **BadLayout**: Poor layout with hot field spanning cache line
2. **GoodLayout**: Optimized layout with hot field in first cache line
3. **Array of Structures**: Alignment issues with AoS patterns
4. **Nested Structures**: Cache issues with nested structs
5. **Tagged Unions**: Structures with union members
6. **Bitfields**: Alignment issues with bitfields
7. **Large Structures**: Multi-cache-line structures
8. **Pointer Structures**: Indirection overhead
9. **Mixed Access Patterns**: Hot/cold field patterns

See `example_main.cpp` for detailed code examples.
