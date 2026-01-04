#!/bin/bash
# Build script for the cache structure analyzer

set -e

echo "Cache Structure Analyzer - Build Script"
echo "======================================="
echo ""

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed"
    echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check for cmake
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake is not installed"
    echo "Install with: sudo apt-get install cmake (Debian/Ubuntu) or brew install cmake (macOS)"
    exit 1
fi

# Setup Python environment
echo "1. Setting up Python environment..."
uv sync

# Setup and build C++
echo ""
echo "2. Setting up CMake build..."
mkdir -p build
cd build

if [ ! -f CMakeCache.txt ]; then
    # Use Debug build type for maximum debug info (-g3)
    # This ensures struct definitions are included in DWARF for auto-inference
    cmake -DCMAKE_BUILD_TYPE=Debug ..
fi

echo ""
echo "3. Building C++ example..."
cmake --build .

echo ""
echo "Build complete!"
echo ""
echo "To run the example:"
echo "  ./build/bin/example"
echo ""
echo "To analyze with perf (recommended for Intel i7-14700K):"
echo "  perf record -e cpu_core/L1-dcache-load-misses/ -g --call-graph dwarf ./build/bin/example"
echo "  perf script > perf_script.txt"
echo "  uv run python ds_cache_analyzer.py --binary ./build/bin/example --perf-script perf_script.txt --mappings examples/example_mappings.yml"
echo ""
echo "Alternative (universal):"
echo "  perf record -e cache-misses -g --call-graph dwarf ./build/bin/example"