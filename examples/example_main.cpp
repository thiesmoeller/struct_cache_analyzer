// Main file for the example program demonstrating cache layout issues
// This file is compilable and can be profiled with perf

#include <cstdint>
#include <iostream>
#include <chrono>
#include <vector>
#include <cstring>

// Struct definitions demonstrating cache layout issues
// These match the examples in example.cpp

// Example 1: Poor layout - hot field spans cache line
struct BadLayout {
    int64_t rarely_used;      // 8 bytes at offset 0
    char padding[56];          // 56 bytes padding
    int hot_field;             // 4 bytes at offset 64 - spans cache line!
    // Total: 68 bytes, spans 2 cache lines
};

// Example 2: Better layout - hot field in first cache line
struct GoodLayout {
    int hot_field;             // 4 bytes at offset 0 - first cache line
    int64_t rarely_used;       // 8 bytes at offset 4
    char padding[52];          // 52 bytes padding
    // Total: 64 bytes, fits in 1 cache line
};

// Example 3: Array of structures with alignment issues
struct LargeStruct {
    int64_t field1;            // 8 bytes
    int64_t field2;            // 8 bytes
    int64_t field3;            // 8 bytes
    int64_t field4;            // 8 bytes
    int64_t field5;            // 8 bytes
    int64_t field6;            // 8 bytes
    int64_t field7;            // 8 bytes
    int64_t field8;            // 8 bytes
    int64_t field9;            // 8 bytes
    // Total: 72 bytes, spans 2 cache lines
    // Accessing array[i].field1 requires loading 2 cache lines per element
};

// Example 4: Optimized for hot fields
struct OptimizedStruct {
    // Hot fields grouped together in first cache line
    int hot_counter;           // 4 bytes at offset 0
    int hot_accumulator;       // 4 bytes at offset 4
    double hot_value;          // 8 bytes at offset 8
    
    // Cold fields in second cache line
    int64_t cold_data[7];      // 56 bytes at offset 16
    // Total: 72 bytes, but hot fields are in first cache line
};

// Example 5: Nested structures with poor layout
struct InnerData {
    int64_t metadata;          // 8 bytes
    char description[48];      // 48 bytes
    // Total: 56 bytes
};

struct NestedStruct {
    int hot_id;                // 4 bytes at offset 0
    InnerData inner;           // 56 bytes at offset 4
    int hot_status;            // 4 bytes at offset 60 - spans cache line!
    char padding[4];           // 4 bytes
    // Total: 68 bytes, spans 2 cache lines
};

// Example 6: Structure with union (tagged union pattern)
struct TaggedUnion {
    int tag;                   // 4 bytes at offset 0
    union {
        struct {
            int hot_value1;    // 4 bytes
            int hot_value2;    // 4 bytes
            double hot_value3; // 8 bytes
        } hot_data;            // 16 bytes at offset 4
        struct {
            char cold_buffer[56]; // 56 bytes
        } cold_data;
    };
    int hot_flag;              // 4 bytes at offset 20
    // Total: 24 bytes, but union can be 64 bytes when cold_data is used
};

// Example 7: Structure with bitfields (can cause alignment issues)
struct BitfieldStruct {
    uint32_t hot_flag1 : 1;    // 1 bit
    uint32_t hot_flag2 : 1;    // 1 bit
    uint32_t hot_flag3 : 1;    // 1 bit
    uint32_t reserved : 29;    // 29 bits
    // Total: 4 bytes at offset 0
    
    int64_t hot_counter;       // 8 bytes at offset 4
    double hot_value;          // 8 bytes at offset 12
    
    uint32_t cold_flags[12];   // 48 bytes at offset 20
    // Total: 68 bytes, spans 2 cache lines
};

// Example 8: Very large structure spanning multiple cache lines
struct MultiCacheLineStruct {
    // First cache line (0-64)
    int hot_id;                // 4 bytes at offset 0
    int hot_priority;          // 4 bytes at offset 4
    double hot_score;         // 8 bytes at offset 8
    int64_t hot_timestamp;     // 8 bytes at offset 16
    char hot_name[40];         // 40 bytes at offset 24
    
    // Second cache line (64-128)
    int64_t data[7];           // 56 bytes at offset 64
    int64_t metadata;          // 8 bytes at offset 120
    
    // Third cache line (128-192)
    double values[8];          // 64 bytes at offset 128
    
    // Total: 192 bytes, spans 3 cache lines
};

// Example 9: Structure with pointer (indirection overhead)
struct PointerStruct {
    int hot_count;             // 4 bytes at offset 0
    int* hot_ptr;              // 8 bytes at offset 8 (pointer)
    int hot_value;             // 4 bytes at offset 16
    char padding[44];          // 44 bytes
    // Total: 60 bytes, but pointer dereference causes cache miss
};

// Example 10: Structure with mixed hot/cold pattern
struct MixedAccessStruct {
    // Hot path fields (first cache line)
    int hot_counter;           // 4 bytes at offset 0
    int hot_index;             // 4 bytes at offset 4
    double hot_sum;            // 8 bytes at offset 8
    int hot_flags[4];          // 16 bytes at offset 16
    
    // Medium access fields (still in first cache line)
    float medium_value;        // 4 bytes at offset 32
    int medium_id;             // 4 bytes at offset 36
    
    // Cold fields (second cache line)
    char cold_description[56]; // 56 bytes at offset 40
    // Total: 96 bytes, spans 2 cache lines
};

// Example usage that would trigger cache misses
void process_array_bad(BadLayout* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Accessing hot_field requires loading 2 cache lines per element
        arr[i].hot_field += 1;  // Cache miss!
    }
}

void process_array_good(GoodLayout* arr, int size) {
    for (int i = 0; i < size; i++) {
        // hot_field is in first cache line
        arr[i].hot_field += 1;  // Better cache behavior
    }
}

void process_large_array(LargeStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Each element spans 2 cache lines
        arr[i].field1 += 1;
    }
}

void process_optimized(OptimizedStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Hot fields are in first cache line
        arr[i].hot_counter++;
        arr[i].hot_accumulator += arr[i].hot_value;
    }
}

void process_nested(NestedStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // hot_status spans cache line boundary
        arr[i].hot_id++;
        arr[i].hot_status += arr[i].inner.metadata;
    }
}

void process_tagged_union(TaggedUnion* arr, int size) {
    for (int i = 0; i < size; i++) {
        if (arr[i].tag == 0) {
            // Access hot union members
            arr[i].hot_data.hot_value1++;
            arr[i].hot_data.hot_value2 += arr[i].hot_data.hot_value3;
            arr[i].hot_flag = 1;
        }
    }
}

void process_bitfield(BitfieldStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Access hot bitfields and fields
        if (arr[i].hot_flag1) {
            arr[i].hot_counter++;
        }
        arr[i].hot_value += arr[i].hot_counter;
    }
}

void process_multi_cacheline(MultiCacheLineStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Access hot fields in first cache line
        arr[i].hot_id++;
        arr[i].hot_score += arr[i].hot_priority;
        // Accessing data requires loading second cache line
        arr[i].data[0] = arr[i].hot_timestamp;
    }
}

void process_pointer(PointerStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Pointer dereference causes cache miss
        arr[i].hot_count++;
        if (arr[i].hot_ptr) {
            *arr[i].hot_ptr = arr[i].hot_value;
        }
    }
}

void process_mixed(MixedAccessStruct* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Hot path - all in first cache line
        arr[i].hot_counter++;
        arr[i].hot_sum += arr[i].hot_index;
        arr[i].hot_flags[0] = arr[i].hot_counter;
        // Medium access - still in first cache line
        arr[i].medium_value = arr[i].hot_sum;
    }
}

int main() {
    const int ARRAY_SIZE = 10000000;
    
    std::cout << "Cache Structure Analyzer Example\n";
    std::cout << "================================\n\n";
    
    // Test BadLayout
    {
        std::vector<BadLayout> bad_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_array_bad(bad_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "BadLayout (spans 2 cache lines): " << duration.count() << " μs\n";
    }
    
    // Test GoodLayout
    {
        std::vector<GoodLayout> good_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_array_good(good_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "GoodLayout (fits in 1 cache line): " << duration.count() << " μs\n";
    }
    
    // Test LargeStruct (AoS issue)
    {
        std::vector<LargeStruct> large_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_large_array(large_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "LargeStruct (AoS alignment issue): " << duration.count() << " μs\n";
    }
    
    // Test OptimizedStruct
    {
        std::vector<OptimizedStruct> opt_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_optimized(opt_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "OptimizedStruct (hot fields grouped): " << duration.count() << " μs\n";
    }
    
    // Test NestedStruct
    {
        std::vector<NestedStruct> nested_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_nested(nested_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "NestedStruct (nested with cache line span): " << duration.count() << " μs\n";
    }
    
    // Test TaggedUnion
    {
        std::vector<TaggedUnion> union_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_tagged_union(union_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "TaggedUnion (union with hot data): " << duration.count() << " μs\n";
    }
    
    // Test BitfieldStruct
    {
        std::vector<BitfieldStruct> bitfield_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_bitfield(bitfield_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "BitfieldStruct (bitfields + hot fields): " << duration.count() << " μs\n";
    }
    
    // Test MultiCacheLineStruct
    {
        std::vector<MultiCacheLineStruct> multi_array(ARRAY_SIZE / 10); // Smaller array due to size
        auto start = std::chrono::high_resolution_clock::now();
        process_multi_cacheline(multi_array.data(), ARRAY_SIZE / 10);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "MultiCacheLineStruct (spans 3 cache lines): " << duration.count() << " μs\n";
    }
    
    // Test PointerStruct
    {
        std::vector<PointerStruct> ptr_array(ARRAY_SIZE);
        // Initialize pointers
        for (int i = 0; i < ARRAY_SIZE; i++) {
            ptr_array[i].hot_ptr = &ptr_array[i].hot_value;
        }
        auto start = std::chrono::high_resolution_clock::now();
        process_pointer(ptr_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "PointerStruct (pointer indirection): " << duration.count() << " μs\n";
    }
    
    // Test MixedAccessStruct
    {
        std::vector<MixedAccessStruct> mixed_array(ARRAY_SIZE);
        auto start = std::chrono::high_resolution_clock::now();
        process_mixed(mixed_array.data(), ARRAY_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "MixedAccessStruct (hot/cold pattern): " << duration.count() << " μs\n";
    }
    
    std::cout << "\nNote: Run with 'perf record' to analyze cache behavior:\n";
    std::cout << "  perf record -e cpu_core/L1-dcache-load-misses/ -g --call-graph dwarf ./example\n";
    std::cout << "  (or use: perf record -e cache-misses -g --call-graph dwarf ./example)\n";
    std::cout << "  perf script > perf_script.txt\n";
    
    return 0;
}
