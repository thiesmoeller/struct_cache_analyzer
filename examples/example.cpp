// Example C++ code demonstrating cache layout issues
// Struct definitions for cache analysis

#include <cstdint>

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

// Example usage that would trigger cache misses
void process_array(BadLayout* arr, int size) {
    for (int i = 0; i < size; i++) {
        // Accessing hot_field requires loading 2 cache lines per element
        arr[i].hot_field += 1;  // Cache miss!
    }
}

void process_array_optimized(GoodLayout* arr, int size) {
    for (int i = 0; i < size; i++) {
        // hot_field is in first cache line
        arr[i].hot_field += 1;  // Better cache behavior
    }
}
