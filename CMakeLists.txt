cmake_minimum_required(VERSION 3.15)
project(CacheStructAnalyzer VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(BUILD_EXAMPLES "Build example programs" ON)

# Compiler flags for debug symbols (required for pahole and auto-inference)
# Use -g3 for maximum debug info including struct definitions
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g3")

# Example executable demonstrating cache layout issues
if(BUILD_EXAMPLES)
    # Note: example.cpp contains struct definitions and example code
    # example_main.cpp contains the main function and usage examples
    add_executable(example 
        examples/example_main.cpp
    )
    target_compile_options(example PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    
    # Set output directory
    set_target_properties(example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()

# Install target
install(TARGETS example
    RUNTIME DESTINATION bin
    COMPONENT examples
)

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "")
