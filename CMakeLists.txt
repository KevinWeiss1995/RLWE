cmake_minimum_required(VERSION 3.15)
project(RLWE_Crypto VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined")

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/rlwe.cpp
    src/ntt.cpp
    src/parameters.cpp
    src/utils.cpp
    src/ntt_backend.cpp
    src/advanced_batch.cpp
    src/advanced_homomorphic.cpp
    src/security.cpp
    src/logging.cpp
)

# Create library
add_library(rlwe_crypto STATIC ${SOURCES})
target_link_libraries(rlwe_crypto Threads::Threads)

# Platform-specific libraries for secure memory management
if(APPLE)
    target_link_libraries(rlwe_crypto "-framework Security")
elseif(UNIX)
    target_link_libraries(rlwe_crypto rt)
elseif(WIN32)
    target_link_libraries(rlwe_crypto kernel32)
endif()

# Add filesystem library for C++17 compatibility
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(rlwe_crypto stdc++fs)
endif()

# Examples
add_executable(basic_example examples/basic_example.cpp)
target_link_libraries(basic_example rlwe_crypto)

add_executable(benchmark examples/benchmark.cpp)
target_link_libraries(benchmark rlwe_crypto)

add_executable(advanced_example examples/advanced_example.cpp)
target_link_libraries(advanced_example rlwe_crypto)

# Enterprise example
add_executable(enterprise_example examples/enterprise_example.cpp)
target_link_libraries(enterprise_example rlwe_crypto)

# Tests
enable_testing()
add_executable(test_rlwe tests/test_rlwe.cpp)
target_link_libraries(test_rlwe rlwe_crypto)
add_test(NAME rlwe_tests COMMAND test_rlwe)

# Enterprise test suite
add_executable(enterprise_tests tests/enterprise_tests.cpp)
target_link_libraries(enterprise_tests rlwe_crypto)
add_test(NAME enterprise_tests COMMAND enterprise_tests)

# Security tests
add_executable(security_tests tests/security_tests.cpp)
target_link_libraries(security_tests rlwe_crypto)
add_test(NAME security_tests COMMAND security_tests)

# Performance benchmarks
add_executable(performance_tests tests/performance_tests.cpp)
target_link_libraries(performance_tests rlwe_crypto)
add_test(NAME performance_tests COMMAND performance_tests)

# Installation
install(TARGETS rlwe_crypto DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
