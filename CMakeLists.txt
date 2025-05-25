# CMakeLists.txt - Arch Linux Optimized Blockchain Core
cmake_minimum_required(VERSION 3.20)
project(blockchain_core VERSION 1.0.0 LANGUAGES CXX)

# Modern C++ standard (Arch supports latest)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Arch-specific optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -flto -DNDEBUG")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -Wall -Wextra -Wpedantic -fsanitize=address,undefined")
endif()

# Arch package detection
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# nlohmann_json - prefer system package on Arch
find_package(nlohmann_json 3.10.0 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "System nlohmann_json not found, using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.2
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# pybind11 - prefer system package on Arch
find_package(pybind11 2.6.0 QUIET)
if(NOT pybind11_FOUND)
    message(STATUS "System pybind11 not found, using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG v2.11.1
    )
    FetchContent_MakeAvailable(pybind11)
endif()

# Source files
set(CORE_HEADERS
    blockchain_core.hpp
    p2p_blockchain_network.hpp
    p2p_node_manager.hpp
    blockchain_p2p_integration.hpp
)

set(BINDING_SOURCES
    python_bindings.cpp
    p2p_python_bindings.cpp
)

# Core library (header-only)
add_library(blockchain_core_lib INTERFACE)
target_include_directories(blockchain_core_lib INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(blockchain_core_lib INTERFACE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# Compiler-specific options
target_compile_features(blockchain_core_lib INTERFACE cxx_std_20)
target_compile_options(blockchain_core_lib INTERFACE
    $<$<CXX_COMPILER_ID:GNU>:-fconcepts>
    $<$<CXX_COMPILER_ID:Clang>:-fcoroutines-ts>
)

# Python module with enhanced P2P bindings
pybind11_add_module(blockchain_core MODULE
    python_bindings.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p2p_python_bindings.cpp
)

target_link_libraries(blockchain_core PRIVATE blockchain_core_lib)

# Enhanced properties for Arch
set_target_properties(blockchain_core PROPERTIES
    CXX_VISIBILITY_PRESET "hidden"
    INTERPROCEDURAL_OPTIMIZATION $<$<CONFIG:Release>:TRUE>
    PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
)

# Version information
target_compile_definitions(blockchain_core PRIVATE 
    VERSION_INFO="${PROJECT_VERSION}"
    BUILD_TIMESTAMP="${CMAKE_BUILD_TIMESTAMP}"
)

# Install targets
install(TARGETS blockchain_core DESTINATION .)
install(FILES ${CORE_HEADERS} DESTINATION include/blockchain_core)

# Testing support
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    if(GTest_FOUND)
        add_subdirectory(tests)
    else()
        message(WARNING "GTest not found, tests disabled")
    endif()
endif()

# Benchmarking support
option(BUILD_BENCHMARKS "Build performance benchmarks" OFF)
if(BUILD_BENCHMARKS)
    find_package(benchmark QUIET)
    if(benchmark_FOUND)
        add_subdirectory(benchmarks)
    else()
        message(WARNING "Google Benchmark not found, benchmarks disabled")
    endif()
endif()

# Documentation
option(BUILD_DOCS "Build documentation" OFF)
if(BUILD_DOCS)
    find_package(Doxygen QUIET)
    if(Doxygen_FOUND)
        set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs)
        doxygen_add_docs(docs ${CORE_HEADERS})
    else()
        message(WARNING "Doxygen not found, documentation disabled")
    endif()
endif()

# Packaging for Arch
set(CPACK_PACKAGE_NAME "blockchain-core")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "High-performance C++ blockchain core with P2P networking")
set(CPACK_PACKAGE_VENDOR "Blockchain Core Team")
set(CPACK_GENERATOR "TXZ")  # Arch Linux format
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")

include(CPack)

# Configuration summary
message(STATUS "")
message(STATUS "Blockchain Core Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "  Python version: ${PYTHON_VERSION_STRING}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Build docs: ${BUILD_DOCS}")
message(STATUS "")

# Custom targets for development
add_custom_target(format
    COMMAND clang-format -i ${CORE_HEADERS} ${BINDING_SOURCES}
    COMMENT "Formatting source code"
)

add_custom_target(lint
    COMMAND clang-tidy ${CORE_HEADERS} -- -I${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running static analysis"
)

add_custom_target(clean-all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMENT "Deep cleaning build directory"
)