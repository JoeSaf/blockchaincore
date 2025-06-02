cmake_minimum_required(VERSION 3.16)
project(BlockchainNode VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set policy for FetchContent timestamps
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

# Compiler-specific options to suppress warnings
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")
    # Suppress specific warnings that are causing issues
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-dangling-reference")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /O2")
    # Suppress MSVC specific warnings
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4100") # unreferenced formal parameter
endif()

# Find packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(include)

# Fetch dependencies
include(FetchContent)

# nlohmann/json
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# ASIO (standalone, no Boost dependency)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# spdlog for logging
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0
)
# Configure spdlog to suppress warnings
set(SPDLOG_BUILD_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(spdlog)

# fmt library
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.1.1
)
FetchContent_MakeAvailable(fmt)

# httplib - Header-only HTTP server
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.1
)
FetchContent_MakeAvailable(httplib)

# ========================
# SOURCE FILE ORGANIZATION
# ========================

# Core blockchain sources (your existing files)
set(BLOCKCHAIN_SOURCES
    src/blockchain/Block.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/TransactionPool.cpp
)

# P2P Network sources (your existing files)
set(P2P_SOURCES
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
)

# API sources (your existing files)
set(API_SOURCES
    src/api/RestApiServer.cpp
)

# Utility sources (your existing files)
set(UTILS_SOURCES
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
)

# NEW: Security Manager sources
set(SECURITY_SOURCES
    src/security/SecurityManager.cpp
)

# NEW: File Blockchain sources
set(FILE_BLOCKCHAIN_SOURCES
    src/blockchain/FileBlockchain.cpp
)

# NEW: CLI Interface sources
set(CLI_SOURCES
    src/cli/CLIInterface.cpp
)

# NEW: Web Interface sources
set(WEB_SOURCES
    src/web/WebInterface.cpp
)

# ========================
# BUILD TARGETS
# ========================

# Main executable - Full Node with all features
add_executable(blockchain_node
    src/main.cpp
    ${BLOCKCHAIN_SOURCES}
    ${P2P_SOURCES}
    ${API_SOURCES}
    ${UTILS_SOURCES}
    ${SECURITY_SOURCES}
    ${FILE_BLOCKCHAIN_SOURCES}
    ${CLI_SOURCES}
    ${WEB_SOURCES}
)

# CLI-only executable - Lightweight version
add_executable(blockchain_cli
    src/cli_main.cpp
    ${BLOCKCHAIN_SOURCES}
    ${P2P_SOURCES}
    ${UTILS_SOURCES}
    ${SECURITY_SOURCES}
    ${FILE_BLOCKCHAIN_SOURCES}
    ${CLI_SOURCES}
)

# ========================
# TARGET CONFIGURATION
# ========================

# Set include directories for both targets
foreach(target blockchain_node blockchain_cli)
    target_include_directories(${target} PRIVATE 
        ${asio_SOURCE_DIR}/asio/include
        ${httplib_SOURCE_DIR}
    )
    
    # Link libraries
    target_link_libraries(${target}
        PRIVATE 
        OpenSSL::SSL 
        OpenSSL::Crypto
        Threads::Threads
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        fmt::fmt
    )
    
    # Preprocessor definitions
    target_compile_definitions(${target} PRIVATE 
        ASIO_STANDALONE
        ASIO_HAS_STD_ADDRESSOF
        ASIO_HAS_STD_ARRAY
        ASIO_HAS_CSTDINT
        ASIO_HAS_STD_SHARED_PTR
        ASIO_HAS_STD_TYPE_TRAITS
        # Suppress specific fmt warnings
        FMT_SUPPRESS_WARNINGS=1
    )
    
    # Suppress warnings for third-party dependencies
    target_compile_options(${target} PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:
            $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-reference>
            $<$<CXX_COMPILER_ID:Clang>:-Wno-unused-parameter>
        >
    )
    
    # Set output directory
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    
    # Add compiler-specific flags for better optimization on Linux
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
            $<$<CONFIG:Debug>:-O0 -g -DDEBUG>
        )
    endif()
endforeach()

# ========================
# TESTING CONFIGURATION
# ========================

# Enable testing
enable_testing()

# Test executable (optional - only if test files exist)
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_main.cpp")
    add_executable(blockchain_node_test
        tests/test_main.cpp
        tests/test_blockchain.cpp
        tests/test_security.cpp
        tests/test_file_blockchain.cpp
        tests/test_p2p.cpp
        ${BLOCKCHAIN_SOURCES}
        ${P2P_SOURCES}
        ${UTILS_SOURCES}
        ${SECURITY_SOURCES}
        ${FILE_BLOCKCHAIN_SOURCES}
    )
    
    # Configure test target
    target_include_directories(blockchain_node_test PRIVATE 
        ${asio_SOURCE_DIR}/asio/include
        ${httplib_SOURCE_DIR}
    )
    
    target_link_libraries(blockchain_node_test
        PRIVATE 
        OpenSSL::SSL 
        OpenSSL::Crypto
        Threads::Threads
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        fmt::fmt
    )
    
    target_compile_definitions(blockchain_node_test PRIVATE 
        ASIO_STANDALONE
        ASIO_HAS_STD_ADDRESSOF
        ASIO_HAS_STD_ARRAY
        ASIO_HAS_CSTDINT
        ASIO_HAS_STD_SHARED_PTR
        ASIO_HAS_STD_TYPE_TRAITS
        FMT_SUPPRESS_WARNINGS=1
    )
    
    set_target_properties(blockchain_node_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    
    add_test(NAME blockchain_tests COMMAND blockchain_node_test)
endif()

# ========================
# INSTALLATION
# ========================

# Install targets
install(TARGETS blockchain_node blockchain_cli DESTINATION bin)

# Install configuration files (if they exist)
if(EXISTS "${CMAKE_SOURCE_DIR}/config")
    install(DIRECTORY config/ DESTINATION etc/blockchain)
endif()

# Install web static files (if they exist)
if(EXISTS "${CMAKE_SOURCE_DIR}/web/static")
    install(DIRECTORY web/static/ DESTINATION share/blockchain/web)
endif()

# ========================
# CUSTOM TARGETS
# ========================

# Run full node
add_custom_target(run
    COMMAND ${CMAKE_BINARY_DIR}/bin/blockchain_node
    DEPENDS blockchain_node
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running blockchain node with all features"
)

# Run CLI interface
add_custom_target(cli
    COMMAND ${CMAKE_BINARY_DIR}/bin/blockchain_cli
    DEPENDS blockchain_cli
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running CLI interface"
)

# Interactive CLI mode
add_custom_target(cli-interactive
    COMMAND ${CMAKE_BINARY_DIR}/bin/blockchain_cli --interactive
    DEPENDS blockchain_cli
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running CLI in interactive mode"
)

# Run tests (if available)
if(TARGET blockchain_node_test)
    add_custom_target(test-run
        COMMAND ${CMAKE_BINARY_DIR}/bin/blockchain_node_test
        DEPENDS blockchain_node_test
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running all tests"
    )
endif()

# Development helpers
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMENT "Cleaning all build artifacts"
)

# Format code (if clang-format is available)
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    add_custom_target(format
        COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include -name "*.cpp" -o -name "*.h" | 
                xargs ${CLANG_FORMAT} -i -style=file
        COMMENT "Formatting source code with clang-format"
    )
endif()

# ========================
# CONFIGURATION STATUS
# ========================

message(STATUS "")
message(STATUS "=== Blockchain Node Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Build targets:")
message(STATUS "  • blockchain_node (full node with web UI)")
message(STATUS "  • blockchain_cli (command-line interface)")
if(TARGET blockchain_node_test)
    message(STATUS "  • blockchain_node_test (test suite)")
endif()
message(STATUS "")
message(STATUS "Components included:")
message(STATUS "  ✓ Blockchain Core")
message(STATUS "  ✓ P2P Network")
message(STATUS "  ✓ REST API Server")
message(STATUS "  ✓ Security Manager (with polymorphic reordering)")
message(STATUS "  ✓ File Storage Blockchain")
message(STATUS "  ✓ CLI Interface")
message(STATUS "  ✓ Web Interface")
message(STATUS "")
message(STATUS "Quick start commands:")
message(STATUS "  make                     # Build all targets")
message(STATUS "  make run                 # Build and run full node")
message(STATUS "  make cli                 # Build and run CLI")
message(STATUS "  make cli-interactive     # Build and run interactive CLI")
if(TARGET blockchain_node_test)
    message(STATUS "  make test-run           # Build and run tests")
endif()
message(STATUS "")
message(STATUS "Your blockchain system includes:")
message(STATUS "  🛡️  Advanced Security (polymorphic chain reordering)")
message(STATUS "  📁  File Storage (chunked, deduplicated)")
message(STATUS "  🌐  P2P Network (true decentralization)")
message(STATUS "  💻  CLI Interface (primary interaction)")
message(STATUS "  🌐  Web Interface (file upload/management)")
message(STATUS "==========================================")
message(STATUS "")