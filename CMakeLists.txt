message(STATUS "Components to build:")
message(cmake_minimum_required(VERSION 3.16)

# Project configuration
project(BlockchainNode 
    VERSION 1.0.0
    DESCRIPTION "Advanced Blockchain File Storage System with Security Features"
    LANGUAGES CXX
)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type defaults
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Platform-specific configuration
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

# Compiler-specific flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-dangling-reference")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /EHsc")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# Configure version header
configure_file(
    ${CMAKE_SOURCE_DIR}/include/version.h.in
    ${CMAKE_BINARY_DIR}/include/version.h
    @ONLY
)

# Find required packages
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Find optional packages
find_package(PkgConfig QUIET)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party
)

# Third-party libraries (header-only)
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)

# Check for required third-party headers
set(REQUIRED_HEADERS
    ${THIRD_PARTY_DIR}/nlohmann/json.hpp
    ${THIRD_PARTY_DIR}/spdlog/spdlog.h
    ${THIRD_PARTY_DIR}/httplib.h
)

foreach(HEADER ${REQUIRED_HEADERS})
    if(NOT EXISTS ${HEADER})
        message(WARNING "Missing third-party header: ${HEADER}")
        message(STATUS "Please ensure all third-party dependencies are in the third_party/ directory")
    endif()
endforeach()

# Core blockchain library
set(BLOCKCHAIN_CORE_SOURCES
    src/blockchain/Block.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/TransactionPool.cpp
    src/blockchain/FileBlockchain.cpp
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
)

add_library(blockchain_core ${BLOCKCHAIN_CORE_SOURCES})
target_link_libraries(blockchain_core 
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)
target_include_directories(blockchain_core PUBLIC 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
)

# P2P networking library
set(P2P_SOURCES
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
)

add_library(p2p_network ${P2P_SOURCES})
target_link_libraries(p2p_network 
    blockchain_core
    Threads::Threads
)

# Security system library
set(SECURITY_SOURCES
    src/security/SecurityManager.cpp
)

add_library(security_system ${SECURITY_SOURCES})
target_link_libraries(security_system 
    blockchain_core
    Threads::Threads
)

# Multi-chain management library
set(MULTICHAIN_SOURCES
    src/multichain/MultiChainManager.cpp
    src/multichain/ChainBridge.cpp
    src/multichain/ConsensusCoordinator.cpp
    src/multichain/ChainFactory.cpp
)

add_library(multichain_manager ${MULTICHAIN_SOURCES})
target_link_libraries(multichain_manager 
    blockchain_core
    p2p_network
    security_system
    Threads::Threads
)

# CLI interface library
set(CLI_SOURCES
    src/cli/CLIInterface.cpp
)

add_library(cli_interface ${CLI_SOURCES})
target_link_libraries(cli_interface 
    blockchain_core
    p2p_network
    security_system
    multichain_manager
)

# Web interface library
set(WEB_SOURCES
    src/web/WebInterface.cpp
)

add_library(web_interface ${WEB_SOURCES})
target_link_libraries(web_interface 
    blockchain_core
    p2p_network
    security_system
    multichain_manager
    Threads::Threads
)

# REST API library
set(API_SOURCES
    src/api/RestApiServer.cpp
)

add_library(rest_api ${API_SOURCES})
target_link_libraries(rest_api 
    blockchain_core
    p2p_network
    Threads::Threads
)

# Main blockchain node executable (with web interface)
add_executable(blockchain_node src/main.cpp)
target_link_libraries(blockchain_node 
    blockchain_core
    p2p_network
    security_system
    multichain_manager
    web_interface
    rest_api
    Threads::Threads
)

# CLI-only executable
add_executable(blockchain_cli src/cli_main.cpp)
target_link_libraries(blockchain_cli 
    blockchain_core
    p2p_network
    security_system
    multichain_manager
    cli_interface
    Threads::Threads
)

# Platform-specific linking
if(WIN32)
    target_link_libraries(blockchain_node ws2_32 wsock32)
    target_link_libraries(blockchain_cli ws2_32 wsock32)
    target_link_libraries(p2p_network ws2_32 wsock32)
    target_link_libraries(web_interface ws2_32 wsock32)
    target_link_libraries(rest_api ws2_32 wsock32)
endif()

# Enable testing (optional)
option(BUILD_TESTS "Build test suite" ON)
if(BUILD_TESTS)
    enable_testing()
    
    # Simple test executable
    add_executable(blockchain_node_test 
        tests/test_main.cpp
        tests/test_blockchain.cpp
        tests/test_crypto.cpp
        tests/test_p2p.cpp
        tests/test_security.cpp
        tests/test_file_storage.cpp
    )
    
    target_link_libraries(blockchain_node_test 
        blockchain_core
        p2p_network
        security_system
        multichain_manager
        cli_interface
        web_interface
        rest_api
    )
    
    add_test(NAME blockchain_tests COMMAND blockchain_node_test)
endif()

# Installation rules
install(TARGETS blockchain_node blockchain_cli 
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/src/web/static 
    DESTINATION share/blockchain_node/web
    OPTIONAL
)

# Create a simple test runner if test files don't exist
if(BUILD_TESTS AND NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/test_main.cpp)
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
    
    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
"#include <iostream>
#include <cassert>
#include \"blockchain/Blockchain.h\"
#include \"utils/Crypto.h\"

int main() {
    std::cout << \"Running blockchain tests...\" << std::endl;
    
    // Basic blockchain test
    try {
        Blockchain blockchain;
        std::cout << \"✓ Blockchain creation successful\" << std::endl;
        
        // Test mining
        auto block = blockchain.mineBlock(\"test_miner\");
        std::cout << \"✓ Block mining successful\" << std::endl;
        
        // Test crypto
        auto hash = Crypto::sha256(\"test\");
        assert(!hash.empty());
        std::cout << \"✓ Crypto hash successful\" << std::endl;
        
        // Test key generation
        auto keyPair = Crypto::generateKeyPair();
        assert(!keyPair.first.empty() && !keyPair.second.empty());
        std::cout << \"✓ Key generation successful\" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << \"Test failed: \" << e.what() << std::endl;
        return 1;
    }
    
    std::cout << \"All tests passed!\" << std::endl;
    return 0;
}
")

    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_blockchain.cpp "// Blockchain tests placeholder\n")
    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_crypto.cpp "// Crypto tests placeholder\n")
    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_p2p.cpp "// P2P tests placeholder\n")
    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_security.cpp "// Security tests placeholder\n")
    file(WRITE ${CMAKE_SOURCE_DIR}/tests/test_file_storage.cpp "// File storage tests placeholder\n")
    
    message(STATUS "Created basic test files in tests/ directory")
endif()

# Development tools
option(ENABLE_CLANG_TIDY "Enable clang-tidy checks" OFF)
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
    if(CLANG_TIDY_EXE)
        set_target_properties(blockchain_core PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
        message(STATUS "clang-tidy enabled")
    endif()
endif()

# Summary
message(STATUS "")
message(STATUS "════════════════════════════════════════")
message(STATUS "  Blockchain Node Build Configuration")
message(STATUS "════════════════════════════════════════")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "")
message(STATUS "Components to build:")
message(STATUS "  ✓ Core Blockchain (Proof-of-Work, UTXO)")
message(STATUS "  ✓ File Storage System (chunked, deduplicated)")
message(STATUS "  ✓ P2P Network (discovery, consensus)")
message(STATUS "  ✓ Security Manager (polymorphic reordering)")
message(STATUS "  ✓ Multi-Chain Manager (cross-chain, bridges)")
message(STATUS "  ✓ CLI Interface (interactive & batch)")
message(STATUS "  ✓ Web Interface (file upload & explorer)")
message(STATUS "  ✓ REST API Server (full blockchain API)")
message(STATUS "")
message(STATUS "Executables:")
message(STATUS "  → blockchain_node (full node with web UI)")
message(STATUS "  → blockchain_cli (command-line interface)")
if(BUILD_TESTS)
    message(STATUS "  → blockchain_node_test (test suite)")
endif()
message(STATUS "════════════════════════════════════════")
message(STATUS "")