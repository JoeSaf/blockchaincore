cmake_minimum_required(VERSION 3.16)

# Project information
project(MultiChainBlockchain 
    VERSION 2.0.0
    DESCRIPTION "Multi-Chain Blockchain System with File Storage"
    LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_CLI "Build CLI interface" ON)
option(BUILD_WEB "Build web interface" ON)
option(ENABLE_SECURITY "Enable security features" ON)
option(ENABLE_SANITIZERS "Enable sanitizers for debug builds" OFF)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wno-dangling-reference  # Suppress GCC 13+ warnings
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
        if(ENABLE_SANITIZERS)
            add_compile_options(-fsanitize=address -fsanitize=undefined)
            add_link_options(-fsanitize=address -fsanitize=undefined)
        endif()
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development packages.")
endif()

# Detect platform-specific libraries
if(WIN32)
    set(PLATFORM_LIBS ws2_32 wsock32)
elseif(UNIX AND NOT APPLE)
    set(PLATFORM_LIBS dl pthread)
elseif(APPLE)
    set(PLATFORM_LIBS dl pthread)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party
    ${OPENSSL_INCLUDE_DIR}
)

# Third-party libraries (header-only)
set(THIRD_PARTY_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/third_party/nlohmann
    ${CMAKE_SOURCE_DIR}/third_party/spdlog/include
    ${CMAKE_SOURCE_DIR}/third_party/httplib
    ${CMAKE_SOURCE_DIR}/third_party/asio/include
)

include_directories(${THIRD_PARTY_INCLUDE_DIRS})

# Suppress third-party warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    include_directories(SYSTEM ${THIRD_PARTY_INCLUDE_DIRS})
endif()

# Core library sources
set(CORE_SOURCES
    # Utilities
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
    
    # Blockchain core
    src/blockchain/Transaction.cpp
    src/blockchain/Block.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/TransactionPool.cpp
    
    # File blockchain
    src/blockchain/FileBlockchain.cpp
    
    # Multi-chain system
    src/MultiChainManager.cpp
    
    # P2P networking
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
    
    # Security
    src/security/SecurityManager.cpp
    
    # API server
    src/api/RestApiServer.cpp
)

# Web interface sources
if(BUILD_WEB)
    list(APPEND CORE_SOURCES
        src/web/WebInterface.cpp
    )
    add_definitions(-DENABLE_WEB_INTERFACE)
endif()

# CLI interface sources
if(BUILD_CLI)
    set(CLI_SOURCES
        src/cli/CLIInterface.cpp
    )
    add_definitions(-DENABLE_CLI_INTERFACE)
endif()

# Create core library
add_library(blockchain_core STATIC ${CORE_SOURCES})

target_link_libraries(blockchain_core
    ${OPENSSL_LIBRARIES}
    ${PLATFORM_LIBS}
    Threads::Threads
)

target_compile_definitions(blockchain_core PRIVATE
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
    HTTPLIB_OPENSSL_SUPPORT
)

if(ENABLE_SECURITY)
    target_compile_definitions(blockchain_core PRIVATE ENABLE_SECURITY_FEATURES)
endif()

# Multi-chain node executable
add_executable(multi_chain_node
    src/multi_chain_main.cpp
)

target_link_libraries(multi_chain_node
    blockchain_core
)

# CLI executable
if(BUILD_CLI)
    add_executable(blockchain_cli
        src/cli_main.cpp
        ${CLI_SOURCES}
    )
    
    target_link_libraries(blockchain_cli
        blockchain_core
    )
endif()

# Original single-chain node (for compatibility)
add_executable(blockchain_node
    src/main.cpp
)

target_link_libraries(blockchain_node
    blockchain_core
)

# Set output directory
set_target_properties(
    multi_chain_node blockchain_node
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

if(BUILD_CLI)
    set_target_properties(
        blockchain_cli
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
endif()


# Installation
install(TARGETS multi_chain_node blockchain_node
    RUNTIME DESTINATION bin
)

if(BUILD_CLI)
    install(TARGETS blockchain_cli
        RUNTIME DESTINATION bin
    )
endif()

# Install headers for development
install(DIRECTORY include/
    DESTINATION include/blockchain
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# Install configuration templates
install(FILES 
    config/node.json.template
    config/security.json.template
    DESTINATION share/blockchain/config
)

# Install documentation
install(FILES 
    README.md
    LICENSE
    INSTALL.md
    DESTINATION share/doc/blockchain
)

# Install systemd service file (Linux only)
if(UNIX AND NOT APPLE)
    install(FILES scripts/multi-chain-blockchain.service
        DESTINATION lib/systemd/system
    )
endif()

# Version configuration
configure_file(
    "${CMAKE_SOURCE_DIR}/include/version.h.in"
    "${CMAKE_BINARY_DIR}/include/version.h"
    @ONLY
)

include_directories(${CMAKE_BINARY_DIR}/include)

# CPack configuration for package generation
set(CPACK_PACKAGE_NAME "multi-chain-blockchain")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_CONTACT "blockchain@example.com")

if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop;TGZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    
    # Debian package specifics
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl-dev, libcurl4-openssl-dev")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    
    # RPM package specifics
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl-devel, libcurl-devel")
    set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
endif()

include(CPack)

# Custom targets
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include -name "*.cpp" -o -name "*.h" | xargs clang-format -i -style=file
    COMMENT "Formatting code with clang-format"
)

add_custom_target(check
    COMMAND cppcheck --enable=all --std=c++17 --suppress=missingIncludeSystem 
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include
    COMMENT "Running static analysis with cppcheck"
)

add_custom_target(demo
    COMMAND ${CMAKE_BINARY_DIR}/bin/multi_chain_node --demo
    DEPENDS multi_chain_node
    COMMENT "Running system demonstration"
)

# Print configuration summary
message(STATUS "")
message(STATUS "Multi-Chain Blockchain Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build CLI: ${BUILD_CLI}")
message(STATUS "  Build web interface: ${BUILD_WEB}")
message(STATUS "  Security features: ${ENABLE_SECURITY}")
message(STATUS "  Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "")
message(STATUS "Installation:")
message(STATUS "  Binary directory: ${CMAKE_INSTALL_PREFIX}/bin")
message(STATUS "  Include directory: ${CMAKE_INSTALL_PREFIX}/include/blockchain")
message(STATUS "")

# Helpful build instructions
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build - run with:")
    message(STATUS "  make multi_chain_node && ./bin/multi_chain_node --demo")
else()
    message(STATUS "Release build - run with:")
    message(STATUS "  make && ./bin/multi_chain_node")
endif()

if(BUILD_TESTS)
    message(STATUS "Run tests with:")
    message(STATUS "  make test")
    message(STATUS "  or: ./bin/blockchain_test")
endif()

message(STATUS "")