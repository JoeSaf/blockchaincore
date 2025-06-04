cmake_minimum_required(VERSION 3.16)

# Project configuration
project(BlockchainNode VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -Wno-dangling-reference -Wno-unused-parameter")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -Wno-unused-parameter")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ========================
# FIND PACKAGES & DEPENDENCIES
# ========================

# Find required packages
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig QUIET)

# Find optional packages for better builds
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    message(STATUS "Using ccache for faster rebuilds")
endif()

# ========================
# THIRD-PARTY DEPENDENCIES
# ========================

# Create third_party directory
set(THIRD_PARTY_DIR "${CMAKE_SOURCE_DIR}/third_party")
file(MAKE_DIRECTORY ${THIRD_PARTY_DIR})

# Download and include nlohmann/json
include(FetchContent)

# nlohmann/json
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    URL_HASH SHA256=d69f9deb6a75e2580465c6c4c5111b89c4dc2fa94e3a85fcd2ffcd9a143d9273
)
FetchContent_MakeAvailable(nlohmann_json)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0
)
FetchContent_MakeAvailable(spdlog)

# httplib (header-only)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.0
)
FetchContent_MakeAvailable(httplib)

# ASIO (standalone, header-only)
FetchContent_Declare(
    asio
    URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-24-0.tar.gz
    URL_HASH SHA256=cbcaaba0f66722787b1a7c33afe1befb3a012b5af3ad7da7ff0f6b8c9b7a8a5a
)
FetchContent_MakeAvailable(asio)

# ========================
# INCLUDE DIRECTORIES
# ========================

# Project include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Third-party includes
include_directories(${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(httplib::httplib INTERFACE HTTPLIB_OPENSSL_SUPPORT)

# OpenSSL includes
include_directories(${OPENSSL_INCLUDE_DIR})

# ========================
# SOURCE FILES ORGANIZATION
# ========================

# Core blockchain sources
set(BLOCKCHAIN_SOURCES
    src/blockchain/Block.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/TransactionPool.cpp
    src/blockchain/FileBlockchain.cpp
)

# Utility sources
set(UTILS_SOURCES
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
)

# P2P Network sources
set(P2P_SOURCES
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
)

# Security system sources
set(SECURITY_SOURCES
    src/security/SecurityManager.cpp
)

# Multi-chain system sources
set(MULTICHAIN_SOURCES
    src/multichain/MultiChainManager.cpp
    src/multichain/ChainBridge.cpp
    src/multichain/ConsensusCoordinator.cpp
    src/multichain/ChainFactory.cpp
)

# CLI interface sources
set(CLI_SOURCES
    src/cli/CLIInterface.cpp
)

# Web interface sources
set(WEB_SOURCES
    src/web/WebInterface.cpp
)

# API server sources
set(API_SOURCES
    src/api/RestApiServer.cpp
)

# All library sources combined
set(ALL_LIB_SOURCES
    ${BLOCKCHAIN_SOURCES}
    ${UTILS_SOURCES}
    ${P2P_SOURCES}
    ${SECURITY_SOURCES}
    ${MULTICHAIN_SOURCES}
    ${CLI_SOURCES}
    ${WEB_SOURCES}
    ${API_SOURCES}
)

# ========================
# LIBRARY CREATION
# ========================

# Create main blockchain library
add_library(blockchain_lib STATIC ${ALL_LIB_SOURCES})

# Link libraries to blockchain_lib
target_link_libraries(blockchain_lib
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        httplib::httplib
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Set library properties
set_target_properties(blockchain_lib PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

# Compiler definitions for the library
target_compile_definitions(blockchain_lib PUBLIC
    ASIO_STANDALONE
    ASIO_HAS_STD_CHRONO
    HTTPLIB_OPENSSL_SUPPORT
    SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG
)

# ========================
# EXECUTABLE TARGETS
# ========================

# Main blockchain node executable
add_executable(blockchain_node src/main.cpp)
target_link_libraries(blockchain_node PRIVATE blockchain_lib)

# CLI executable  
add_executable(blockchain_cli src/cli_main.cpp)
target_link_libraries(blockchain_cli PRIVATE blockchain_lib)

# Set executable properties
set_target_properties(blockchain_node blockchain_cli PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ========================
# TESTING CONFIGURATION
# ========================

# Enable testing
enable_testing()

# Add test sources (if they exist)
if(EXISTS "${CMAKE_SOURCE_DIR}/tests")
    add_subdirectory(tests)
else()
    # Create basic test executable
    add_executable(blockchain_node_test 
        src/test_main.cpp  # We'll create this basic test file
    )
    target_link_libraries(blockchain_node_test PRIVATE blockchain_lib)
    
    # Add basic test
    add_test(NAME basic_test COMMAND blockchain_node_test)
endif()

# ========================
# INSTALLATION CONFIGURATION
# ========================

# Install executables
install(TARGETS blockchain_node blockchain_cli
    RUNTIME DESTINATION bin
)

# Install headers (for development)
install(DIRECTORY include/
    DESTINATION include/blockchain
    FILES_MATCHING PATTERN "*.h"
)

# Install library
install(TARGETS blockchain_lib
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# ========================
# PACKAGING CONFIGURATION
# ========================

# CPack configuration for creating packages
set(CPACK_PACKAGE_NAME "BlockchainNode")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced Multi-Chain Blockchain System")
set(CPACK_PACKAGE_VENDOR "Blockchain Development Team")
set(CPACK_PACKAGE_CONTACT "blockchain@example.com")

# Platform-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
elseif(APPLE)
    set(CPACK_GENERATOR "ZIP;DragNDrop")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# ========================
# DEVELOPMENT TOOLS
# ========================

# Find development tools
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    # Add format target
    file(GLOB_RECURSE ALL_SOURCE_FILES
        "${CMAKE_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/*.h"
        "${CMAKE_SOURCE_DIR}/include/*.h"
    )
    
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i -style=file ${ALL_SOURCE_FILES}
        COMMENT "Formatting source code"
    )
endif()

find_program(CLANG_TIDY clang-tidy)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY} -checks=-*,readability-*,performance-*,modernize-*)
endif()

# ========================
# CONFIGURATION SUMMARY
# ========================

message(STATUS "====================================")
message(STATUS "Blockchain Node Configuration Summary")
message(STATUS "====================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

if(CCACHE_PROGRAM)
    message(STATUS "Using ccache: YES")
endif()

if(CLANG_FORMAT)
    message(STATUS "clang-format available: YES (run 'make format')")
endif()

if(CLANG_TIDY)
    message(STATUS "clang-tidy available: YES")
endif()

message(STATUS "====================================")
message(STATUS "Build targets:")
message(STATUS "  blockchain_node    - Full node with web interface")
message(STATUS "  blockchain_cli     - Command line interface") 
message(STATUS "  blockchain_lib     - Core library")
message(STATUS "  blockchain_node_test - Test suite")
message(STATUS "====================================")

# ========================
# CUSTOM TARGETS
# ========================

# Custom target for running the node
add_custom_target(run
    COMMAND $<TARGET_FILE:blockchain_node>
    DEPENDS blockchain_node
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running blockchain node"
)

# Custom target for running CLI
add_custom_target(run-cli
    COMMAND $<TARGET_FILE:blockchain_cli> --help
    DEPENDS blockchain_cli
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running blockchain CLI"
)

# Custom target for running tests
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS blockchain_node_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running tests"
)