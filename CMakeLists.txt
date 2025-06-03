cmake_minimum_required(VERSION 3.16)
project(BlockchainNode VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -Wextra")

# Disable specific warnings that are problematic
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-dangling-reference -Wno-unused-parameter")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Find spdlog
find_package(spdlog REQUIRED)

# Find fmt (usually comes with spdlog)
find_package(fmt REQUIRED)

# Find nlohmann_json
find_package(nlohmann_json REQUIRED)

# ASIO (header-only)
find_path(ASIO_INCLUDE_DIR asio.hpp PATHS /usr/include /usr/local/include)
if(NOT ASIO_INCLUDE_DIR)
    message(FATAL_ERROR "ASIO headers not found. Please install libasio-dev")
endif()

# httplib (header-only) - Check if available
find_path(HTTPLIB_INCLUDE_DIR httplib.h 
    PATHS 
    /usr/include 
    /usr/local/include
    ${CMAKE_SOURCE_DIR}/third_party
    ${CMAKE_SOURCE_DIR}/include/third_party
)

if(NOT HTTPLIB_INCLUDE_DIR)
    message(WARNING "httplib.h not found. Web interface will not be available.")
    set(ENABLE_WEB_INTERFACE OFF)
else()
    set(ENABLE_WEB_INTERFACE ON)
    message(STATUS "Found httplib at: ${HTTPLIB_INCLUDE_DIR}")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${ASIO_INCLUDE_DIR})

if(ENABLE_WEB_INTERFACE)
    include_directories(${HTTPLIB_INCLUDE_DIR})
    add_compile_definitions(ENABLE_WEB_INTERFACE)
    add_compile_definitions(HTTPLIB_OPENSSL_SUPPORT)
endif()

# Core blockchain library sources
set(BLOCKCHAIN_CORE_SOURCES
    # Blockchain core
    src/blockchain/Block.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/TransactionPool.cpp
    src/blockchain/FileBlockchain.cpp
    
    # Utilities
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
    
    # Security
    src/security/SecurityManager.cpp
    
    # P2P Network
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
)

# API Server sources (conditional)
set(API_SERVER_SOURCES)
if(ENABLE_WEB_INTERFACE)
    list(APPEND API_SERVER_SOURCES
        src/api/RestApiServer.cpp
        src/web/WebInterface.cpp
    )
endif()

# CLI sources
set(CLI_SOURCES
    src/cli/CLIInterface.cpp
)

# Create core blockchain library
add_library(blockchain_core STATIC ${BLOCKCHAIN_CORE_SOURCES})

target_link_libraries(blockchain_core
    PUBLIC
    ${OPENSSL_LIBRARIES}
    spdlog::spdlog
    fmt::fmt
    nlohmann_json::nlohmann_json
    Threads::Threads
)

target_include_directories(blockchain_core
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${ASIO_INCLUDE_DIR}
)

# Create API server library (conditional)
if(ENABLE_WEB_INTERFACE)
    add_library(api_server STATIC ${API_SERVER_SOURCES})
    
    target_link_libraries(api_server
        PUBLIC
        blockchain_core
        ${OPENSSL_LIBRARIES}
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
        Threads::Threads
    )
    
    target_include_directories(api_server
        PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${HTTPLIB_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )
endif()

# Create CLI library
add_library(cli_interface STATIC ${CLI_SOURCES})

target_link_libraries(cli_interface
    PUBLIC
    blockchain_core
    spdlog::spdlog
    fmt::fmt
    nlohmann_json::nlohmann_json
)

target_include_directories(cli_interface
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Main node executable
add_executable(blockchain_node src/main.cpp)

target_link_libraries(blockchain_node
    PRIVATE
    blockchain_core
    ${OPENSSL_LIBRARIES}
    spdlog::spdlog
    fmt::fmt
    nlohmann_json::nlohmann_json
    Threads::Threads
)

if(ENABLE_WEB_INTERFACE)
    target_link_libraries(blockchain_node PRIVATE api_server)
endif()

# CLI executable
add_executable(blockchain_cli src/cli_main.cpp)

target_link_libraries(blockchain_cli
    PRIVATE
    blockchain_core
    cli_interface
    ${OPENSSL_LIBRARIES}
    spdlog::spdlog
    fmt::fmt
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# Set output directories
set_target_properties(blockchain_node blockchain_cli
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS blockchain_node blockchain_cli
    RUNTIME DESTINATION bin
)

# Install web static files if web interface is enabled
if(ENABLE_WEB_INTERFACE)
    install(DIRECTORY src/web/static/
        DESTINATION share/blockchain_node/web
        FILES_MATCHING PATTERN "*.html" PATTERN "*.css" PATTERN "*.js"
    )
endif()

# Version configuration
configure_file(
    ${CMAKE_SOURCE_DIR}/include/version.h.in
    ${CMAKE_BINARY_DIR}/include/version.h
    @ONLY
)

# Add the configured version header to include path
target_include_directories(blockchain_core PUBLIC ${CMAKE_BINARY_DIR}/include)

# Print build information
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Web interface: ${ENABLE_WEB_INTERFACE}")

if(ENABLE_WEB_INTERFACE)
    message(STATUS "httplib found at: ${HTTPLIB_INCLUDE_DIR}")
endif()

# Optional: Add tests
option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    
    # Add test subdirectory if it exists
    if(EXISTS ${CMAKE_SOURCE_DIR}/tests)
        add_subdirectory(tests)
    endif()
endif()

# Optional: Documentation
option(BUILD_DOCS "Build documentation" OFF)

if(BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY)
        add_custom_target(docs
            ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    endif()
endif()

# Debug information
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug mode enabled - additional logging available")
    add_compile_definitions(DEBUG_MODE)
endif()

# Platform-specific settings
if(WIN32)
    # Windows-specific settings
    target_compile_definitions(blockchain_core PRIVATE WIN32_LEAN_AND_MEAN)
    target_compile_definitions(blockchain_core PRIVATE _WIN32_WINNT=0x0601)
elseif(UNIX)
    # Unix-specific settings
    target_link_libraries(blockchain_core PUBLIC dl)
endif()

# Optimization flags for release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(blockchain_core PRIVATE -O3 -march=native)
    endif()
endif()

# Summary
message(STATUS "=== Build Configuration Summary ===")
message(STATUS "Blockchain Node: blockchain_node")
message(STATUS "CLI Tool: blockchain_cli")
message(STATUS "Core Library: blockchain_core")
if(ENABLE_WEB_INTERFACE)
    message(STATUS "API Server: api_server")
    message(STATUS "Web Interface: ENABLED")
else()
    message(STATUS "Web Interface: DISABLED (httplib not found)")
endif()
message(STATUS "=====================================")