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

# Source files
set(SOURCES
    src/main.cpp
    src/blockchain/Block.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/TransactionPool.cpp
    src/p2p/P2PNetwork.cpp
    src/p2p/MessageHandler.cpp
    src/api/RestApiServer.cpp
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
)

# Create executable
add_executable(blockchain_node ${SOURCES})

# Set include directories for the target
target_include_directories(blockchain_node PRIVATE 
    ${asio_SOURCE_DIR}/asio/include
    ${httplib_SOURCE_DIR}
)

# Link libraries
target_link_libraries(blockchain_node 
    PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    fmt::fmt
)

# Preprocessor definitions
target_compile_definitions(blockchain_node PRIVATE 
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
target_compile_options(blockchain_node PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:
        $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-reference>
        $<$<CXX_COMPILER_ID:Clang>:-Wno-unused-parameter>
    >
)

# Set output directory
set_target_properties(blockchain_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Add compiler-specific flags for better optimization on Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(blockchain_node PRIVATE
        $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
        $<$<CONFIG:Debug>:-O0 -g -DDEBUG>
    )
endif()

# Install target
install(TARGETS blockchain_node DESTINATION bin)

# Enable testing
enable_testing()

# Add custom target for running with verbose output
add_custom_target(run
    COMMAND ${CMAKE_BINARY_DIR}/bin/blockchain_node
    DEPENDS blockchain_node
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running blockchain node"
)

# Add custom target for cleaning build artifacts
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMENT "Cleaning all build artifacts"
)