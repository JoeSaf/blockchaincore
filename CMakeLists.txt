cmake_minimum_required(VERSION 3.16)
project(BlockchainFileSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pthread")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Try to find spdlog, if not found, we'll use header-only mode
find_package(spdlog QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found, downloading header-only version...")
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/third_party/spdlog)
    if(NOT EXISTS ${CMAKE_SOURCE_DIR}/third_party/spdlog/spdlog.h)
        file(DOWNLOAD 
            https://github.com/gabime/spdlog/releases/download/v1.12.0/spdlog.h
            ${CMAKE_SOURCE_DIR}/third_party/spdlog/spdlog.h
            SHOW_PROGRESS
        )
    endif()
    add_library(spdlog INTERFACE)
    target_include_directories(spdlog INTERFACE ${CMAKE_SOURCE_DIR}/third_party)
endif()

# Create third_party directory and download dependencies
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/third_party/nlohmann)

# Download nlohmann/json if not exists
if(NOT EXISTS ${CMAKE_SOURCE_DIR}/third_party/nlohmann/json.hpp)
    message(STATUS "Downloading nlohmann/json...")
    file(DOWNLOAD 
        https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
        ${CMAKE_SOURCE_DIR}/third_party/nlohmann/json.hpp
        SHOW_PROGRESS
    )
endif()

# Download httplib if not exists
if(NOT EXISTS ${CMAKE_SOURCE_DIR}/third_party/httplib.h)
    message(STATUS "Downloading cpp-httplib...")
    file(DOWNLOAD 
        https://github.com/yhirose/cpp-httplib/releases/download/v0.14.1/httplib.h
        ${CMAKE_SOURCE_DIR}/third_party/httplib.h
        SHOW_PROGRESS
    )
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party)
include_directories(${CMAKE_SOURCE_DIR})

# Source files
set(BLOCKCHAIN_SOURCES
    src/blockchain/Block.cpp
    src/blockchain/Blockchain.cpp
    src/blockchain/Transaction.cpp
    src/blockchain/TransactionPool.cpp
    src/blockchain/FileBlockchain.cpp
)

set(UTILS_SOURCES
    src/utils/Crypto.cpp
    src/utils/Utils.cpp
)

set(P2P_SOURCES
    src/p2p/P2PNetwork.cpp
)

set(SECURITY_SOURCES
    src/security/SecurityManager.cpp
)

set(API_SOURCES
    src/api/RestApiServer.cpp
)

set(WEB_SOURCES
    src/web/WebInterface.cpp
)

set(CLI_SOURCES
    src/cli/CLIInterface.cpp
)

set(MULTICHAIN_SOURCES
    src/multichain/MultiChainManager.cpp
    src/multichain/ChainFactory.cpp
    src/multichain/ChainBridge.cpp
    src/multichain/ConsensusCoordinator.cpp
)

# Create libraries
add_library(utils_lib STATIC ${UTILS_SOURCES})
target_link_libraries(utils_lib OpenSSL::SSL OpenSSL::Crypto)

add_library(blockchain_lib STATIC ${BLOCKCHAIN_SOURCES})
target_link_libraries(blockchain_lib utils_lib)

add_library(p2p_lib STATIC ${P2P_SOURCES})
target_link_libraries(p2p_lib utils_lib blockchain_lib)

add_library(security_lib STATIC ${SECURITY_SOURCES})
target_link_libraries(security_lib blockchain_lib utils_lib)

add_library(api_lib STATIC ${API_SOURCES})
target_link_libraries(api_lib blockchain_lib p2p_lib utils_lib)

add_library(web_lib STATIC ${WEB_SOURCES})
target_link_libraries(web_lib blockchain_lib p2p_lib security_lib utils_lib)

add_library(multichain_lib STATIC ${MULTICHAIN_SOURCES})
target_link_libraries(multichain_lib blockchain_lib p2p_lib security_lib utils_lib)

add_library(cli_lib STATIC ${CLI_SOURCES})
target_link_libraries(cli_lib blockchain_lib p2p_lib security_lib multichain_lib utils_lib)

# Main executable
add_executable(blockchain_node src/main.cpp)
target_link_libraries(blockchain_node 
    multichain_lib
    web_lib
    api_lib
    security_lib
    p2p_lib
    blockchain_lib
    utils_lib
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)

# CLI executable
add_executable(blockchain_cli src/cli_main.cpp)
target_link_libraries(blockchain_cli 
    cli_lib
    multichain_lib
    security_lib
    p2p_lib
    blockchain_lib
    utils_lib
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)

# Link spdlog appropriately
if(spdlog_FOUND)
    target_link_libraries(utils_lib spdlog::spdlog)
    target_link_libraries(blockchain_node spdlog::spdlog)
    target_link_libraries(blockchain_cli spdlog::spdlog)
else()
    target_link_libraries(utils_lib spdlog)
    target_link_libraries(blockchain_node spdlog)
    target_link_libraries(blockchain_cli spdlog)
endif()

# Set output directories
set_target_properties(blockchain_node blockchain_cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Copy static web files to build directory
add_custom_command(TARGET blockchain_node POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/src/web/static
    ${CMAKE_BINARY_DIR}/src/web/static
)

# Installation
install(TARGETS blockchain_node blockchain_cli
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/src/web/static/
    DESTINATION share/blockchain/web/static
)

message(STATUS "Configuration complete. Run 'make' to build.")