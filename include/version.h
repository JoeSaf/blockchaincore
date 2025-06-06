#pragma once

#define BLOCKCHAIN_VERSION_MAJOR @BlockchainNode_VERSION_MAJOR@
#define BLOCKCHAIN_VERSION_MINOR @BlockchainNode_VERSION_MINOR@
#define BLOCKCHAIN_VERSION_PATCH @BlockchainNode_VERSION_PATCH@
#define BLOCKCHAIN_VERSION_STRING "@BlockchainNode_VERSION@"

namespace Version {
    constexpr int MAJOR = @BlockchainNode_VERSION_MAJOR@;
    constexpr int MINOR = @BlockchainNode_VERSION_MINOR@;
    constexpr int PATCH = @BlockchainNode_VERSION_PATCH@;
    constexpr const char* STRING = "@BlockchainNode_VERSION@";
}