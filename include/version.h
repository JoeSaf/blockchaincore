#pragma once

#define BLOCKCHAIN_VERSION_MAJOR @BlockchainNode_VERSION_MAJOR@
#define BLOCKCHAIN_VERSION_MINOR @BlockchainNode_VERSION_MINOR@
#define BLOCKCHAIN_VERSION_PATCH @BlockchainNode_VERSION_PATCH@
#define BLOCKCHAIN_VERSION_STRING "@BlockchainNode_VERSION@"

namespace Version {
    constexpr int MAJOR = BLOCKCHAIN_VERSION_MAJOR;
    constexpr int MINOR = BLOCKCHAIN_VERSION_MINOR;
    constexpr int PATCH = BLOCKCHAIN_VERSION_PATCH;
    constexpr const char* STRING = BLOCKCHAIN_VERSION_STRING;
}