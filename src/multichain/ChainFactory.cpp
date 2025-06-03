// =======================================================================================
// src/multichain/ChainFactory.cpp
// =======================================================================================

#include "multichain/MultiChainManager.h"
#include "blockchain/FileBlockchain.h"
#include <spdlog/spdlog.h>

std::shared_ptr<Blockchain> ChainFactory::createChain(ChainType type, const ChainConfig& config) {
    switch (type) {
        case ChainType::MAIN_CHAIN:
        case ChainType::IDENTITY_CHAIN:
        case ChainType::SIDECHAIN:
        case ChainType::PRIVATE_CHAIN:
        case ChainType::TEST_CHAIN:
            return std::make_shared<Blockchain>();
            
        case ChainType::FILE_CHAIN:
            return std::make_shared<FileBlockchain>();
            
        default:
            spdlog::error("Unknown chain type: {}", static_cast<int>(type));
            return nullptr;
    }
}

std::shared_ptr<FileBlockchain> ChainFactory::createFileChain(const ChainConfig& config) {
    auto fileChain = std::make_shared<FileBlockchain>();
    
    // Configure file-specific settings
    FileBlockchain::FileBlockchainConfig fileConfig;
    if (config.customConfig.contains("maxChunkSize")) {
        fileConfig.maxChunkSize = config.customConfig["maxChunkSize"];
    }
    if (config.customConfig.contains("maxFileSize")) {
        fileConfig.maxFileSize = config.customConfig["maxFileSize"];
    }
    
    fileChain->setConfig(fileConfig);
    return fileChain;
}

ChainConfig ChainFactory::createDefaultConfig(ChainType type, const std::string& name) {
    switch (type) {
        case ChainType::MAIN_CHAIN:
            return getMainChainTemplate();
        case ChainType::FILE_CHAIN:
            return getFileChainTemplate();
        case ChainType::IDENTITY_CHAIN:
            return getIdentityChainTemplate();
        case ChainType::SIDECHAIN:
            return getSidechainTemplate();
        case ChainType::PRIVATE_CHAIN:
            return getPrivateChainTemplate();
        case ChainType::TEST_CHAIN:
            return getTestChainTemplate();
        default:
            return getMainChainTemplate();
    }
}

ChainConfig ChainFactory::getMainChainTemplate() {
    ChainConfig config;
    config.type = ChainType::MAIN_CHAIN;
    config.name = "MainChain";
    config.description = "Primary blockchain for transactions";
    config.difficulty = 4;
    config.blockTimeTarget = 10;
    config.miningReward = 50.0;
    config.p2pPort = 8333;
    config.apiPort = 8080;
    config.isActive = true;
    config.isPublic = true;
    return config;
}

ChainConfig ChainFactory::getFileChainTemplate() {
    ChainConfig config;
    config.type = ChainType::FILE_CHAIN;
    config.name = "FileChain";
    config.description = "Specialized blockchain for file storage";
    config.difficulty = 2;
    config.blockTimeTarget = 5;
    config.miningReward = 25.0;
    config.p2pPort = 8335;
    config.apiPort = 8082;
    config.isActive = true;
    config.isPublic = true;
    
    // File-specific configuration
    config.customConfig["maxChunkSize"] = 1024 * 1024; // 1MB
    config.customConfig["maxFileSize"] = 100 * 1024 * 1024; // 100MB
    config.customConfig["enableDeduplication"] = true;
    config.customConfig["enableCompression"] = true;
    
    return config;
}

ChainConfig ChainFactory::getIdentityChainTemplate() {
    ChainConfig config;
    config.type = ChainType::IDENTITY_CHAIN;
    config.name = "IdentityChain";
    config.description = "Identity and access management blockchain";
    config.difficulty = 3;
    config.blockTimeTarget = 15;
    config.miningReward = 10.0;
    config.p2pPort = 8337;
    config.apiPort = 8084;
    config.isActive = false;
    config.isPublic = true;
    return config;
}

ChainConfig ChainFactory::getSidechainTemplate() {
    ChainConfig config;
    config.type = ChainType::SIDECHAIN;
    config.name = "Sidechain";
    config.description = "General purpose sidechain";
    config.difficulty = 2;
    config.blockTimeTarget = 5;
    config.miningReward = 20.0;
    config.p2pPort = 8339;
    config.apiPort = 8086;
    config.isActive = false;
    config.isPublic = true;
    return config;
}

ChainConfig ChainFactory::getPrivateChainTemplate() {
    ChainConfig config;
    config.type = ChainType::PRIVATE_CHAIN;
    config.name = "PrivateChain";
    config.description = "Private/permissioned blockchain";
    config.difficulty = 1;
    config.blockTimeTarget = 3;
    config.miningReward = 5.0;
    config.p2pPort = 8341;
    config.apiPort = 8088;
    config.isActive = false;
    config.isPublic = false;
    return config;
}

ChainConfig ChainFactory::getTestChainTemplate() {
    ChainConfig config;
    config.type = ChainType::TEST_CHAIN;
    config.name = "TestChain";
    config.description = "Testing and development blockchain";
    config.difficulty = 1;
    config.blockTimeTarget = 1;
    config.miningReward = 100.0;
    config.p2pPort = 8343;
    config.apiPort = 8090;
    config.isActive = false;
    config.isPublic = false;
    return config;
}