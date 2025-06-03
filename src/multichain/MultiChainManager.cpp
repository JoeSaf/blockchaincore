// =======================================================================================
// MultiChainManager Implementation Files
// =======================================================================================

// src/multichain/MultiChainManager.cpp
#include "multichain/MultiChainManager.h"
#include "utils/Crypto.h"
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <thread>
#include <chrono>

// ChainConfig implementations
nlohmann::json ChainConfig::toJson() const {
    nlohmann::json json;
    json["chainId"] = chainId;
    json["type"] = static_cast<int>(type);
    json["name"] = name;
    json["description"] = description;
    json["difficulty"] = difficulty;
    json["blockTimeTarget"] = blockTimeTarget;
    json["miningReward"] = miningReward;
    json["p2pPort"] = p2pPort;
    json["apiPort"] = apiPort;
    json["isActive"] = isActive;
    json["isPublic"] = isPublic;
    json["genesisValidators"] = genesisValidators;
    json["customConfig"] = customConfig;
    return json;
}

void ChainConfig::fromJson(const nlohmann::json& json) {
    chainId = json["chainId"];
    type = static_cast<ChainType>(json["type"]);
    name = json["name"];
    description = json["description"];
    difficulty = json["difficulty"];
    blockTimeTarget = json["blockTimeTarget"];
    miningReward = json["miningReward"];
    p2pPort = json["p2pPort"];
    apiPort = json["apiPort"];
    isActive = json["isActive"];
    isPublic = json["isPublic"];
    genesisValidators = json["genesisValidators"].get<std::vector<std::string>>();
    customConfig = json["customConfig"];
}

// CrossChainTransaction implementations
nlohmann::json CrossChainTransaction::toJson() const {
    nlohmann::json json;
    json["transactionId"] = transactionId;
    json["sourceChainId"] = sourceChainId;
    json["targetChainId"] = targetChainId;
    json["sourceAddress"] = sourceAddress;
    json["targetAddress"] = targetAddress;
    json["amount"] = amount;
    json["payload"] = payload;
    json["proof"] = proof;
    json["timestamp"] = timestamp;
    json["isConfirmed"] = isConfirmed;
    json["confirmations"] = confirmations;
    return json;
}

void CrossChainTransaction::fromJson(const nlohmann::json& json) {
    transactionId = json["transactionId"];
    sourceChainId = json["sourceChainId"];
    targetChainId = json["targetChainId"];
    sourceAddress = json["sourceAddress"];
    targetAddress = json["targetAddress"];
    amount = json["amount"];
    payload = json["payload"];
    proof = json["proof"];
    timestamp = json["timestamp"];
    isConfirmed = json["isConfirmed"];
    confirmations = json["confirmations"];
}

// MultiChainManager implementation
MultiChainManager::MultiChainManager()
    : autoScalingEnabled_(false)
    , loadBalancingEnabled_(false)
    , globalDifficulty_(4)
    , globalBlockTime_(10)
    , running_(false) {
    
    consensusCoordinator_ = std::make_unique<ConsensusCoordinator>();
    
    // Load default templates
    loadDefaultTemplates();
    
    // Initialize default chains
    initializeDefaultChains();
    
    // Start worker threads
    startWorkerThreads();
    
    spdlog::info("MultiChainManager initialized with cross-chain capabilities");
}

MultiChainManager::~MultiChainManager() {
    stopWorkerThreads();
}

std::string MultiChainManager::createChain(const ChainConfig& config) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    if (!validateChainConfig(config)) {
        throw std::invalid_argument("Invalid chain configuration");
    }
    
    if (chains_.size() >= DEFAULT_MAX_CHAINS) {
        throw std::runtime_error("Maximum number of chains reached");
    }
    
    std::string chainId = generateChainId(config.name, config.type);
    
    // Create the blockchain based on type
    auto blockchain = ChainFactory::createChain(config.type, config);
    if (!blockchain) {
        throw std::runtime_error("Failed to create blockchain instance");
    }
    
    // Create P2P network for the chain
    auto p2pNetwork = std::make_shared<P2PNetwork>(config.p2pPort, config.p2pPort + 1);
    
    // Create security manager for the chain
    auto securityManager = std::make_shared<SecurityManager>(blockchain);
    
    // Store all components
    chains_[chainId] = blockchain;
    chainConfigs_[chainId] = config;
    chainNetworks_[chainId] = p2pNetwork;
    chainSecurityManagers_[chainId] = securityManager;
    
    // Setup cross-chain bridges if needed
    if (config.isPublic) {
        for (const auto& [existingChainId, existingConfig] : chainConfigs_) {
            if (existingConfig.isPublic && existingChainId != chainId) {
                createBridge(chainId, existingChainId);
                createBridge(existingChainId, chainId);
            }
        }
    }
    
    // Trigger callback
    if (chainCreatedCallback_) {
        chainCreatedCallback_(chainId);
    }
    
    spdlog::info("Created new chain: {} (Type: {}, ID: {})", 
                 config.name, static_cast<int>(config.type), chainId);
    
    return chainId;
}

bool MultiChainManager::startChain(const std::string& chainId) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    auto configIt = chainConfigs_.find(chainId);
    if (configIt == chainConfigs_.end()) {
        return false;
    }
    
    auto networkIt = chainNetworks_.find(chainId);
    if (networkIt != chainNetworks_.end()) {
        bool started = networkIt->second->start();
        if (started) {
            configIt->second.isActive = true;
            spdlog::info("Started chain: {}", chainId);
        }
        return started;
    }
    
    return false;
}

std::shared_ptr<Blockchain> MultiChainManager::getChain(const std::string& chainId) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    auto it = chains_.find(chainId);
    if (it != chains_.end()) {
        return it->second;
    }
    
    return nullptr;
}

bool MultiChainManager::createBridge(const std::string& sourceChainId, const std::string& targetChainId) {
    std::lock_guard<std::mutex> lock(bridgesMutex_);
    
    std::string bridgeId = generateBridgeId(sourceChainId, targetChainId);
    
    auto bridge = std::make_shared<ChainBridge>(sourceChainId, targetChainId);
    bridge->enableBridge();
    
    bridges_[bridgeId] = bridge;
    
    spdlog::info("Created bridge: {} -> {}", sourceChainId, targetChainId);
    return true;
}

std::shared_ptr<ChainBridge> MultiChainManager::getBridge(const std::string& sourceChainId, 
                                                         const std::string& targetChainId) {
    std::lock_guard<std::mutex> lock(bridgesMutex_);
    
    std::string bridgeId = generateBridgeId(sourceChainId, targetChainId);
    auto it = bridges_.find(bridgeId);
    
    if (it != bridges_.end()) {
        return it->second;
    }
    
    return nullptr;
}

// Private helper methods
std::string MultiChainManager::generateChainId(const std::string& name, ChainType type) {
    std::string typeStr = std::to_string(static_cast<int>(type));
    std::string data = name + typeStr + std::to_string(std::time(nullptr));
    return "chain_" + Crypto::sha256(data).substr(0, 16);
}

std::string MultiChainManager::generateBridgeId(const std::string& sourceChain, const std::string& targetChain) {
    return sourceChain + "_to_" + targetChain;
}

bool MultiChainManager::validateChainConfig(const ChainConfig& config) const {
    if (config.name.empty() || config.difficulty == 0 || config.blockTimeTarget == 0) {
        return false;
    }
    
    if (config.p2pPort == 0 || config.apiPort == 0) {
        return false;
    }
    
    return true;
}

void MultiChainManager::initializeDefaultChains() {
    // Create main chain
    auto mainConfig = ChainFactory::createDefaultConfig(ChainType::MAIN_CHAIN, "MainChain");
    mainConfig.p2pPort = 8333;
    mainConfig.apiPort = 8080;
    createChain(mainConfig);
    
    // Create file storage chain
    auto fileConfig = ChainFactory::createDefaultConfig(ChainType::FILE_CHAIN, "FileChain");
    fileConfig.p2pPort = 8335;
    fileConfig.apiPort = 8082;
    createChain(fileConfig);
    
    spdlog::info("Initialized default blockchain ecosystem");
}

void MultiChainManager::loadDefaultTemplates() {
    chainTemplates_["main"] = ChainFactory::createDefaultConfig(ChainType::MAIN_CHAIN, "Template");
    chainTemplates_["file"] = ChainFactory::createDefaultConfig(ChainType::FILE_CHAIN, "Template");
    chainTemplates_["identity"] = ChainFactory::createDefaultConfig(ChainType::IDENTITY_CHAIN, "Template");
    chainTemplates_["sidechain"] = ChainFactory::createDefaultConfig(ChainType::SIDECHAIN, "Template");
    chainTemplates_["private"] = ChainFactory::createDefaultConfig(ChainType::PRIVATE_CHAIN, "Template");
    chainTemplates_["test"] = ChainFactory::createDefaultConfig(ChainType::TEST_CHAIN, "Template");
}

void MultiChainManager::startWorkerThreads() {
    if (running_) return;
    
    running_ = true;
    
    workerThreads_.emplace_back(&MultiChainManager::consensusWorkerLoop, this);
    workerThreads_.emplace_back(&MultiChainManager::crossChainWorkerLoop, this);
    workerThreads_.emplace_back(&MultiChainManager::healthMonitorLoop, this);
    
    spdlog::debug("Started MultiChainManager worker threads");
}

void MultiChainManager::stopWorkerThreads() {
    if (!running_) return;
    
    running_ = false;
    
    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    workerThreads_.clear();
    spdlog::debug("Stopped MultiChainManager worker threads");
}

void MultiChainManager::consensusWorkerLoop() {
    while (running_) {
        try {
            performGlobalConsensus();
        } catch (const std::exception& e) {
            spdlog::error("Consensus worker error: {}", e.what());
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(DEFAULT_CONSENSUS_INTERVAL));
    }
}

void MultiChainManager::crossChainWorkerLoop() {
    while (running_) {
        try {
            // Process pending cross-chain transactions
            std::lock_guard<std::mutex> lock(bridgesMutex_);
            
            for (auto& [txId, transaction] : crossChainTransactions_) {
                if (!transaction.isConfirmed) {
                    auto bridge = getBridge(transaction.sourceChainId, transaction.targetChainId);
                    if (bridge && bridge->verifyCrossChainProof(transaction)) {
                        if (bridge->executeCrossChainTransaction(transaction)) {
                            transaction.isConfirmed = true;
                            transaction.confirmations++;
                            
                            if (crossChainTransactionCallback_) {
                                crossChainTransactionCallback_(transaction);
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            spdlog::error("Cross-chain worker error: {}", e.what());
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void MultiChainManager::healthMonitorLoop() {
    while (running_) {
        try {
            performHealthCheck();
        } catch (const std::exception& e) {
            spdlog::error("Health monitor error: {}", e.what());
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

