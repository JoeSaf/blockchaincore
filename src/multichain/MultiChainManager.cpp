// src/multichain/MultiChainManager.cpp
#include "multichain/MultiChainManager.h"
#include "blockchain/Blockchain.h"
#include "blockchain/FileBlockchain.h"
#include "p2p/P2PNetwork.h"
#include "security/SecurityManager.h"
#include "utils/Crypto.h"
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <thread>
#include <chrono>
#include <iostream>

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

std::shared_ptr<FileBlockchain> MultiChainManager::getFileChain(const std::string& chainId) {
    auto blockchain = getChain(chainId);
    return std::dynamic_pointer_cast<FileBlockchain>(blockchain);
}

std::vector<std::string> MultiChainManager::getAllChainIds() const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    std::vector<std::string> chainIds;
    for (const auto& [chainId, config] : chainConfigs_) {
        chainIds.push_back(chainId);
    }
    return chainIds;
}

bool MultiChainManager::isChainActive(const std::string& chainId) const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    auto it = chainConfigs_.find(chainId);
    if (it != chainConfigs_.end()) {
        return it->second.isActive;
    }
    return false;
}

uint32_t MultiChainManager::getChainHeight(const std::string& chainId) const {
    auto blockchain = const_cast<MultiChainManager*>(this)->getChain(chainId);
    if (blockchain) {
        return blockchain->getChainHeight();
    }
    return 0;
}

nlohmann::json MultiChainManager::getChainStatus(const std::string& chainId) const {
    nlohmann::json status;
    
    auto configIt = chainConfigs_.find(chainId);
    if (configIt != chainConfigs_.end()) {
        status = configIt->second.toJson();
        
        auto blockchain = const_cast<MultiChainManager*>(this)->getChain(chainId);
        if (blockchain) {
            status["height"] = blockchain->getChainHeight();
            status["totalSupply"] = blockchain->getTotalSupply();
        }
    }
    
    return status;
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

std::string MultiChainManager::initiateCrossChainTransfer(const std::string& sourceChainId,
                                                        const std::string& targetChainId,
                                                        const std::string& fromAddress,
                                                        const std::string& toAddress,
                                                        double amount,
                                                        const nlohmann::json& payload) {
    std::lock_guard<std::mutex> lock(bridgesMutex_);
    
    // Get the bridge
    auto bridge = getBridge(sourceChainId, targetChainId);
    if (!bridge || !bridge->isEnabled()) {
        throw std::runtime_error("Bridge not available between chains");
    }
    
    // Create cross-chain transaction
    CrossChainTransaction transaction;
    transaction.transactionId = Crypto::generateRandomString(32);
    transaction.sourceChainId = sourceChainId;
    transaction.targetChainId = targetChainId;
    transaction.sourceAddress = fromAddress;
    transaction.targetAddress = toAddress;
    transaction.amount = amount;
    transaction.payload = payload;
    transaction.timestamp = std::time(nullptr);
    transaction.isConfirmed = false;
    transaction.confirmations = 0;
    
    // Validate source chain has sufficient balance
    auto sourceChain = getChain(sourceChainId);
    if (!sourceChain) {
        throw std::runtime_error("Source chain not found");
    }
    
    double balance = sourceChain->getBalance(fromAddress);
    if (balance < amount) {
        throw std::runtime_error("Insufficient balance for cross-chain transfer");
    }
    
    // Generate cryptographic proof
    std::string proofData = transaction.transactionId + sourceChainId + targetChainId + 
                           fromAddress + toAddress + std::to_string(amount);
    transaction.proof = Crypto::sha256(proofData);
    
    // Store pending transaction
    crossChainTransactions_[transaction.transactionId] = transaction;
    
    // Initiate transfer through bridge
    bridge->initiateCrossChainTransfer(fromAddress, toAddress, amount, payload);
    
    // Trigger callback
    if (crossChainTransactionCallback_) {
        crossChainTransactionCallback_(transaction);
    }
    
    spdlog::info("Initiated cross-chain transfer: {} -> {} (Amount: {}, TxID: {})",
                 sourceChainId, targetChainId, amount, transaction.transactionId);
    
    return transaction.transactionId;
}

bool MultiChainManager::performGlobalConsensus() {
    spdlog::info("Performing global consensus across all chains");
    
    std::vector<std::string> activeChains;
    {
        std::lock_guard<std::mutex> lock(chainsMutex_);
        for (const auto& [chainId, config] : chainConfigs_) {
            if (config.isActive) {
                activeChains.push_back(chainId);
            }
        }
    }
    
    bool consensusAchieved = consensusCoordinator_->validateCrossChainConsensus(activeChains);
    
    if (consensusAchieved) {
        // Synchronize all chains
        consensusCoordinator_->coordinateChainSynchronization();
        
        // Process pending cross-chain transactions
        for (auto& [txId, transaction] : crossChainTransactions_) {
            if (!transaction.isConfirmed) {
                auto bridge = getBridge(transaction.sourceChainId, transaction.targetChainId);
                if (bridge && bridge->verifyCrossChainProof(transaction)) {
                    bridge->executeCrossChainTransaction(transaction);
                    transaction.isConfirmed = true;
                    transaction.confirmations = 1;
                }
            }
        }
    }
    
    if (globalConsensusCallback_) {
        globalConsensusCallback_(consensusAchieved);
    }
    
    return consensusAchieved;
}

nlohmann::json MultiChainManager::getGlobalMetrics() const {
    nlohmann::json metrics;
    metrics["totalChains"] = chains_.size();
    metrics["activeChains"] = 0;
    metrics["crossChainTransactions"] = crossChainTransactions_.size();
    metrics["maxHeight"] = 0;
    
    for (const auto& [chainId, config] : chainConfigs_) {
        if (config.isActive) {
            metrics["activeChains"] = metrics["activeChains"].get<int>() + 1;
        }
        
        uint32_t height = getChainHeight(chainId);
        if (height > metrics["maxHeight"].get<uint32_t>()) {
            metrics["maxHeight"] = height;
        }
    }
    
    return metrics;
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
    try {
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
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize default chains: {}", e.what());
    }
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


// Method called from main.cpp signalHandler
bool MultiChainManager::stopChain(const std::string& chainId) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    auto configIt = chainConfigs_.find(chainId);
    if (configIt == chainConfigs_.end()) {
        spdlog::warn("Chain {} not found for stopping", chainId);
        return false;
    }
    
    auto networkIt = chainNetworks_.find(chainId);
    if (networkIt != chainNetworks_.end()) {
        networkIt->second->stop();
        spdlog::info("Stopped P2P network for chain: {}", chainId);
    }
    
    // Mark chain as inactive
    configIt->second.isActive = false;
    
    spdlog::info("Stopped chain: {}", chainId);
    return true;
}

// Method called from main.cpp initializeP2PNetwork
void MultiChainManager::setNetworkCoordinator(std::shared_ptr<P2PNetwork> coordinator) {
    networkCoordinator_ = coordinator;
    spdlog::info("Set global network coordinator for multi-chain system");
}

// Method called from main.cpp initializeSecuritySystem
void MultiChainManager::setGlobalSecurityManager(std::shared_ptr<SecurityManager> securityManager) {
    globalSecurityManager_ = securityManager;
    spdlog::info("Set global security manager for multi-chain system");
}

// Method called from main.cpp security callback
void MultiChainManager::handleSecurityThreat(const std::string& chainId, const SecurityViolation& threat) {
    spdlog::warn("Handling security threat on chain {}: {}", chainId, threat.description);
    
    // Get the specific chain's security manager
    auto securityIt = chainSecurityManagers_.find(chainId);
    if (securityIt != chainSecurityManagers_.end()) {
        // Handle threat on specific chain
        auto& chainSecurity = securityIt->second;
        
        // Quarantine if critical
        if (threat.level == ThreatLevel::CRITICAL) {
            spdlog::error("Critical threat detected on chain {}, initiating quarantine", chainId);
            chainSecurity->quarantineInfectedBlocks();
        }
        
        // Trigger reorder if high threat level
        if (threat.level == ThreatLevel::HIGH || threat.level == ThreatLevel::CRITICAL) {
            spdlog::warn("High-level threat on chain {}, triggering polymorphic reorder", chainId);
            chainSecurity->triggerPolymorphicReorder("Multi-chain security threat response");
        }
    }
    
    // If global security manager is available, coordinate across chains
    if (globalSecurityManager_) {
        globalSecurityManager_->performSecurityScan();
        
        // Check if we need global response
        auto allChainIds = getAllChainIds();
        for (const auto& otherChainId : allChainIds) {
            if (otherChainId != chainId) {
                auto otherSecurityIt = chainSecurityManagers_.find(otherChainId);
                if (otherSecurityIt != chainSecurityManagers_.end()) {
                    // Perform preventive scan on other chains
                    otherSecurityIt->second->performSecurityScan();
                }
            }
        }
    }
}

// Method called from main.cpp security callback
bool MultiChainManager::synchronizeAllChains() {
    spdlog::info("Synchronizing all chains in multi-chain system");
    
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    bool allSynchronized = true;
    
    // Use consensus coordinator to synchronize
    if (consensusCoordinator_) {
        consensusCoordinator_->coordinateChainSynchronization();
    }
    
    // Synchronize each chain with its peers
    for (const auto& [chainId, network] : chainNetworks_) {
        if (chainConfigs_[chainId].isActive) {
            try {
                // Request chain sync from peers
                auto peers = network->getConnectedPeers();
                if (!peers.empty()) {
                    // Find highest chain height among peers
                    uint32_t maxPeerHeight = 0;
                    for (const auto& peer : peers) {
                        maxPeerHeight = std::max(maxPeerHeight, peer.chainHeight);
                    }
                    
                    // Sync if peers have higher height
                    auto chain = chains_[chainId];
                    if (chain && maxPeerHeight > chain->getChainHeight()) {
                        spdlog::info("Chain {} needs sync: local={}, peers={}", 
                                   chainId, chain->getChainHeight(), maxPeerHeight);
                        
                        // Request missing blocks (simplified)
                        auto chain = chains_[chainId];
                        if (chain && maxPeerHeight > chain->getChainHeight()) {
                            spdlog::info("Chain {} needs sync: local={}, peers={}", 
                               chainId, chain->getChainHeight(), maxPeerHeight);
                            spdlog::info("Manual chain sync required for chain {}", chainId);
                            }
                    }
                }
            } catch (const std::exception& e) {
                spdlog::error("Failed to synchronize chain {}: {}", chainId, e.what());
                allSynchronized = false;
            }
        }
    }
    
    spdlog::info("Chain synchronization completed, success: {}", allSynchronized);
    return allSynchronized;
}

// Method called from healthMonitorLoop
bool MultiChainManager::performHealthCheck() {
    bool allHealthy = true;
    
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    for (const auto& [chainId, config] : chainConfigs_) {
        if (!config.isActive) {
            continue; // Skip inactive chains
        }
        
        try {
            // Check blockchain health
            auto chain = chains_[chainId];
            if (!chain) {
                spdlog::error("Health check failed: Chain {} not found", chainId);
                allHealthy = false;
                continue;
            }
            
            // Validate chain integrity
            if (!chain->isValidChain()) {
                spdlog::error("Health check failed: Chain {} is invalid", chainId);
                allHealthy = false;
                continue;
            }
            
            // Check network connectivity
            auto network = chainNetworks_[chainId];
            if (network && !network->isRunning()) {
                spdlog::warn("Health check warning: Network for chain {} is not running", chainId);
                // Try to restart network
                if (!network->start()) {
                    spdlog::error("Failed to restart network for chain {}", chainId);
                    allHealthy = false;
                }
            }
            
            // Check security status
            auto security = chainSecurityManagers_[chainId];
            if (security) {
                auto threatLevel = security->assessThreatLevel();
                if (threatLevel == ThreatLevel::CRITICAL) {
                    spdlog::error("Health check failed: Chain {} has critical security threats", chainId);
                    allHealthy = false;
                }
            }
            
            // Log healthy chains at debug level
            spdlog::debug("Health check passed for chain: {}", chainId);
            
        } catch (const std::exception& e) {
            spdlog::error("Health check exception for chain {}: {}", chainId, e.what());
            allHealthy = false;
        }
    }
    
    if (allHealthy) {
        spdlog::debug("All chains passed health check");
    } else {
        spdlog::warn("Some chains failed health check");
    }
    
    return allHealthy;
}

// Additional required methods that are referenced but missing

std::vector<std::string> MultiChainManager::getAllChainIds() const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    std::vector<std::string> chainIds;
    chainIds.reserve(chainConfigs_.size());
    
    for (const auto& [chainId, config] : chainConfigs_) {
        chainIds.push_back(chainId);
    }
    
    return chainIds;
}

nlohmann::json MultiChainManager::getChainStatus(const std::string& chainId) const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    nlohmann::json status;
    
    auto configIt = chainConfigs_.find(chainId);
    if (configIt == chainConfigs_.end()) {
        status["error"] = "Chain not found";
        return status;
    }
    
    const auto& config = configIt->second;
    status["chainId"] = chainId;
    status["name"] = config.name;
    status["type"] = static_cast<int>(config.type);
    status["isActive"] = config.isActive;
    status["isPublic"] = config.isPublic;
    status["p2pPort"] = config.p2pPort;
    status["apiPort"] = config.apiPort;
    
    // Add chain-specific data
    auto chainIt = chains_.find(chainId);
    if (chainIt != chains_.end()) {
        status["height"] = chainIt->second->getChainHeight();
        status["difficulty"] = chainIt->second->getDifficulty();
        status["mempoolSize"] = chainIt->second->getTransactionPool().getTransactionCount();
    }
    
    // Add network data
    auto networkIt = chainNetworks_.find(chainId);
    if (networkIt != chainNetworks_.end()) {
        status["networkRunning"] = networkIt->second->isRunning();
        status["peerCount"] = networkIt->second->getPeerCount();
    }
    
    return status;
}

nlohmann::json MultiChainManager::getGlobalMetrics() const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    nlohmann::json metrics;
    
    metrics["totalChains"] = static_cast<int>(chains_.size());
    metrics["activeChains"] = 0;
    metrics["totalBlocks"] = 0;
    metrics["maxHeight"] = 0;
    metrics["totalTransactions"] = 0;
    metrics["crossChainTransactions"] = static_cast<int>(crossChainTransactions_.size());
    metrics["totalBridges"] = static_cast<int>(bridges_.size());
    
    for (const auto& [chainId, config] : chainConfigs_) {
        if (config.isActive) {
            metrics["activeChains"] = metrics["activeChains"].get<int>() + 1;
        }
        
        auto chainIt = chains_.find(chainId);
        if (chainIt != chains_.end()) {
            uint32_t height = chainIt->second->getChainHeight();
            metrics["totalBlocks"] = metrics["totalBlocks"].get<int>() + static_cast<int>(height);
            metrics["maxHeight"] = std::max(metrics["maxHeight"].get<int>(), static_cast<int>(height));
            
            const auto& chain = chainIt->second->getChain();
            for (const auto& block : chain) {
                metrics["totalTransactions"] = metrics["totalTransactions"].get<int>() + static_cast<int>(block.getTransactions().size());
            }
        }
    }
    
    return metrics;
}

bool MultiChainManager::performGlobalConsensus() {
    spdlog::debug("Performing global consensus across all chains");
    
    std::vector<std::string> activeChains;
    {
        std::lock_guard<std::mutex> lock(chainsMutex_);
        for (const auto& [chainId, config] : chainConfigs_) {
            if (config.isActive) {
                activeChains.push_back(chainId);
            }
        }
    }
    
    bool consensusAchieved = consensusCoordinator_->validateCrossChainConsensus(activeChains);
    
    if (consensusAchieved) {
        // Synchronize all chains
        consensusCoordinator_->coordinateChainSynchronization();
        
        // Process pending cross-chain transactions
        for (auto& [txId, transaction] : crossChainTransactions_) {
            if (!transaction.isConfirmed) {
                auto bridge = getBridge(transaction.sourceChainId, transaction.targetChainId);
                if (bridge && bridge->verifyCrossChainProof(transaction)) {
                    bridge->executeCrossChainTransaction(transaction);
                    transaction.isConfirmed = true;
                    transaction.confirmations = 1;
                }
            }
        }
    }
    
    if (globalConsensusCallback_) {
        globalConsensusCallback_(consensusAchieved);
    }
    
    return consensusAchieved;
}

std::shared_ptr<FileBlockchain> MultiChainManager::getFileChain(const std::string& chainId) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    auto it = chains_.find(chainId);
    if (it != chains_.end()) {
        // Try to cast to FileBlockchain
        return std::dynamic_pointer_cast<FileBlockchain>(it->second);
    }
    
    return nullptr;
}