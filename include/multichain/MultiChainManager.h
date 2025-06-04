// =======================================================================================
// MultiChainManager System - Complete Integration
// =======================================================================================

// include/multichain/MultiChainManager.h
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>
#include "../blockchain/Blockchain.h"
#include "../blockchain/FileBlockchain.h"
#include "../p2p/P2PNetwork.h"
#include "../security/SecurityManager.h"
#include "../utils/Crypto.h"

// Chain types supported by the multi-chain system
enum class ChainType {
    MAIN_CHAIN,           // Primary blockchain for transactions
    FILE_CHAIN,           // Specialized file storage chain
    IDENTITY_CHAIN,       // Identity and access management
    SIDECHAIN,           // General purpose sidechain
    PRIVATE_CHAIN,       // Private/permissioned chain
    TEST_CHAIN           // Testing and development chain
};

// Chain configuration structure
struct ChainConfig {
    std::string chainId;
    ChainType type;
    std::string name;
    std::string description;
    uint32_t difficulty;
    uint32_t blockTimeTarget;
    double miningReward;
    uint16_t p2pPort;
    uint16_t apiPort;
    bool isActive;
    bool isPublic;
    std::vector<std::string> genesisValidators;
    nlohmann::json customConfig;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// Cross-chain transaction structure
struct CrossChainTransaction {
    std::string transactionId;
    std::string sourceChainId;
    std::string targetChainId;
    std::string sourceAddress;
    std::string targetAddress;
    double amount;
    nlohmann::json payload;
    std::string proof;
    std::time_t timestamp;
    bool isConfirmed;
    uint32_t confirmations;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// Chain bridge for cross-chain operations
class ChainBridge {
public:
    ChainBridge(const std::string& sourceChainId, const std::string& targetChainId);
    
    // Cross-chain operations
    std::string initiateCrossChainTransfer(const std::string& fromAddress, 
                                         const std::string& toAddress, 
                                         double amount,
                                         const nlohmann::json& payload = {});
    
    bool verifyCrossChainProof(const CrossChainTransaction& transaction);
    bool executeCrossChainTransaction(const CrossChainTransaction& transaction);
    
    // Bridge management
    void enableBridge() { enabled_ = true; }
    void disableBridge() { enabled_ = false; }
    bool isEnabled() const { return enabled_; }
    
    // Statistics
    uint64_t getTotalTransfers() const { return totalTransfers_; }
    double getTotalVolume() const { return totalVolume_; }

private:
    std::string sourceChainId_;
    std::string targetChainId_;
    std::atomic<bool> enabled_;
    std::atomic<uint64_t> totalTransfers_;
    std::atomic<double> totalVolume_;
    mutable std::mutex bridgeMutex_;
};

// Multi-chain consensus coordinator
class ConsensusCoordinator {
public:
    ConsensusCoordinator();
    
    // Consensus management
    bool validateCrossChainConsensus(const std::vector<std::string>& chainIds);
    void coordinateChainSynchronization();
    bool resolveChainConflicts(const std::string& chainId);
    
    // Validator management
    void addValidator(const std::string& chainId, const std::string& validatorAddress);
    void removeValidator(const std::string& chainId, const std::string& validatorAddress);
    std::vector<std::string> getValidators(const std::string& chainId) const;
    
    // Consensus algorithms
    bool performPoSConsensus(const std::string& chainId);
    bool performPoWConsensus(const std::string& chainId);
    bool performPBFTConsensus(const std::string& chainId);

private:
    std::unordered_map<std::string, std::vector<std::string>> chainValidators_;
    mutable std::mutex consensusMutex_;
};

// Main MultiChainManager class
class MultiChainManager {
public:
    // Constructor
    MultiChainManager();
    
    // Destructor
    ~MultiChainManager();
    
    // ========================
    // CHAIN MANAGEMENT
    // ========================
    
    // Chain lifecycle
    std::string createChain(const ChainConfig& config);
    bool startChain(const std::string& chainId);
    bool stopChain(const std::string& chainId);
    bool removeChain(const std::string& chainId);
    
    // Chain access
    std::shared_ptr<Blockchain> getChain(const std::string& chainId);
    std::shared_ptr<FileBlockchain> getFileChain(const std::string& chainId);
    std::vector<std::string> getAllChainIds() const;
    std::vector<ChainConfig> getAllChainConfigs() const;
    
    // Chain status
    bool isChainActive(const std::string& chainId) const;
    uint32_t getChainHeight(const std::string& chainId) const;
    nlohmann::json getChainStatus(const std::string& chainId) const;
    nlohmann::json getAllChainsStatus() const;
    
    // ========================
    // CROSS-CHAIN OPERATIONS
    // ========================
    
    // Bridge management
    bool createBridge(const std::string& sourceChainId, const std::string& targetChainId);
    bool removeBridge(const std::string& sourceChainId, const std::string& targetChainId);
    std::shared_ptr<ChainBridge> getBridge(const std::string& sourceChainId, 
                                          const std::string& targetChainId);
    
    // Cross-chain transactions
    std::string initiateCrossChainTransfer(const std::string& sourceChainId,
                                         const std::string& targetChainId,
                                         const std::string& fromAddress,
                                         const std::string& toAddress,
                                         double amount,
                                         const nlohmann::json& payload = {});
    
    bool confirmCrossChainTransaction(const std::string& transactionId);
    CrossChainTransaction getCrossChainTransaction(const std::string& transactionId) const;
    std::vector<CrossChainTransaction> getPendingCrossChainTransactions() const;
    
    // ========================
    // CONSENSUS COORDINATION
    // ========================
    
    // Global consensus
    bool performGlobalConsensus();
    bool synchronizeAllChains();
    void resolveInterChainConflicts();
    
    // Validator management
    void registerValidator(const std::string& chainId, const std::string& validatorAddress);
    void unregisterValidator(const std::string& chainId, const std::string& validatorAddress);
    
    // ========================
    // SECURITY INTEGRATION
    // ========================
    
    // Security coordination
    void setGlobalSecurityManager(std::shared_ptr<SecurityManager> securityManager);
    bool performGlobalSecurityScan();
    void handleSecurityThreat(const std::string& chainId, const SecurityViolation& threat);
    void triggerGlobalPolymorphicReorder(const std::string& reason);
    
    // ========================
    // NETWORK COORDINATION
    // ========================
    
    // P2P network management
    void setNetworkCoordinator(std::shared_ptr<P2PNetwork> coordinator);
    bool broadcastToAllChains(const nlohmann::json& message);
    void synchronizeNetworkTopology();
    
    // ========================
    // DATA MANAGEMENT
    // ========================
    
    // File distribution across chains
    std::string distributeFile(const std::vector<uint8_t>& fileData, 
                              const std::string& filename,
                              const std::string& uploaderAddress,
                              const std::vector<std::string>& targetChains);
    
    std::vector<uint8_t> retrieveDistributedFile(const std::string& fileId,
                                                const std::vector<std::string>& sourceChains);
    
    // Data redundancy and backup
    bool createChainBackup(const std::string& chainId, const std::string& backupPath);
    bool restoreChainFromBackup(const std::string& chainId, const std::string& backupPath);
    
    // ========================
    // ANALYTICS AND MONITORING
    // ========================
    
    // Performance metrics
    nlohmann::json getGlobalMetrics() const;
    nlohmann::json getChainMetrics(const std::string& chainId) const;
    double getGlobalThroughput() const;
    
    // Health monitoring
    bool performHealthCheck();
    std::vector<std::string> getUnhealthyChains() const;
    void repairChain(const std::string& chainId);
    
    // ========================
    // CONFIGURATION
    // ========================
    
    // Global settings
    void setGlobalDifficulty(uint32_t difficulty);
    void setGlobalBlockTime(uint32_t blockTime);
    void enableAutoScaling(bool enable) { autoScalingEnabled_ = enable; }
    void enableLoadBalancing(bool enable) { loadBalancingEnabled_ = enable; }
    
    // Chain templates
    void registerChainTemplate(const std::string& templateName, const ChainConfig& config);
    ChainConfig getChainTemplate(const std::string& templateName) const;
    std::string createChainFromTemplate(const std::string& templateName, 
                                       const std::string& chainName);
    
    // ========================
    // CALLBACKS AND EVENTS
    // ========================
    
    // Event callbacks
    void setChainCreatedCallback(std::function<void(const std::string&)> callback);
    void setCrossChainTransactionCallback(std::function<void(const CrossChainTransaction&)> callback);
    void setGlobalConsensusCallback(std::function<void(bool)> callback);
    
    // ========================
    // PERSISTENCE
    // ========================
    
    // Save/load state
    bool saveMultiChainState(const std::string& filename) const;
    bool loadMultiChainState(const std::string& filename);
    
    // Configuration management
    bool saveConfiguration(const std::string& filename) const;
    bool loadConfiguration(const std::string& filename);

private:
    // Core data structures
    std::unordered_map<std::string, std::shared_ptr<Blockchain>> chains_;
    std::unordered_map<std::string, ChainConfig> chainConfigs_;
    std::unordered_map<std::string, std::shared_ptr<P2PNetwork>> chainNetworks_;
    std::unordered_map<std::string, std::shared_ptr<SecurityManager>> chainSecurityManagers_;
    
    // Cross-chain infrastructure
    std::unordered_map<std::string, std::shared_ptr<ChainBridge>> bridges_;
    std::unordered_map<std::string, CrossChainTransaction> crossChainTransactions_;
    std::unique_ptr<ConsensusCoordinator> consensusCoordinator_;
    
    // Global components
    std::shared_ptr<SecurityManager> globalSecurityManager_;
    std::shared_ptr<P2PNetwork> networkCoordinator_;
    
    // Configuration
    std::unordered_map<std::string, ChainConfig> chainTemplates_;
    bool autoScalingEnabled_;
    bool loadBalancingEnabled_;
    uint32_t globalDifficulty_;
    uint32_t globalBlockTime_;
    
    // Threading and synchronization
    mutable std::mutex chainsMutex_;
    mutable std::mutex bridgesMutex_;
    mutable std::mutex configMutex_;
    std::vector<std::thread> workerThreads_;
    std::atomic<bool> running_;
    
    // Callbacks
    std::function<void(const std::string&)> chainCreatedCallback_;
    std::function<void(const CrossChainTransaction&)> crossChainTransactionCallback_;
    std::function<void(bool)> globalConsensusCallback_;
    
    // Internal methods
    void startWorkerThreads();
    void stopWorkerThreads();
    void consensusWorkerLoop();
    void crossChainWorkerLoop();
    void healthMonitorLoop();
    
    std::string generateChainId(const std::string& name, ChainType type);
    std::string generateBridgeId(const std::string& sourceChain, const std::string& targetChain);
    
    bool validateChainConfig(const ChainConfig& config) const;
    bool validateCrossChainTransaction(const CrossChainTransaction& transaction) const;
    
    void initializeDefaultChains();
    void setupDefaultBridges();
    void loadDefaultTemplates();
    
    // Constants
    static constexpr uint32_t DEFAULT_MAX_CHAINS = 10;
    static constexpr uint32_t DEFAULT_BRIDGE_TIMEOUT = 300; // 5 minutes
    static constexpr uint32_t DEFAULT_CONSENSUS_INTERVAL = 60; // 1 minute
};

// Factory class for creating specific chain types
class ChainFactory {
public:
    static std::shared_ptr<Blockchain> createChain(ChainType type, const ChainConfig& config);
    static std::shared_ptr<FileBlockchain> createFileChain(const ChainConfig& config);
    static ChainConfig createDefaultConfig(ChainType type, const std::string& name);
    
private:
    static ChainConfig getMainChainTemplate();
    static ChainConfig getFileChainTemplate();
    static ChainConfig getIdentityChainTemplate();
    static ChainConfig getSidechainTemplate();
    static ChainConfig getPrivateChainTemplate();
    static ChainConfig getTestChainTemplate();
};

// =======================================================================================
// Implementation snippets (would be in separate .cpp files)
// =======================================================================================

// src/multichain/MultiChainManager.cpp (key methods)

std::string MultiChainManager::createChain(const ChainConfig& config) {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    if (!validateChainConfig(config)) {
        throw std::invalid_argument("Invalid chain configuration");
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

std::string MultiChainManager::initiateCrossChainTransfer(
    const std::string& sourceChainId,
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

// Integration with existing CLI (add to CLIInterface.cpp)
int CLIInterface::cmdMultiChain(const std::vector<std::string>& args) {
    if (!multiChainManager_) {
        printError("MultiChainManager not available");
        return 1;
    }
    
    if (args.size() < 2) {
        printError("Usage: multichain <command> [options]");
        return 1;
    }
    
    std::string command = args[1];
    
    if (command == "list") {
        auto chainIds = multiChainManager_->getAllChainIds();
        printInfo("Active Chains:");
        for (const auto& chainId : chainIds) {
            auto status = multiChainManager_->getChainStatus(chainId);
            std::cout << "  " << chainId << " - Height: " << status["height"] 
                     << " - Status: " << status["status"] << std::endl;
        }
    }
    else if (command == "create") {
        if (args.size() < 4) {
            printError("Usage: multichain create <type> <name>");
            return 1;
        }
        
        std::string typeStr = args[2];
        std::string name = args[3];
        
        ChainType type = ChainType::MAIN_CHAIN;
        if (typeStr == "file") type = ChainType::FILE_CHAIN;
        else if (typeStr == "identity") type = ChainType::IDENTITY_CHAIN;
        else if (typeStr == "side") type = ChainType::SIDECHAIN;
        else if (typeStr == "private") type = ChainType::PRIVATE_CHAIN;
        else if (typeStr == "test") type = ChainType::TEST_CHAIN;
        
        auto config = ChainFactory::createDefaultConfig(type, name);
        std::string chainId = multiChainManager_->createChain(config);
        
        printSuccess("Created chain: " + chainId);
    }
    else if (command == "transfer") {
        if (args.size() < 7) {
            printError("Usage: multichain transfer <source-chain> <target-chain> <from> <to> <amount>");
            return 1;
        }
        
        std::string sourceChain = args[2];
        std::string targetChain = args[3];
        std::string fromAddress = args[4];
        std::string toAddress = args[5];
        double amount = std::stod(args[6]);
        
        try {
            std::string txId = multiChainManager_->initiateCrossChainTransfer(
                sourceChain, targetChain, fromAddress, toAddress, amount);
            printSuccess("Cross-chain transfer initiated: " + txId);
        } catch (const std::exception& e) {
            printError("Transfer failed: " + std::string(e.what()));
            return 1;
        }
    }
    
    return 0;
}