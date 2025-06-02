#pragma once

#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../blockchain/Block.h"
#include "../blockchain/Blockchain.h"

// Security threat levels
enum class ThreatLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Security event types
enum class SecurityEvent {
    CORRUPTED_BLOCK_DETECTED,
    CHAIN_INTEGRITY_VIOLATION,
    INFECTED_BLOCK_QUARANTINED,
    POLYMORPHIC_REORDER_TRIGGERED,
    USER_DATA_MIGRATED,
    PEER_MALICIOUS_BEHAVIOR,
    CONSENSUS_ATTACK_DETECTED
};

// Security violation details
struct SecurityViolation {
    SecurityEvent event;
    ThreatLevel level;
    uint32_t blockIndex;
    std::string blockHash;
    std::string description;
    std::time_t timestamp;
    std::string peerSource;
    
    nlohmann::json toJson() const;
};

// Infected block information
struct InfectedBlock {
    uint32_t index;
    std::string hash;
    std::string originalPreviousHash;
    std::string corruptedData;
    std::time_t detectionTime;
    std::vector<std::string> affectedUserData;
    bool quarantined;
    
    nlohmann::json toJson() const;
};

// Chain reordering configuration
struct ReorderConfig {
    uint32_t triggerThreshold;      // Number of violations before reorder
    uint32_t maxReorderBlocks;      // Maximum blocks to reorder
    double randomnessFactor;        // 0.0-1.0, higher = more random
    bool enableAutoReorder;         // Auto-trigger reordering
    uint32_t reorderCooldown;       // Seconds between reorders
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

class SecurityManager {
public:
    // Constructor
    explicit SecurityManager(std::shared_ptr<Blockchain> blockchain);
    
    // Destructor
    ~SecurityManager() = default;
    
    // Main security operations
    bool performSecurityScan();
    bool detectCorruptedBlocks();
    bool verifyChainIntegrity();
    bool quarantineInfectedBlocks();
    bool migrateUserData();
    bool executePolymorphicReorder();
    
    // Block validation and monitoring
    bool validateBlockSecurity(const Block& block, const Block* previousBlock = nullptr);
    bool isBlockCorrupted(const Block &block) const;
    //bool isBlockCorrupted(const Block &block);
    bool hasChainIntegrityViolation(uint32_t startIndex, uint32_t endIndex);
    
    // Threat detection
    ThreatLevel assessThreatLevel() const;
    std::vector<SecurityViolation> getActiveThreats() const;
    std::vector<InfectedBlock> getQuarantinedBlocks() const;
    
    // Polymorphic chain reordering
    void triggerPolymorphicReorder(const std::string& reason = "");
    bool canExecuteReorder() const;
    std::vector<uint32_t> generateReorderSequence(uint32_t blockCount);
    bool validateReorderedChain(const std::vector<Block>& reorderedChain);
    
    // User data protection
    std::vector<std::string> extractUserDataFromBlock(const Block& block);
    bool preserveUserDataIntegrity(const std::vector<std::string>& userData);
    void migrateDataToCleanChain(const std::vector<std::string>& userData);
    
    // Security configuration
    void setReorderConfig(const ReorderConfig& config) { reorderConfig_ = config; }
    const ReorderConfig& getReorderConfig() const { return reorderConfig_; }
    void enableRealTimeMonitoring(bool enable) { realTimeMonitoring_ = enable; }
    
    // Security callbacks and alerts
    void setSecurityEventCallback(std::function<void(const SecurityViolation&)> callback);
    void setChainReorderCallback(std::function<void(const std::vector<Block>&)> callback);
    void alertCriticalSecurity(const SecurityViolation& violation);
    
    // Security statistics and reporting
    uint32_t getTotalViolationsCount() const { return totalViolations_; }
    uint32_t getReorderCount() const { return reorderCount_; }
    std::time_t getLastSecurityScan() const { return lastSecurityScan_; }
    double getChainIntegrityScore() const;
    nlohmann::json generateSecurityReport() const;
    
    // Consensus and peer validation
    bool validatePeerReportedViolation(const SecurityViolation& violation, const std::string& peerId);
    void reportViolationToPeers(const SecurityViolation& violation);
    bool achieveConsensusOnThreat(const SecurityViolation& violation);
    
    // Persistence
    bool saveSecurityState(const std::string& filename) const;
    bool loadSecurityState(const std::string& filename);
    
    // Constants
    static constexpr uint32_t DEFAULT_REORDER_THRESHOLD = 5;
    static constexpr uint32_t MAX_QUARANTINE_BLOCKS = 100;
    static constexpr double DEFAULT_RANDOMNESS_FACTOR = 0.7;
    static constexpr uint32_t SECURITY_SCAN_INTERVAL = 60; // seconds

private:
    // Core data
    std::shared_ptr<Blockchain> blockchain_;
    mutable std::mutex securityMutex_;
    
    // Security state
    std::vector<SecurityViolation> violations_;
    std::vector<InfectedBlock> quarantinedBlocks_;
    std::unordered_set<std::string> corruptedHashes_;
    std::unordered_map<uint32_t, std::string> integrityViolations_;
    
    // Configuration
    ReorderConfig reorderConfig_;
    bool realTimeMonitoring_;
    std::time_t lastSecurityScan_;
    std::time_t lastReorderTime_;
    
    // Statistics
    uint32_t totalViolations_;
    uint32_t reorderCount_;
    uint32_t dataRecoveryCount_;
    
    // Callbacks
    std::function<void(const SecurityViolation&)> securityEventCallback_;
    std::function<void(const std::vector<Block>&)> chainReorderCallback_;
    
    // Core security algorithms
    bool performDeepBlockAnalysis(const Block& block);
    bool checkHashIntegrity(const Block& block);
    bool validateTransactionIntegrity(const Block& block);
    bool detectAnomalousPatterns(const std::vector<Block>& blocks);
    
    // Chain reordering implementation
    std::vector<uint32_t> fisherYatesShuffle(std::vector<uint32_t> indices, double randomnessFactor);
    bool preserveChainLogic(const std::vector<Block>& originalChain, std::vector<Block>& reorderedChain);
    void updateBlockReferences(std::vector<Block>& chain);
    bool verifyReorderIntegrity(const std::vector<Block>& reorderedChain);
    
    // Data migration helpers
    std::vector<std::string> identifyAffectedUserData(const InfectedBlock& infectedBlock);
    bool createCleanDataBlock(const std::vector<std::string>& userData);
    void markDataAsMigrated(const std::vector<std::string>& userData);
    
    // Threat assessment helpers
    ThreatLevel calculateThreatLevel(const SecurityViolation& violation);
    bool isViolationCritical(const SecurityViolation& violation);
    void escalateThreat(SecurityViolation& violation);
    
    // Consensus helpers
    std::unordered_map<std::string, SecurityViolation> peerReportedViolations_;
    bool validateViolationConsistency(const SecurityViolation& v1, const SecurityViolation& v2);
    uint32_t countPeerAgreement(const SecurityViolation& violation);
    
    // Utility functions
    std::string generateSecurityHash(const Block& block);
    bool isReorderCooldownActive() const;
    void logSecurityEvent(const SecurityViolation& violation);
    std::string threatLevelToString(ThreatLevel level) const;
    std::string securityEventToString(SecurityEvent event) const;
};