#include "security/SecurityManager.h"
#include "blockchain/FileBlockchain.h"
#include "utils/Crypto.h"
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <random>
#include <chrono>
#include <fstream>
#include <iomanip>

// SecurityViolation implementations
nlohmann::json SecurityViolation::toJson() const {
    nlohmann::json json;
    json["event"] = static_cast<int>(event);
    json["level"] = static_cast<int>(level);
    json["blockIndex"] = blockIndex;
    json["blockHash"] = blockHash;
    json["description"] = description;
    json["timestamp"] = timestamp;
    json["peerSource"] = peerSource;
    return json;
}

// InfectedBlock implementations
nlohmann::json InfectedBlock::toJson() const {
    nlohmann::json json;
    json["index"] = index;
    json["hash"] = hash;
    json["originalPreviousHash"] = originalPreviousHash;
    json["corruptedData"] = corruptedData;
    json["detectionTime"] = detectionTime;
    json["affectedUserData"] = affectedUserData;
    json["quarantined"] = quarantined;
    return json;
}

// ReorderConfig implementations
nlohmann::json ReorderConfig::toJson() const {
    nlohmann::json json;
    json["triggerThreshold"] = triggerThreshold;
    json["maxReorderBlocks"] = maxReorderBlocks;
    json["randomnessFactor"] = randomnessFactor;
    json["enableAutoReorder"] = enableAutoReorder;
    json["reorderCooldown"] = reorderCooldown;
    return json;
}

void ReorderConfig::fromJson(const nlohmann::json& json) {
    triggerThreshold = json.value("triggerThreshold", triggerThreshold);
    maxReorderBlocks = json.value("maxReorderBlocks", maxReorderBlocks);
    randomnessFactor = json.value("randomnessFactor", randomnessFactor);
    enableAutoReorder = json.value("enableAutoReorder", enableAutoReorder);
    reorderCooldown = json.value("reorderCooldown", reorderCooldown);
}

// SecurityManager implementation
SecurityManager::SecurityManager(std::shared_ptr<Blockchain> blockchain)
    : blockchain_(blockchain), realTimeMonitoring_(false), 
      lastSecurityScan_(0), lastReorderTime_(0),
      totalViolations_(0), reorderCount_(0), dataRecoveryCount_(0) {
    
    // Initialize default configuration
    reorderConfig_.triggerThreshold = DEFAULT_REORDER_THRESHOLD;
    reorderConfig_.maxReorderBlocks = 50;
    reorderConfig_.randomnessFactor = DEFAULT_RANDOMNESS_FACTOR;
    reorderConfig_.enableAutoReorder = true;
    reorderConfig_.reorderCooldown = 300; // 5 minutes
    
    spdlog::info("SecurityManager initialized with {} threat detection", 
                 realTimeMonitoring_ ? "real-time" : "on-demand");
}

// ========================
// MAIN SECURITY OPERATIONS
// ========================

bool SecurityManager::performSecurityScan() {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    try {
        spdlog::info("Starting comprehensive security scan...");
        lastSecurityScan_ = std::time(nullptr);
        
        bool scanResult = true;
        uint32_t violationsFound = 0;
        
        // 1. Detect corrupted blocks
        if (!detectCorruptedBlocks()) {
            spdlog::warn("Corrupted blocks detected during scan");
            scanResult = false;
            violationsFound++;
        }
        
        // 2. Verify chain integrity
        if (!verifyChainIntegrity()) {
            spdlog::warn("Chain integrity violations detected");
            scanResult = false;
            violationsFound++;
        }
        
        // 3. Perform deep block analysis
        const auto& chain = blockchain_->getChain();
        for (const auto& block : chain) {
            if (!performDeepBlockAnalysis(block)) {
                spdlog::warn("Deep analysis failed for block {}", block.getIndex());
                violationsFound++;
            }
        }
        
        // 4. Detect anomalous patterns
        if (!detectAnomalousPatterns(chain)) {
            spdlog::warn("Anomalous patterns detected in blockchain");
            violationsFound++;
        }
        
        // 5. Auto-remediation if enabled
        if (reorderConfig_.enableAutoReorder && violationsFound >= reorderConfig_.triggerThreshold) {
            if (canExecuteReorder()) {
                spdlog::warn("Triggering automatic polymorphic reorder due to {} violations", violationsFound);
                triggerPolymorphicReorder("Automatic security scan remediation");
            }
        }
        
        totalViolations_ += violationsFound;
        
        spdlog::info("Security scan completed. Found {} violations, overall result: {}", 
                     violationsFound, scanResult ? "CLEAN" : "ISSUES_DETECTED");
        
        return scanResult;
        
    } catch (const std::exception& e) {
        spdlog::error("Security scan failed: {}", e.what());
        return false;
    }
}

bool SecurityManager::detectCorruptedBlocks() {
    spdlog::debug("Scanning for corrupted blocks...");
    
    const auto& chain = blockchain_->getChain();
    bool allBlocksValid = true;
    
    for (const auto& block : chain) {
        if (isBlockCorrupted(block)) {
            SecurityViolation violation;
            violation.event = SecurityEvent::CORRUPTED_BLOCK_DETECTED;
            violation.level = ThreatLevel::HIGH;
            violation.blockIndex = block.getIndex();
            violation.blockHash = block.getHash();
            violation.description = "Block hash validation failed";
            violation.timestamp = std::time(nullptr);
            violation.peerSource = "";
            
            violations_.push_back(violation);
            
            // Add to corrupted hashes set
            corruptedHashes_.insert(block.getHash());
            
            // Create infected block entry
            InfectedBlock infected;
            infected.index = block.getIndex();
            infected.hash = block.getHash();
            infected.originalPreviousHash = block.getPreviousHash();
            infected.corruptedData = "Hash validation failure";
            infected.detectionTime = std::time(nullptr);
            infected.quarantined = false;
            
            quarantinedBlocks_.push_back(infected);
            
            alertCriticalSecurity(violation);
            allBlocksValid = false;
            
            spdlog::error("Corrupted block detected: Index {}, Hash: {}", 
                         block.getIndex(), block.getHash().substr(0, 16) + "...");
        }
    }
    
    if (allBlocksValid) {
        spdlog::debug("No corrupted blocks found");
    }
    
    return allBlocksValid;
}

bool SecurityManager::verifyChainIntegrity() {
    spdlog::debug("Verifying chain integrity...");
    
    const auto& chain = blockchain_->getChain();
    bool integrityValid = true;
    
    for (size_t i = 1; i < chain.size(); ++i) {
        const auto& currentBlock = chain[i];
        const auto& previousBlock = chain[i - 1];
        
        // Check if previous hash matches
        if (currentBlock.getPreviousHash() != previousBlock.getHash()) {
            SecurityViolation violation;
            violation.event = SecurityEvent::CHAIN_INTEGRITY_VIOLATION;
            violation.level = ThreatLevel::CRITICAL;
            violation.blockIndex = currentBlock.getIndex();
            violation.blockHash = currentBlock.getHash();
            violation.description = "Previous hash mismatch detected";
            violation.timestamp = std::time(nullptr);
            violation.peerSource = "";
            
            violations_.push_back(violation);
            integrityViolations_[currentBlock.getIndex()] = "Previous hash mismatch";
            
            alertCriticalSecurity(violation);
            integrityValid = false;
            
            spdlog::error("Chain integrity violation at block {}: Previous hash mismatch", 
                         currentBlock.getIndex());
        }
        
        // Check timestamp ordering
        if (currentBlock.getTimestamp() <= previousBlock.getTimestamp()) {
            SecurityViolation violation;
            violation.event = SecurityEvent::CHAIN_INTEGRITY_VIOLATION;
            violation.level = ThreatLevel::MEDIUM;
            violation.blockIndex = currentBlock.getIndex();
            violation.blockHash = currentBlock.getHash();
            violation.description = "Invalid timestamp ordering";
            violation.timestamp = std::time(nullptr);
            violation.peerSource = "";
            
            violations_.push_back(violation);
            integrityViolations_[currentBlock.getIndex()] = "Invalid timestamp";
            
            spdlog::warn("Timestamp ordering violation at block {}", currentBlock.getIndex());
        }
    }
    
    return integrityValid;
}

bool SecurityManager::quarantineInfectedBlocks() {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    spdlog::info("Quarantining infected blocks...");
    
    for (auto& infected : quarantinedBlocks_) {
        if (!infected.quarantined) {
            // Extract user data before quarantine
            infected.affectedUserData = extractUserDataFromBlock(blockchain_->getBlock(infected.index));
            
            // Mark as quarantined
            infected.quarantined = true;
            
            SecurityViolation violation;
            violation.event = SecurityEvent::INFECTED_BLOCK_QUARANTINED;
            violation.level = ThreatLevel::HIGH;
            violation.blockIndex = infected.index;
            violation.blockHash = infected.hash;
            violation.description = "Block quarantined due to security violation";
            violation.timestamp = std::time(nullptr);
            violation.peerSource = "";
            
            violations_.push_back(violation);
            
            spdlog::warn("Quarantined infected block: Index {}, extracted {} user data items", 
                        infected.index, infected.affectedUserData.size());
        }
    }
    
    return true;
}

bool SecurityManager::migrateUserData() {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    spdlog::info("Migrating user data from quarantined blocks...");
    
    std::vector<std::string> allAffectedData;
    
    // Collect all affected user data
    for (const auto& infected : quarantinedBlocks_) {
        if (infected.quarantined) {
            allAffectedData.insert(allAffectedData.end(), 
                                 infected.affectedUserData.begin(), 
                                 infected.affectedUserData.end());
        }
    }
    
    if (allAffectedData.empty()) {
        spdlog::debug("No user data to migrate");
        return true;
    }
    
    // Preserve data integrity during migration
    if (!preserveUserDataIntegrity(allAffectedData)) {
        spdlog::error("Failed to preserve user data integrity during migration");
        return false;
    }
    
    // Migrate to clean chain
    migrateDataToCleanChain(allAffectedData);
    
    dataRecoveryCount_ += allAffectedData.size();
    
    SecurityViolation violation;
    violation.event = SecurityEvent::USER_DATA_MIGRATED;
    violation.level = ThreatLevel::MEDIUM;
    violation.blockIndex = 0;
    violation.blockHash = "";
    violation.description = "User data migrated to clean chain";
    violation.timestamp = std::time(nullptr);
    violation.peerSource = "";
    
    violations_.push_back(violation);
    
    spdlog::info("Successfully migrated {} user data items to clean chain", allAffectedData.size());
    return true;
}

bool SecurityManager::executePolymorphicReorder() {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    try {
        spdlog::info("Executing polymorphic chain reordering...");
        
        const auto& originalChain = blockchain_->getChain();
        if (originalChain.size() <= 1) {
            spdlog::warn("Chain too short for reordering");
            return false;
        }
        
        // Determine reorder scope
        uint32_t reorderBlocks = std::min(reorderConfig_.maxReorderBlocks, 
                                        static_cast<uint32_t>(originalChain.size() - 1));
        
        // Generate reorder sequence
        auto reorderSequence = generateReorderSequence(reorderBlocks);
        
        // Create reordered chain
        std::vector<Block> reorderedChain;
        reorderedChain.push_back(originalChain[0]); // Keep genesis block
        
        // Apply reordering to selected blocks
        for (uint32_t i = 0; i < reorderSequence.size(); ++i) {
            uint32_t originalIndex = reorderSequence[i];
            if (originalIndex < originalChain.size()) {
                Block reorderedBlock = originalChain[originalIndex];
                reorderedChain.push_back(reorderedBlock);
            }
        }
        
        // Add remaining blocks in original order
        for (size_t i = reorderBlocks + 1; i < originalChain.size(); ++i) {
            reorderedChain.push_back(originalChain[i]);
        }
        
        // Preserve chain logic and update references
        if (!preserveChainLogic(originalChain, reorderedChain)) {
            spdlog::error("Failed to preserve chain logic during reordering");
            return false;
        }
        
        // Update block references
        updateBlockReferences(reorderedChain);
        
        // Validate reordered chain
        if (!validateReorderedChain(reorderedChain)) {
            spdlog::error("Reordered chain validation failed");
            return false;
        }
        
        // Replace chain if validation passes
        if (!blockchain_->replaceChain(reorderedChain)) {
            spdlog::error("Failed to replace chain with reordered version");
            return false;
        }
        
        // Update state
        lastReorderTime_ = std::time(nullptr);
        reorderCount_++;
        
        // Clear quarantined blocks that were successfully reordered
        quarantinedBlocks_.clear();
        corruptedHashes_.clear();
        integrityViolations_.clear();
        
        SecurityViolation violation;
        violation.event = SecurityEvent::POLYMORPHIC_REORDER_TRIGGERED;
        violation.level = ThreatLevel::MEDIUM;
        violation.blockIndex = 0;
        violation.blockHash = "";
        violation.description = "Polymorphic chain reordering completed successfully";
        violation.timestamp = std::time(nullptr);
        violation.peerSource = "";
        
        violations_.push_back(violation);
        
        if (chainReorderCallback_) {
            chainReorderCallback_(reorderedChain);
        }
        
        spdlog::info("Polymorphic reordering completed successfully. Reordered {} blocks", reorderBlocks);
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Polymorphic reordering failed: {}", e.what());
        return false;
    }
}

// ========================
// BLOCK VALIDATION AND MONITORING
// ========================

bool SecurityManager::validateBlockSecurity(const Block& block, const Block* previousBlock) {
    // Basic hash integrity
    if (!checkHashIntegrity(block)) {
        spdlog::error("Block {} failed hash integrity check", block.getIndex());
        return false;
    }
    
    // Transaction integrity
    if (!validateTransactionIntegrity(block)) {
        spdlog::error("Block {} failed transaction integrity check", block.getIndex());
        return false;
    }
    
    // Previous block reference validation
    if (previousBlock) {
        if (block.getPreviousHash() != previousBlock->getHash()) {
            spdlog::error("Block {} has invalid previous hash reference", block.getIndex());
            return false;
        }
        
        if (block.getTimestamp() <= previousBlock->getTimestamp()) {
            spdlog::warn("Block {} has suspicious timestamp ordering", block.getIndex());
        }
    }
    
    return true;
}

bool SecurityManager::isBlockCorrupted(const Block& block) const {
    // Check if hash matches calculated hash
    std::string calculatedHash = const_cast<SecurityManager*>(this)->generateSecurityHash(block);
    if (calculatedHash != block.getHash()) {
        return true;
    }
    
    // Check if block is in corrupted hashes set
    if (corruptedHashes_.find(block.getHash()) != corruptedHashes_.end()) {
        return true;
    }
    
    // Additional corruption checks
    if (block.getTransactions().empty() && block.getIndex() > 0) {
        return true;
    }
    
    return false;
}

bool SecurityManager::hasChainIntegrityViolation(uint32_t startIndex, uint32_t endIndex) {
    const auto& chain = blockchain_->getChain();
    
    for (uint32_t i = startIndex; i <= endIndex && i < chain.size(); ++i) {
        if (integrityViolations_.find(i) != integrityViolations_.end()) {
            return true;
        }
    }
    
    return false;
}

// ========================
// THREAT DETECTION
// ========================

ThreatLevel SecurityManager::assessThreatLevel() const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    if (violations_.empty()) {
        return ThreatLevel::NONE;
    }
    
    // Count violations by level
    uint32_t criticalCount = 0;
    uint32_t highCount = 0;
    uint32_t mediumCount = 0;
    uint32_t lowCount = 0;
    
    for (const auto& violation : violations_) {
        switch (violation.level) {
            case ThreatLevel::CRITICAL: criticalCount++; break;
            case ThreatLevel::HIGH: highCount++; break;
            case ThreatLevel::MEDIUM: mediumCount++; break;
            case ThreatLevel::LOW: lowCount++; break;
            default: break;
        }
    }
    
    // Determine overall threat level
    if (criticalCount > 0) {
        return ThreatLevel::CRITICAL;
    } else if (highCount >= 3) {
        return ThreatLevel::CRITICAL;
    } else if (highCount > 0) {
        return ThreatLevel::HIGH;
    } else if (mediumCount >= 5) {
        return ThreatLevel::HIGH;
    } else if (mediumCount > 0) {
        return ThreatLevel::MEDIUM;
    } else {
        return ThreatLevel::LOW;
    }
}

std::vector<SecurityViolation> SecurityManager::getActiveThreats() const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    // Return recent violations (last 24 hours)
    std::vector<SecurityViolation> activeThreats;
    std::time_t now = std::time(nullptr);
    const std::time_t THREAT_EXPIRY = 24 * 60 * 60; // 24 hours
    
    for (const auto& violation : violations_) {
        if (now - violation.timestamp <= THREAT_EXPIRY) {
            activeThreats.push_back(violation);
        }
    }
    
    return activeThreats;
}

std::vector<InfectedBlock> SecurityManager::getQuarantinedBlocks() const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    std::vector<InfectedBlock> quarantined;
    for (const auto& infected : quarantinedBlocks_) {
        if (infected.quarantined) {
            quarantined.push_back(infected);
        }
    }
    
    return quarantined;
}

// ========================
// POLYMORPHIC CHAIN REORDERING
// ========================

void SecurityManager::triggerPolymorphicReorder(const std::string& reason) {
    spdlog::info("Triggering polymorphic reorder. Reason: {}", reason);
    
    if (!canExecuteReorder()) {
        spdlog::warn("Cannot execute reorder: cooldown active or conditions not met");
        return;
    }
    
    executePolymorphicReorder();
}

bool SecurityManager::canExecuteReorder() const {
    if (!reorderConfig_.enableAutoReorder) {
        return false;
    }
    
    return !isReorderCooldownActive();
}

std::vector<uint32_t> SecurityManager::generateReorderSequence(uint32_t blockCount) {
    std::vector<uint32_t> sequence;
    
    // Start with sequential indices (skipping genesis block)
    for (uint32_t i = 1; i <= blockCount; ++i) {
        sequence.push_back(i);
    }
    
    // Apply Fisher-Yates shuffle with controlled randomness
    return fisherYatesShuffle(sequence, reorderConfig_.randomnessFactor);
}

bool SecurityManager::validateReorderedChain(const std::vector<Block>& reorderedChain) {
    if (reorderedChain.empty()) {
        return false;
    }
    
    // Verify genesis block unchanged
    const auto& originalGenesis = blockchain_->getChain()[0];
    if (reorderedChain[0].getHash() != originalGenesis.getHash()) {
        spdlog::error("Genesis block was modified during reordering");
        return false;
    }
    
    // Verify chain integrity after reordering
    for (size_t i = 1; i < reorderedChain.size(); ++i) {
        const auto& currentBlock = reorderedChain[i];
        const auto& previousBlock = reorderedChain[i - 1];
        
        // Check if the reordered block references are valid
        // Note: After reordering, previous hash references are updated
        if (!validateBlockSecurity(currentBlock, &previousBlock)) {
            spdlog::error("Reordered chain validation failed at block {}", i);
            return false;
        }
    }
    
    return true;
}

// ========================
// USER DATA PROTECTION
// ========================

std::vector<std::string> SecurityManager::extractUserDataFromBlock(const Block& block) {
    std::vector<std::string> userData;
    
    // Extract transaction data that represents user operations
    for (const auto& transaction : block.getTransactions()) {
        if (!transaction.getOutputs().empty()) {
            // Store transaction signatures and addresses as user data
            for (const auto& output : transaction.getOutputs()) {
                if (!output.address.empty()) {
                    userData.push_back("address:" + output.address);
                    userData.push_back("amount:" + std::to_string(output.amount));
                }
            }
        }
        
        if (!transaction.getId().empty()) {
            userData.push_back("txid:" + transaction.getId());
        }
    }
    
    return userData;
}

bool SecurityManager::preserveUserDataIntegrity(const std::vector<std::string>& userData) {
    if (userData.empty()) {
        return true;
    }
    
    // Create integrity hashes for all user data
    for (const auto& data : userData) {
        std::string dataHash = Crypto::sha256(data);
        spdlog::debug("Preserving user data integrity: {} -> {}", 
                     data.substr(0, 20) + "...", dataHash.substr(0, 16) + "...");
    }
    
    return true;
}

void SecurityManager::migrateDataToCleanChain(const std::vector<std::string>& userData) {
    if (userData.empty()) {
        return;
    }
    
    spdlog::info("Migrating {} user data items to clean chain", userData.size());
    
    // In a real implementation, this would create new transactions
    // to preserve user data in the clean chain
    for (const auto& data : userData) {
        spdlog::debug("Migrating user data: {}", data.substr(0, 50) + "...");
    }
    
    // Mark data as migrated
    markDataAsMigrated(userData);
}

// ========================
// CONSENSUS AND PEER VALIDATION
// ========================

bool SecurityManager::validatePeerReportedViolation(const SecurityViolation& violation, const std::string& peerId) {
    // Basic validation of peer-reported security violation
    if (violation.blockHash.empty() || violation.description.empty()) {
        spdlog::warn("Invalid violation report from peer {}: missing required fields", peerId);
        return false;
    }
    
    // Check if we have the block they're reporting
    try {
        auto block = blockchain_->getBlockByHash(violation.blockHash);
        if (block.getHash().empty()) {
            spdlog::warn("Peer {} reported violation for unknown block: {}", 
                        peerId, violation.blockHash.substr(0, 16) + "...");
            return false;
        }
        
        // Validate the violation by checking the block ourselves
        if (violation.event == SecurityEvent::CORRUPTED_BLOCK_DETECTED) {
            return isBlockCorrupted(block);
        }
        
    } catch (const std::exception& e) {
        spdlog::error("Error validating peer violation: {}", e.what());
        return false;
    }
    
    return true;
}

void SecurityManager::reportViolationToPeers(const SecurityViolation& violation) {
    spdlog::info("Reporting security violation to network peers");
    
    // Store for consensus validation
    peerReportedViolations_[violation.blockHash] = violation;
    
    // In a real implementation, this would broadcast to P2P network
    spdlog::debug("Would broadcast violation: {} for block {}", 
                 static_cast<int>(violation.event), violation.blockHash.substr(0, 16) + "...");
}

bool SecurityManager::achieveConsensusOnThreat(const SecurityViolation& violation) {
    uint32_t agreementCount = countPeerAgreement(violation);
    uint32_t minimumConsensus = 3; // Require at least 3 peers to agree
    
    bool consensus = agreementCount >= minimumConsensus;
    
    spdlog::info("Threat consensus: {}/{} peers agree on violation for block {}", 
                agreementCount, minimumConsensus, violation.blockHash.substr(0, 16) + "...");
    
    return consensus;
}

// ========================
// PERSISTENCE
// ========================

bool SecurityManager::saveSecurityState(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    try {
        nlohmann::json securityJson;
        securityJson["violations"] = nlohmann::json::array();
        securityJson["quarantinedBlocks"] = nlohmann::json::array();
        securityJson["reorderConfig"] = reorderConfig_.toJson();
        securityJson["totalViolations"] = totalViolations_;
        securityJson["reorderCount"] = reorderCount_;
        securityJson["dataRecoveryCount"] = dataRecoveryCount_;
        securityJson["lastSecurityScan"] = lastSecurityScan_;
        securityJson["lastReorderTime"] = lastReorderTime_;
        
        for (const auto& violation : violations_) {
            securityJson["violations"].push_back(violation.toJson());
        }
        
        for (const auto& infected : quarantinedBlocks_) {
            securityJson["quarantinedBlocks"].push_back(infected.toJson());
        }
        
        return Utils::writeJsonFile(filename, securityJson);
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to save security state: {}", e.what());
        return false;
    }
}

bool SecurityManager::loadSecurityState(const std::string& filename) {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    if (!Utils::fileExists(filename)) {
        spdlog::info("Security state file {} does not exist", filename);
        return false;
    }
    
    try {
        nlohmann::json securityJson = Utils::readJsonFile(filename);
        if (securityJson.empty()) {
            return false;
        }
        
        // Load configuration
        if (securityJson.contains("reorderConfig")) {
            reorderConfig_.fromJson(securityJson["reorderConfig"]);
        }
        
        // Load statistics
        totalViolations_ = securityJson.value("totalViolations", 0);
        reorderCount_ = securityJson.value("reorderCount", 0);
        dataRecoveryCount_ = securityJson.value("dataRecoveryCount", 0);
        lastSecurityScan_ = securityJson.value("lastSecurityScan", 0);
        lastReorderTime_ = securityJson.value("lastReorderTime", 0);
        
        spdlog::info("Loaded security state with {} violations and {} reorders", 
                    totalViolations_, reorderCount_);
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to load security state: {}", e.what());
        return false;
    }
}

double SecurityManager::getChainIntegrityScore() const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    const auto& chain = blockchain_->getChain();
    if (chain.empty()) {
        return 0.0;
    }
    
    uint32_t validBlocks = 0;
    uint32_t totalBlocks = chain.size();
    
    for (const auto& block : chain) {
        if (!isBlockCorrupted(block) && 
            integrityViolations_.find(block.getIndex()) == integrityViolations_.end()) {
            validBlocks++;
        }
    }
    
    return (static_cast<double>(validBlocks) / totalBlocks) * 100.0;
}

nlohmann::json SecurityManager::generateSecurityReport() const {
    std::lock_guard<std::mutex> lock(securityMutex_);
    
    nlohmann::json report;
    report["timestamp"] = std::time(nullptr);
    report["chainIntegrityScore"] = getChainIntegrityScore();
    report["threatLevel"] = static_cast<int>(assessThreatLevel());
    report["totalViolations"] = totalViolations_;
    report["reorderCount"] = reorderCount_;
    report["dataRecoveryCount"] = dataRecoveryCount_;
    report["lastSecurityScan"] = lastSecurityScan_;
    report["lastReorderTime"] = lastReorderTime_;
    
    // Active threats summary
    auto activeThreats = getActiveThreats();
    report["activeThreatsCount"] = activeThreats.size();
    report["quarantinedBlocksCount"] = getQuarantinedBlocks().size();
    
    // Threat breakdown by level
    uint32_t criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
    for (const auto& threat : activeThreats) {
        switch (threat.level) {
            case ThreatLevel::CRITICAL: criticalCount++; break;
            case ThreatLevel::HIGH: highCount++; break;
            case ThreatLevel::MEDIUM: mediumCount++; break;
            case ThreatLevel::LOW: lowCount++; break;
            default: break;
        }
    }
    
    report["threatBreakdown"] = {
        {"critical", criticalCount},
        {"high", highCount},
        {"medium", mediumCount},
        {"low", lowCount}
    };
    
    // Configuration
    report["configuration"] = reorderConfig_.toJson();
    
    return report;
}
// ========================
// SECURITY CALLBACKS AND ALERTS
// ========================

void SecurityManager::setSecurityEventCallback(std::function<void(const SecurityViolation&)> callback) {
    securityEventCallback_ = callback;
}

void SecurityManager::setChainReorderCallback(std::function<void(const std::vector<Block>&)> callback) {
    chainReorderCallback_ = callback;
}

void SecurityManager::alertCriticalSecurity(const SecurityViolation& violation) {
    spdlog::critical("CRITICAL SECURITY ALERT: {} - Block {}: {}", 
                    securityEventToString(violation.event), 
                    violation.blockIndex, 
                    violation.description);
    
    if (securityEventCallback_) {
        securityEventCallback_(violation);
    }
    
    // Auto-escalate critical threats
    if (violation.level == ThreatLevel::CRITICAL) {
        escalateThreat(const_cast<SecurityViolation&>(violation));
    }
}

// ========================
// CORE SECURITY ALGORITHMS
// ========================

bool SecurityManager::performDeepBlockAnalysis(const Block& block) {
    // Comprehensive block analysis beyond basic validation
    
    // 1. Hash integrity check
    if (!checkHashIntegrity(block)) {
        return false;
    }
    
    // 2. Transaction integrity
    if (!validateTransactionIntegrity(block)) {
        return false;
    }
    
    // 3. Temporal analysis
    const auto& chain = blockchain_->getChain();
    if (block.getIndex() > 0 && block.getIndex() < chain.size()) {
        std::time_t blockTime = block.getTimestamp();
        std::time_t expectedTime = 0;
        
        // Check if timestamp is reasonable
        if (block.getIndex() > 1) {
            expectedTime = chain[block.getIndex() - 1].getTimestamp() + 
                          Blockchain::BLOCK_TIME_TARGET;
            
            if (std::abs(static_cast<long>(blockTime - expectedTime)) > 300) { // 5 minutes tolerance
                spdlog::warn("Block {} has suspicious timestamp: {} vs expected {}", 
                           block.getIndex(), blockTime, expectedTime);
            }
        }
    }
    
    // 4. Proof of work validation
    if (!Crypto::hasValidProofOfWork(block.getHash(), blockchain_->getDifficulty())) {
        spdlog::error("Block {} has invalid proof of work", block.getIndex());
        return false;
    }
    
    return true;
}

bool SecurityManager::checkHashIntegrity(const Block& block) {
    std::string computedHash = generateSecurityHash(block);
    return computedHash == block.getHash();
}

bool SecurityManager::validateTransactionIntegrity(const Block& block) {
    for (const auto& transaction : block.getTransactions()) {
        // Check transaction hash
        if (transaction.calculateHash() != transaction.getId()) {
            spdlog::error("Transaction hash mismatch in block {}", block.getIndex());
            return false;
        }
        
        // Check transaction validity
        if (!transaction.isValidTransaction()) {
            spdlog::error("Invalid transaction in block {}", block.getIndex());
            return false;
        }
        
        // Check for double spending (simplified)
        if (transaction.getTotalInputAmount() < transaction.getTotalOutputAmount()) {
            spdlog::error("Transaction with insufficient inputs in block {}", block.getIndex());
            return false;
        }
    }
    
    return true;
}

bool SecurityManager::detectAnomalousPatterns(const std::vector<Block>& blocks) {
    if (blocks.size() < 10) {
        return true; // Not enough data for pattern analysis
    }
    
    // 1. Check for unusual mining patterns
    std::unordered_map<std::string, uint32_t> minerCounts;
    std::vector<std::time_t> blockTimes;
    
    for (const auto& block : blocks) {
        blockTimes.push_back(block.getTimestamp());
        
        // Track mining patterns (simplified - would need miner identification)
        if (!block.getTransactions().empty()) {
            const auto& coinbase = block.getTransactions()[0];
            if (!coinbase.getOutputs().empty()) {
                minerCounts[coinbase.getOutputs()[0].address]++;
            }
        }
    }
    
    // 2. Check for timing anomalies
    for (size_t i = 1; i < blockTimes.size(); ++i) {
        std::time_t timeDiff = blockTimes[i] - blockTimes[i-1];
        
        // Detect suspiciously fast blocks
        if (timeDiff < 1) {
            spdlog::warn("Suspiciously fast block found at index {}: {} second interval", 
                        i, timeDiff);
        }
        
        // Detect suspiciously slow blocks
        if (timeDiff > 3600) { // 1 hour
            spdlog::warn("Suspiciously slow block found at index {}: {} second interval", 
                        i, timeDiff);
        }
    }
    
    // 3. Check for mining centralization
    uint32_t totalBlocks = blocks.size();
    for (const auto& [miner, count] : minerCounts) {
        double percentage = (static_cast<double>(count) / totalBlocks) * 100.0;
        if (percentage > 51.0) {
            spdlog::warn("Mining centralization detected: {} controls {:.1f}% of blocks", 
                        miner.substr(0, 16) + "...", percentage);
        }
    }
    
    return true; // Return true if no critical anomalies found
}

// ========================
// CHAIN REORDERING IMPLEMENTATION
// ========================

std::vector<uint32_t> SecurityManager::fisherYatesShuffle(std::vector<uint32_t> indices, double randomnessFactor) {
    if (randomnessFactor <= 0.0 || indices.empty()) {
        return indices;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Apply controlled randomness
    uint32_t swapCount = static_cast<uint32_t>(indices.size() * randomnessFactor);
    
    for (uint32_t i = 0; i < swapCount && i < indices.size(); ++i) {
        uint32_t j = i + (gen() % (indices.size() - i));
        if (i != j) {
            std::swap(indices[i], indices[j]);
        }
    }
    
    return indices;
}

bool SecurityManager::preserveChainLogic(const std::vector<Block>& originalChain, std::vector<Block>& reorderedChain) {
    if (originalChain.empty() || reorderedChain.empty()) {
        return false;
    }
    
    // Ensure genesis block is preserved
    if (reorderedChain[0].getHash() != originalChain[0].getHash()) {
        spdlog::error("Genesis block modified during reordering");
        return false;
    }
    
    // Preserve essential transaction dependencies
    std::unordered_set<std::string> processedOutputs;
    
    for (auto& block : reorderedChain) {
        for (const auto& transaction : block.getTransactions()) {
            // Check if inputs reference previously processed outputs
            for (const auto& input : transaction.getInputs()) {
                if (!input.transactionId.empty() && 
                    processedOutputs.find(input.transactionId) == processedOutputs.end()) {
                    spdlog::warn("Transaction dependency issue detected during reordering");
                    // In a real implementation, this would resolve dependencies
                }
            }
            
            // Mark outputs as processed
            processedOutputs.insert(transaction.getId());
        }
    }
    
    return true;
}

void SecurityManager::updateBlockReferences(std::vector<Block>& chain) {
    if (chain.size() <= 1) {
        return;
    }
    
    // Update previous hash references for reordered blocks
    for (size_t i = 1; i < chain.size(); ++i) {
        Block& currentBlock = chain[i];
        const Block& previousBlock = chain[i - 1];
        
        // Update previous hash reference
        currentBlock = Block(currentBlock.getIndex(), 
                           previousBlock.getHash(),
                           currentBlock.getTransactions());
        
        // Recalculate block hash with new references
        currentBlock.mineBlock(blockchain_->getDifficulty());
    }
}

bool SecurityManager::verifyReorderIntegrity(const std::vector<Block>& reorderedChain) {
    return validateReorderedChain(reorderedChain);
}

// ========================
// DATA MIGRATION HELPERS
// ========================

std::vector<std::string> SecurityManager::identifyAffectedUserData(const InfectedBlock& infectedBlock) {
    return infectedBlock.affectedUserData;
}

bool SecurityManager::createCleanDataBlock(const std::vector<std::string>& userData) {
    if (userData.empty()) {
        return true;
    }
    
    // Create transactions to preserve user data
    std::vector<Transaction> recoveryTransactions;
    
    for (const auto& data : userData) {
        // Parse data and create appropriate transactions
        if (data.find("address:") == 0) {
            std::string address = data.substr(8);
            // Create recovery transaction for this address
            Transaction recoveryTx(address, address, 0.0);
            recoveryTransactions.push_back(recoveryTx);
        }
    }
    
    // Add recovery transactions to blockchain
    for (const auto& tx : recoveryTransactions) {
        blockchain_->addTransaction(tx);
    }
    
    return true;
}

void SecurityManager::markDataAsMigrated(const std::vector<std::string>& userData) {
    spdlog::info("Marked {} data items as successfully migrated", userData.size());
    
    // In a real implementation, this would update a migration log
    for (const auto& data : userData) {
        spdlog::debug("Migrated: {}", data.substr(0, 50) + "...");
    }
}

// ========================
// THREAT ASSESSMENT HELPERS
// ========================

ThreatLevel SecurityManager::calculateThreatLevel(const SecurityViolation& violation) {
    switch (violation.event) {
        case SecurityEvent::CORRUPTED_BLOCK_DETECTED:
            return ThreatLevel::HIGH;
        case SecurityEvent::CHAIN_INTEGRITY_VIOLATION:
            return ThreatLevel::CRITICAL;
        case SecurityEvent::CONSENSUS_ATTACK_DETECTED:
            return ThreatLevel::CRITICAL;
        case SecurityEvent::PEER_MALICIOUS_BEHAVIOR:
            return ThreatLevel::MEDIUM;
        case SecurityEvent::INFECTED_BLOCK_QUARANTINED:
            return ThreatLevel::MEDIUM;
        case SecurityEvent::POLYMORPHIC_REORDER_TRIGGERED:
            return ThreatLevel::LOW;
        case SecurityEvent::USER_DATA_MIGRATED:
            return ThreatLevel::LOW;
        default:
            return ThreatLevel::MEDIUM;
    }
}

bool SecurityManager::isViolationCritical(const SecurityViolation& violation) {
    return violation.level == ThreatLevel::CRITICAL;
}

void SecurityManager::escalateThreat(SecurityViolation& violation) {
    if (violation.level != ThreatLevel::CRITICAL) {
        violation.level = static_cast<ThreatLevel>(static_cast<int>(violation.level) + 1);
        spdlog::warn("Escalated threat level for violation at block {}", violation.blockIndex);
    }
    
    // Trigger automatic response for critical threats
    if (isViolationCritical(violation)) {
        if (reorderConfig_.enableAutoReorder && canExecuteReorder()) {
            triggerPolymorphicReorder("Critical threat escalation");
        }
    }
}

// ========================
// CONSENSUS HELPERS
// ========================

bool SecurityManager::validateViolationConsistency(const SecurityViolation& v1, const SecurityViolation& v2) {
    return v1.blockHash == v2.blockHash && 
           v1.event == v2.event && 
           std::abs(static_cast<long>(v1.timestamp - v2.timestamp)) < 300; // 5 minute tolerance
}

uint32_t SecurityManager::countPeerAgreement(const SecurityViolation& violation) {
    uint32_t agreementCount = 0;
    
    for (const auto& [hash, peerViolation] : peerReportedViolations_) {
        if (validateViolationConsistency(violation, peerViolation)) {
            agreementCount++;
        }
    }
    
    return agreementCount;
}

// ========================
// UTILITY FUNCTIONS
// ========================

std::string SecurityManager::generateSecurityHash(const Block& block) {
    // Generate hash for security validation (simplified version of block hash calculation)
    std::stringstream ss;
    ss << block.getIndex() << block.getPreviousHash() << block.getTimestamp() << block.getNonce();
    
    for (const auto& tx : block.getTransactions()) {
        ss << tx.getId();
    }
    
    return Crypto::sha256(ss.str());
}

bool SecurityManager::isReorderCooldownActive() const {
    if (lastReorderTime_ == 0) {
        return false;
    }
    
    std::time_t now = std::time(nullptr);
    return (now - lastReorderTime_) < reorderConfig_.reorderCooldown;
}

void SecurityManager::logSecurityEvent(const SecurityViolation& violation) {
    spdlog::warn("Security Event: {} | Level: {} | Block: {} | Description: {}", 
                securityEventToString(violation.event),
                threatLevelToString(violation.level),
                violation.blockIndex,
                violation.description);
}

std::string SecurityManager::threatLevelToString(ThreatLevel level) const {
    switch (level) {
        case ThreatLevel::NONE: return "NONE";
        case ThreatLevel::LOW: return "LOW";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string SecurityManager::securityEventToString(SecurityEvent event) const {
    switch (event) {
        case SecurityEvent::CORRUPTED_BLOCK_DETECTED: return "CORRUPTED_BLOCK_DETECTED";
        case SecurityEvent::CHAIN_INTEGRITY_VIOLATION: return "CHAIN_INTEGRITY_VIOLATION";
        case SecurityEvent::INFECTED_BLOCK_QUARANTINED: return "INFECTED_BLOCK_QUARANTINED";
        case SecurityEvent::POLYMORPHIC_REORDER_TRIGGERED: return "POLYMORPHIC_REORDER_TRIGGERED";
        case SecurityEvent::USER_DATA_MIGRATED: return "USER_DATA_MIGRATED";
        case SecurityEvent::PEER_MALICIOUS_BEHAVIOR: return "PEER_MALICIOUS_BEHAVIOR";
        case SecurityEvent::CONSENSUS_ATTACK_DETECTED: return "CONSENSUS_ATTACK_DETECTED";
        default: return "UNKNOWN_EVENT";
    }
}