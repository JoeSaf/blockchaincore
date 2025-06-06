// =======================================================================================
// src/multichain/ChainBridge.cpp - Alternative Solution with Mutex
// =======================================================================================

#include "multichain/MultiChainManager.h"
#include "utils/Crypto.h"
#include <spdlog/spdlog.h>

ChainBridge::ChainBridge(const std::string& sourceChainId, const std::string& targetChainId)
    : sourceChainId_(sourceChainId)
    , targetChainId_(targetChainId)
    , enabled_(false)
    , totalTransfers_(0)
    , totalVolume_(0.0) {
    
    spdlog::debug("Created bridge: {} -> {}", sourceChainId, targetChainId);
}

std::string ChainBridge::initiateCrossChainTransfer(const std::string& fromAddress, 
                                                   const std::string& toAddress, 
                                                   double amount,
                                                   const nlohmann::json& payload) {
    if (!enabled_) {
        throw std::runtime_error("Bridge is disabled");
    }
    
    std::lock_guard<std::mutex> lock(bridgeMutex_);
    
    // Generate unique transfer ID
    std::string transferId = Crypto::generateRandomString(32);
    
    // Update statistics - SIMPLE FIX: Since we already have mutex lock, just use regular operations
    totalTransfers_.fetch_add(1);  // This works for atomic<uint64_t>
    totalVolume_.store(totalVolume_.load() + amount);  // Load current value, add amount, store back
    
    spdlog::info("Initiated cross-chain transfer: {} ({} -> {}, Amount: {})",
                 transferId, sourceChainId_, targetChainId_, amount);
    
    return transferId;
}

bool ChainBridge::verifyCrossChainProof(const CrossChainTransaction& transaction) {
    // Verify cryptographic proof
    std::string expectedProof = transaction.transactionId + transaction.sourceChainId + 
                               transaction.targetChainId + transaction.sourceAddress + 
                               transaction.targetAddress + std::to_string(transaction.amount);
    
    std::string computedProof = Crypto::sha256(expectedProof);
    
    return computedProof == transaction.proof;
}

bool ChainBridge::executeCrossChainTransaction(const CrossChainTransaction& transaction) {
    if (!enabled_) {
        return false;
    }
    
    // In a real implementation, this would:
    // 1. Lock funds on source chain
    // 2. Create corresponding transaction on target chain
    // 3. Update balances accordingly
    // 4. Handle rollback if needed
    
    spdlog::info("Executed cross-chain transaction: {} (Amount: {})",
                 transaction.transactionId, transaction.amount);
    
    return true;
}