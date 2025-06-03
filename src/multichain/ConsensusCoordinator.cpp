// =======================================================================================
// src/multichain/ConsensusCoordinator.cpp
// =======================================================================================

#include "multichain/MultiChainManager.h"
#include <spdlog/spdlog.h>
#include <algorithm>

ConsensusCoordinator::ConsensusCoordinator() {
    spdlog::debug("ConsensusCoordinator initialized");
}

bool ConsensusCoordinator::validateCrossChainConsensus(const std::vector<std::string>& chainIds) {
    std::lock_guard<std::mutex> lock(consensusMutex_);
    
    // Simple consensus: all chains must be synchronized
    for (const auto& chainId : chainIds) {
        auto validators = getValidators(chainId);
        if (validators.size() < 1) {
            spdlog::warn("Chain {} has no validators", chainId);
            return false;
        }
    }
    
    spdlog::debug("Cross-chain consensus validated for {} chains", chainIds.size());
    return true;
}

void ConsensusCoordinator::coordinateChainSynchronization() {
    std::lock_guard<std::mutex> lock(consensusMutex_);
    
    // Coordinate synchronization across all registered chains
    for (const auto& [chainId, validators] : chainValidators_) {
        if (!validators.empty()) {
            spdlog::debug("Synchronizing chain: {} with {} validators", 
                         chainId, validators.size());
        }
    }
}

void ConsensusCoordinator::addValidator(const std::string& chainId, const std::string& validatorAddress) {
    std::lock_guard<std::mutex> lock(consensusMutex_);
    
    chainValidators_[chainId].push_back(validatorAddress);
    spdlog::info("Added validator {} to chain {}", validatorAddress, chainId);
}

std::vector<std::string> ConsensusCoordinator::getValidators(const std::string& chainId) const {
    std::lock_guard<std::mutex> lock(consensusMutex_);
    
    auto it = chainValidators_.find(chainId);
    if (it != chainValidators_.end()) {
        return it->second;
    }
    
    return {};
}

