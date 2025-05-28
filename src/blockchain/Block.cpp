#include "blockchain/Block.h"
#include "utils/Crypto.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <spdlog/spdlog.h>

Block::Block(uint32_t index, const std::string& previousHash, 
             const std::vector<Transaction>& transactions)
    : index_(index)
    , previousHash_(previousHash)
    , timestamp_(std::time(nullptr))
    , transactions_(transactions)
    , nonce_(0) {
    
    merkleRoot_ = calculateMerkleRoot();
    hash_ = calculateHash();
    
    spdlog::debug("Created new block with index: {}", index_);
}

Block::Block() : index_(0), previousHash_("0"), timestamp_(std::time(nullptr)), nonce_(0) {
    // Genesis block creation
    Transaction genesisTransaction;
    genesisTransaction.setId("genesis");
    transactions_.push_back(genesisTransaction);
    
    merkleRoot_ = calculateMerkleRoot();
    hash_ = calculateHash();
    
    spdlog::info("Created genesis block");
}

Block::Block(const nlohmann::json& json) {
    fromJson(json);
}

void Block::mineBlock(uint32_t difficulty) {
    std::string target(difficulty, '0');
    auto start = std::chrono::high_resolution_clock::now();
    
    spdlog::info("Mining block {} with difficulty {}", index_, difficulty);
    
    do {
        nonce_++;
        hash_ = calculateHash();
        
        // Log progress every 100,000 iterations
        if (nonce_ % 100000 == 0) {
            spdlog::debug("Mining progress - nonce: {}, hash: {}", 
                         nonce_, hash_.substr(0, 16) + "...");
        }
        
    } while (hash_.substr(0, difficulty) != target);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    spdlog::info("Block {} mined successfully! Nonce: {}, Time: {}ms", 
                 index_, nonce_, duration.count());
    spdlog::info("Block hash: {}", hash_);
}

std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << index_ << previousHash_ << timestamp_ << merkleRoot_ << nonce_;
    
    return Crypto::sha256(ss.str());
}

bool Block::isValidBlock(const Block* previousBlock) const {
    // Check if hash is correctly calculated
    if (hash_ != calculateHash()) {
        spdlog::error("Block {} has invalid hash", index_);
        return false;
    }
    
    // Check merkle root
    if (merkleRoot_ != calculateMerkleRoot()) {
        spdlog::error("Block {} has invalid merkle root", index_);
        return false;
    }
    
    // Check if block has transactions
    if (transactions_.empty()) {
        spdlog::error("Block {} has no transactions", index_);
        return false;
    }
    
    // Validate all transactions
    if (!hasValidTransactions()) {
        spdlog::error("Block {} contains invalid transactions", index_);
        return false;
    }
    
    // Check previous block reference
    if (previousBlock != nullptr) {
        if (index_ != previousBlock->getIndex() + 1) {
            spdlog::error("Block {} has incorrect index", index_);
            return false;
        }
        
        if (previousHash_ != previousBlock->getHash()) {
            spdlog::error("Block {} has incorrect previous hash", index_);
            return false;
        }
        
        if (timestamp_ <= previousBlock->getTimestamp()) {
            spdlog::error("Block {} has invalid timestamp", index_);
            return false;
        }
    }
    
    return true;
}

std::string Block::calculateMerkleRoot() const {
    if (transactions_.empty()) {
        return Crypto::sha256("empty");
    }
    
    std::vector<std::string> hashes;
    for (const auto& tx : transactions_) {
        hashes.push_back(tx.calculateHash());
    }
    
    // Build merkle tree
    while (hashes.size() > 1) {
        std::vector<std::string> newLevel;
        
        for (size_t i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) {
                newLevel.push_back(Crypto::sha256(hashes[i] + hashes[i + 1]));
            } else {
                newLevel.push_back(Crypto::sha256(hashes[i] + hashes[i]));
            }
        }
        
        hashes = std::move(newLevel);
    }
    
    return hashes[0];
}

std::string Block::hashTransactions() const {
    std::stringstream ss;
    for (const auto& tx : transactions_) {
        ss << tx.calculateHash();
    }
    return Crypto::sha256(ss.str());
}

bool Block::hasValidTransactions() const {
    for (const auto& transaction : transactions_) {
        if (!transaction.isValidTransaction()) {
            return false;
        }
    }
    return true;
}

nlohmann::json Block::toJson() const {
    nlohmann::json json;
    json["index"] = index_;
    json["previousHash"] = previousHash_;
    json["hash"] = hash_;
    json["timestamp"] = timestamp_;
    json["nonce"] = nonce_;
    json["merkleRoot"] = merkleRoot_;
    
    json["transactions"] = nlohmann::json::array();
    for (const auto& tx : transactions_) {
        json["transactions"].push_back(tx.toJson());
    }
    
    return json;
}

void Block::fromJson(const nlohmann::json& json) {
    index_ = json["index"];
    previousHash_ = json["previousHash"];
    hash_ = json["hash"];
    timestamp_ = json["timestamp"];
    nonce_ = json["nonce"];
    merkleRoot_ = json["merkleRoot"];
    
    transactions_.clear();
    for (const auto& txJson : json["transactions"]) {
        transactions_.emplace_back(txJson);
    }
}

std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block #" << index_ << "\n";
    ss << "Hash: " << hash_ << "\n";
    ss << "Previous Hash: " << previousHash_ << "\n";
    ss << "Timestamp: " << timestamp_ << "\n";
    ss << "Nonce: " << nonce_ << "\n";
    ss << "Merkle Root: " << merkleRoot_ << "\n";
    ss << "Transactions: " << transactions_.size() << "\n";
    
    for (size_t i = 0; i < transactions_.size(); ++i) {
        ss << "  Transaction " << i << ": " << transactions_[i].getId() << "\n";
    }
    
    return ss.str();
}

bool Block::operator==(const Block& other) const {
    return hash_ == other.hash_ && 
           index_ == other.index_ && 
           previousHash_ == other.previousHash_;
}

bool Block::operator!=(const Block& other) const {
    return !(*this == other);
}
