#pragma once

#include <string>
#include <vector>
#include <memory>
#include <ctime>
#include <nlohmann/json.hpp>
#include "Transaction.h"

class Block {
public:
    // Constructor for new block
    Block(uint32_t index, const std::string& previousHash, 
          const std::vector<Transaction>& transactions);
    
    // Constructor for genesis block
    Block();
    
    // Constructor from JSON
    explicit Block(const nlohmann::json& json);
    
    // Destructor
    ~Block() = default;
    
    // Mining function
    void mineBlock(uint32_t difficulty);
    
    // Calculate block hash
    std::string calculateHash() const;
    
    // Validate block
    bool isValidBlock(const Block* previousBlock = nullptr) const;
    
    // Getters
    uint32_t getIndex() const { return index_; }
    const std::string& getPreviousHash() const { return previousHash_; }
    const std::string& getHash() const { return hash_; }
    std::time_t getTimestamp() const { return timestamp_; }
    const std::vector<Transaction>& getTransactions() const { return transactions_; }
    uint32_t getNonce() const { return nonce_; }
    const std::string& getMerkleRoot() const { return merkleRoot_; }
    
    // Setters
    void setHash(const std::string& hash) { hash_ = hash; }
    
    // JSON serialization
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    
    // String representation
    std::string toString() const;
    
    // Operators
    bool operator==(const Block& other) const;
    bool operator!=(const Block& other) const;

private:
    uint32_t index_;
    std::string previousHash_;
    std::string hash_;
    std::time_t timestamp_;
    std::vector<Transaction> transactions_;
    uint32_t nonce_;
    std::string merkleRoot_;
    
    // Helper functions
    std::string calculateMerkleRoot() const;
    std::string hashTransactions() const;
    bool hasValidTransactions() const;
};
