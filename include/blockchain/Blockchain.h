#pragma once

#include <vector>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include "Block.h"
#include "Transaction.h"
#include "TransactionPool.h"

class Blockchain {
public:
    // Constructor
    Blockchain();
    
    // Destructor
    ~Blockchain() = default;
    
    // Block operations
    bool addBlock(const Block& block);
    Block createNewBlock(const std::vector<Transaction>& transactions);
    Block mineBlock(const std::string& minerAddress);
    
    // Chain validation
    bool isValidChain() const;
    bool isValidBlock(const Block& block, const Block& previousBlock) const;
    
    // Chain management
    bool replaceChain(const std::vector<Block>& newChain);
    void resolveConflicts(const std::vector<std::vector<Block>>& chains);
    
    // Transaction operations
    bool addTransaction(const Transaction& transaction);
    bool isValidTransaction(const Transaction& transaction) const;
    double getBalance(const std::string& address) const;
    std::vector<TransactionOutput> getUnspentTransactionOutputs(const std::string& address) const;
    
    // Getters
    const std::vector<Block>& getChain() const { return chain_; }
    uint32_t getChainHeight() const { return static_cast<uint32_t>(chain_.size()); }
    const Block& getLatestBlock() const;
    Block getBlock(uint32_t index) const;
    Block getBlockByHash(const std::string& hash) const;
    
    // Mining difficulty
    uint32_t getDifficulty() const { return difficulty_; }
    void adjustDifficulty();
    
    // Transaction pool access
    TransactionPool& getTransactionPool() { return transactionPool_; }
    const TransactionPool& getTransactionPool() const { return transactionPool_; }
    
    // Persistence
    bool saveToFile(const std::string& filename) const;
    bool loadFromFile(const std::string& filename);
    
    // JSON serialization
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    
    // Statistics
    double getTotalSupply() const;
    uint32_t getTotalTransactions() const;
    double getAverageBlockTime() const;
    std::string getNetworkHashRate() const;
    
    // Constants
    static constexpr double MINING_REWARD = 50.0;
    static constexpr uint32_t BLOCK_TIME_TARGET = 10; // seconds
    static constexpr uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 10; // reorders the blocks
    static constexpr uint32_t MAX_BLOCK_SIZE = 1000000; // bytes
    static constexpr double MIN_TRANSACTION_FEE = 0.001;

private:
    std::vector<Block> chain_;
    TransactionPool transactionPool_;
    uint32_t difficulty_;
    mutable std::mutex chainMutex_;
    
    // UTXO tracking
    std::unordered_map<std::string, std::vector<TransactionOutput>> utxoSet_;
    
    // Helper functions
    void createGenesisBlock();
    void updateUTXOSet(const Block& block);
    bool hasValidProofOfWork(const Block& block) const;
    std::time_t getTimeDifference(uint32_t startIndex, uint32_t endIndex) const;
    
    // Transaction validation helpers
    bool hasValidInputs(const Transaction& transaction) const;
    bool hasValidOutputs(const Transaction& transaction) const;
    bool isDoubleSpend(const Transaction& transaction) const;
};
