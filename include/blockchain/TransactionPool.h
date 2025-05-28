#pragma once

#include <vector>
#include <unordered_map>
#include <mutex>
#include <nlohmann/json.hpp>
#include "Transaction.h"

class TransactionPool {
public:
    // Constructor
    TransactionPool();
    
    // Destructor
    ~TransactionPool() = default;
    
    // Transaction management
    bool addTransaction(const Transaction& transaction);
    bool removeTransaction(const std::string& transactionId);
    void clearPool();
    
    // Transaction retrieval
    Transaction getTransaction(const std::string& transactionId) const;
    std::vector<Transaction> getTransactions() const;
    std::vector<Transaction> getTransactions(size_t maxCount) const;
    std::vector<Transaction> getTransactionsByFee(size_t maxCount) const;
    
    // Pool information
    size_t getTransactionCount() const;
    bool hasTransaction(const std::string& transactionId) const;
    bool isEmpty() const;
    
    // Transaction validation
    bool isValidTransaction(const Transaction& transaction) const;
    std::vector<Transaction> getValidTransactions() const;
    
    // Fee-based operations
    double getTotalFees() const;
    double getAverageFee() const;
    Transaction getHighestFeeTransaction() const;
    
    // Pool management
    void removeExpiredTransactions(std::time_t maxAge = 3600); // 1 hour default
    void removeLowFeeTransactions(double minFee);
    size_t getMaxPoolSize() const { return maxPoolSize_; }
    void setMaxPoolSize(size_t maxSize) { maxPoolSize_ = maxSize; }
    
    // Serialization
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    
    // Statistics
    struct PoolStatistics {
        size_t totalTransactions;
        double totalAmount;
        double totalFees;
        double averageFee;
        std::time_t oldestTransaction;
        std::time_t newestTransaction;
    };
    
    PoolStatistics getStatistics() const;

private:
    std::unordered_map<std::string, Transaction> transactions_;
    mutable std::mutex poolMutex_;
    size_t maxPoolSize_;
    
    // Helper functions
    void enforcePoolSizeLimit();
    bool isTransactionExpired(const Transaction& transaction, std::time_t maxAge) const;
};
