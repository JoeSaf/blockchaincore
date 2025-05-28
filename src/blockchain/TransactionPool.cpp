#include "blockchain/TransactionPool.h"
#include <algorithm>
#include <spdlog/spdlog.h>

TransactionPool::TransactionPool() : maxPoolSize_(1000) {
    spdlog::debug("Transaction pool initialized with max size: {}", maxPoolSize_);
}

bool TransactionPool::addTransaction(const Transaction& transaction) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    // Check if transaction already exists
    if (transactions_.find(transaction.getId()) != transactions_.end()) {
        spdlog::debug("Transaction {} already exists in pool", transaction.getId());
        return false;
    }
    
    // Validate transaction
    if (!isValidTransaction(transaction)) {
        spdlog::warn("Invalid transaction rejected: {}", transaction.getId());
        return false;
    }
    
    // Add transaction to pool
    transactions_[transaction.getId()] = transaction;
    
    // Enforce pool size limit
    enforcePoolSizeLimit();
    
    spdlog::debug("Added transaction {} to pool (pool size: {})", 
                 transaction.getId(), transactions_.size());
    
    return true;
}

bool TransactionPool::removeTransaction(const std::string& transactionId) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    auto it = transactions_.find(transactionId);
    if (it != transactions_.end()) {
        transactions_.erase(it);
        spdlog::debug("Removed transaction {} from pool", transactionId);
        return true;
    }
    
    return false;
}

void TransactionPool::clearPool() {
    std::lock_guard<std::mutex> lock(poolMutex_);
    size_t count = transactions_.size();
    transactions_.clear();
    spdlog::info("Cleared {} transactions from pool", count);
}

Transaction TransactionPool::getTransaction(const std::string& transactionId) const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    auto it = transactions_.find(transactionId);
    if (it != transactions_.end()) {
        return it->second;
    }
    
    return Transaction(); // Empty transaction if not found
}

std::vector<Transaction> TransactionPool::getTransactions() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    std::vector<Transaction> result;
    result.reserve(transactions_.size());
    
    for (const auto& pair : transactions_) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<Transaction> TransactionPool::getTransactions(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    std::vector<Transaction> result;
    result.reserve(std::min(maxCount, transactions_.size()));
    
    size_t count = 0;
    for (const auto& pair : transactions_) {
        if (count >= maxCount) break;
        result.push_back(pair.second);
        count++;
    }
    
    return result;
}

std::vector<Transaction> TransactionPool::getTransactionsByFee(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    std::vector<Transaction> result;
    result.reserve(transactions_.size());
    
    // Get all transactions
    for (const auto& pair : transactions_) {
        result.push_back(pair.second);
    }
    
    // Sort by fee (highest first)
    std::sort(result.begin(), result.end(), [](const Transaction& a, const Transaction& b) {
        return a.getFee() > b.getFee();
    });
    
    // Limit to maxCount
    if (result.size() > maxCount) {
        result.resize(maxCount);
    }
    
    return result;
}

size_t TransactionPool::getTransactionCount() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    return transactions_.size();
}

bool TransactionPool::hasTransaction(const std::string& transactionId) const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    return transactions_.find(transactionId) != transactions_.end();
}

bool TransactionPool::isEmpty() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    return transactions_.empty();
}

bool TransactionPool::isValidTransaction(const Transaction& transaction) const {
    // Basic validation
    if (!transaction.isValidTransaction()) {
        return false;
    }
    
    // Check if transaction is well-formed
    if (!transaction.isWellFormed()) {
        return false;
    }
    
    // Check minimum fee
    if (transaction.getFee() < 0.001) { // Minimum fee requirement
        spdlog::debug("Transaction {} rejected: fee too low ({})", 
                     transaction.getId(), transaction.getFee());
        return false;
    }
    
    return true;
}

std::vector<Transaction> TransactionPool::getValidTransactions() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    std::vector<Transaction> validTransactions;
    
    for (const auto& pair : transactions_) {
        if (isValidTransaction(pair.second)) {
            validTransactions.push_back(pair.second);
        }
    }
    
    return validTransactions;
}

double TransactionPool::getTotalFees() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    double totalFees = 0.0;
    for (const auto& pair : transactions_) {
        totalFees += pair.second.getFee();
    }
    
    return totalFees;
}

double TransactionPool::getAverageFee() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    if (transactions_.empty()) {
        return 0.0;
    }
    
    return getTotalFees() / transactions_.size();
}

Transaction TransactionPool::getHighestFeeTransaction() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    if (transactions_.empty()) {
        return Transaction();
    }
    
    auto maxIt = std::max_element(transactions_.begin(), transactions_.end(),
        [](const auto& a, const auto& b) {
            return a.second.getFee() < b.second.getFee();
        });
    
    return maxIt->second;
}

void TransactionPool::removeExpiredTransactions(std::time_t maxAge) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    size_t removedCount = 0;
    auto it = transactions_.begin();
    
    while (it != transactions_.end()) {
        if (isTransactionExpired(it->second, maxAge)) {
            it = transactions_.erase(it);
            removedCount++;
        } else {
            ++it;
        }
    }
    
    if (removedCount > 0) {
        spdlog::info("Removed {} expired transactions from pool", removedCount);
    }
}

void TransactionPool::removeLowFeeTransactions(double minFee) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    size_t removedCount = 0;
    auto it = transactions_.begin();
    
    while (it != transactions_.end()) {
        if (it->second.getFee() < minFee) {
            it = transactions_.erase(it);
            removedCount++;
        } else {
            ++it;
        }
    }
    
    if (removedCount > 0) {
        spdlog::info("Removed {} low-fee transactions from pool", removedCount);
    }
}

nlohmann::json TransactionPool::toJson() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    nlohmann::json json;
    json["maxPoolSize"] = maxPoolSize_;
    json["transactionCount"] = transactions_.size();
    json["transactions"] = nlohmann::json::array();
    
    for (const auto& pair : transactions_) {
        json["transactions"].push_back(pair.second.toJson());
    }
    
    return json;
}

void TransactionPool::fromJson(const nlohmann::json& json) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    transactions_.clear();
    
    if (json.contains("maxPoolSize")) {
        maxPoolSize_ = json["maxPoolSize"];
    }
    
    if (json.contains("transactions")) {
        for (const auto& txJson : json["transactions"]) {
            Transaction tx(txJson);
            transactions_[tx.getId()] = tx;
        }
    }
}

TransactionPool::PoolStatistics TransactionPool::getStatistics() const {
    std::lock_guard<std::mutex> lock(poolMutex_);
    
    PoolStatistics stats;
    stats.totalTransactions = transactions_.size();
    stats.totalAmount = 0.0;
    stats.totalFees = 0.0;
    stats.oldestTransaction = std::time(nullptr);
    stats.newestTransaction = 0;
    
    if (transactions_.empty()) {
        return stats;
    }
    
    for (const auto& pair : transactions_) {
        const Transaction& tx = pair.second;
        
        stats.totalAmount += tx.getTotalOutputAmount();
        stats.totalFees += tx.getFee();
        
        if (tx.getTimestamp() < stats.oldestTransaction) {
            stats.oldestTransaction = tx.getTimestamp();
        }
        
        if (tx.getTimestamp() > stats.newestTransaction) {
            stats.newestTransaction = tx.getTimestamp();
        }
    }
    
    stats.averageFee = stats.totalFees / stats.totalTransactions;
    
    return stats;
}

void TransactionPool::enforcePoolSizeLimit() {
    if (transactions_.size() <= maxPoolSize_) {
        return;
    }
    
    // Remove transactions with lowest fees first
    std::vector<std::pair<std::string, double>> txFees;
    
    for (const auto& pair : transactions_) {
        txFees.emplace_back(pair.first, pair.second.getFee());
    }
    
    // Sort by fee (lowest first)
    std::sort(txFees.begin(), txFees.end(),
        [](const auto& a, const auto& b) {
            return a.second < b.second;
        });
    
    // Remove lowest fee transactions until we're under the limit
    size_t toRemove = transactions_.size() - maxPoolSize_;
    for (size_t i = 0; i < toRemove && i < txFees.size(); ++i) {
        transactions_.erase(txFees[i].first);
    }
    
    spdlog::debug("Pool size limit enforced: removed {} transactions", toRemove);
}

bool TransactionPool::isTransactionExpired(const Transaction& transaction, std::time_t maxAge) const {
    std::time_t now = std::time(nullptr);
    return (now - transaction.getTimestamp()) > maxAge;
}
