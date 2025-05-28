#include "blockchain/Blockchain.h"
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <fstream>

Blockchain::Blockchain() : difficulty_(4) {
    createGenesisBlock();
    spdlog::info("Blockchain initialized with genesis block");
}

bool Blockchain::addBlock(const Block& block) {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (chain_.empty()) {
        spdlog::error("Cannot add block to empty chain");
        return false;
    }
    
    const Block& previousBlock = chain_.back();
    
    if (!isValidBlock(block, previousBlock)) {
        spdlog::error("Invalid block rejected: {}", block.getIndex());
        return false;
    }
    
    chain_.push_back(block);
    updateUTXOSet(block);
    
    // Remove transactions from mempool that are now in the block
    for (const auto& tx : block.getTransactions()) {
        transactionPool_.removeTransaction(tx.getId());
    }
    
    spdlog::info("Added block {} to blockchain (height: {})", 
                 block.getIndex(), chain_.size());
    
    return true;
}

Block Blockchain::createNewBlock(const std::vector<Transaction>& transactions) {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (chain_.empty()) {
        spdlog::error("Cannot create block on empty chain");
        return Block();
    }
    
    const Block& latestBlock = chain_.back();
    uint32_t newIndex = latestBlock.getIndex() + 1;
    
    return Block(newIndex, latestBlock.getHash(), transactions);
}

Block Blockchain::mineBlock(const std::string& minerAddress) {
    // Get transactions from mempool
    auto pendingTransactions = transactionPool_.getTransactionsByFee(100); // Max 100 transactions
    
    // Add coinbase transaction
    Transaction coinbaseTransaction = Transaction::createCoinbaseTransaction(minerAddress, MINING_REWARD);
    pendingTransactions.insert(pendingTransactions.begin(), coinbaseTransaction);
    
    // Create new block
    Block newBlock = createNewBlock(pendingTransactions);
    
    // Mine the block
    newBlock.mineBlock(difficulty_);
    
    // Add to blockchain
    if (addBlock(newBlock)) {
        spdlog::info("Successfully mined block {} with {} transactions", 
                     newBlock.getIndex(), pendingTransactions.size());
        
        // Adjust difficulty if needed
        if (newBlock.getIndex() % DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
            adjustDifficulty();
        }
        
        return newBlock;
    }
    
    spdlog::error("Failed to add mined block to blockchain");
    return Block();
}

bool Blockchain::isValidChain() const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (chain_.empty()) {
        return false;
    }
    
    // Check genesis block
    if (chain_[0].getIndex() != 0 || chain_[0].getPreviousHash() != "0") {
        spdlog::error("Invalid genesis block");
        return false;
    }
    
    // Check all subsequent blocks
    for (size_t i = 1; i < chain_.size(); ++i) {
        if (!isValidBlock(chain_[i], chain_[i-1])) {
            spdlog::error("Invalid block at index {}", i);
            return false;
        }
    }
    
    return true;
}

bool Blockchain::isValidBlock(const Block& block, const Block& previousBlock) const {
    // Basic block validation
    if (!block.isValidBlock(&previousBlock)) {
        return false;
    }
    
    // Check proof of work
    if (!hasValidProofOfWork(block)) {
        spdlog::error("Block {} has invalid proof of work", block.getIndex());
        return false;
    }
    
    // Validate all transactions in the block
    for (const auto& transaction : block.getTransactions()) {
        if (!isValidTransaction(transaction)) {
            spdlog::error("Block {} contains invalid transaction: {}", 
                         block.getIndex(), transaction.getId());
            return false;
        }
    }
    
    return true;
}

bool Blockchain::replaceChain(const std::vector<Block>& newChain) {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (newChain.size() <= chain_.size()) {
        spdlog::debug("New chain is not longer than current chain");
        return false;
    }
    
    // Validate the new chain
    for (size_t i = 1; i < newChain.size(); ++i) {
        if (!isValidBlock(newChain[i], newChain[i-1])) {
            spdlog::error("Invalid block in new chain at index {}", i);
            return false;
        }
    }
    
    // Replace current chain
    chain_ = newChain;
    
    // Rebuild UTXO set
    utxoSet_.clear();
    for (const auto& block : chain_) {
        updateUTXOSet(block);
    }
    
    spdlog::info("Replaced blockchain with longer valid chain (height: {})", chain_.size());
    return true;
}

void Blockchain::resolveConflicts(const std::vector<std::vector<Block>>& chains) {
    const std::vector<Block>* longestChain = &chain_;
    
    for (const auto& chain : chains) {
        if (chain.size() > longestChain->size()) {
            // Validate the chain before considering it
            bool isValid = true;
            for (size_t i = 1; i < chain.size() && isValid; ++i) {
                if (!isValidBlock(chain[i], chain[i-1])) {
                    isValid = false;
                }
            }
            
            if (isValid) {
                longestChain = &chain;
            }
        }
    }
    
    if (longestChain != &chain_) {
        replaceChain(*longestChain);
    }
}

bool Blockchain::addTransaction(const Transaction& transaction) {
    if (!isValidTransaction(transaction)) {
        spdlog::warn("Invalid transaction rejected: {}", transaction.getId());
        return false;
    }
    
    return transactionPool_.addTransaction(transaction);
}

bool Blockchain::isValidTransaction(const Transaction& transaction) const {
    // Basic transaction validation
    if (!transaction.isValidTransaction()) {
        return false;
    }
    
    // Check for double spending
    if (isDoubleSpend(transaction)) {
        spdlog::warn("Double spend detected in transaction: {}", transaction.getId());
        return false;
    }
    
    // Validate inputs
    if (!hasValidInputs(transaction)) {
        return false;
    }
    
    // Validate outputs
    if (!hasValidOutputs(transaction)) {
        return false;
    }
    
    return true;
}

double Blockchain::getBalance(const std::string& address) const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    auto utxos = getUnspentTransactionOutputs(address);
    double balance = 0.0;
    
    for (const auto& utxo : utxos) {
        balance += utxo.amount;
    }
    
    return balance;
}

std::vector<TransactionOutput> Blockchain::getUnspentTransactionOutputs(const std::string& address) const {
    std::vector<TransactionOutput> utxos;
    
    auto it = utxoSet_.find(address);
    if (it != utxoSet_.end()) {
        utxos = it->second;
    }
    
    return utxos;
}

const Block& Blockchain::getLatestBlock() const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (chain_.empty()) {
        throw std::runtime_error("Blockchain is empty");
    }
    
    return chain_.back();
}

Block Blockchain::getBlock(uint32_t index) const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (index >= chain_.size()) {
        throw std::out_of_range("Block index out of range");
    }
    
    return chain_[index];
}

Block Blockchain::getBlockByHash(const std::string& hash) const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    for (const auto& block : chain_) {
        if (block.getHash() == hash) {
            return block;
        }
    }
    
    return Block(); // Empty block if not found
}

void Blockchain::adjustDifficulty() {
    if (chain_.size() < DIFFICULTY_ADJUSTMENT_INTERVAL) {
        return;
    }
    
    std::time_t timeDiff = getTimeDifference(
        chain_.size() - DIFFICULTY_ADJUSTMENT_INTERVAL, 
        chain_.size() - 1
    );
    
    std::time_t expectedTime = BLOCK_TIME_TARGET * DIFFICULTY_ADJUSTMENT_INTERVAL;
    
    if (timeDiff < expectedTime / 2) {
        difficulty_++;
        spdlog::info("Difficulty increased to {}", difficulty_);
    } else if (timeDiff > expectedTime * 2) {
        if (difficulty_ > 1) {
            difficulty_--;
            spdlog::info("Difficulty decreased to {}", difficulty_);
        }
    }
}

bool Blockchain::saveToFile(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    try {
        nlohmann::json json = toJson();
        return Utils::writeJsonFile(filename, json);
    } catch (const std::exception& e) {
        spdlog::error("Failed to save blockchain to file {}: {}", filename, e.what());
        return false;
    }
}

bool Blockchain::loadFromFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (!Utils::fileExists(filename)) {
        spdlog::info("Blockchain file {} does not exist", filename);
        return false;
    }
    
    try {
        nlohmann::json json = Utils::readJsonFile(filename);
        if (json.empty()) {
            return false;
        }
        
        fromJson(json);
        spdlog::info("Loaded blockchain from file {} with {} blocks", filename, chain_.size());
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to load blockchain from file {}: {}", filename, e.what());
        return false;
    }
}

nlohmann::json Blockchain::toJson() const {
    nlohmann::json json;
    json["difficulty"] = difficulty_;
    json["chainHeight"] = chain_.size();
    
    json["chain"] = nlohmann::json::array();
    for (const auto& block : chain_) {
        json["chain"].push_back(block.toJson());
    }
    
    json["transactionPool"] = transactionPool_.toJson();
    
    return json;
}

void Blockchain::fromJson(const nlohmann::json& json) {
    chain_.clear();
    utxoSet_.clear();
    
    if (json.contains("difficulty")) {
        difficulty_ = json["difficulty"];
    }
    
    if (json.contains("chain")) {
        for (const auto& blockJson : json["chain"]) {
            chain_.emplace_back(blockJson);
        }
        
        // Rebuild UTXO set
        for (const auto& block : chain_) {
            updateUTXOSet(block);
        }
    }
    
    if (json.contains("transactionPool")) {
        transactionPool_.fromJson(json["transactionPool"]);
    }
}

double Blockchain::getTotalSupply() const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    return (chain_.size() - 1) * MINING_REWARD; // Exclude genesis block
}

uint32_t Blockchain::getTotalTransactions() const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    uint32_t totalTx = 0;
    for (const auto& block : chain_) {
        totalTx += static_cast<uint32_t>(block.getTransactions().size());
    }
    
    return totalTx;
}

double Blockchain::getAverageBlockTime() const {
    std::lock_guard<std::mutex> lock(chainMutex_);
    
    if (chain_.size() < 2) {
        return 0.0;
    }
    
    std::time_t totalTime = getTimeDifference(0, chain_.size() - 1);
    return static_cast<double>(totalTime) / (chain_.size() - 1);
}

std::string Blockchain::getNetworkHashRate() const {
    // Simplified hash rate calculation
    if (chain_.size() < 2) {
        return "0 H/s";
    }
    
    double avgBlockTime = getAverageBlockTime();
    if (avgBlockTime == 0) {
        return "0 H/s";
    }
    
    // Estimate based on difficulty and block time
    double hashRate = std::pow(2, difficulty_) / avgBlockTime;
    
    if (hashRate > 1e9) {
        return std::to_string(static_cast<int>(hashRate / 1e9)) + " GH/s";
    } else if (hashRate > 1e6) {
        return std::to_string(static_cast<int>(hashRate / 1e6)) + " MH/s";
    } else if (hashRate > 1e3) {
        return std::to_string(static_cast<int>(hashRate / 1e3)) + " KH/s";
    } else {
        return std::to_string(static_cast<int>(hashRate)) + " H/s";
    }
}

void Blockchain::createGenesisBlock() {
    Block genesisBlock;
    chain_.push_back(genesisBlock);
    updateUTXOSet(genesisBlock);
}

void Blockchain::updateUTXOSet(const Block& block) {
    // Process each transaction in the block
    for (const auto& transaction : block.getTransactions()) {
        // Remove spent outputs
        for (const auto& input : transaction.getInputs()) {
            auto it = utxoSet_.find(input.transactionId);
            if (it != utxoSet_.end()) {
                auto& outputs = it->second;
                outputs.erase(
                    std::remove_if(outputs.begin(), outputs.end(),
                        [&input](const TransactionOutput& /*output*/) {
                            return false; // Simplified - would need proper UTXO tracking
                        }),
                    outputs.end()
                );
                
                if (outputs.empty()) {
                    utxoSet_.erase(it);
                }
            }
        }
        
        // Add new outputs
        for (const auto& output : transaction.getOutputs()) {
            utxoSet_[output.address].push_back(output);
        }
    }
}

bool Blockchain::hasValidProofOfWork(const Block& block) const {
    std::string target(difficulty_, '0');
    return block.getHash().substr(0, difficulty_) == target;
}

std::time_t Blockchain::getTimeDifference(uint32_t startIndex, uint32_t endIndex) const {
    if (startIndex >= chain_.size() || endIndex >= chain_.size() || startIndex >= endIndex) {
        return 0;
    }
    
    return chain_[endIndex].getTimestamp() - chain_[startIndex].getTimestamp();
}

bool Blockchain::hasValidInputs(const Transaction& transaction) const {
    // Simplified input validation
    for (const auto& input : transaction.getInputs()) {
        if (input.transactionId.empty()) {
            return false;
        }
    }
    return true;
}

bool Blockchain::hasValidOutputs(const Transaction& transaction) const {
    for (const auto& output : transaction.getOutputs()) {
        if (output.amount <= 0 || output.address.empty()) {
            return false;
        }
    }
    return true;
}

bool Blockchain::isDoubleSpend(const Transaction& transaction) const {
    // Simplified double spend check
    for (const auto& input : transaction.getInputs()) {
        // Check if this input is already spent in mempool
        auto pendingTx = transactionPool_.getTransactions();
        for (const auto& pending : pendingTx) {
            for (const auto& pendingInput : pending.getInputs()) {
                if (pendingInput.transactionId == input.transactionId &&
                    pendingInput.outputIndex == input.outputIndex) {
                    return true; // Double spend detected
                }
            }
        }
    }
    return false;
}