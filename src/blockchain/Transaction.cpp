#include "blockchain/Transaction.h"
#include "utils/Crypto.h"
#include <sstream>
#include <algorithm>
#include <set>
#include <spdlog/spdlog.h>

// TransactionInput implementations
nlohmann::json TransactionInput::toJson() const {
    nlohmann::json json;
    json["transactionId"] = transactionId;
    json["outputIndex"] = outputIndex;
    json["signature"] = signature;
    json["publicKey"] = publicKey;
    return json;
}

void TransactionInput::fromJson(const nlohmann::json& json) {
    transactionId = json["transactionId"];
    outputIndex = json["outputIndex"];
    signature = json["signature"];
    publicKey = json["publicKey"];
}

// TransactionOutput implementations
nlohmann::json TransactionOutput::toJson() const {
    nlohmann::json json;
    json["address"] = address;
    json["amount"] = amount;
    return json;
}

void TransactionOutput::fromJson(const nlohmann::json& json) {
    address = json["address"];
    amount = json["amount"];
}

// Transaction implementations
Transaction::Transaction(const std::string& fromAddress, const std::string& toAddress, 
                        double amount, const std::string& privateKey)
    : timestamp_(std::time(nullptr)) {
    
    // Create simple transaction with one input and one output
    TransactionOutput output;
    output.address = toAddress;
    output.amount = amount;
    outputs_.push_back(output);
    
    id_ = calculateHash();
    
    if (!privateKey.empty()) {
        signTransaction(privateKey);
    }
    
    spdlog::debug("Created transaction: {} -> {} ({})", fromAddress, toAddress, amount);
}

Transaction::Transaction(const std::vector<TransactionInput>& inputs,
                        const std::vector<TransactionOutput>& outputs)
    : inputs_(inputs), outputs_(outputs), timestamp_(std::time(nullptr)) {
    
    id_ = calculateHash();
    spdlog::debug("Created transaction with {} inputs and {} outputs", 
                 inputs_.size(), outputs_.size());
}

Transaction::Transaction(const nlohmann::json& json) {
    fromJson(json);
}

std::string Transaction::calculateHash() const {
    std::stringstream ss;
    ss << timestamp_;
    
    for (const auto& input : inputs_) {
        ss << input.transactionId << input.outputIndex;
    }
    
    for (const auto& output : outputs_) {
        ss << output.address << output.amount;
    }
    
    return Crypto::sha256(ss.str());
}

void Transaction::signTransaction(const std::string& privateKey) {
    if (privateKey.empty()) {
        spdlog::error("Cannot sign transaction with empty private key");
        return;
    }
    
    std::string dataToSign = getTransactionData();
    signature_ = Crypto::signData(dataToSign, privateKey);
    
    spdlog::debug("Transaction {} signed", id_);
}

bool Transaction::isValidTransaction() const {
    // Check basic structure
    if (!isWellFormed()) {
        return false;
    }
    
    // Check signature if present
    if (!signature_.empty() && !verifyInputSignatures()) {
        spdlog::error("Transaction {} has invalid signature", id_);
        return false;
    }
    
    // Check if hash is correct
    if (id_ != calculateHash()) {
        spdlog::error("Transaction {} has invalid hash", id_);
        return false;
    }
    
    // Check amounts
    double totalInput = getTotalInputAmount();
    double totalOutput = getTotalOutputAmount();
    
    if (totalInput < totalOutput) {
        spdlog::error("Transaction {} has insufficient input amount", id_);
        return false;
    }
    
    return true;
}

bool Transaction::isWellFormed() const {
    // Check if transaction has outputs
    if (outputs_.empty()) {
        spdlog::error("Transaction {} has no outputs", id_);
        return false;
    }
    
    // Check for negative amounts
    for (const auto& output : outputs_) {
        if (output.amount <= 0) {
            spdlog::error("Transaction {} has negative or zero output amount", id_);
            return false;
        }
        
        if (!isValidAddress(output.address)) {
            spdlog::error("Transaction {} has invalid address: {}", id_, output.address);
            return false;
        }
    }
    
    // Check for duplicate inputs
    std::set<std::pair<std::string, uint32_t>> inputSet;
    for (const auto& input : inputs_) {
        auto key = std::make_pair(input.transactionId, input.outputIndex);
        if (inputSet.count(key)) {
            spdlog::error("Transaction {} has duplicate inputs", id_);
            return false;
        }
        inputSet.insert(key);
    }
    
    return true;
}

double Transaction::getTotalInputAmount() const {
    // In a real implementation, this would look up the actual UTXO amounts
    // For now, we return a placeholder value
    return inputs_.size() * 100.0; // Placeholder
}

double Transaction::getTotalOutputAmount() const {
    double total = 0.0;
    for (const auto& output : outputs_) {
        total += output.amount;
    }
    return total;
}

double Transaction::getFee() const {
    return getTotalInputAmount() - getTotalOutputAmount();
}

nlohmann::json Transaction::toJson() const {
    nlohmann::json json;
    json["id"] = id_;
    json["timestamp"] = timestamp_;
    json["signature"] = signature_;
    
    json["inputs"] = nlohmann::json::array();
    for (const auto& input : inputs_) {
        json["inputs"].push_back(input.toJson());
    }
    
    json["outputs"] = nlohmann::json::array();
    for (const auto& output : outputs_) {
        json["outputs"].push_back(output.toJson());
    }
    
    return json;
}

void Transaction::fromJson(const nlohmann::json& json) {
    id_ = json["id"];
    timestamp_ = json["timestamp"];
    signature_ = json.value("signature", "");
    
    inputs_.clear();
    if (json.contains("inputs")) {
        for (const auto& inputJson : json["inputs"]) {
            TransactionInput input;
            input.fromJson(inputJson);
            inputs_.push_back(input);
        }
    }
    
    outputs_.clear();
    for (const auto& outputJson : json["outputs"]) {
        TransactionOutput output;
        output.fromJson(outputJson);
        outputs_.push_back(output);
    }
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction ID: " << id_ << "\n";
    ss << "Timestamp: " << timestamp_ << "\n";
    ss << "Inputs: " << inputs_.size() << "\n";
    
    for (size_t i = 0; i < inputs_.size(); ++i) {
        ss << "  Input " << i << ": " << inputs_[i].transactionId 
           << ":" << inputs_[i].outputIndex << "\n";
    }
    
    ss << "Outputs: " << outputs_.size() << "\n";
    for (size_t i = 0; i < outputs_.size(); ++i) {
        ss << "  Output " << i << ": " << outputs_[i].address 
           << " (" << outputs_[i].amount << ")\n";
    }
    
    ss << "Fee: " << getFee() << "\n";
    
    return ss.str();
}

bool Transaction::operator==(const Transaction& other) const {
    return id_ == other.id_;
}

bool Transaction::operator!=(const Transaction& other) const {
    return !(*this == other);
}

Transaction Transaction::createCoinbaseTransaction(const std::string& minerAddress, double reward) {
    Transaction coinbase;
    coinbase.timestamp_ = std::time(nullptr);
    
    // Coinbase transaction has no inputs (mining reward)
    TransactionOutput output;
    output.address = minerAddress;
    output.amount = reward;
    coinbase.outputs_.push_back(output);
    
    coinbase.id_ = coinbase.calculateHash();
    
    spdlog::debug("Created coinbase transaction for miner: {} (reward: {})", 
                 minerAddress, reward);
    
    return coinbase;
}

bool Transaction::isValidAddress(const std::string& address) {
    // Simple address validation - in a real implementation this would be more robust
    return !address.empty() && address.length() >= 10 && address.length() <= 100;
}

std::string Transaction::getTransactionData() const {
    std::stringstream ss;
    ss << id_ << timestamp_;
    
    for (const auto& input : inputs_) {
        ss << input.transactionId << input.outputIndex;
    }
    
    for (const auto& output : outputs_) {
        ss << output.address << output.amount;
    }
    
    return ss.str();
}

bool Transaction::verifyInputSignatures() const {
    if (signature_.empty()) {
        return true; // No signature to verify
    }
    
    std::string dataToVerify = getTransactionData();
    
    // In a real implementation, we would verify each input's signature
    // For now, we do a basic verification
    return Crypto::verifySignature(dataToVerify, signature_, "");
}