#pragma once

#include <string>
#include <vector>
#include <ctime>
#include <nlohmann/json.hpp>

struct TransactionInput {
    std::string transactionId;
    uint32_t outputIndex;
    std::string signature;
    std::string publicKey;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

struct TransactionOutput {
    std::string address;
    double amount;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

class Transaction {
public:
    // Constructor for new transaction
    Transaction(const std::string& fromAddress, const std::string& toAddress, 
                double amount, const std::string& privateKey = "");
    
    // Constructor with inputs/outputs
    Transaction(const std::vector<TransactionInput>& inputs,
                const std::vector<TransactionOutput>& outputs);
    
    // Constructor from JSON
    explicit Transaction(const nlohmann::json& json);
    
    // Default constructor
    Transaction() = default;
    
    // Destructor
    ~Transaction() = default;
    
    // Calculate transaction hash
    std::string calculateHash() const;
    
    // Sign transaction
    void signTransaction(const std::string& privateKey);
    
    // Verify transaction signature
    bool isValidTransaction() const;
    
    // Check if transaction is properly formed
    bool isWellFormed() const;
    
    // Getters
    const std::string& getId() const { return id_; }
    const std::vector<TransactionInput>& getInputs() const { return inputs_; }
    const std::vector<TransactionOutput>& getOutputs() const { return outputs_; }
    std::time_t getTimestamp() const { return timestamp_; }
    const std::string& getSignature() const { return signature_; }
    double getTotalInputAmount() const;
    double getTotalOutputAmount() const;
    double getFee() const;
    
    // Setters
    void setId(const std::string& id) { id_ = id; }
    void setSignature(const std::string& signature) { signature_ = signature; }
    
    // JSON serialization
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    
    // String representation
    std::string toString() const;
    
    // Operators
    bool operator==(const Transaction& other) const;
    bool operator!=(const Transaction& other) const;
    
    // Static helper functions
    static Transaction createCoinbaseTransaction(const std::string& minerAddress, double reward);
    static bool isValidAddress(const std::string& address);

private:
    std::string id_;
    std::vector<TransactionInput> inputs_;
    std::vector<TransactionOutput> outputs_;
    std::time_t timestamp_;
    std::string signature_;
    
    // Helper functions
    std::string getTransactionData() const;
    bool verifyInputSignatures() const;
};
