#pragma once

#include <memory>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>
#include "blockchain/Blockchain.h"
#include "blockchain/FileBlockchain.h"
#include "p2p/P2PNetwork.h"
#include "security/SecurityManager.h"

// Chain types in our multi-chain system
enum class ChainType {
    MAIN_CHAIN,     // User registration, peer management, governance
    FILE_CHAIN,     // File storage and retrieval operations
    AUTH_CHAIN,     // Authentication, permissions, access control
    IDENTITY_CHAIN  // User identity management and verification
};

// Cross-chain message for communication between chains
struct CrossChainMessage {
    ChainType sourceChain;
    ChainType targetChain;
    std::string messageId;
    std::string messageType;  // "USER_CREATED", "FILE_UPLOADED", "PERMISSION_GRANTED"
    nlohmann::json payload;
    std::time_t timestamp;
    std::string signature;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// Main chain transaction - lightweight, only for core operations
class MainChainTransaction : public Transaction {
public:
    enum class MainOperation {
        PEER_REGISTRATION,
        USER_REGISTRATION,
        GOVERNANCE_VOTE,
        CHAIN_COORDINATION,
        CROSS_CHAIN_MESSAGE
    };
    
    MainChainTransaction(MainOperation operation, const std::string& userAddress);
    
    void setPeerInfo(const PeerInfo& peer);
    void setUserInfo(const nlohmann::json& userInfo);
    void setCrossChainMessage(const CrossChainMessage& message);
    
    MainOperation getOperation() const { return operation_; }
    const nlohmann::json& getData() const { return data_; }
    
    bool isValidTransaction() const override;
    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

private:
    MainOperation operation_;
    nlohmann::json data_;
};

// Authentication chain for permissions and access control
class AuthChain : public Blockchain {
public:
    AuthChain();
    
    // Permission management
    bool grantPermission(const std::string& userId, const std::string& resource, 
                        const std::string& permission);
    bool revokePermission(const std::string& userId, const std::string& resource, 
                         const std::string& permission);
    bool hasPermission(const std::string& userId, const std::string& resource, 
                      const std::string& permission) const;
    
    // Session management
    std::string createSession(const std::string& userId, const std::string& ipAddress);
    bool validateSession(const std::string& sessionId) const;
    void revokeSession(const std::string& sessionId);
    
    // Authentication
    bool authenticateUser(const std::string& userId, const std::string& credentials);
    
private:
    std::unordered_map<std::string, nlohmann::json> permissions_;
    std::unordered_map<std::string, nlohmann::json> sessions_;
    mutable std::mutex authMutex_;
};

// Identity chain for user management
class IdentityChain : public Blockchain {
public:
    IdentityChain();
    
    // User management
    std::string createUser(const std::string& username, const std::string& email, 
                          const std::string& publicKey);
    bool updateUserProfile(const std::string& userId, const nlohmann::json& profile);
    nlohmann::json getUserProfile(const std::string& userId) const;
    bool deactivateUser(const std::string& userId);
    
    // Identity verification
    bool verifyIdentity(const std::string& userId, const std::string& signature, 
                       const std::string& data) const;
    std::string getUserPublicKey(const std::string& userId) const;
    
private:
    std::unordered_map<std::string, nlohmann::json> userProfiles_;
    mutable std::mutex identityMutex_;
};

// Multi-chain coordinator - manages all chains and cross-chain communication
class MultiChainManager {
public:
    MultiChainManager();
    ~MultiChainManager() = default;
    
    // Chain management
    bool initializeChains();
    void shutdownChains();
    bool isChainHealthy(ChainType type) const;
    
    // User operations (coordinates across chains)
    std::string registerUser(const std::string& username, const std::string& email, 
                            const std::string& password);
    bool authenticateUser(const std::string& username, const std::string& password);
    std::string createUserSession(const std::string& userId, const std::string& ipAddress);
    
    // File operations (delegates to file chain)
    std::string uploadFile(const std::vector<uint8_t>& fileData, const std::string& filename,
                          const std::string& userId);
    std::vector<uint8_t> downloadFile(const std::string& fileId, const std::string& userId);
    std::vector<FileMetadata> listUserFiles(const std::string& userId);
    bool deleteFile(const std::string& fileId, const std::string& userId);
    
    // Cross-chain communication
    bool sendCrossChainMessage(const CrossChainMessage& message);
    void processCrossChainMessages();
    
    // Chain access
    std::shared_ptr<Blockchain> getMainChain() { return mainChain_; }
    std::shared_ptr<FileBlockchain> getFileChain() { return fileChain_; }
    std::shared_ptr<AuthChain> getAuthChain() { return authChain_; }
    std::shared_ptr<IdentityChain> getIdentityChain() { return identityChain_; }
    
    // Network integration
    void setP2PNetwork(std::shared_ptr<P2PNetwork> network);
    void broadcastChainUpdate(ChainType chainType, const Block& block);
    
    // Security
    void setSecurityManager(std::shared_ptr<SecurityManager> security);
    bool performSecurityScan();
    void handleSecurityViolation(ChainType chainType, const SecurityViolation& violation);
    
    // Statistics
    nlohmann::json getSystemStatus() const;
    nlohmann::json getChainStatistics() const;
    
    // Persistence
    bool saveAllChains() const;
    bool loadAllChains();

private:
    // Individual chains
    std::shared_ptr<Blockchain> mainChain_;
    std::shared_ptr<FileBlockchain> fileChain_;
    std::shared_ptr<AuthChain> authChain_;
    std::shared_ptr<IdentityChain> identityChain_;
    
    // Cross-chain communication
    std::vector<CrossChainMessage> messageQueue_;
    std::mutex messageQueueMutex_;
    
    // Network and security
    std::shared_ptr<P2PNetwork> p2pNetwork_;
    std::shared_ptr<SecurityManager> securityManager_;
    
    // Chain coordination
    std::unordered_map<ChainType, std::string> chainPaths_;
    mutable std::mutex chainsMutex_;
    
    // Helper methods
    bool validateCrossChainMessage(const CrossChainMessage& message) const;
    void processUserCreationMessage(const CrossChainMessage& message);
    void processFileUploadMessage(const CrossChainMessage& message);
    void processPermissionMessage(const CrossChainMessage& message);
    
    // User coordination
    bool createUserInAllChains(const std::string& userId, const nlohmann::json& userInfo);
    void notifyChainOfUserCreation(ChainType chainType, const std::string& userId, 
                                  const nlohmann::json& userInfo);
    
    // File operation coordination
    bool validateFileAccess(const std::string& userId, const std::string& fileId, 
                           const std::string& operation) const;
    void updateFilePermissions(const std::string& fileId, const std::string& userId);
};

// Implementation starts here

// CrossChainMessage implementation
nlohmann::json CrossChainMessage::toJson() const {
    nlohmann::json json;
    json["sourceChain"] = static_cast<int>(sourceChain);
    json["targetChain"] = static_cast<int>(targetChain);
    json["messageId"] = messageId;
    json["messageType"] = messageType;
    json["payload"] = payload;
    json["timestamp"] = timestamp;
    json["signature"] = signature;
    return json;
}

void CrossChainMessage::fromJson(const nlohmann::json& json) {
    sourceChain = static_cast<ChainType>(json["sourceChain"]);
    targetChain = static_cast<ChainType>(json["targetChain"]);
    messageId = json["messageId"];
    messageType = json["messageType"];
    payload = json["payload"];
    timestamp = json["timestamp"];
    signature = json["signature"];
}

// MainChainTransaction implementation
MainChainTransaction::MainChainTransaction(MainOperation operation, const std::string& userAddress)
    : Transaction(), operation_(operation) {
    
    TransactionOutput output;
    output.address = userAddress;
    output.amount = 0.001; // Minimal fee for main chain operations
    outputs_.push_back(output);
    
    timestamp_ = std::time(nullptr);
    id_ = calculateHash();
}

void MainChainTransaction::setPeerInfo(const PeerInfo& peer) {
    data_["peerInfo"] = peer.toJson();
    id_ = calculateHash();
}

void MainChainTransaction::setUserInfo(const nlohmann::json& userInfo) {
    data_["userInfo"] = userInfo;
    id_ = calculateHash();
}

void MainChainTransaction::setCrossChainMessage(const CrossChainMessage& message) {
    data_["crossChainMessage"] = message.toJson();
    id_ = calculateHash();
}

bool MainChainTransaction::isValidTransaction() const {
    if (!Transaction::isValidTransaction()) {
        return false;
    }
    
    // Validate main chain specific operations
    switch (operation_) {
        case MainOperation::PEER_REGISTRATION:
            return data_.contains("peerInfo");
        case MainOperation::USER_REGISTRATION:
            return data_.contains("userInfo");
        case MainOperation::CROSS_CHAIN_MESSAGE:
            return data_.contains("crossChainMessage");
        default:
            return true;
    }
}

nlohmann::json MainChainTransaction::toJson() const {
    nlohmann::json json = Transaction::toJson();
    json["mainOperation"] = static_cast<int>(operation_);
    json["data"] = data_;
    return json;
}

void MainChainTransaction::fromJson(const nlohmann::json& json) {
    Transaction::fromJson(json);
    operation_ = static_cast<MainOperation>(json["mainOperation"]);
    data_ = json["data"];
}

// AuthChain implementation
AuthChain::AuthChain() : Blockchain() {
    spdlog::info("AuthChain initialized");
}

bool AuthChain::grantPermission(const std::string& userId, const std::string& resource, 
                               const std::string& permission) {
    std::lock_guard<std::mutex> lock(authMutex_);
    
    std::string permKey = userId + ":" + resource;
    if (!permissions_[permKey].contains("permissions")) {
        permissions_[permKey]["permissions"] = nlohmann::json::array();
    }
    
    auto& perms = permissions_[permKey]["permissions"];
    if (std::find(perms.begin(), perms.end(), permission) == perms.end()) {
        perms.push_back(permission);
        
        // Create permission transaction
        MainChainTransaction tx(MainChainTransaction::MainOperation::GOVERNANCE_VOTE, userId);
        nlohmann::json permData;
        permData["action"] = "grant";
        permData["resource"] = resource;
        permData["permission"] = permission;
        permData["timestamp"] = std::time(nullptr);
        tx.setUserInfo(permData);
        
        addTransaction(tx);
        return true;
    }
    
    return false;
}

bool AuthChain::hasPermission(const std::string& userId, const std::string& resource, 
                             const std::string& permission) const {
    std::lock_guard<std::mutex> lock(authMutex_);
    
    std::string permKey = userId + ":" + resource;
    if (permissions_.find(permKey) == permissions_.end()) {
        return false;
    }
    
    const auto& perms = permissions_.at(permKey)["permissions"];
    return std::find(perms.begin(), perms.end(), permission) != perms.end();
}

std::string AuthChain::createSession(const std::string& userId, const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(authMutex_);
    
    std::string sessionId = Crypto::generateRandomString(32);
    
    nlohmann::json session;
    session["userId"] = userId;
    session["ipAddress"] = ipAddress;
    session["createdAt"] = std::time(nullptr);
    session["expiresAt"] = std::time(nullptr) + 3600; // 1 hour
    session["isValid"] = true;
    
    sessions_[sessionId] = session;
    return sessionId;
}

bool AuthChain::validateSession(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(authMutex_);
    
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return false;
    }
    
    const auto& session = it->second;
    std::time_t now = std::time(nullptr);
    
    return session["isValid"].get<bool>() && 
           now < session["expiresAt"].get<std::time_t>();
}

// IdentityChain implementation
IdentityChain::IdentityChain() : Blockchain() {
    spdlog::info("IdentityChain initialized");
}

std::string IdentityChain::createUser(const std::string& username, const std::string& email, 
                                     const std::string& publicKey) {
    std::lock_guard<std::mutex> lock(identityMutex_);
    
    std::string userId = Crypto::sha256(username + email + std::to_string(std::time(nullptr)));
    
    nlohmann::json profile;
    profile["userId"] = userId;
    profile["username"] = username;
    profile["email"] = email;
    profile["publicKey"] = publicKey;
    profile["createdAt"] = std::time(nullptr);
    profile["isActive"] = true;
    profile["reputation"] = 100; // Starting reputation
    
    userProfiles_[userId] = profile;
    
    // Create identity transaction
    MainChainTransaction tx(MainChainTransaction::MainOperation::USER_REGISTRATION, userId);
    tx.setUserInfo(profile);
    addTransaction(tx);
    
    spdlog::info("User created in IdentityChain: {}", userId);
    return userId;
}

nlohmann::json IdentityChain::getUserProfile(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    
    auto it = userProfiles_.find(userId);
    if (it != userProfiles_.end()) {
        return it->second;
    }
    
    return nlohmann::json{};
}

bool IdentityChain::verifyIdentity(const std::string& userId, const std::string& signature, 
                                  const std::string& data) const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    
    auto it = userProfiles_.find(userId);
    if (it == userProfiles_.end()) {
        return false;
    }
    
    const std::string& publicKey = it->second["publicKey"];
    return Crypto::verifySignature(data, signature, publicKey);
}

// MultiChainManager implementation
MultiChainManager::MultiChainManager() {
    chainPaths_[ChainType::MAIN_CHAIN] = "main_chain.json";
    chainPaths_[ChainType::FILE_CHAIN] = "file_chain.json";
    chainPaths_[ChainType::AUTH_CHAIN] = "auth_chain.json";
    chainPaths_[ChainType::IDENTITY_CHAIN] = "identity_chain.json";
}

bool MultiChainManager::initializeChains() {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    try {
        // Initialize all chains
        mainChain_ = std::make_shared<Blockchain>();
        fileChain_ = std::make_shared<FileBlockchain>();
        authChain_ = std::make_shared<AuthChain>();
        identityChain_ = std::make_shared<IdentityChain>();
        
        // Load existing chains if they exist
        loadAllChains();
        
        spdlog::info("Multi-chain system initialized successfully");
        spdlog::info("Main Chain Height: {}", mainChain_->getChainHeight());
        spdlog::info("File Chain Height: {}", fileChain_->getChainHeight());
        spdlog::info("Auth Chain Height: {}", authChain_->getChainHeight());
        spdlog::info("Identity Chain Height: {}", identityChain_->getChainHeight());
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain system: {}", e.what());
        return false;
    }
}

std::string MultiChainManager::registerUser(const std::string& username, const std::string& email, 
                                           const std::string& password) {
    try {
        // Generate key pair for the user
        auto keyPair = Crypto::generateKeyPair();
        std::string publicKey = keyPair.second;
        std::string privateKey = keyPair.first;
        
        // Create user in identity chain
        std::string userId = identityChain_->createUser(username, email, publicKey);
        
        // Hash password for auth chain
        std::string passwordHash = Crypto::sha256(password + userId);
        
        // Create user info for cross-chain communication
        nlohmann::json userInfo;
        userInfo["userId"] = userId;
        userInfo["username"] = username;
        userInfo["email"] = email;
        userInfo["publicKey"] = publicKey;
        userInfo["passwordHash"] = passwordHash;
        userInfo["createdAt"] = std::time(nullptr);
        
        // Register in main chain for coordination
        MainChainTransaction mainTx(MainChainTransaction::MainOperation::USER_REGISTRATION, userId);
        mainTx.setUserInfo(userInfo);
        mainChain_->addTransaction(mainTx);
        
        // Send cross-chain messages to other chains
        CrossChainMessage fileChainMsg;
        fileChainMsg.sourceChain = ChainType::MAIN_CHAIN;
        fileChainMsg.targetChain = ChainType::FILE_CHAIN;
        fileChainMsg.messageId = Crypto::generateRandomString(16);
        fileChainMsg.messageType = "USER_CREATED";
        fileChainMsg.payload = userInfo;
        fileChainMsg.timestamp = std::time(nullptr);
        
        CrossChainMessage authChainMsg = fileChainMsg;
        authChainMsg.targetChain = ChainType::AUTH_CHAIN;
        
        sendCrossChainMessage(fileChainMsg);
        sendCrossChainMessage(authChainMsg);
        
        spdlog::info("User registered across all chains: {}", userId);
        return userId;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to register user: {}", e.what());
        return "";
    }
}

std::string MultiChainManager::uploadFile(const std::vector<uint8_t>& fileData, 
                                         const std::string& filename, const std::string& userId) {
    try {
        // Verify user exists and has permissions
        auto userProfile = identityChain_->getUserProfile(userId);
        if (userProfile.empty()) {
            spdlog::error("User not found: {}", userId);
            return "";
        }
        
        if (!authChain_->hasPermission(userId, "file_system", "upload")) {
            // Grant default upload permission for registered users
            authChain_->grantPermission(userId, "file_system", "upload");
            authChain_->grantPermission(userId, "file_system", "download");
            authChain_->grantPermission(userId, "file_system", "list");
        }
        
        // Upload file to file chain (isolated from main chain)
        std::string fileId = fileChain_->uploadFileData(fileData, filename, userId);
        
        if (!fileId.empty()) {
            // Notify main chain of file upload via cross-chain message
            CrossChainMessage msg;
            msg.sourceChain = ChainType::FILE_CHAIN;
            msg.targetChain = ChainType::MAIN_CHAIN;
            msg.messageId = Crypto::generateRandomString(16);
            msg.messageType = "FILE_UPLOADED";
            msg.payload["fileId"] = fileId;
            msg.payload["filename"] = filename;
            msg.payload["userId"] = userId;
            msg.payload["fileSize"] = fileData.size();
            msg.timestamp = std::time(nullptr);
            
            sendCrossChainMessage(msg);
            
            spdlog::info("File uploaded successfully: {} by user {}", fileId, userId);
        }
        
        return fileId;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to upload file: {}", e.what());
        return "";
    }
}

std::vector<uint8_t> MultiChainManager::downloadFile(const std::string& fileId, 
                                                     const std::string& userId) {
    try {
        // Check permissions
        if (!validateFileAccess(userId, fileId, "download")) {
            spdlog::error("User {} does not have permission to download file {}", userId, fileId);
            return {};
        }
        
        // Download from file chain
        auto fileData = fileChain_->downloadFile(fileId);
        
        if (!fileData.empty()) {
            // Log access in auth chain
            nlohmann::json accessLog;
            accessLog["userId"] = userId;
            accessLog["fileId"] = fileId;
            accessLog["operation"] = "download";
            accessLog["timestamp"] = std::time(nullptr);
            
            MainChainTransaction tx(MainChainTransaction::MainOperation::GOVERNANCE_VOTE, userId);
            tx.setUserInfo(accessLog);
            authChain_->addTransaction(tx);
            
            spdlog::info("File downloaded: {} by user {}", fileId, userId);
        }
        
        return fileData;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to download file: {}", e.what());
        return {};
    }
}

bool MultiChainManager::sendCrossChainMessage(const CrossChainMessage& message) {
    std::lock_guard<std::mutex> lock(messageQueueMutex_);
    
    if (validateCrossChainMessage(message)) {
        messageQueue_.push_back(message);
        return true;
    }
    
    return false;
}

void MultiChainManager::processCrossChainMessages() {
    std::lock_guard<std::mutex> lock(messageQueueMutex_);
    
    for (const auto& message : messageQueue_) {
        try {
            if (message.messageType == "USER_CREATED") {
                processUserCreationMessage(message);
            } else if (message.messageType == "FILE_UPLOADED") {
                processFileUploadMessage(message);
            } else if (message.messageType == "PERMISSION_GRANTED") {
                processPermissionMessage(message);
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to process cross-chain message: {}", e.what());
        }
    }
    
    messageQueue_.clear();
}

bool MultiChainManager::validateFileAccess(const std::string& userId, const std::string& fileId, 
                                          const std::string& operation) const {
    // Check if user exists
    auto userProfile = identityChain_->getUserProfile(userId);
    if (userProfile.empty()) {
        return false;
    }
    
    // Check general file system permissions
    if (!authChain_->hasPermission(userId, "file_system", operation)) {
        return false;
    }
    
    // Check specific file permissions
    if (fileChain_->fileExists(fileId)) {
        auto metadata = fileChain_->getFileMetadata(fileId);
        if (metadata.uploaderAddress == userId) {
            return true; // Owner has full access
        }
        
        // Check if file has been shared with this user
        return authChain_->hasPermission(userId, "file:" + fileId, operation);
    }
    
    return false;
}

nlohmann::json MultiChainManager::getSystemStatus() const {
    std::lock_guard<std::mutex> lock(chainsMutex_);
    
    nlohmann::json status;
    status["timestamp"] = std::time(nullptr);
    status["chains"] = nlohmann::json::object();
    
    status["chains"]["main"] = {
        {"height", mainChain_->getChainHeight()},
        {"difficulty", mainChain_->getDifficulty()},
        {"mempool_size", mainChain_->getTransactionPool().getTransactionCount()},
        {"healthy", isChainHealthy(ChainType::MAIN_CHAIN)}
    };
    
    status["chains"]["file"] = {
        {"height", fileChain_->getChainHeight()},
        {"file_count", fileChain_->getTotalFileCount()},
        {"storage_used", fileChain_->getTotalStorageUsed()},
        {"healthy", isChainHealthy(ChainType::FILE_CHAIN)}
    };
    
    status["chains"]["auth"] = {
        {"height", authChain_->getChainHeight()},
        {"healthy", isChainHealthy(ChainType::AUTH_CHAIN)}
    };
    
    status["chains"]["identity"] = {
        {"height", identityChain_->getChainHeight()},
        {"healthy", isChainHealthy(ChainType::IDENTITY_CHAIN)}
    };
    
    status["cross_chain"] = {
        {"pending_messages", messageQueue_.size()}
    };
    
    return status;
}

bool MultiChainManager::saveAllChains() const {
    bool success = true;
    
    success &= mainChain_->saveToFile(chainPaths_.at(ChainType::MAIN_CHAIN));
    success &= fileChain_->saveToFile(chainPaths_.at(ChainType::FILE_CHAIN));
    success &= authChain_->saveToFile(chainPaths_.at(ChainType::AUTH_CHAIN));
    success &= identityChain_->saveToFile(chainPaths_.at(ChainType::IDENTITY_CHAIN));
    
    if (success) {
        spdlog::info("All chains saved successfully");
    } else {
        spdlog::error("Failed to save one or more chains");
    }
    
    return success;
}

bool MultiChainManager::loadAllChains() {
    bool success = true;
    
    if (Utils::fileExists(chainPaths_.at(ChainType::MAIN_CHAIN))) {
        success &= mainChain_->loadFromFile(chainPaths_.at(ChainType::MAIN_CHAIN));
    }
    
    if (Utils::fileExists(chainPaths_.at(ChainType::FILE_CHAIN))) {
        success &= fileChain_->loadFromFile(chainPaths_.at(ChainType::FILE_CHAIN));
    }
    
    if (Utils::fileExists(chainPaths_.at(ChainType::AUTH_CHAIN))) {
        success &= authChain_->loadFromFile(chainPaths_.at(ChainType::AUTH_CHAIN));
    }
    
    if (Utils::fileExists(chainPaths_.at(ChainType::IDENTITY_CHAIN))) {
        success &= identityChain_->loadFromFile(chainPaths_.at(ChainType::IDENTITY_CHAIN));
    }
    
    return success;
}

bool MultiChainManager::isChainHealthy(ChainType type) const {
    try {
        switch (type) {
            case ChainType::MAIN_CHAIN:
                return mainChain_ && mainChain_->isValidChain();
            case ChainType::FILE_CHAIN:
                return fileChain_ && fileChain_->isValidChain();
            case ChainType::AUTH_CHAIN:
                return authChain_ && authChain_->isValidChain();
            case ChainType::IDENTITY_CHAIN:
                return identityChain_ && identityChain_->isValidChain();
            default:
                return false;
        }
    } catch (const std::exception& e) {
        spdlog::error("Chain health check failed: {}", e.what());
        return false;
    }
}