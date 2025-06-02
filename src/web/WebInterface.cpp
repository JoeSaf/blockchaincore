#include "web/WebInterface.h"
#include "blockchain/FileBlockchain.h"
#include "utils/Crypto.h"
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>  
#include <fstream>
#include <sstream>
#include <regex>
#include <random>
#include <iomanip>
#include "FileBlockchain.h"

// Forward declarations for enums
enum class SecurityEvent;
enum class ThreatLevel;

// User struct implementations
nlohmann::json User::toJson() const {
    nlohmann::json json;
    json["userId"] = userId;
    json["username"] = username;
    json["email"] = email;
    json["walletAddress"] = walletAddress;
    json["registrationTime"] = registrationTime;
    json["lastLogin"] = lastLogin;
    json["isActive"] = isActive;
    json["permissions"] = permissions;
    json["storageQuota"] = storageQuota;
    json["storageUsed"] = storageUsed;
    return json;
}

void User::fromJson(const nlohmann::json& json) {
    userId = json["userId"];
    username = json["username"];
    email = json["email"];
    walletAddress = json["walletAddress"];
    registrationTime = json["registrationTime"];
    lastLogin = json["lastLogin"];
    isActive = json["isActive"];
    permissions = json["permissions"];
    storageQuota = json["storageQuota"];
    storageUsed = json["storageUsed"];
}

// UserSession struct implementations
nlohmann::json UserSession::toJson() const {
    nlohmann::json json;
    json["sessionId"] = sessionId;
    json["userId"] = userId;
    json["creationTime"] = creationTime;
    json["lastAccess"] = lastAccess;
    json["expirationTime"] = expirationTime;
    json["ipAddress"] = ipAddress;
    json["isValid"] = isValid;
    return json;
}

void UserSession::fromJson(const nlohmann::json& json) {
    sessionId = json["sessionId"];
    userId = json["userId"];
    creationTime = json["creationTime"];
    lastAccess = json["lastAccess"];
    expirationTime = json["expirationTime"];
    ipAddress = json["ipAddress"];
    isValid = json["isValid"];
}

// UploadStatus struct implementation
nlohmann::json UploadStatus::toJson() const {
    nlohmann::json json;
    json["uploadId"] = uploadId;
    json["fileId"] = fileId;
    json["filename"] = filename;
    json["totalSize"] = totalSize;
    json["uploadedSize"] = uploadedSize;
    json["percentage"] = percentage;
    json["status"] = status;
    json["startTime"] = startTime;
    json["lastUpdate"] = lastUpdate;
    return json;
}

// WebInterface implementation
WebInterface::WebInterface(uint16_t port)
    : port_(port), running_(false), maxUploadSize_(DEFAULT_MAX_UPLOAD_SIZE),
      sessionTimeout_(DEFAULT_SESSION_TIMEOUT), registrationEnabled_(true),
      staticFilesPath_("web/static") {
    
    server_ = std::make_unique<httplib::Server>();
    setupRoutes();
    loadUsers();
    
    spdlog::info("WebInterface initialized on port {}", port_);
}

WebInterface::~WebInterface() {
    stop();
    saveUsers();
}

bool WebInterface::start() {
    if (running_) {
        spdlog::warn("WebInterface is already running");
        return false;
    }
    
    try {
        serverThread_ = std::thread([this]() {
            running_ = true;
            spdlog::info("Starting WebInterface on port {}", port_);
            
            // Configure server
            server_->set_read_timeout(30, 0);  // 30 seconds
            server_->set_write_timeout(30, 0);
            server_->set_payload_max_length(maxUploadSize_);
            
            // Start server
            bool success = server_->listen("0.0.0.0", port_);
            if (!success) {
                spdlog::error("Failed to start web server on port {}", port_);
                running_ = false;
            }
        });
        
        // Give server time to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (running_) {
            spdlog::info("WebInterface started successfully on http://localhost:{}", port_);
            return true;
        }
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to start WebInterface: {}", e.what());
        running_ = false;
        return false;
    }
    
    return false;
}

void WebInterface::stop() {
    if (!running_) return;
    
    running_ = false;
    
    try {
        server_->stop();
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
        spdlog::info("WebInterface stopped");
    } catch (const std::exception& e) {
        spdlog::error("Error stopping WebInterface: {}", e.what());
    }
}

void WebInterface::setFileBlockchain(std::shared_ptr<FileBlockchain> blockchain) {
    fileBlockchain_ = blockchain;
    spdlog::debug("FileBlockchain reference set for WebInterface");
}

void WebInterface::setP2PNetwork(std::shared_ptr<P2PNetwork> network) {
    p2pNetwork_ = network;
    spdlog::debug("P2PNetwork reference set for WebInterface");
}

void WebInterface::setSecurityManager(std::shared_ptr<SecurityManager> securityManager) {
    securityManager_ = securityManager;
    spdlog::debug("SecurityManager reference set for WebInterface");
}

void WebInterface::setupRoutes() {
    // Enable CORS
    server_->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    
    // Static files
    server_->set_mount_point("/", staticFilesPath_);
    
    // Main pages
    server_->Get("/", [this](const httplib::Request& req, httplib::Response& res) {
        handleHomePage(req, res);
    });
    
    server_->Get("/login", [this](const httplib::Request& req, httplib::Response& res) {
        handleLoginPage(req, res);
    });
    
    server_->Get("/register", [this](const httplib::Request& req, httplib::Response& res) {
        handleRegisterPage(req, res);
    });
    
    server_->Get("/dashboard", [this](const httplib::Request& req, httplib::Response& res) {
        handleDashboard(req, res);
    });
    
    // Authentication API
    server_->Post("/api/auth/login", [this](const httplib::Request& req, httplib::Response& res) {
        handleLogin(req, res);
    });
    
    server_->Post("/api/auth/logout", [this](const httplib::Request& req, httplib::Response& res) {
        handleLogout(req, res);
    });
    
    server_->Post("/api/auth/register", [this](const httplib::Request& req, httplib::Response& res) {
        handleRegister(req, res);
    });
    
    // File management API
    server_->Post("/api/files/upload", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileUpload(req, res);
    });
    
    server_->Get(R"(/api/files/download/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileDownload(req, res);
    });
    
    server_->Get("/api/files/list", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileList(req, res);
    });
    
    server_->Delete(R"(/api/files/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileDelete(req, res);
    });
    
    // Blockchain API
    server_->Get("/api/status", [this](const httplib::Request& req, httplib::Response& res) {
        handleBlockchainStatus(req, res);
    });
    
    server_->Get("/api/blockchain", [this](const httplib::Request& req, httplib::Response& res) {
        handleBlockExplorer(req, res);
    });
    
    server_->Get("/api/security/status", [this](const httplib::Request& req, httplib::Response& res) {
        handleSecurityStatus(req, res);
    });
    
    server_->Post("/api/security/scan", [this](const httplib::Request& req, httplib::Response& res) {
        User* user = getAuthenticatedUser(req);
        if (!user) {
            sendErrorResponse(res, "Authentication required", 401);
            return;
        }
        
        if (securityManager_) {
            bool result = securityManager_->performSecurityScan();
            nlohmann::json response;
            response["success"] = result;
            response["message"] = result ? "Security scan completed" : "Security scan failed";
            sendJSONResponse(res, response);
        } else {
            sendErrorResponse(res, "Security manager not available", 503);
        }
    });
    
    spdlog::debug("WebInterface routes configured");
}

// ========================
// AUTHENTICATION HANDLERS
// ========================

void WebInterface::handleLogin(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json requestData = nlohmann::json::parse(req.body);
        
        if (!requestData.contains("username") || !requestData.contains("password")) {
            sendErrorResponse(res, "Username and password required");
            return;
        }
        
        std::string username = requestData["username"];
        std::string password = requestData["password"];
        
        if (!authenticateUser(username, password)) {
            logSecurityEvent("Failed login attempt", "", req.get_header_value("X-Real-IP"));
            sendErrorResponse(res, "Invalid username or password", 401);
            return;
        }
        
        User* user = getUserByUsername(username);
        if (!user) {
            sendErrorResponse(res, "User not found", 404);
            return;
        }
        
        // Create session
        std::string sessionId = createSession(user->userId, req.get_header_value("X-Real-IP"));
        user->lastLogin = std::time(nullptr);
        updateUser(*user);
        
        nlohmann::json response;
        response["success"] = true;
        response["sessionId"] = sessionId;
        response["user"] = user->toJson();
        
        logSecurityEvent("Successful login", user->userId, req.get_header_value("X-Real-IP"));
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Login error: {}", e.what());
        sendErrorResponse(res, "Login failed", 500);
    }
}

void WebInterface::handleRegister(const httplib::Request& req, httplib::Response& res) {
    if (!registrationEnabled_) {
        sendErrorResponse(res, "Registration is disabled", 403);
        return;
    }
    
    try {
        nlohmann::json requestData = nlohmann::json::parse(req.body);
        
        if (!requestData.contains("username") || !requestData.contains("password") || !requestData.contains("email")) {
            sendErrorResponse(res, "Username, password, and email required");
            return;
        }
        
        std::string username = requestData["username"];
        std::string password = requestData["password"];
        std::string email = requestData["email"];
        
        // Validate input
        if (!isValidUsername(username)) {
            sendErrorResponse(res, "Invalid username format");
            return;
        }
        
        if (!isValidPassword(password)) {
            sendErrorResponse(res, "Password must be at least 8 characters");
            return;
        }
        
        if (!isValidEmail(email)) {
            sendErrorResponse(res, "Invalid email format");
            return;
        }
        
        // Check if user exists
        if (getUserByUsername(username)) {
            sendErrorResponse(res, "Username already exists");
            return;
        }
        
        // Create user
        std::string userId = createUser(username, password, email);
        if (userId.empty()) {
            sendErrorResponse(res, "Failed to create user", 500);
            return;
        }
        
        nlohmann::json response;
        response["success"] = true;
        response["message"] = "User created successfully";
        response["userId"] = userId;
        
        logSecurityEvent("New user registration", userId, req.get_header_value("X-Real-IP"));
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Registration error: {}", e.what());
        sendErrorResponse(res, "Registration failed", 500);
    }
}

void WebInterface::handleLogout(const httplib::Request& req, httplib::Response& res) {
    std::string sessionId = extractSessionFromRequest(req);
    if (!sessionId.empty()) {
        invalidateSession(sessionId);
    }
    
    nlohmann::json response;
    response["success"] = true;
    response["message"] = "Logged out successfully";
    sendJSONResponse(res, response);
}

// ========================
// FILE MANAGEMENT HANDLERS
// ========================

void WebInterface::handleFileUpload(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    if (!fileBlockchain_) {
        sendErrorResponse(res, "File blockchain not available", 503);
        return;
    }
    
    try {
        // Parse multipart form data
        auto file_it = req.files.find("file");
        if (file_it == req.files.end()) {
            sendErrorResponse(res, "No file uploaded");
            return;
        }
        
        const auto& file = file_it->second;
        
        // Validate file
        if (!validateUploadedFile(file.filename, file.content.size())) {
            sendErrorResponse(res, "File validation failed");
            return;
        }
        
        // Check storage quota
        if (user->storageUsed + file.content.size() > user->storageQuota) {
            sendErrorResponse(res, "Storage quota exceeded");
            return;
        }
        
        // Upload file to blockchain
        std::vector<uint8_t> fileData(file.content.begin(), file.content.end());
        std::string fileId = fileBlockchain_->uploadFileData(fileData, file.filename, user->walletAddress);
        
        if (fileId.empty()) {
            sendErrorResponse(res, "Failed to upload file to blockchain", 500);
            return;
        }
        
        // Update user storage
        user->storageUsed += file.content.size();
        updateUser(*user);
        
        // Broadcast to network
        if (p2pNetwork_) {
            // Would broadcast file metadata to peers
            spdlog::debug("File metadata would be broadcasted to {} peers", p2pNetwork_->getPeerCount());
        }
        
        nlohmann::json response;
        response["success"] = true;
        response["fileId"] = fileId;
        response["filename"] = file.filename;
        response["size"] = file.content.size();
        response["message"] = "File uploaded successfully";
        
        logSecurityEvent("File uploaded", user->userId, req.get_header_value("X-Real-IP"));
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("File upload error: {}", e.what());
        sendErrorResponse(res, "File upload failed", 500);
    }
}

void WebInterface::handleFileDownload(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    if (!fileBlockchain_) {
        sendErrorResponse(res, "File blockchain not available", 503);
        return;
    }
    
    try {
        std::string fileId = req.matches[1];
        
        if (!fileBlockchain_->fileExists(fileId)) {
            sendErrorResponse(res, "File not found", 404);
            return;
        }
        
        // Check permissions (simplified - would implement proper access control)
        auto metadata = fileBlockchain_->getFileMetadata(fileId);
        
        auto fileData = fileBlockchain_->downloadFile(fileId);
        if (fileData.empty()) {
            sendErrorResponse(res, "Failed to download file", 500);
            return;
        }
        
        sendFileResponse(res, fileData, metadata.originalName, metadata.mimeType);
        logSecurityEvent("File downloaded", user->userId, req.get_header_value("X-Real-IP"));
        
    } catch (const std::exception& e) {
        spdlog::error("File download error: {}", e.what());
        sendErrorResponse(res, "File download failed", 500);
    }
}

void WebInterface::handleFileList(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    if (!fileBlockchain_) {
        sendErrorResponse(res, "File blockchain not available", 503);
        return;
    }
    
    try {
        auto files = fileBlockchain_->listFiles(user->walletAddress);
        
        nlohmann::json response;
        response["success"] = true;
        response["files"] = nlohmann::json::array();
        
        for (const auto& file : files) {
            nlohmann::json fileJson;
            fileJson["fileId"] = file.fileId;
            fileJson["originalName"] = file.originalName;
            fileJson["fileSize"] = file.fileSize;
            fileJson["uploadTime"] = file.uploadTime;
            fileJson["mimeType"] = file.mimeType;
            response["files"].push_back(fileJson);
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("File list error: {}", e.what());
        sendErrorResponse(res, "Failed to list files", 500);
    }
}

void WebInterface::handleFileDelete(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    if (!fileBlockchain_) {
        sendErrorResponse(res, "File blockchain not available", 503);
        return;
    }
    
    try {
        std::string fileId = req.matches[1];
        
        if (!fileBlockchain_->fileExists(fileId)) {
            sendErrorResponse(res, "File not found", 404);
            return;
        }
        
        // Check if user owns the file
        auto metadata = fileBlockchain_->getFileMetadata(fileId);
        if (metadata.uploaderAddress != user->walletAddress) {
            sendErrorResponse(res, "Access denied", 403);
            return;
        }
        
        // Delete file from blockchain
        bool result = fileBlockchain_->deleteFile(fileId, user->walletAddress);
        if (!result) {
            sendErrorResponse(res, "Failed to delete file", 500);
            return;
        }
        
        // Update user storage
        user->storageUsed -= metadata.fileSize;
        updateUser(*user);
        
        nlohmann::json response;
        response["success"] = true;
        response["message"] = "File deleted successfully";
        sendJSONResponse(res, response);
        
        logSecurityEvent("File deleted", user->userId, req.get_header_value("X-Real-IP"));
        
    } catch (const std::exception& e) {
        spdlog::error("File delete error: {}", e.what());
        sendErrorResponse(res, "File deletion failed", 500);
    }
}

// ========================
// BLOCKCHAIN STATUS HANDLERS
// ========================

void WebInterface::handleBlockchainStatus(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        
        if (fileBlockchain_) {
            response["chainHeight"] = fileBlockchain_->getChainHeight();
            response["totalSupply"] = fileBlockchain_->getTotalSupply();
            response["totalTransactions"] = fileBlockchain_->getTotalTransactions();
            response["fileCount"] = fileBlockchain_->getTotalFileCount();
            response["storageUsed"] = fileBlockchain_->getTotalStorageUsed();
        }
        
        if (p2pNetwork_) {
            response["peerCount"] = p2pNetwork_->getPeerCount();
            response["networkRunning"] = p2pNetwork_->isRunning();
        }
        
        if (securityManager_) {
            response["threatLevel"] = static_cast<int>(securityManager_->assessThreatLevel());
            response["integrityScore"] = securityManager_->getChainIntegrityScore();
            response["quarantinedBlocks"] = securityManager_->getQuarantinedBlocks().size();
            response["reorderCount"] = securityManager_->getReorderCount();
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Status error: {}", e.what());
        sendErrorResponse(res, "Failed to get status", 500);
    }
}

void WebInterface::handleSecurityStatus(const httplib::Request& req, httplib::Response& res) {
    if (!securityManager_) {
        sendErrorResponse(res, "Security manager not available", 503);
        return;
    }
    
    try {
        auto threats = securityManager_->getActiveThreats();
        auto quarantined = securityManager_->getQuarantinedBlocks();
        
        nlohmann::json response;
        response["success"] = true;
        response["threatLevel"] = static_cast<int>(securityManager_->assessThreatLevel());
        response["integrityScore"] = securityManager_->getChainIntegrityScore();
        response["activeThreats"] = threats.size();
        response["quarantinedBlocks"] = quarantined.size();
        response["totalViolations"] = securityManager_->getTotalViolationsCount();
        response["reorderCount"] = securityManager_->getReorderCount();
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Security status error: {}", e.what());
        sendErrorResponse(res, "Failed to get security status", 500);
    }
}

// ========================
// PAGE HANDLERS
// ========================

void WebInterface::handleHomePage(const httplib::Request& req, httplib::Response& res) {
    // Check if user is authenticated
    User* user = getAuthenticatedUser(req);
    if (user) {
        // Redirect to dashboard if logged in
        res.status = 302;
        res.set_header("Location", "/dashboard");
        return;
    }
    
    // Serve login page for unauthenticated users
    handleLoginPage(req, res);
}

void WebInterface::handleLoginPage(const httplib::Request& req, httplib::Response& res) {
    std::string html = generateLoginPage();
    sendHTMLResponse(res, html);
}

void WebInterface::handleRegisterPage(const httplib::Request& req, httplib::Response& res) {
    if (!registrationEnabled_) {
        std::string html = R"(<!DOCTYPE html>
<html><head><title>Registration Disabled</title></head>
<body style="text-align:center; padding:50px;">
<h1>Registration Disabled</h1>
<p>User registration is currently disabled.</p>
<a href="/login">Return to Login</a>
</body></html>)";
        sendHTMLResponse(res, html);
        return;
    }
    
    std::string html = generateRegisterPage();
    sendHTMLResponse(res, html);
}

void WebInterface::handleDashboard(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        res.status = 302;
        res.set_header("Location", "/login");
        return;
    }
    
    std::string html = generateDashboard(*user);
    sendHTMLResponse(res, html);
}

void WebInterface::handleBlockExplorer(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        response["blocks"] = nlohmann::json::array();
        
        if (fileBlockchain_) {
            const auto& chain = fileBlockchain_->getChain();
            
            // Return last 10 blocks
            size_t startIndex = chain.size() > 10 ? chain.size() - 10 : 0;
            for (size_t i = startIndex; i < chain.size(); ++i) {
                nlohmann::json blockJson;
                blockJson["index"] = chain[i].getIndex();
                blockJson["hash"] = chain[i].getHash();
                blockJson["previousHash"] = chain[i].getPreviousHash();
                blockJson["timestamp"] = chain[i].getTimestamp();
                blockJson["transactionCount"] = chain[i].getTransactions().size();
                response["blocks"].push_back(blockJson);
            }
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Block explorer error: {}", e.what());
        sendErrorResponse(res, "Failed to get blockchain data", 500);
    }
}

// ========================
// USER MANAGEMENT
// ========================

std::string WebInterface::createUser(const std::string& username, const std::string& password, const std::string& email) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    try {
        User user;
        user.userId = Crypto::generateRandomString(16);
        user.username = username;
        user.passwordHash = hashPassword(password);
        user.email = email;
        user.walletAddress = Crypto::generateRandomAddress();
        user.registrationTime = std::time(nullptr);
        user.lastLogin = 0;
        user.isActive = true;
        user.permissions = nlohmann::json::object();
        user.storageQuota = 1024 * 1024 * 1024; // 1GB default
        user.storageUsed = 0;
        
        users_[user.userId] = user;
        usernames_[username] = user.userId;
        
        spdlog::info("Created user: {} ({})", username, user.userId);
        return user.userId;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to create user: {}", e.what());
        return "";
    }
}

bool WebInterface::authenticateUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto it = usernames_.find(username);
    if (it == usernames_.end()) {
        return false;
    }
    
    auto userIt = users_.find(it->second);
    if (userIt == users_.end()) {
        return false;
    }
    
    return verifyPassword(password, userIt->second.passwordHash);
}

User* WebInterface::getUserByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto it = usernames_.find(username);
    if (it == usernames_.end()) {
        return nullptr;
    }
    
    auto userIt = users_.find(it->second);
    if (userIt == users_.end()) {
        return nullptr;
    }
    
    return &userIt->second;
}

// ========================
// SESSION MANAGEMENT
// ========================

std::string WebInterface::createSession(const std::string& userId, const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    
    UserSession session;
    session.sessionId = generateSessionId();
    session.userId = userId;
    session.creationTime = std::time(nullptr);
    session.lastAccess = session.creationTime;
    session.expirationTime = session.creationTime + sessionTimeout_;
    session.ipAddress = ipAddress;
    session.isValid = true;
    
    sessions_[session.sessionId] = session;
    
    // Clean up old sessions
    cleanupExpiredSessions();
    
    return session.sessionId;
}

bool WebInterface::validateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return false;
    }
    
    UserSession& session = it->second;
    std::time_t now = std::time(nullptr);
    
    if (!session.isValid || now > session.expirationTime) {
        sessions_.erase(it);
        return false;
    }
    
    // Update last access
    session.lastAccess = now;
    session.expirationTime = now + sessionTimeout_;
    
    return true;
}

User* WebInterface::getAuthenticatedUser(const httplib::Request& req) {
    std::string sessionId = extractSessionFromRequest(req);
    if (sessionId.empty() || !validateSession(sessionId)) {
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto sessionIt = sessions_.find(sessionId);
    if (sessionIt == sessions_.end()) {
        return nullptr;
    }
    
    std::lock_guard<std::mutex> userLock(usersMutex_);
    auto userIt = users_.find(sessionIt->second.userId);
    if (userIt == users_.end()) {
        return nullptr;
    }
    
    return &userIt->second;
}

// ========================
// UTILITY FUNCTIONS
// ========================

void WebInterface::sendJSONResponse(httplib::Response& res, const nlohmann::json& json, int status) {
    res.status = status;
    res.set_header("Content-Type", "application/json");
    res.body = json.dump();
}

void WebInterface::sendErrorResponse(httplib::Response& res, const std::string& error, int status) {
    nlohmann::json response;
    response["success"] = false;
    response["error"] = error;
    response["timestamp"] = std::time(nullptr);
    sendJSONResponse(res, response, status);
}

void WebInterface::sendHTMLResponse(httplib::Response& res, const std::string& html) {
    res.status = 200;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    res.body = html;
}

void WebInterface::sendFileResponse(httplib::Response& res, const std::vector<uint8_t>& data, 
                                   const std::string& filename, const std::string& mimeType) {
    res.status = 200;
    res.set_header("Content-Type", mimeType.empty() ? "application/octet-stream" : mimeType);
    res.set_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    res.body = std::string(data.begin(), data.end());
}

std::string WebInterface::hashPassword(const std::string& password, const std::string& salt) {
    std::string saltToUse = salt.empty() ? generateSalt() : salt;
    return Crypto::sha256(password + saltToUse) + ":" + saltToUse;
}

std::string WebInterface::generateSalt() {
    return Crypto::generateRandomString(16);
}

bool WebInterface::verifyPassword(const std::string& password, const std::string& hash) {
    size_t colonPos = hash.find(':');
    if (colonPos == std::string::npos) {
        return false;
    }
    
    std::string storedHash = hash.substr(0, colonPos);
    std::string salt = hash.substr(colonPos + 1);
    
    std::string computedHash = Crypto::sha256(password + salt);
    return computedHash == storedHash;
}

std::string WebInterface::extractSessionFromRequest(const httplib::Request& req) {
    // Try Authorization header first
    auto authHeader = req.get_header_value("Authorization");
    if (!authHeader.empty() && authHeader.substr(0, 7) == "Bearer ") {
        return authHeader.substr(7);
    }
    
    // Try cookie
    auto cookie = req.get_header_value("Cookie");
    if (!cookie.empty()) {
        std::regex sessionRegex("sessionId=([^;]+)");
        std::smatch match;
        if (std::regex_search(cookie, match, sessionRegex)) {
            return match[1];
        }
    }
    
    return "";
}

std::string WebInterface::generateSessionId() {
    return Crypto::generateRandomString(32);
}

bool WebInterface::isValidEmail(const std::string& email) {
    std::regex emailRegex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return std::regex_match(email, emailRegex);
}

bool WebInterface::isValidUsername(const std::string& username) {
    return username.length() >= 3 && username.length() <= MAX_USERNAME_LENGTH &&
           std::all_of(username.begin(), username.end(), [](char c) {
               return std::isalnum(c) || c == '_' || c == '-';
           });
}

bool WebInterface::isValidPassword(const std::string& password) {
    return password.length() >= MIN_PASSWORD_LENGTH;
}

bool WebInterface::validateUploadedFile(const std::string& filename, uint64_t fileSize) {
    if (filename.empty() || fileSize == 0) {
        return false;
    }
    
    if (fileSize > maxUploadSize_) {
        return false;
    }
    
    // Check for dangerous file extensions (basic security)
    std::vector<std::string> dangerousExtensions = {".exe", ".bat", ".cmd", ".scr", ".pif"};
    for (const auto& ext : dangerousExtensions) {
        if (filename.length() >= ext.length() &&
            filename.compare(filename.length() - ext.length(), ext.length(), ext) == 0) {
            return false;
        }
    }
    
    return true;
}

void WebInterface::cleanupExpiredSessions() {
    std::time_t now = std::time(nullptr);
    auto it = sessions_.begin();
    
    while (it != sessions_.end()) {
        if (!it->second.isValid || now > it->second.expirationTime) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void WebInterface::invalidateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    sessions_.erase(sessionId);
}

bool WebInterface::updateUser(const User& user) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    users_[user.userId] = user;
    return true;
}

void WebInterface::loadUsers() {
    try {
        if (Utils::fileExists("users.json")) {
            nlohmann::json usersJson = Utils::readJsonFile("users.json");
            
            std::lock_guard<std::mutex> lock(usersMutex_);
            users_.clear();
            usernames_.clear();
            
            for (const auto& userJson : usersJson["users"]) {
                User user;
                user.fromJson(userJson);
                users_[user.userId] = user;
                usernames_[user.username] = user.userId;
            }
            
            spdlog::info("Loaded {} users from file", users_.size());
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to load users: {}", e.what());
    }
}

void WebInterface::saveUsers() {
    try {
        nlohmann::json usersJson;
        usersJson["users"] = nlohmann::json::array();
        
        std::lock_guard<std::mutex> lock(usersMutex_);
        for (const auto& [userId, user] : users_) {
            usersJson["users"].push_back(user.toJson());
        }
        
        Utils::writeJsonFile("users.json", usersJson);
        spdlog::debug("Saved {} users to file", users_.size());
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to save users: {}", e.what());
    }
}

void WebInterface::logSecurityEvent(const std::string& event, const std::string& userId, const std::string& ipAddress) {
    spdlog::info("Security Event: {} | User: {} | IP: {}", event, userId, ipAddress);
}

// ========================
// HTML GENERATION
// ========================

std::string WebInterface::generateLoginPage(const std::string& errorMessage) {
    std::stringstream html;
    
    html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Storage - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            width: 100%;
            margin-bottom: 15px;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
        }
        .register-link a {
            color: #667eea;
            text-decoration: none;
        }
        .register-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔗 Blockchain Storage</div>
        
        )";
    
    if (!errorMessage.empty()) {
        html << "<div class=\"error\">" << errorMessage << "</div>";
    }
    
    html << R"(
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Login</button>
        </form>
        
        )";
    
    if (registrationEnabled_) {
        html << R"(
        <div class="register-link">
            Don't have an account? <a href="/register">Register here</a>
        </div>
        )";
    }
    
    html << R"(
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    localStorage.setItem('sessionId', result.sessionId);
                    window.location.href = '/dashboard';
                } else {
                    alert('Login failed: ' + result.error);
                }
            } catch (error) {
                alert('Login error: ' + error.message);
            }
        });
    </script>
</body>
</html>)";
    
    return html.str();
}

std::string WebInterface::generateRegisterPage(const std::string& errorMessage) {
    std::stringstream html;
    
    html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Storage - Register</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .register-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            width: 100%;
            margin-bottom: 15px;
        }
        .btn:hover { transform: translateY(-2px); }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }
        .login-link {
            text-align: center;
            margin-top: 20px;
        }
        .login-link a {
            color: #667eea;
            text-decoration: none;
        }
        .login-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="register-container">
        <div class="logo">🔗 Blockchain Storage</div>)";
    
    if (!errorMessage.empty()) {
        html << "<div class=\"error\">" << errorMessage << "</div>";
    }
    
    html << R"(
        <form id="registerForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirmPassword">Confirm Password</label>
                <input type="password" id="confirmPassword" name="confirmPassword" required>
            </div>
            <button type="submit" class="btn">Create Account</button>
        </form>
        <div class="login-link">
            Already have an account? <a href="/login">Login here</a>
        </div>
    </div>
    <script>
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });
                const result = await response.json();
                if (result.success) {
                    alert('Registration successful! Please login.');
                    window.location.href = '/login';
                } else {
                    alert('Registration failed: ' + result.error);
                }
            } catch (error) {
                alert('Registration error: ' + error.message);
            }
        });
    </script>
</body>
</html>)";
    
    return html.str();
}

std::string WebInterface::generateDashboard(const User& user) {
    std::stringstream html;
    
    html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Storage - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .navbar {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 15px 25px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: white;
        }
        .nav-links {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        .nav-links a, .nav-links button {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background 0.3s;
            border: none;
            background: none;
            cursor: pointer;
            font-size: 14px;
        }
        .nav-links a:hover, .nav-links button:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 15px;
            text-align: center;
        }
        .metric-value {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .metric-label {
            font-size: 14px;
            opacity: 0.9;
        }
        .file-upload-area {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 50px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            margin: 20px 0;
        }
        .file-upload-area:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .file-table th, .file-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e1e5e9;
        }
        .file-table th {
            background: rgba(102, 126, 234, 0.1);
            font-weight: 600;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            margin-right: 5px;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-danger {
            background: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="navbar">
            <div class="logo">🔗 Blockchain Storage</div>
            <div class="nav-links">
                <span>Welcome, )" << user.username << R"(</span>
                <button onclick="logout()">Logout</button>
            </div>
        </nav>
        
        <div class="card">
            <h2>📊 Dashboard</h2>
            <div class="grid">
                <div class="metric-card">
                    <div class="metric-value" id="chainHeight">0</div>
                    <div class="metric-label">Chain Height</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="fileCount">0</div>
                    <div class="metric-label">Your Files</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="storageUsed">)" << formatFileSize(user.storageUsed) << R"(</div>
                    <div class="metric-label">Storage Used</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="peerCount">0</div>
                    <div class="metric-label">Network Peers</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📁 File Upload</h2>
            <div class="file-upload-area" id="uploadArea">
                <div style="font-size: 48px; margin-bottom: 20px;">📤</div>
                <h3>Drop files here or click to upload</h3>
                <p style="color: #666; margin-top: 10px;">Maximum file size: )" << formatFileSize(maxUploadSize_) << R"(</p>
                <input type="file" id="fileInput" style="display: none;" multiple>
            </div>
            
            <div id="uploadProgress" style="display: none;">
                <div style="background: #e1e5e9; border-radius: 10px; overflow: hidden; margin: 10px 0;">
                    <div id="progressBar" style="background: linear-gradient(90deg, #667eea, #764ba2); height: 10px; width: 0%; transition: width 0.3s;"></div>
                </div>
                <div id="uploadStatus">Uploading...</div>
            </div>
        </div>
        
        <div class="card">
            <h2>📂 Your Files</h2>
            <table class="file-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Upload Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="fileList">
                    <!-- Files will be loaded here -->
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            const sessionId = localStorage.getItem('sessionId');
            if (!sessionId) {
                window.location.href = '/login';
                return;
            }
            
            setupFileUpload();
            refreshData();
            setInterval(refreshData, 30000); // Refresh every 30 seconds
        });
        
        // File upload setup and other JavaScript functions...
        function setupFileUpload() {
            const uploadArea = document.getElementById('uploadArea');
            const fileInput = document.getElementById('fileInput');
            
            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.style.background = 'rgba(102, 126, 234, 0.2)';
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.style.background = '';
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.style.background = '';
                handleFiles(e.dataTransfer.files);
            });
            fileInput.addEventListener('change', (e) => {
                handleFiles(e.target.files);
            });
        }
        
        async function handleFiles(files) {
            const sessionId = localStorage.getItem('sessionId');
            const progressDiv = document.getElementById('uploadProgress');
            const progressBar = document.getElementById('progressBar');
            const statusDiv = document.getElementById('uploadStatus');
            
            progressDiv.style.display = 'block';
            
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const formData = new FormData();
                formData.append('file', file);
                
                statusDiv.textContent = 'Uploading ' + file.name + '...';
                
                try {
                    const response = await fetch('/api/files/upload', {
                        method: 'POST',
                        headers: {
                            'Authorization': 'Bearer ' + sessionId
                        },
                        body: formData
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        console.log('File uploaded:', result.fileId);
                    } else {
                        alert('Upload failed: ' + result.error);
                    }
                    
                    const progress = ((i + 1) / files.length) * 100;
                    progressBar.style.width = progress + '%';
                    
                } catch (error) {
                    alert('Upload error: ' + error.message);
                }
            }
            
            statusDiv.textContent = 'Upload complete!';
            setTimeout(() => {
                progressDiv.style.display = 'none';
                progressBar.style.width = '0%';
            }, 2000);
            
            refreshFiles();
        }
        
        async function refreshData() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('chainHeight').textContent = data.chainHeight || 0;
                    document.getElementById('peerCount').textContent = data.peerCount || 0;
                }
            } catch (error) {
                console.error('Failed to refresh status:', error);
            }
        }
        
        async function refreshFiles() {
            const sessionId = localStorage.getItem('sessionId');
            if (!sessionId) return;
            
            try {
                const response = await fetch('/api/files/list', {
                    headers: {
                        'Authorization': 'Bearer ' + sessionId
                    }
                });
                const data = await response.json();
                
                if (data.success) {
                    const fileList = document.getElementById('fileList');
                    fileList.innerHTML = '';
                    
                    document.getElementById('fileCount').textContent = data.files.length;
                    
                    data.files.forEach(file => {
                        const row = document.createElement('tr');
                        row.innerHTML = 
                            '<td>' + file.originalName + '</td>' +
                            '<td>' + formatBytes(file.fileSize) + '</td>' +
                            '<td>' + new Date(file.uploadTime * 1000).toLocaleDateString() + '</td>' +
                            '<td>' +
                                '<button class="btn" onclick="downloadFile(\'' + file.fileId + '\')">Download</button>' +
                                '<button class="btn btn-danger" onclick="deleteFile(\'' + file.fileId + '\')">Delete</button>' +
                            '</td>';
                        fileList.appendChild(row);
                    });
                }
            } catch (error) {
                console.error('Failed to refresh files:', error);
            }
        }
        
        async function downloadFile(fileId) {
            const sessionId = localStorage.getItem('sessionId');
            try {
                const response = await fetch('/api/files/download/' + fileId, {
                    headers: {
                        'Authorization': 'Bearer ' + sessionId
                    }
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = fileId;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                } else {
                    alert('Download failed');
                }
            } catch (error) {
                alert('Download error: ' + error.message);
            }
        }
        
        async function deleteFile(fileId) {
            if (!confirm('Are you sure you want to delete this file?')) return;
            
            const sessionId = localStorage.getItem('sessionId');
            try {
                const response = await fetch('/api/files/' + fileId, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + sessionId
                    }
                });
                
                const result = await response.json();
                if (result.success) {
                    refreshFiles();
                } else {
                    alert('Delete failed: ' + result.error);
                }
            } catch (error) {
                alert('Delete error: ' + error.message);
            }
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function logout() {
            localStorage.removeItem('sessionId');
            window.location.href = '/login';
        }
    </script>
</body>
</html>)";
    
    return html.str();
}

std::string WebInterface::formatFileSize(uint64_t bytes) const {
    if (bytes == 0) return "0 B";
    
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    return oss.str();
}

std::string WebInterface::formatTimestamp(std::time_t timestamp) const {
    return Utils::formatTimestamp(timestamp);
}

// ========================
// ADDITIONAL MISSING METHODS
// ========================

void WebInterface::handleProfile(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    nlohmann::json response;
    response["success"] = true;
    response["user"] = user->toJson();
    sendJSONResponse(res, response);
}

void WebInterface::handleChangePassword(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    try {
        nlohmann::json requestData = nlohmann::json::parse(req.body);
        
        if (!requestData.contains("currentPassword") || !requestData.contains("newPassword")) {
            sendErrorResponse(res, "Current password and new password required");
            return;
        }
        
        std::string currentPassword = requestData["currentPassword"];
        std::string newPassword = requestData["newPassword"];
        
        if (!verifyPassword(currentPassword, user->passwordHash)) {
            sendErrorResponse(res, "Current password is incorrect", 401);
            return;
        }
        
        if (!isValidPassword(newPassword)) {
            sendErrorResponse(res, "New password must be at least 8 characters");
            return;
        }
        
        user->passwordHash = hashPassword(newPassword);
        updateUser(*user);
        
        nlohmann::json response;
        response["success"] = true;
        response["message"] = "Password changed successfully";
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Change password error: {}", e.what());
        sendErrorResponse(res, "Password change failed", 500);
    }
}

void WebInterface::handleFileInfo(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    if (!fileBlockchain_) {
        sendErrorResponse(res, "File blockchain not available", 503);
        return;
    }
    
    try {
        std::string fileId = req.matches[1];
        
        if (!fileBlockchain_->fileExists(fileId)) {
            sendErrorResponse(res, "File not found", 404);
            return;
        }
        
        auto metadata = fileBlockchain_->getFileMetadata(fileId);
        
        nlohmann::json response;
        response["success"] = true;
        response["fileId"] = metadata.fileId;
        response["originalName"] = metadata.originalName;
        response["fileSize"] = metadata.fileSize;
        response["mimeType"] = metadata.mimeType;
        response["uploadTime"] = metadata.uploadTime;
        response["uploaderAddress"] = metadata.uploaderAddress;
        response["isComplete"] = metadata.isComplete;
        response["totalChunks"] = metadata.totalChunks;
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("File info error: {}", e.what());
        sendErrorResponse(res, "Failed to get file info", 500);
    }
}

void WebInterface::handleFileShare(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    try {
        nlohmann::json requestData = nlohmann::json::parse(req.body);
        
        if (!requestData.contains("fileId") || !requestData.contains("targetUser")) {
            sendErrorResponse(res, "File ID and target user required");
            return;
        }
        
        std::string fileId = requestData["fileId"];
        std::string targetUser = requestData["targetUser"];
        
        // For now, just return success (implement actual sharing logic later)
        nlohmann::json response;
        response["success"] = true;
        response["message"] = "File sharing feature coming soon";
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("File share error: {}", e.what());
        sendErrorResponse(res, "File sharing failed", 500);
    }
}

void WebInterface::handleUploadProgress(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    try {
        std::string uploadId = req.get_param_value("uploadId");
        if (uploadId.empty()) {
            sendErrorResponse(res, "Upload ID required");
            return;
        }
        
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        auto it = uploads_.find(uploadId);
        if (it == uploads_.end()) {
            sendErrorResponse(res, "Upload not found", 404);
            return;
        }
        
        nlohmann::json response;
        response["success"] = true;
        response["upload"] = it->second.toJson();
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Upload progress error: {}", e.what());
        sendErrorResponse(res, "Failed to get upload progress", 500);
    }
}

void WebInterface::handleChunkedUpload(const httplib::Request& req, httplib::Response& res) {
    // For now, redirect to regular upload
    handleFileUpload(req, res);
}

void WebInterface::handleUploadCancel(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
    try {
        std::string uploadId = req.get_param_value("uploadId");
        if (uploadId.empty()) {
            sendErrorResponse(res, "Upload ID required");
            return;
        }
        
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        uploads_.erase(uploadId);
        
        nlohmann::json response;
        response["success"] = true;
        response["message"] = "Upload cancelled";
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Upload cancel error: {}", e.what());
        sendErrorResponse(res, "Failed to cancel upload", 500);
    }
}

void WebInterface::handleTransactionExplorer(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        response["transactions"] = nlohmann::json::array();
        
        if (fileBlockchain_) {
            const auto& mempool = fileBlockchain_->getTransactionPool();
            auto transactions = mempool.getTransactions(20); // Get last 20 transactions
            
            for (const auto& tx : transactions) {
                nlohmann::json txJson;
                txJson["id"] = tx.getId();
                txJson["timestamp"] = tx.getTimestamp();
                txJson["inputCount"] = tx.getInputs().size();
                txJson["outputCount"] = tx.getOutputs().size();
                txJson["fee"] = tx.getFee();
                response["transactions"].push_back(txJson);
            }
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Transaction explorer error: {}", e.what());
        sendErrorResponse(res, "Failed to get transaction data", 500);
    }
}

void WebInterface::handleNetworkStatus(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        
        if (p2pNetwork_) {
            response["isRunning"] = p2pNetwork_->isRunning();
            response["peerCount"] = p2pNetwork_->getPeerCount();
            response["nodeId"] = p2pNetwork_->getNodeId();
            response["messagesSent"] = p2pNetwork_->getMessagesSent();
            response["messagesReceived"] = p2pNetwork_->getMessagesReceived();
            response["bytesTransferred"] = p2pNetwork_->getBytesTransferred();
            
            auto peers = p2pNetwork_->getConnectedPeers();
            response["peers"] = nlohmann::json::array();
            for (const auto& peer : peers) {
                response["peers"].push_back(peer.toJson());
            }
        } else {
            response["isRunning"] = false;
            response["peerCount"] = 0;
            response["peers"] = nlohmann::json::array();
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Network status error: {}", e.what());
        sendErrorResponse(res, "Failed to get network status", 500);
    }
}

// ========================
// UTILITY HELPER METHODS
// ========================

User* WebInterface::getUserById(const std::string& userId) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto it = users_.find(userId);
    if (it != users_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

UserSession* WebInterface::getSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

void WebInterface::updateSessionAccess(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.lastAccess = std::time(nullptr);
        it->second.expirationTime = it->second.lastAccess + sessionTimeout_;
    }
}

bool WebInterface::deleteUser(const std::string& userId) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto userIt = users_.find(userId);
    if (userIt != users_.end()) {
        // Remove from username mapping
        usernames_.erase(userIt->second.username);
        users_.erase(userIt);
        return true;
    }
    
    return false;
}

bool WebInterface::validateRequestParameters(const httplib::Request& req, const std::vector<std::string>& required) {
    for (const auto& param : required) {
        if (!req.has_param(param.c_str()) || req.get_param_value(param.c_str()).empty()) {
            return false;
        }
    }
    return true;
}

std::string WebInterface::sanitizeInput(const std::string& input) {
    std::string sanitized = input;
    
    // Remove potentially dangerous characters
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '<'), sanitized.end());
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '>'), sanitized.end());
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '"'), sanitized.end());
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '\''), sanitized.end());
    
    return sanitized;
}

std::string WebInterface::processFileUpload(const httplib::Request& req, const User& user) {
    // This method is already implemented in handleFileUpload
    // Return upload ID for tracking
    return generateUploadId();
}

bool WebInterface::isRequestSecure(const httplib::Request& req) {
    // Check if request is over HTTPS (simplified)
    auto scheme = req.get_header_value("X-Forwarded-Proto");
    return scheme == "https" || req.get_header_value("Host").find("localhost") != std::string::npos;
}

std::string WebInterface::escapeHTML(const std::string& text) {
    std::string escaped = text;
    
    std::string::size_type pos = 0;
    while ((pos = escaped.find("&", pos)) != std::string::npos) {
        escaped.replace(pos, 1, "&amp;");
        pos += 5;
    }
    
    pos = 0;
    while ((pos = escaped.find("<", pos)) != std::string::npos) {
        escaped.replace(pos, 1, "&lt;");
        pos += 4;
    }
    
    pos = 0;
    while ((pos = escaped.find(">", pos)) != std::string::npos) {
        escaped.replace(pos, 1, "&gt;");
        pos += 4;
    }
    
    return escaped;
}

std::string WebInterface::urlEncode(const std::string& text) {
    return Utils::urlEncode(text);
}

std::string WebInterface::generateUploadId() {
    return Crypto::generateRandomString(16);
}

void WebInterface::updateUploadStatus(const std::string& uploadId, const UploadStatus& status) {
    std::lock_guard<std::mutex> lock(uploadsMutex_);
    uploads_[uploadId] = status;
}

bool WebInterface::checkRateLimit(const std::string& ipAddress) {
    // Simple rate limiting - could be enhanced with actual rate tracking
    return true;
}

void WebInterface::loadConfiguration() {
    try {
        if (Utils::fileExists("web_config.json")) {
            nlohmann::json config = Utils::readJsonFile("web_config.json");
            if (config.contains("maxUploadSize")) {
                maxUploadSize_ = config["maxUploadSize"];
            }
            if (config.contains("sessionTimeout")) {
                sessionTimeout_ = config["sessionTimeout"];
            }
            if (config.contains("registrationEnabled")) {
                registrationEnabled_ = config["registrationEnabled"];
            }
            spdlog::debug("Web configuration loaded");
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to load web configuration: {}", e.what());
    }
}

void WebInterface::saveConfiguration() {
    try {
        nlohmann::json config;
        config["maxUploadSize"] = maxUploadSize_;
        config["sessionTimeout"] = sessionTimeout_;
        config["registrationEnabled"] = registrationEnabled_;
        
        Utils::writeJsonFile("web_config.json", config);
        spdlog::debug("Web configuration saved");
    } catch (const std::exception& e) {
        spdlog::error("Failed to save web configuration: {}", e.what());
    }
}