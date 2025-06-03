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
    
    spdlog::info("WebInterface initialized on port {} (API + Static Files)", port_);
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
            server_->set_read_timeout(30, 0);
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
    // Enable CORS for all requests
    server_->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    
    // Handle CORS preflight requests
    server_->Options(".*", [](const httplib::Request& /*req*/, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.status = 200;
    });
    
    // Serve static files (your working index.html)
    server_->set_mount_point("/", staticFilesPath_);
    
    // ========================
    // AUTHENTICATION API
    // ========================
    
    server_->Post("/api/auth/login", [this](const httplib::Request& req, httplib::Response& res) {
        handleLogin(req, res);
    });
    
    server_->Post("/api/auth/logout", [this](const httplib::Request& req, httplib::Response& res) {
        handleLogout(req, res);
    });
    
    server_->Post("/api/auth/register", [this](const httplib::Request& req, httplib::Response& res) {
        handleRegister(req, res);
    });
    
    server_->Get("/api/auth/profile", [this](const httplib::Request& req, httplib::Response& res) {
        handleProfile(req, res);
    });
    
    server_->Post("/api/auth/change-password", [this](const httplib::Request& req, httplib::Response& res) {
        handleChangePassword(req, res);
    });
    
    // ========================
    // FILE MANAGEMENT API
    // ========================
    
    server_->Post("/api/files/upload", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileUpload(req, res);
    });
    
    server_->Post("/api/files/upload/chunked", [this](const httplib::Request& req, httplib::Response& res) {
        handleChunkedUpload(req, res);
    });
    
    server_->Get("/api/files/upload/progress", [this](const httplib::Request& req, httplib::Response& res) {
        handleUploadProgress(req, res);
    });
    
    server_->Delete("/api/files/upload", [this](const httplib::Request& req, httplib::Response& res) {
        handleUploadCancel(req, res);
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
    
    server_->Get(R"(/api/files/info/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileInfo(req, res);
    });
    
    server_->Post("/api/files/share", [this](const httplib::Request& req, httplib::Response& res) {
        handleFileShare(req, res);
    });
    
    // ========================
    // BLOCKCHAIN API
    // ========================
    
    server_->Get("/api/status", [this](const httplib::Request& req, httplib::Response& res) {
        handleBlockchainStatus(req, res);
    });
    
    server_->Get("/api/blockchain", [this](const httplib::Request& req, httplib::Response& res) {
        handleBlockExplorer(req, res);
    });
    
    server_->Get("/api/blockchain/search", [this](const httplib::Request& req, httplib::Response& res) {
        handleBlockchainSearch(req, res);
    });
    
    server_->Get("/api/transactions", [this](const httplib::Request& req, httplib::Response& res) {
        handleTransactionExplorer(req, res);
    });
    
    // ========================
    // NETWORK API
    // ========================
    
    server_->Get("/api/network/status", [this](const httplib::Request& req, httplib::Response& res) {
        handleNetworkStatus(req, res);
    });
    
    // ========================
    // SECURITY API
    // ========================
    
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
    
    server_->Post("/api/security/reorder", [this](const httplib::Request& req, httplib::Response& res) {
        User* user = getAuthenticatedUser(req);
        if (!user) {
            sendErrorResponse(res, "Authentication required", 401);
            return;
        }
        
        if (securityManager_) {
            nlohmann::json requestData;
            try {
                requestData = nlohmann::json::parse(req.body);
            } catch (...) {
                requestData = nlohmann::json::object();
            }
            
            std::string reason = requestData.value("reason", "Manual web interface trigger");
            securityManager_->triggerPolymorphicReorder(reason);
            
            nlohmann::json response;
            response["success"] = true;
            response["message"] = "Polymorphic reorder initiated";
            sendJSONResponse(res, response);
        } else {
            sendErrorResponse(res, "Security manager not available", 503);
        }
    });
    
    server_->Get("/api/security/alerts", [this](const httplib::Request& req, httplib::Response& res) {
        if (securityManager_) {
            auto threats = securityManager_->getActiveThreats();
            nlohmann::json response;
            response["success"] = true;
            response["alerts"] = nlohmann::json::array();
            
            for (const auto& threat : threats) {
                nlohmann::json alertJson;
                alertJson["event"] = static_cast<int>(threat.event);
                alertJson["level"] = static_cast<int>(threat.level);
                alertJson["blockIndex"] = threat.blockIndex;
                alertJson["description"] = threat.description;
                alertJson["timestamp"] = threat.timestamp;
                response["alerts"].push_back(alertJson);
            }
            
            sendJSONResponse(res, response);
        } else {
            sendErrorResponse(res, "Security manager not available", 503);
        }
    });
    
    spdlog::debug("WebInterface routes configured - API endpoints + static file serving");
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
        // Check if request has multipart data
        if (req.is_multipart_form_data()) {
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
            
            // Convert to binary data
            std::vector<uint8_t> fileData(file.content.begin(), file.content.end());
            
            // Upload to blockchain
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
                spdlog::debug("File metadata broadcasted to {} peers", p2pNetwork_->getPeerCount());
            }
            
            nlohmann::json response;
            response["success"] = true;
            response["fileId"] = fileId;
            response["filename"] = file.filename;
            response["size"] = file.content.size();
            response["message"] = "File uploaded successfully";
            
            logSecurityEvent("File uploaded", user->userId, req.get_header_value("X-Real-IP"));
            sendJSONResponse(res, response);
            
        } else {
            sendErrorResponse(res, "Invalid multipart form data");
        }
        
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
            fileJson["isComplete"] = file.isComplete;
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
        
        auto metadata = fileBlockchain_->getFileMetadata(fileId);
        if (metadata.uploaderAddress != user->walletAddress) {
            sendErrorResponse(res, "Access denied", 403);
            return;
        }
        
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
        response["fileHash"] = metadata.fileHash;
        
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
    
    nlohmann::json response;
    response["success"] = true;
    response["message"] = "File sharing feature coming soon";
    sendJSONResponse(res, response);
}

// ========================
// UPLOAD MANAGEMENT HANDLERS
// ========================

void WebInterface::handleChunkedUpload(const httplib::Request& req, httplib::Response& res) {
    // For now, redirect to regular upload
    handleFileUpload(req, res);
}

void WebInterface::handleUploadProgress(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
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
}

void WebInterface::handleUploadCancel(const httplib::Request& req, httplib::Response& res) {
    User* user = getAuthenticatedUser(req);
    if (!user) {
        sendErrorResponse(res, "Authentication required", 401);
        return;
    }
    
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
            response["difficulty"] = fileBlockchain_->getDifficulty();
            response["averageBlockTime"] = fileBlockchain_->getAverageBlockTime();
        }
        
        if (p2pNetwork_) {
            response["peerCount"] = p2pNetwork_->getPeerCount();
            response["networkRunning"] = p2pNetwork_->isRunning();
            response["nodeId"] = p2pNetwork_->getNodeId();
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

void WebInterface::handleBlockExplorer(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        response["blocks"] = nlohmann::json::array();
        
        if (fileBlockchain_) {
            const auto& chain = fileBlockchain_->getChain();
            
            // Return last 20 blocks
            size_t startIndex = chain.size() > 20 ? chain.size() - 20 : 0;
            for (size_t i = startIndex; i < chain.size(); ++i) {
                nlohmann::json blockJson;
                blockJson["index"] = chain[i].getIndex();
                blockJson["hash"] = chain[i].getHash();
                blockJson["previousHash"] = chain[i].getPreviousHash();
                blockJson["timestamp"] = chain[i].getTimestamp();
                blockJson["transactionCount"] = chain[i].getTransactions().size();
                blockJson["nonce"] = chain[i].getNonce();
                blockJson["merkleRoot"] = chain[i].getMerkleRoot();
                response["blocks"].push_back(blockJson);
            }
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Block explorer error: {}", e.what());
        sendErrorResponse(res, "Failed to get blockchain data", 500);
    }
}

void WebInterface::handleBlockchainSearch(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string query = req.get_param_value("q");
        if (query.empty()) {
            sendErrorResponse(res, "Search query required");
            return;
        }
        
        nlohmann::json response;
        response["success"] = true;
        response["results"] = nlohmann::json::array();
        
        if (fileBlockchain_) {
            // Search blocks by index or hash
            if (std::isdigit(query[0])) {
                try {
                    uint32_t blockIndex = std::stoul(query);
                    if (blockIndex < fileBlockchain_->getChainHeight()) {
                        auto block = fileBlockchain_->getBlock(blockIndex);
                        nlohmann::json result;
                        result["type"] = "block";
                        result["data"] = nlohmann::json::object();
                        result["data"]["index"] = block.getIndex();
                        result["data"]["hash"] = block.getHash();
                        result["data"]["previousHash"] = block.getPreviousHash();
                        result["data"]["timestamp"] = block.getTimestamp();
                        result["data"]["transactionCount"] = block.getTransactions().size();
                        result["data"]["nonce"] = block.getNonce();
                        result["data"]["merkleRoot"] = block.getMerkleRoot();
                        response["results"].push_back(result);
                    }
                } catch (const std::exception& e) {
                    // If not a valid number or block not found, continue with other searches
                    spdlog::debug("Block search failed for query '{}': {}", query, e.what());
                }
            }
            
            // Search blocks by hash if query looks like a hash (hexadecimal, 64 chars for SHA256)
            if (query.length() == 64 && std::all_of(query.begin(), query.end(), ::isxdigit)) {
                try {
                    auto block = fileBlockchain_->getBlockByHash(query);
                    if (!block.getHash().empty()) {
                        nlohmann::json result;
                        result["type"] = "block";
                        result["data"] = nlohmann::json::object();
                        result["data"]["index"] = block.getIndex();
                        result["data"]["hash"] = block.getHash();
                        result["data"]["previousHash"] = block.getPreviousHash();
                        result["data"]["timestamp"] = block.getTimestamp();
                        result["data"]["transactionCount"] = block.getTransactions().size();
                        result["data"]["nonce"] = block.getNonce();
                        result["data"]["merkleRoot"] = block.getMerkleRoot();
                        response["results"].push_back(result);
                    }
                } catch (const std::exception& e) {
                    spdlog::debug("Block hash search failed for query '{}': {}", query, e.what());
                }
            }
            
            // Search files by name or ID (only if we didn't find a block)
            if (response["results"].empty()) {
                try {
                    auto files = fileBlockchain_->searchFiles(query);
                    for (const auto& file : files) {
                        nlohmann::json result;
                        result["type"] = "file";
                        result["data"] = nlohmann::json::object();
                        result["data"]["fileId"] = file.fileId;
                        result["data"]["originalName"] = file.originalName;
                        result["data"]["fileSize"] = file.fileSize;
                        result["data"]["mimeType"] = file.mimeType;
                        result["data"]["uploadTime"] = file.uploadTime;
                        result["data"]["uploaderAddress"] = file.uploaderAddress;
                        result["data"]["isComplete"] = file.isComplete;
                        result["data"]["totalChunks"] = file.totalChunks;
                        result["data"]["fileHash"] = file.fileHash;
                        response["results"].push_back(result);
                    }
                } catch (const std::exception& e) {
                    spdlog::debug("File search failed for query '{}': {}", query, e.what());
                }
            }
            
            // Search by file ID directly if it looks like one (32 hex characters)
            if (query.length() == 32 && std::all_of(query.begin(), query.end(), ::isxdigit)) {
                try {
                    if (fileBlockchain_->fileExists(query)) {
                        auto metadata = fileBlockchain_->getFileMetadata(query);
                        nlohmann::json result;
                        result["type"] = "file";
                        result["data"] = nlohmann::json::object();
                        result["data"]["fileId"] = metadata.fileId;
                        result["data"]["originalName"] = metadata.originalName;
                        result["data"]["fileSize"] = metadata.fileSize;
                        result["data"]["mimeType"] = metadata.mimeType;
                        result["data"]["uploadTime"] = metadata.uploadTime;
                        result["data"]["uploaderAddress"] = metadata.uploaderAddress;
                        result["data"]["isComplete"] = metadata.isComplete;
                        result["data"]["totalChunks"] = metadata.totalChunks;
                        result["data"]["fileHash"] = metadata.fileHash;
                        response["results"].push_back(result);
                    }
                } catch (const std::exception& e) {
                    spdlog::debug("File ID search failed for query '{}': {}", query, e.what());
                }
            }
            
            // Search transactions in mempool by ID
            if (query.length() == 64 && std::all_of(query.begin(), query.end(), ::isxdigit)) {
                try {
                    const auto& mempool = fileBlockchain_->getTransactionPool();
                    auto transaction = mempool.getTransaction(query);
                    if (!transaction.getId().empty()) {
                        nlohmann::json result;
                        result["type"] = "transaction";
                        result["data"] = nlohmann::json::object();
                        result["data"]["id"] = transaction.getId();
                        result["data"]["timestamp"] = transaction.getTimestamp();
                        result["data"]["inputCount"] = transaction.getInputs().size();
                        result["data"]["outputCount"] = transaction.getOutputs().size();
                        result["data"]["totalInputAmount"] = transaction.getTotalInputAmount();
                        result["data"]["totalOutputAmount"] = transaction.getTotalOutputAmount();
                        result["data"]["fee"] = transaction.getFee();
                        response["results"].push_back(result);
                    }
                } catch (const std::exception& e) {
                    spdlog::debug("Transaction search failed for query '{}': {}", query, e.what());
                }
            }
        }
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Blockchain search error: {}", e.what());
        sendErrorResponse(res, "Search failed", 500);
    }
}
void WebInterface::handleTransactionExplorer(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["success"] = true;
        response["transactions"] = nlohmann::json::array();
        
        if (fileBlockchain_) {
            const auto& mempool = fileBlockchain_->getTransactionPool();
            auto transactions = mempool.getTransactions(50); // Get last 50 transactions
            
            for (const auto& tx : transactions) {
                nlohmann::json txJson;
                txJson["id"] = tx.getId();
                txJson["timestamp"] = tx.getTimestamp();
                txJson["inputCount"] = tx.getInputs().size();
                txJson["outputCount"] = tx.getOutputs().size();
                txJson["fee"] = tx.getFee();
                txJson["totalInputAmount"] = tx.getTotalInputAmount();
                txJson["totalOutputAmount"] = tx.getTotalOutputAmount();
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
                nlohmann::json peerJson;
                peerJson["peerId"] = peer.peerId;
                peerJson["ipAddress"] = peer.ipAddress;
                peerJson["port"] = peer.port;
                peerJson["chainHeight"] = peer.chainHeight;
                peerJson["lastSeen"] = peer.lastSeen;
                peerJson["isConnected"] = peer.isConnected;
                response["peers"].push_back(peerJson);
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
        response["lastSecurityScan"] = securityManager_->getLastSecurityScan();
        
        sendJSONResponse(res, response);
        
    } catch (const std::exception& e) {
        spdlog::error("Security status error: {}", e.what());
        sendErrorResponse(res, "Failed to get security status", 500);
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

User* WebInterface::getUserById(const std::string& userId) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto it = users_.find(userId);
    if (it != users_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

bool WebInterface::updateUser(const User& user) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    users_[user.userId] = user;
    return true;
}

bool WebInterface::deleteUser(const std::string& userId) {
    std::lock_guard<std::mutex> lock(usersMutex_);
    
    auto userIt = users_.find(userId);
    if (userIt != users_.end()) {
        usernames_.erase(userIt->second.username);
        users_.erase(userIt);
        return true;
    }
    
    return false;
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

void WebInterface::invalidateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    sessions_.erase(sessionId);
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
    res.set_header("Access-Control-Allow-Origin", "*");
    res.body = json.dump();
}

void WebInterface::sendErrorResponse(httplib::Response& res, const std::string& error, int status) {
    nlohmann::json response;
    response["success"] = false;
    response["error"] = error;
    response["timestamp"] = std::time(nullptr);
    sendJSONResponse(res, response, status);
}

void WebInterface::sendFileResponse(httplib::Response& res, const std::vector<uint8_t>& data, 
                                   const std::string& filename, const std::string& mimeType) {
    res.status = 200;
    res.set_header("Content-Type", mimeType.empty() ? "application/octet-stream" : mimeType);
    res.set_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    res.set_header("Access-Control-Allow-Origin", "*");
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

std::string WebInterface::generateUploadId() {
    return Crypto::generateRandomString(16);
}

void WebInterface::updateUploadStatus(const std::string& uploadId, const UploadStatus& status) {
    std::lock_guard<std::mutex> lock(uploadsMutex_);
    uploads_[uploadId] = status;
    
    // Clean up old uploads (older than 1 hour)
    std::time_t now = std::time(nullptr);
    auto it = uploads_.begin();
    while (it != uploads_.end()) {
        if (now - it->second.lastUpdate > 3600) { // 1 hour
            it = uploads_.erase(it);
        } else {
            ++it;
        }
    }
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
        spdlog::warn("File validation failed: empty filename or zero size");
        return false;
    }
    
    if (fileSize > maxUploadSize_) {
        spdlog::warn("File validation failed: size {} exceeds limit {}", fileSize, maxUploadSize_);
        return false;
    }
    
    // Check filename length
    if (filename.length() > 255) {
        spdlog::warn("File validation failed: filename too long");
        return false;
    }
    
    // Check for dangerous file extensions
    std::vector<std::string> dangerousExtensions = {
        ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".msi", ".dll",
        ".vbs", ".js", ".jar", ".app", ".deb", ".rpm", ".dmg", ".pkg"
    };
    
    std::string lowerFilename = filename;
    std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);
    
    for (const auto& ext : dangerousExtensions) {
        if (lowerFilename.length() >= ext.length() &&
            lowerFilename.compare(lowerFilename.length() - ext.length(), ext.length(), ext) == 0) {
            spdlog::warn("File validation failed: dangerous extension {}", ext);
            return false;
        }
    }
    
    // Check for null bytes and path traversal
    if (filename.find('\0') != std::string::npos ||
        filename.find("..") != std::string::npos ||
        filename.find("/") != std::string::npos ||
        filename.find("\\") != std::string::npos) {
        spdlog::warn("File validation failed: security check");
        return false;
    }
    
    return true;
}

void WebInterface::logSecurityEvent(const std::string& event, const std::string& userId, const std::string& ipAddress) {
    spdlog::info("Security Event: {} | User: {} | IP: {}", event, userId, ipAddress);
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