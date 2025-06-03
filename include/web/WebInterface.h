#pragma once

#include <memory>
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "../blockchain/Blockchain.h"
#include "../p2p/P2PNetwork.h"
#include "../blockchain/FileBlockchain.h"
#include "../security/SecurityManager.h"

// User authentication structure
struct User {
    std::string userId;
    std::string username;
    std::string passwordHash;
    std::string email;
    std::string walletAddress;
    std::time_t registrationTime;
    std::time_t lastLogin;
    bool isActive;
    nlohmann::json permissions;
    uint64_t storageQuota;
    uint64_t storageUsed;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// Session management
struct UserSession {
    std::string sessionId;
    std::string userId;
    std::time_t creationTime;
    std::time_t lastAccess;
    std::time_t expirationTime;
    std::string ipAddress;
    bool isValid;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// File upload status
struct UploadStatus {
    std::string uploadId;
    std::string fileId;
    std::string filename;
    uint64_t totalSize;
    uint64_t uploadedSize;
    double percentage;
    std::string status; // "uploading", "completed", "failed", "cancelled"
    std::time_t startTime;
    std::time_t lastUpdate;
    
    nlohmann::json toJson() const;
};

class WebInterface {
public:
    // Constructor
    WebInterface(uint16_t port = 8080);
    
    // Destructor
    ~WebInterface();
    
    // Server lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    
    // Component setup
    void setFileBlockchain(std::shared_ptr<FileBlockchain> blockchain);
    void setP2PNetwork(std::shared_ptr<P2PNetwork> network);
    void setSecurityManager(std::shared_ptr<SecurityManager> securityManager);
    
    // Configuration
    void setPort(uint16_t port) { port_ = port; }
    void setMaxUploadSize(uint64_t maxSize) { maxUploadSize_ = maxSize; }
    void setSessionTimeout(uint32_t timeoutSeconds) { sessionTimeout_ = timeoutSeconds; }
    void enableRegistration(bool enable) { registrationEnabled_ = enable; }

private:
    // Server components
    uint16_t port_;
    std::unique_ptr<httplib::Server> server_;
    std::atomic<bool> running_;
    std::thread serverThread_;
    
    // Core components
    std::shared_ptr<FileBlockchain> fileBlockchain_;
    std::shared_ptr<P2PNetwork> p2pNetwork_;
    std::shared_ptr<SecurityManager> securityManager_;
    
    // User management
    std::unordered_map<std::string, User> users_;           // userId -> User
    std::unordered_map<std::string, std::string> usernames_; // username -> userId
    std::unordered_map<std::string, UserSession> sessions_; // sessionId -> Session
    std::unordered_map<std::string, UploadStatus> uploads_; // uploadId -> Status
    mutable std::mutex usersMutex_;
    mutable std::mutex sessionsMutex_;
    mutable std::mutex uploadsMutex_;
    
    // Configuration
    uint64_t maxUploadSize_;
    uint32_t sessionTimeout_;
    bool registrationEnabled_;
    std::string staticFilesPath_;
    
    // Setup functions
    void setupRoutes();
    void setupStaticFiles();
    void loadUsers();
    void saveUsers();
    
    // ========================
    // AUTHENTICATION ROUTES
    // ========================
    
    void handleLogin(const httplib::Request& req, httplib::Response& res);
    void handleLogout(const httplib::Request& req, httplib::Response& res);
    void handleRegister(const httplib::Request& req, httplib::Response& res);
    void handleProfile(const httplib::Request& req, httplib::Response& res);
    void handleChangePassword(const httplib::Request& req, httplib::Response& res);
    
    // ========================
    // FILE MANAGEMENT ROUTES
    // ========================
    
    void handleFileUpload(const httplib::Request& req, httplib::Response& res);
    void handleFileDownload(const httplib::Request& req, httplib::Response& res);
    void handleFileList(const httplib::Request& req, httplib::Response& res);
    void handleFileDelete(const httplib::Request& req, httplib::Response& res);
    void handleFileInfo(const httplib::Request& req, httplib::Response& res);
    void handleFileShare(const httplib::Request& req, httplib::Response& res);
    
    // Upload progress and chunked uploads
    void handleUploadProgress(const httplib::Request& req, httplib::Response& res);
    void handleChunkedUpload(const httplib::Request& req, httplib::Response& res);
    void handleUploadCancel(const httplib::Request& req, httplib::Response& res);
    
    // ========================
    // BLOCKCHAIN EXPLORER ROUTES
    // ========================
    
    void handleBlockchainStatus(const httplib::Request& req, httplib::Response& res);
    void handleBlockExplorer(const httplib::Request& req, httplib::Response& res);
    void handleBlockchainSearch(const httplib::Request& req, httplib::Response& res);  // ADDED
    void handleTransactionExplorer(const httplib::Request& req, httplib::Response& res);
    void handleNetworkStatus(const httplib::Request& req, httplib::Response& res);
    void handleSecurityStatus(const httplib::Request& req, httplib::Response& res);
    
    // ========================
    // STATIC PAGE ROUTES
    // ========================
    
    void handleHomePage(const httplib::Request& req, httplib::Response& res);
    void handleLoginPage(const httplib::Request& req, httplib::Response& res);
    void handleRegisterPage(const httplib::Request& req, httplib::Response& res);
    void handleDashboard(const httplib::Request& req, httplib::Response& res);
    void handleFileManager(const httplib::Request& req, httplib::Response& res);
    void handleBlockchainExplorer(const httplib::Request& req, httplib::Response& res);
    void handleSecurityPanel(const httplib::Request& req, httplib::Response& res);
    
    // ========================
    // USER MANAGEMENT
    // ========================
    
    // User operations
    std::string createUser(const std::string& username, const std::string& password, 
                          const std::string& email);
    bool authenticateUser(const std::string& username, const std::string& password);
    User* getUserById(const std::string& userId);
    User* getUserByUsername(const std::string& username);
    bool updateUser(const User& user);
    bool deleteUser(const std::string& userId);
    
    // Password management
    std::string hashPassword(const std::string& password, const std::string& salt = "");
    std::string generateSalt();
    bool verifyPassword(const std::string& password, const std::string& hash);
    
    // ========================
    // SESSION MANAGEMENT
    // ========================
    
    // Session operations
    std::string createSession(const std::string& userId, const std::string& ipAddress);
    bool validateSession(const std::string& sessionId);
    UserSession* getSession(const std::string& sessionId);
    void updateSessionAccess(const std::string& sessionId);
    void invalidateSession(const std::string& sessionId);
    void cleanupExpiredSessions();
    
    // Session utilities
    std::string generateSessionId();
    std::string extractSessionFromRequest(const httplib::Request& req);
    User* getAuthenticatedUser(const httplib::Request& req);
    
    // ========================
    // HTML GENERATION
    // ========================
    
    // Page templates
    std::string generateLoginPage(const std::string& errorMessage = "");
    std::string generateRegisterPage(const std::string& errorMessage = "");
    std::string generateDashboard(const User& user);
    std::string generateFileManager(const User& user);
    std::string generateBlockchainExplorer();
    std::string generateSecurityPanel();
    
    // HTML components
    std::string generateHeader(const std::string& title, bool includeAuth = true);
    std::string generateFooter();
    std::string generateNavigation(const User* user = nullptr);
    std::string generateFileTable(const std::vector<FileMetadata>& files);
    std::string generateBlockTable(const std::vector<Block>& blocks);
    std::string generateSecurityAlerts(const std::vector<SecurityViolation>& violations);
    
    // ========================
    // JAVASCRIPT GENERATION
    // ========================
    
    std::string generateFileUploadJS();
    std::string generateBlockchainExplorerJS();
    std::string generateSecurityMonitorJS();
    std::string generateDashboardJS();
    
    // ========================
    // CSS GENERATION
    // ========================
    
    std::string generateMainCSS();
    std::string generateFileManagerCSS();
    std::string generateBlockchainExplorerCSS();
    
    // ========================
    // UTILITY FUNCTIONS
    // ========================
    
    // Response helpers
    void sendJSONResponse(httplib::Response& res, const nlohmann::json& json, int status = 200);
    void sendErrorResponse(httplib::Response& res, const std::string& error, int status = 400);
    void sendHTMLResponse(httplib::Response& res, const std::string& html);
    void sendFileResponse(httplib::Response& res, const std::vector<uint8_t>& data, 
                         const std::string& filename, const std::string& mimeType);
    
    // Request validation
    bool validateRequestParameters(const httplib::Request& req, const std::vector<std::string>& required);
    std::string sanitizeInput(const std::string& input);
    bool isValidEmail(const std::string& email);
    bool isValidUsername(const std::string& username);
    bool isValidPassword(const std::string& password);
    
    // File upload helpers
    std::string processFileUpload(const httplib::Request& req, const User& user);
    bool validateUploadedFile(const std::string& filename, uint64_t fileSize);
    std::string generateUploadId();
    void updateUploadStatus(const std::string& uploadId, const UploadStatus& status);
    
    // Security helpers
    bool isRequestSecure(const httplib::Request& req);
    void logSecurityEvent(const std::string& event, const std::string& userId, 
                         const std::string& ipAddress);
    bool checkRateLimit(const std::string& ipAddress);
    
    // Formatting helpers
    std::string formatFileSize(uint64_t bytes);
    std::string formatTimestamp(std::time_t timestamp);
    std::string escapeHTML(const std::string& text);
    std::string urlEncode(const std::string& text);
    
    // Configuration helpers
    void loadConfiguration();
    void saveConfiguration();
    
    // Constants
    static constexpr uint32_t DEFAULT_SESSION_TIMEOUT = 3600; // 1 hour
    static constexpr uint64_t DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB
    static constexpr size_t MAX_USERNAME_LENGTH = 50;
    static constexpr size_t MIN_PASSWORD_LENGTH = 8;
};