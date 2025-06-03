#ifndef HTTPLIB_IMPLEMENTATION
#define HTTPLIB_IMPLEMENTATION
#endif

#pragma once

#include <third_party/httplib.h>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <third_party/nlohmann/json.hpp> 
#include "../blockchain/Blockchain.h"
#include "../p2p/P2PNetwork.h"

class RestApiServer {
public:
    // Constructor
    RestApiServer(uint16_t port = 8080);
    
    // Destructor
    ~RestApiServer();
    
    // Server lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    
    // Set blockchain and network references
    void setBlockchain(std::shared_ptr<Blockchain> blockchain);
    void setP2PNetwork(std::shared_ptr<P2PNetwork> network);
    
    // Configuration
    void setPort(uint16_t port) { port_ = port; }
    uint16_t getPort() const { return port_; }
    void enableCORS(bool enable) { corsEnabled_ = enable; }
    
    // Statistics
    uint64_t getRequestCount() const { return requestCount_; }

private:
    uint16_t port_;
    std::atomic<bool> running_;
    std::atomic<uint64_t> requestCount_;
    bool corsEnabled_;
    
    std::unique_ptr<httplib::Server> server_;
    std::shared_ptr<Blockchain> blockchain_;
    std::shared_ptr<P2PNetwork> p2pNetwork_;
    std::thread serverThread_;
    
    // Route handlers
    void setupRoutes();
    
    // Blockchain endpoints
    void handleGetBlockchain(const httplib::Request& req, httplib::Response& res);
    void handleGetBlock(const httplib::Request& req, httplib::Response& res);
    void handleGetBlockByHash(const httplib::Request& req, httplib::Response& res);
    void handleGetLatestBlock(const httplib::Request& req, httplib::Response& res);
    
    // Transaction endpoints
    void handleGetTransactions(const httplib::Request& req, httplib::Response& res);
    void handleGetTransaction(const httplib::Request& req, httplib::Response& res);
    void handleCreateTransaction(const httplib::Request& req, httplib::Response& res);
    void handleGetMempool(const httplib::Request& req, httplib::Response& res);
    
    // Mining endpoints
    void handleMineBlock(const httplib::Request& req, httplib::Response& res);
    void handleGetDifficulty(const httplib::Request& req, httplib::Response& res);
    
    // Network endpoints
    void handleGetPeers(const httplib::Request& req, httplib::Response& res);
    void handleGetNetworkStatus(const httplib::Request& req, httplib::Response& res);
    void handleConnectToPeer(const httplib::Request& req, httplib::Response& res);
    
    // Node endpoints
    void handleGetNodeStatus(const httplib::Request& req, httplib::Response& res);
    void handleGetNodeInfo(const httplib::Request& req, httplib::Response& res);
    void handleGetStatistics(const httplib::Request& req, httplib::Response& res);
    
    // Wallet endpoints
    void handleGetBalance(const httplib::Request& req, httplib::Response& res);
    void handleGenerateAddress(const httplib::Request& req, httplib::Response& res);
    
    // Utility functions
    void setErrorResponse(httplib::Response& res, int code, const std::string& message);
    void setSuccessResponse(httplib::Response& res, const nlohmann::json& data);
    void addCORSHeaders(httplib::Response& res);
    void logRequest(const httplib::Request& req);
    bool validateJsonRequest(const httplib::Request& req, nlohmann::json& json);
    
    // Input validation
    bool isValidAddress(const std::string& address);
    bool isValidAmount(double amount);
    bool isValidBlockIndex(const std::string& indexStr, uint32_t& index);
};