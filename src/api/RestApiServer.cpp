#ifndef HTTPLIB_IMPLEMENTATION
#define HTTPLIB_IMPLEMENTATION
#endif
#include "api/RestApiServer.h"
#include "utils/Crypto.h"
#include <spdlog/spdlog.h>
#include <regex>

RestApiServer::RestApiServer(uint16_t port)
    : port_(port), running_(false), requestCount_(0), corsEnabled_(true) {
    
    server_ = std::make_unique<httplib::Server>();
    setupRoutes();
    
    spdlog::info("REST API Server initialized on port {}", port_);
}

RestApiServer::~RestApiServer() {
    stop();
}

bool RestApiServer::start() {
    if (running_) {
        spdlog::warn("REST API Server is already running");
        return false;
    }
    
    if (!blockchain_) {
        spdlog::error("Cannot start REST API Server without blockchain reference");
        return false;
    }
    
    try {
        serverThread_ = std::thread([this]() {
            running_ = true;
            spdlog::info("Starting REST API Server on port {}", port_);
            
            // Set server configuration
            server_->set_read_timeout(5, 0); // 5 seconds
            server_->set_write_timeout(5, 0);
            
            // Start listening
            bool success = server_->listen("0.0.0.0", port_);
            if (!success) {
                spdlog::error("Failed to start HTTP server on port {}", port_);
                running_ = false;
            }
        });
        
        // Give the server a moment to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (running_) {
            spdlog::info("REST API Server started successfully");
            return true;
        }
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to start REST API Server: {}", e.what());
        running_ = false;
        return false;
    }
    
    return false;
}

void RestApiServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    try {
        server_->stop();
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
        spdlog::info("REST API Server stopped");
    } catch (const std::exception& e) {
        spdlog::error("Error stopping REST API Server: {}", e.what());
    }
}

void RestApiServer::setBlockchain(std::shared_ptr<Blockchain> blockchain) {
    blockchain_ = blockchain;
    spdlog::debug("Blockchain reference set for REST API Server");
}

void RestApiServer::setP2PNetwork(std::shared_ptr<P2PNetwork> network) {
    p2pNetwork_ = network;
    spdlog::debug("P2P Network reference set for REST API Server");
}

void RestApiServer::setupRoutes() {
    // CORS preflight handler
    server_->Options(".*", [this](const httplib::Request& req, httplib::Response& res) {
        addCORSHeaders(res);
        res.status = 200;
    });
    
    // Blockchain endpoints
    server_->Get("/api/blockchain", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetBlockchain(req, res);
    });
    
    server_->Get(R"(/api/block/(\d+))", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetBlock(req, res);
    });
    
    server_->Get(R"(/api/block/hash/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetBlockByHash(req, res);
    });
    
    server_->Get("/api/block/latest", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetLatestBlock(req, res);
    });
    
    // Transaction endpoints
    server_->Get("/api/transactions", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetTransactions(req, res);
    });
    
    server_->Post("/api/transactions", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleCreateTransaction(req, res);
    });
    
    server_->Get(R"(/api/transaction/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetTransaction(req, res);
    });
    
    server_->Get("/api/mempool", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetMempool(req, res);
    });
    
    // Mining endpoints
    server_->Post("/api/mine", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleMineBlock(req, res);
    });
    
    server_->Get("/api/difficulty", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetDifficulty(req, res);
    });
    
    // Network endpoints
    server_->Get("/api/peers", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetPeers(req, res);
    });
    
    server_->Get("/api/network/status", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetNetworkStatus(req, res);
    });
    
    server_->Post("/api/network/connect", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleConnectToPeer(req, res);
    });
    
    // Node endpoints
    server_->Get("/api/status", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetNodeStatus(req, res);
    });
    
    server_->Get("/api/info", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetNodeInfo(req, res);
    });
    
    server_->Get("/api/statistics", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetStatistics(req, res);
    });
    
    // Wallet endpoints
    server_->Get(R"(/api/balance/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGetBalance(req, res);
    });
    
    server_->Get("/api/address/generate", [this](const httplib::Request& req, httplib::Response& res) {
        logRequest(req);
        handleGenerateAddress(req, res);
    });
    
    spdlog::debug("API routes configured");
}

void RestApiServer::handleGetBlockchain(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["chain"] = blockchain_->toJson()["chain"];
        response["length"] = blockchain_->getChainHeight();
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get blockchain: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetBlock(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string indexStr = req.matches[1];
        uint32_t index;
        
        if (!isValidBlockIndex(indexStr, index)) {
            setErrorResponse(res, 400, "Invalid block index");
            return;
        }
        
        if (index >= blockchain_->getChainHeight()) {
            setErrorResponse(res, 404, "Block not found");
            return;
        }
        
        Block block = blockchain_->getBlock(index);
        setSuccessResponse(res, block.toJson());
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get block: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetBlockByHash(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string hash = req.matches[1];
        if (hash.empty()) {
            setErrorResponse(res, 400, "Block hash is required");
            return;
        }
        
        Block block = blockchain_->getBlockByHash(hash);
        if (block.getHash().empty()) {
            setErrorResponse(res, 404, "Block not found");
            return;
        }
        
        setSuccessResponse(res, block.toJson());
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get block: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetLatestBlock(const httplib::Request& req, httplib::Response& res) {
    try {
        const Block& block = blockchain_->getLatestBlock();
        setSuccessResponse(res, block.toJson());
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get latest block: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetTransactions(const httplib::Request& req, httplib::Response& res) {
    try {
        const auto& mempool = blockchain_->getTransactionPool();
        nlohmann::json response;
        response["transactions"] = mempool.toJson()["transactions"];
        response["count"] = mempool.getTransactionCount();
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get transactions: " + std::string(e.what()));
    }
}

void RestApiServer::handleCreateTransaction(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json requestJson;
        if (!validateJsonRequest(req, requestJson)) {
            setErrorResponse(res, 400, "Invalid JSON in request body");
            return;
        }
        
        if (!requestJson.contains("from") || !requestJson.contains("to") || !requestJson.contains("amount")) {
            setErrorResponse(res, 400, "Missing required fields: from, to, amount");
            return;
        }
        
        std::string from = requestJson["from"];
        std::string to = requestJson["to"];
        double amount = requestJson["amount"];
        
        if (!isValidAddress(from) || !isValidAddress(to)) {
            setErrorResponse(res, 400, "Invalid address format");
            return;
        }
        
        if (!isValidAmount(amount)) {
            setErrorResponse(res, 400, "Invalid amount");
            return;
        }
        
        Transaction transaction(from, to, amount);
        
        if (!blockchain_->addTransaction(transaction)) {
            setErrorResponse(res, 400, "Failed to add transaction to mempool");
            return;
        }
        
        // Broadcast transaction to network
        if (p2pNetwork_) {
            p2pNetwork_->broadcastTransaction(transaction);
        }
        
        nlohmann::json response;
        response["transaction"] = transaction.toJson();
        response["message"] = "Transaction added to mempool";
        
        setSuccessResponse(res, response);
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to create transaction: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetTransaction(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string txId = req.matches[1];
        if (txId.empty()) {
            setErrorResponse(res, 400, "Transaction ID is required");
            return;
        }
        
        // Search in mempool first
        const auto& mempool = blockchain_->getTransactionPool();
        auto transaction = mempool.getTransaction(txId);
        
        if (transaction.getId().empty()) {
            setErrorResponse(res, 404, "Transaction not found");
            return;
        }
        
        setSuccessResponse(res, transaction.toJson());
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get transaction: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetMempool(const httplib::Request& req, httplib::Response& res) {
    try {
        const auto& mempool = blockchain_->getTransactionPool();
        setSuccessResponse(res, mempool.toJson());
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get mempool: " + std::string(e.what()));
    }
}

void RestApiServer::handleMineBlock(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json requestJson;
        if (!validateJsonRequest(req, requestJson)) {
            setErrorResponse(res, 400, "Invalid JSON in request body");
            return;
        }
        
        std::string minerAddress = "default_miner";
        if (requestJson.contains("minerAddress")) {
            minerAddress = requestJson["minerAddress"];
        }
        
        if (!isValidAddress(minerAddress)) {
            minerAddress = Crypto::generateRandomAddress();
        }
        
        Block newBlock = blockchain_->mineBlock(minerAddress);
        
        // Broadcast new block to network
        if (p2pNetwork_) {
            p2pNetwork_->broadcastBlock(newBlock);
        }
        
        nlohmann::json response;
        response["block"] = newBlock.toJson();
        response["message"] = "Block mined successfully";
        
        setSuccessResponse(res, response);
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to mine block: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetDifficulty(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["difficulty"] = blockchain_->getDifficulty();
        response["chainHeight"] = blockchain_->getChainHeight();
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get difficulty: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetPeers(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        if (p2pNetwork_) {
            auto peers = p2pNetwork_->getConnectedPeers();
            response["peers"] = nlohmann::json::array();
            
            for (const auto& peer : peers) {
                response["peers"].push_back(peer.toJson());
            }
            
            response["count"] = peers.size();
        } else {
            response["peers"] = nlohmann::json::array();
            response["count"] = 0;
        }
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get peers: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetNetworkStatus(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        
        if (p2pNetwork_) {
            response["nodeId"] = p2pNetwork_->getNodeId();
            response["peerCount"] = p2pNetwork_->getPeerCount();
            response["chainHeight"] = p2pNetwork_->getChainHeight();
            response["messagesSent"] = p2pNetwork_->getMessagesSent();
            response["messagesReceived"] = p2pNetwork_->getMessagesReceived();
            response["bytesTransferred"] = p2pNetwork_->getBytesTransferred();
            response["isRunning"] = p2pNetwork_->isRunning();
        } else {
            response["nodeId"] = "not_available";
            response["peerCount"] = 0;
            response["chainHeight"] = blockchain_->getChainHeight();
            response["isRunning"] = false;
        }
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get network status: " + std::string(e.what()));
    }
}

void RestApiServer::handleConnectToPeer(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json requestJson;
        if (!validateJsonRequest(req, requestJson)) {
            setErrorResponse(res, 400, "Invalid JSON in request body");
            return;
        }
        
        if (!requestJson.contains("ip") || !requestJson.contains("port")) {
            setErrorResponse(res, 400, "Missing required fields: ip, port");
            return;
        }
        
        std::string ip = requestJson["ip"];
        uint16_t port = requestJson["port"];
        
        if (!p2pNetwork_) {
            setErrorResponse(res, 500, "P2P network not available");
            return;
        }
        
        bool success = p2pNetwork_->connectToPeer(ip, port);
        
        nlohmann::json response;
        response["success"] = success;
        response["message"] = success ? "Connection initiated" : "Failed to connect";
        
        setSuccessResponse(res, response);
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to connect to peer: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetNodeStatus(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["chainHeight"] = blockchain_->getChainHeight();
        response["difficulty"] = blockchain_->getDifficulty();
        response["mempoolSize"] = blockchain_->getTransactionPool().getTransactionCount();
        response["totalSupply"] = blockchain_->getTotalSupply();
        response["apiRequestCount"] = requestCount_.load();
        response["timestamp"] = std::time(nullptr);
        
        if (p2pNetwork_) {
            response["peerCount"] = p2pNetwork_->getPeerCount();
            response["networkRunning"] = p2pNetwork_->isRunning();
        }
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get node status: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetNodeInfo(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["version"] = "1.0.0";
        response["nodeType"] = "full_node";
        response["apiPort"] = port_;
        response["features"] = nlohmann::json::array({"mining", "p2p", "transactions"});
        
        if (p2pNetwork_) {
            response["nodeId"] = p2pNetwork_->getNodeId();
        }
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get node info: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetStatistics(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json response;
        response["totalTransactions"] = blockchain_->getTotalTransactions();
        response["averageBlockTime"] = blockchain_->getAverageBlockTime();
        response["networkHashRate"] = blockchain_->getNetworkHashRate();
        response["chainHeight"] = blockchain_->getChainHeight();
        response["totalSupply"] = blockchain_->getTotalSupply();
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get statistics: " + std::string(e.what()));
    }
}

void RestApiServer::handleGetBalance(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string address = req.matches[1];
        if (address.empty()) {
            setErrorResponse(res, 400, "Address is required");
            return;
        }
        
        if (!isValidAddress(address)) {
            setErrorResponse(res, 400, "Invalid address format");
            return;
        }
        
        double balance = blockchain_->getBalance(address);
        
        nlohmann::json response;
        response["address"] = address;
        response["balance"] = balance;
        
        setSuccessResponse(res, response);
        
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to get balance: " + std::string(e.what()));
    }
}

void RestApiServer::handleGenerateAddress(const httplib::Request& req, httplib::Response& res) {
    try {
        auto keyPair = Crypto::generateKeyPair();
        std::string address = Crypto::generateAddress(keyPair.second);
        
        nlohmann::json response;
        response["address"] = address;
        response["publicKey"] = keyPair.second;
        response["privateKey"] = keyPair.first;
        
        setSuccessResponse(res, response);
    } catch (const std::exception& e) {
        setErrorResponse(res, 500, "Failed to generate address: " + std::string(e.what()));
    }
}

void RestApiServer::setErrorResponse(httplib::Response& res, int code, const std::string& message) {
    nlohmann::json response;
    response["success"] = false;
    response["error"] = message;
    response["timestamp"] = std::time(nullptr);
    
    res.status = code;
    res.set_header("Content-Type", "application/json");
    res.body = response.dump();
    
    addCORSHeaders(res);
}

void RestApiServer::setSuccessResponse(httplib::Response& res, const nlohmann::json& data) {
    nlohmann::json response;
    response["success"] = true;
    response["data"] = data;
    response["timestamp"] = std::time(nullptr);
    
    res.status = 200;
    res.set_header("Content-Type", "application/json");
    res.body = response.dump();
    
    addCORSHeaders(res);
}

void RestApiServer::addCORSHeaders(httplib::Response& res) {
    if (corsEnabled_) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
}

void RestApiServer::logRequest(const httplib::Request& req) {
    requestCount_++;
    spdlog::debug("API Request: {} {}", req.method, req.path);
}

bool RestApiServer::validateJsonRequest(const httplib::Request& req, nlohmann::json& json) {
    try {
        json = nlohmann::json::parse(req.body);
        return true;
    } catch (const nlohmann::json::parse_error& e) {
        spdlog::error("JSON parse error: {}", e.what());
        return false;
    }
}

bool RestApiServer::isValidAddress(const std::string& address) {
    return !address.empty() && address.length() >= 10 && address.length() <= 100;
}

bool RestApiServer::isValidAmount(double amount) {
    return amount > 0 && amount <= 1000000;
}

bool RestApiServer::isValidBlockIndex(const std::string& indexStr, uint32_t& index) {
    try {
        index = std::stoul(indexStr);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}