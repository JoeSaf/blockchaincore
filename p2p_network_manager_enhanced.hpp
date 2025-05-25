// p2p_network_manager_enhanced.hpp - Complete Network Manager
#ifndef P2P_NETWORK_MANAGER_ENHANCED_HPP
#define P2P_NETWORK_MANAGER_ENHANCED_HPP

#include "p2p_types.hpp"
#include "p2p_message.hpp"
#include "p2p_peer.hpp"
#include "blockchain_core.hpp"
#include <asio.hpp>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>

namespace blockchain {
namespace p2p {

// ----- Enhanced P2P Network Manager -----
class P2PNetworkManager {
private:
    // Core components
    asio::io_context ioContext_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::unique_ptr<PeerManager> peerManager_;
    
    // Threading
    std::vector<std::thread> workerThreads_;
    std::thread acceptorThread_;
    std::thread heartbeatThread_;
    std::thread maintenanceThread_;
    std::atomic<bool> running_{false};
    
    // Configuration
    NetworkConfig config_;
    uint16_t listeningPort_;
    std::string nodeId_;
    
    // Statistics
    NetworkStats stats_;
    
    // Event handlers
    MessageHandler messageHandler_;
    PeerEventHandler peerEventHandler_;
    BlockchainEventHandler blockchainHandler_;
    
    // Blockchain integration callbacks
    std::function<void(const json&)> onBlockReceived_;
    std::function<void(const json&)> onTransactionReceived_;
    std::function<json()> getLatestBlock_;
    std::function<std::vector<json>()> getPendingTransactions_;
    std::function<bool(const json&)> validateBlock_;
    std::function<bool(const json&)> validateTransaction_;
    
public:
    explicit P2PNetworkManager(uint16_t port = DEFAULT_P2P_PORT, const NetworkConfig& config = NetworkConfig{})
        : listeningPort_(port), config_(config) {
        
        if (!config_.isValid()) {
            throw std::invalid_argument("Invalid network configuration");
        }
        
        // Generate unique node ID
        nodeId_ = CryptoUtils::generatePeerId();
        
        // Initialize peer manager
        peerManager_ = std::make_unique<PeerManager>(ioContext_, config_);
        
        // Set up event handlers
        setupEventHandlers();
    }
    
    ~P2PNetworkManager() {
        stop();
    }
    
    // ----- Network Lifecycle -----
    
    bool start() {
        if (running_) return true;
        
        try {
            // Create acceptor
            acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(
                ioContext_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), listeningPort_));
            
            // Configure acceptor
            acceptor_->set_option(asio::ip::tcp::acceptor::reuse_address(true));
            
            running_ = true;
            stats_.startTime = std::chrono::system_clock::now();
            
            // Start worker threads
            size_t numThreads = config_.messageProcessingThreads;
            workerThreads_.reserve(numThreads);
            
            for (size_t i = 0; i < numThreads; ++i) {
                workerThreads_.emplace_back([this] {
                    ioContext_.run();
                });
            }
            
            // Start acceptor thread
            acceptorThread_ = std::thread(&P2PNetworkManager::acceptorLoop, this);
            
            // Start maintenance threads
            heartbeatThread_ = std::thread(&P2PNetworkManager::heartbeatLoop, this);
            maintenanceThread_ = std::thread(&P2PNetworkManager::maintenanceLoop, this);
            
            std::cout << "P2P Network Manager started on port " << listeningPort_ 
                      << " with node ID: " << nodeId_ << std::endl;
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Failed to start P2P Network Manager: " << e.what() << std::endl;
            running_ = false;
            return false;
        }
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        
        // Stop accepting new connections
        if (acceptor_) {
            std::error_code ec;
            acceptor_->close(ec);
        }
        
        // Disconnect all peers
        if (peerManager_) {
            auto peers = peerManager_->getAllPeers();
            for (auto& peer : peers) {
                peer->disconnect();
            }
        }
        
        // Stop io_context
        ioContext_.stop();
        
        // Join all threads
        if (acceptorThread_.joinable()) acceptorThread_.join();
        if (heartbeatThread_.joinable()) heartbeatThread_.join();
        if (maintenanceThread_.joinable()) maintenanceThread_.join();
        
        for (auto& thread : workerThreads_) {
            if (thread.joinable()) thread.join();
        }
        
        workerThreads_.clear();
        
        std::cout << "P2P Network Manager stopped" << std::endl;
    }
    
    bool isRunning() const {
        return running_;
    }
    
    // ----- Peer Management -----
    
    bool connectToPeer(const std::string& address, uint16_t port) {
        if (!running_) return false;
        
        auto peer = peerManager_->addPeer(address, port);
        if (!peer) {
            return false; // Peer limit reached or already exists
        }
        
        stats_.connectionAttempts++;
        
        if (peer->connect()) {
            // Perform handshake
            if (peer->performHandshake(nodeId_, PROTOCOL_VERSION, listeningPort_)) {
                stats_.successfulConnections++;
                stats_.peerCount++;
                
                if (peer->getPeerInfo().outbound) {
                    stats_.outboundConnections++;
                }
                
                return true;
            } else {
                peerManager_->removePeer(peer->getPeerInfo().peerId);
                stats_.failedConnections++;
                return false;
            }
        } else {
            peerManager_->removePeer(peer->getPeerInfo().peerId);
            stats_.failedConnections++;
            return false;
        }
    }
    
    void disconnectFromPeer(const std::string& peerId) {
        auto peer = peerManager_->getPeer(peerId);
        if (peer) {
            peer->disconnect();
            peerManager_->removePeer(peerId);
            stats_.peerCount--;
            
            if (peer->getPeerInfo().outbound) {
                stats_.outboundConnections--;
            } else {
                stats_.inboundConnections--;
            }
        }
    }
    
    size_t getPeerCount() const {
        return peerManager_->getPeerCount();
    }
    
    std::vector<json> getPeerList() const {
        auto peers = peerManager_->getAllPeers();
        std::vector<json> result;
        result.reserve(peers.size());
        
        for (const auto& peer : peers) {
            if (peer->isConnected()) {
                result.push_back(peer->getPeerInfo().toJson());
            }
        }
        
        return result;
    }
    
    std::vector<std::shared_ptr<PeerConnection>> getConnectedPeers() const {
        auto allPeers = peerManager_->getAllPeers();
        std::vector<std::shared_ptr<PeerConnection>> connectedPeers;
        
        for (const auto& peer : allPeers) {
            if (peer->isConnected() && peer->isHandshakeCompleted()) {
                connectedPeers.push_back(peer);
            }
        }
        
        return connectedPeers;
    }
    
    // ----- Message Broadcasting -----
    
    void broadcastMessage(const P2PMessage& message) {
        peerManager_->broadcastMessage(message);
        stats_.messagesSent += getConnectedPeers().size();
        stats_.bytesSent += message.getTotalSize() * getConnectedPeers().size();
    }
    
    bool sendMessageToPeer(const std::string& peerId, const P2PMessage& message) {
        auto peer = peerManager_->getPeer(peerId);
        if (peer && peer->isConnected()) {
            bool success = peer->sendMessage(message);
            if (success) {
                stats_.messagesSent++;
                stats_.bytesSent += message.getTotalSize();
            }
            return success;
        }
        return false;
    }
    
    // ----- Blockchain Integration -----
    
    void broadcastBlock(const json& blockData) {
        if (!running_) return;
        
        auto message = P2PMessage::createBlockAnnouncement(nodeId_, blockData);
        broadcastMessage(message);
        
        std::cout << "Broadcasted block to " << getConnectedPeers().size() << " peers" << std::endl;
    }
    
    void broadcastTransaction(const json& transactionData) {
        if (!running_) return;
        
        auto message = P2PMessage::createTransaction(nodeId_, transactionData);
        broadcastMessage(message);
        
        std::cout << "Broadcasted transaction to " << getConnectedPeers().size() << " peers" << std::endl;
    }
    
    void requestSync() {
        if (!running_) return;
        
        auto message = P2PMessage::createSyncRequest(nodeId_, 0);
        broadcastMessage(message);
        
        std::cout << "Requested blockchain sync from " << getConnectedPeers().size() << " peers" << std::endl;
    }
    
    // ----- Bootstrap Management -----
    
    void addBootstrapNode(const std::string& address, uint16_t port) {
        peerManager_->addBootstrapNode(address, port);
        std::cout << "Added bootstrap node: " << address << ":" << port << std::endl;
    }
    
    void removeBootstrapNode(const std::string& address, uint16_t port) {
        // Implementation would remove from bootstrap list
        std::cout << "Removed bootstrap node: " << address << ":" << port << std::endl;
    }
    
    void connectToBootstrapNodes() {
        auto bootstrapNodes = peerManager_->getBootstrapNodes();
        
        for (const auto& node : bootstrapNodes) {
            if (getPeerCount() >= config_.maxPeers) break;
            
            std::cout << "Connecting to bootstrap node: " << node.getAddress() << std::endl;
            connectToPeer(node.address, node.port);
            
            // Small delay between connections
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    // ----- Configuration -----
    
    const NetworkConfig& getConfig() const {
        return config_;
    }
    
    void updateConfig(const NetworkConfig& newConfig) {
        if (newConfig.isValid()) {
            config_ = newConfig;
            std::cout << "Network configuration updated" << std::endl;
        }
    }
    
    // ----- Status and Statistics -----
    
    json getNetworkStatus() const {
        auto peerStats = peerManager_->getStats();
        
        return {
            {"node_id", nodeId_},
            {"listening_port", listeningPort_},
            {"running", running_.load()},
            {"uptime_seconds", stats_.getUptimeSeconds()},
            {"peer_count", getPeerCount()},
            {"connected_peers", getConnectedPeers().size()},
            {"messages_sent", stats_.messagesSent.load()},
            {"messages_received", stats_.messagesReceived.load()},
            {"bytes_sent", stats_.bytesSent.load()},
            {"bytes_received", stats_.bytesReceived.load()},
            {"connection_attempts", stats_.connectionAttempts.load()},
            {"successful_connections", stats_.successfulConnections.load()},
            {"failed_connections", stats_.failedConnections.load()},
            {"connection_success_rate", stats_.getConnectionSuccessRate()},
            {"average_message_rate", stats_.getAverageMessageRate()},
            {"peer_stats", peerStats}
        };
    }
    
    json getNetworkStats() const {
        return stats_.toJson();
    }
    
    std::string getNodeId() const {
        return nodeId_;
    }
    
    uint16_t getListeningPort() const {
        return listeningPort_;
    }
    
    // ----- Event Handlers -----
    
    void setMessageHandler(MessageHandler handler) {
        messageHandler_ = handler;
        peerManager_->setMessageHandler(handler);
    }
    
    void setPeerEventHandler(PeerEventHandler handler) {
        peerEventHandler_ = handler;
        peerManager_->setPeerEventHandler(handler);
    }
    
    // ----- Blockchain Integration Callbacks -----
    
    void connectToBlockchain(
        std::function<void(const json&)> onBlockReceived,
        std::function<void(const json&)> onTransactionReceived,
        std::function<json()> getLatestBlock,
        std::function<std::vector<json>()> getPendingTransactions,
        std::function<bool(const json&)> validateBlock,
        std::function<bool(const json&)> validateTransaction
    ) {
        onBlockReceived_ = onBlockReceived;
        onTransactionReceived_ = onTransactionReceived;
        getLatestBlock_ = getLatestBlock;
        getPendingTransactions_ = getPendingTransactions;
        validateBlock_ = validateBlock;
        validateTransaction_ = validateTransaction;
        
        std::cout << "Blockchain integration callbacks configured" << std::endl;
    }

private:
    // ----- Event Handler Setup -----
    
    void setupEventHandlers() {
        // Set up message handler
        peerManager_->setMessageHandler([this](const std::string& peerId, MessageType type, const std::string& payload) {
            handleMessage(peerId, type, payload);
        });
        
        // Set up peer event handler
        peerManager_->setPeerEventHandler([this](const std::string& peerId, PeerEvent event, const std::string& data) {
            handlePeerEvent(peerId, event, data);
        });
    }
    
    // ----- Network Loops -----
    
    void acceptorLoop() {
        while (running_) {
            try {
                auto socket = std::make_shared<asio::ip::tcp::socket>(ioContext_);
                
                std::error_code ec;
                acceptor_->accept(*socket, ec);
                
                if (ec) {
                    if (running_) {
                        std::cerr << "Accept error: " << ec.message() << std::endl;
                    }
                    continue;
                }
                
                // Add incoming peer
                auto peer = peerManager_->addIncomingPeer(socket);
                if (peer) {
                    stats_.inboundConnections++;
                    stats_.peerCount++;
                    
                    // Perform handshake in background
                    std::thread([this, peer] {
                        if (!peer->performHandshake(nodeId_, PROTOCOL_VERSION, listeningPort_)) {
                            peerManager_->removePeer(peer->getPeerInfo().peerId);
                            stats_.inboundConnections--;
                            stats_.peerCount--;
                        }
                    }).detach();
                    
                } else {
                    // Peer limit reached, close connection
                    socket->close();
                }
                
            } catch (const std::exception& e) {
                if (running_) {
                    std::cerr << "Acceptor error: " << e.what() << std::endl;
                }
            }
        }
    }
    
    void heartbeatLoop() {
        while (running_) {
            try {
                auto peers = getConnectedPeers();
                
                for (auto& peer : peers) {
                    if (peer->isConnected() && peer->isHandshakeCompleted()) {
                        peer->sendHeartbeat();
                        
                        // Check if peer is still alive
                        if (!peer->isHeartbeatAlive()) {
                            std::cout << "Peer " << peer->getPeerInfo().peerId 
                                      << " heartbeat timeout, disconnecting" << std::endl;
                            peer->disconnect();
                        }
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(config_.heartbeatInterval));
                
            } catch (const std::exception& e) {
                std::cerr << "Heartbeat error: " << e.what() << std::endl;
            }
        }
    }
    
    void maintenanceLoop() {
        while (running_) {
            try {
                // Clean up disconnected peers
                auto peers = peerManager_->getAllPeers();
                for (auto& peer : peers) {
                    if (!peer->isConnected()) {
                        peerManager_->removePeer(peer->getPeerInfo().peerId);
                    }
                }
                
                // Try to maintain minimum peer connections
                if (getConnectedPeers().size() < config_.maxPeers / 2) {
                    connectToBootstrapNodes();
                }
                
                // Log statistics periodically
                if (config_.enableLogging) {
                    auto status = getNetworkStatus();
                    std::cout << "Network Status - Peers: " << status["peer_count"] 
                              << ", Messages: " << status["messages_received"] 
                              << ", Uptime: " << status["uptime_seconds"] << "s" << std::endl;
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(30));
                
            } catch (const std::exception& e) {
                std::cerr << "Maintenance error: " << e.what() << std::endl;
            }
        }
    }
    
    // ----- Message and Event Handling -----
    
    void handleMessage(const std::string& peerId, MessageType type, const std::string& payload) {
        stats_.messagesReceived++;
        stats_.bytesReceived += payload.size();
        
        try {
            json payloadJson = json::parse(payload);
            
            switch (type) {
                case MessageType::BLOCK_ANNOUNCEMENT:
                    if (onBlockReceived_ && validateBlock_) {
                        auto blockData = payloadJson["block"];
                        if (validateBlock_(blockData)) {
                            onBlockReceived_(blockData);
                        }
                    }
                    break;
                    
                case MessageType::TRANSACTION:
                    if (onTransactionReceived_ && validateTransaction_) {
                        auto txData = payloadJson["transaction"];
                        if (validateTransaction_(txData)) {
                            onTransactionReceived_(txData);
                        }
                    }
                    break;
                    
                case MessageType::SYNC_REQUEST:
                    handleSyncRequest(peerId, payloadJson);
                    break;
                    
                case MessageType::PEER_LIST_REQUEST:
                    handlePeerListRequest(peerId);
                    break;
                    
                default:
                    // Forward to user handler if set
                    if (messageHandler_) {
                        messageHandler_(peerId, type, payload);
                    }
                    break;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error handling message from " << peerId << ": " << e.what() << std::endl;
        }
    }
    
    void handlePeerEvent(const std::string& peerId, PeerEvent event, const std::string& data) {
        switch (event) {
            case PeerEvent::CONNECTED:
                std::cout << "Peer connected: " << peerId << std::endl;
                break;
                
            case PeerEvent::DISCONNECTED:
                std::cout << "Peer disconnected: " << peerId << std::endl;
                break;
                
            case PeerEvent::HANDSHAKE_COMPLETED:
                std::cout << "Handshake completed with: " << peerId << std::endl;
                break;
                
            case PeerEvent::ERROR_OCCURRED:
                std::cerr << "Peer error [" << peerId << "]: " << data << std::endl;
                break;
                
            default:
                break;
        }
        
        // Forward to user handler if set
        if (peerEventHandler_) {
            peerEventHandler_(peerId, event, data);
        }
    }
    
    void handleSyncRequest(const std::string& peerId, const json& request) {
        if (!getLatestBlock_) return;
        
        try {
            size_t fromBlock = request.value("from_block", 0);
            auto latestBlock = getLatestBlock_();
            
            // Send sync response
            json response = {
                {"latest_block", latestBlock},
                {"from_block", fromBlock},
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()}
            };
            
            P2PMessage syncResponse(MessageType::SYNC_RESPONSE, response);
            syncResponse.setSenderId(nodeId_);
            
            sendMessageToPeer(peerId, syncResponse);
            
        } catch (const std::exception& e) {
            std::cerr << "Error handling sync request: " << e.what() << std::endl;
        }
    }
    
    void handlePeerListRequest(const std::string& peerId) {
        try {
            auto peerList = getPeerList();
            
            json response = {
                {"peers", peerList},
                {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()}
            };
            
            P2PMessage peerListResponse(MessageType::PEER_LIST_RESPONSE, response);
            peerListResponse.setSenderId(nodeId_);
            
            sendMessageToPeer(peerId, peerListResponse);
            
        } catch (const std::exception& e) {
            std::cerr << "Error handling peer list request: " << e.what() << std::endl;
        }
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_NETWORK_MANAGER_ENHANCED_HPP