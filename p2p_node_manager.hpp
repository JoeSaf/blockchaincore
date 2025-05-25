// p2p_node_manager.hpp - Continuation of P2P implementation
#ifndef P2P_NODE_MANAGER_HPP
#define P2P_NODE_MANAGER_HPP

#include "p2p_blockchain_network.hpp"
#include <thread>
#include <atomic>
#include <condition_variable>

namespace blockchain {
namespace p2p {

// ----- Main P2P Node Class -----
class BlockchainP2PNode {
private:
    // Core components
    std::string nodeId_;
    std::string version_;
    uint16_t listenPort_;
    
    // Network management
    std::unique_ptr<AddressManager> addressManager_;
    std::unique_ptr<MessageHandler> messageHandler_;
    
    // Peer management
    std::unordered_map<std::string, std::shared_ptr<PeerConnection>> peers_;
    mutable std::shared_mutex peersMutex_;
    std::atomic<size_t> outboundConnections_;
    std::atomic<size_t> inboundConnections_;
    
    // Server socket for incoming connections
    int serverSocket_;
    std::atomic<bool> running_;
    
    // Background threads
    std::vector<std::thread> workerThreads_;
    std::thread serverThread_;
    std::thread maintenanceThread_;
    
    // Thread synchronization
    std::condition_variable shutdownCondition_;
    std::mutex shutdownMutex_;
    
    // Blockchain integration
    std::function<void(const json&)> blockchainSyncCallback_;
    std::function<json()> getLatestBlockCallback_;
    std::function<std::vector<json>()> getPendingTransactionsCallback_;
    std::function<bool(const json&)> validateBlockCallback_;
    std::function<bool(const json&)> validateTransactionCallback_;
    
    // Statistics
    std::atomic<uint64_t> messagesReceived_;
    std::atomic<uint64_t> messagesSent_;
    std::atomic<uint64_t> bytesReceived_;
    std::atomic<uint64_t> bytesSent_;
    system_clock::time_point startTime_;
    
public:
    BlockchainP2PNode(uint16_t port = DEFAULT_P2P_PORT) 
        : listenPort_(port), serverSocket_(-1), running_(false),
          outboundConnections_(0), inboundConnections_(0),
          messagesReceived_(0), messagesSent_(0), 
          bytesReceived_(0), bytesSent_(0),
          startTime_(system_clock::now()) {
        
        nodeId_ = CryptoUtils::generatePeerId();
        version_ = "BlockchainP2P/1.0.0";
        
        addressManager_ = std::make_unique<AddressManager>();
        messageHandler_ = std::make_unique<MessageHandler>();
        
        setupMessageHandlers();
    }
    
    ~BlockchainP2PNode() {
        stop();
    }
    
    // ----- Core Node Operations -----
    
    bool start() {
        if (running_) return true;
        
        std::cout << "Starting P2P node on port " << listenPort_ << std::endl;
        std::cout << "Node ID: " << nodeId_ << std::endl;
        
        // Create server socket
        if (!createServerSocket()) {
            std::cerr << "Failed to create server socket" << std::endl;
            return false;
        }
        
        running_ = true;
        
        // Start background threads
        serverThread_ = std::thread(&BlockchainP2PNode::serverLoop, this);
        maintenanceThread_ = std::thread(&BlockchainP2PNode::maintenanceLoop, this);
        
        // Start worker threads for peer management
        size_t numWorkers = std::max(2u, std::thread::hardware_concurrency() / 2);
        for (size_t i = 0; i < numWorkers; ++i) {
            workerThreads_.emplace_back(&BlockchainP2PNode::workerLoop, this);
        }
        
        // Connect to bootstrap peers
        connectToBootstrapPeers();
        
        std::cout << "P2P node started successfully" << std::endl;
        return true;
    }
    
    void stop() {
        if (!running_) return;
        
        std::cout << "Stopping P2P node..." << std::endl;
        running_ = false;
        
        // Close server socket
        if (serverSocket_ >= 0) {
            close(serverSocket_);
            serverSocket_ = -1;
        }
        
        // Disconnect all peers
        {
            std::unique_lock<std::shared_mutex> lock(peersMutex_);
            for (auto& [id, peer] : peers_) {
                peer->disconnect();
            }
            peers_.clear();
        }
        
        // Join threads
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
        
        if (maintenanceThread_.joinable()) {
            maintenanceThread_.join();
        }
        
        for (auto& worker : workerThreads_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        
        workerThreads_.clear();
        
        std::cout << "P2P node stopped" << std::endl;
    }
    
    // ----- Peer Management -----
    
    bool connectToPeer(const NetworkAddress& address) {
        if (outboundConnections_ >= MAX_OUTBOUND_PEERS) {
            return false;
        }
        
        std::string peerId = address.toString();
        
        // Check if already connected
        {
            std::shared_lock<std::shared_mutex> lock(peersMutex_);
            if (peers_.find(peerId) != peers_.end()) {
                return true; // Already connected
            }
        }
        
        auto peer = std::make_shared<PeerConnection>(address, true);
        
        if (!peer->connect()) {
            addressManager_->markTried(address);
            return false;
        }
        
        if (!peer->performHandshake(nodeId_, version_)) {
            peer->disconnect();
            addressManager_->markTried(address);
            return false;
        }
        
        // Add to peer list
        {
            std::unique_lock<std::shared_mutex> lock(peersMutex_);
            peers_[peerId] = peer;
        }
        
        outboundConnections_++;
        
        std::cout << "Connected to peer: " << address.toString() << std::endl;
        
        // Start peer message processing
        std::thread peerThread(&BlockchainP2PNode::processPeer, this, peer);
        peerThread.detach();
        
        return true;
    }
    
    void disconnectPeer(const std::string& peerId) {
        std::shared_ptr<PeerConnection> peer;
        
        {
            std::unique_lock<std::shared_mutex> lock(peersMutex_);
            auto it = peers_.find(peerId);
            if (it != peers_.end()) {
                peer = it->second;
                peers_.erase(it);
            }
        }
        
        if (peer) {
            if (peer->isOutbound()) {
                outboundConnections_--;
            } else {
                inboundConnections_--;
            }
            
            peer->disconnect();
            std::cout << "Disconnected peer: " << peerId << std::endl;
        }
    }
    
    // ----- Broadcasting -----
    
    void broadcastBlock(const json& block) {
        Message msg(MessageType::BLOCK);
        std::string blockStr = block.dump();
        msg.payload.assign(blockStr.begin(), blockStr.end());
        msg.checksum = CryptoUtils::sha256(msg.payload);
        
        broadcastMessage(msg);
        
        std::cout << "Broadcasted block to " << getPeerCount() << " peers" << std::endl;
    }
    
    void broadcastTransaction(const json& transaction) {
        Message msg(MessageType::TX);
        std::string txStr = transaction.dump();
        msg.payload.assign(txStr.begin(), txStr.end());
        msg.checksum = CryptoUtils::sha256(msg.payload);
        
        broadcastMessage(msg);
        
        std::cout << "Broadcasted transaction to " << getPeerCount() << " peers" << std::endl;
    }
    
    void requestBlockchainSync() {
        Message msg(MessageType::BLOCKCHAIN_SYNC);
        json syncRequest = {
            {"type", "request"},
            {"latest_block_hash", ""},
            {"height", 0}
        };
        
        if (getLatestBlockCallback_) {
            auto latestBlock = getLatestBlockCallback_();
            if (!latestBlock.empty()) {
                syncRequest["latest_block_hash"] = latestBlock.value("hash", "");
                syncRequest["height"] = latestBlock.value("index", 0);
            }
        }
        
        std::string syncStr = syncRequest.dump();
        msg.payload.assign(syncStr.begin(), syncStr.end());
        
        broadcastMessage(msg);
        
        std::cout << "Requested blockchain sync from peers" << std::endl;
    }
    
    // ----- Blockchain Integration Callbacks -----
    
    void setBlockchainSyncCallback(std::function<void(const json&)> callback) {
        blockchainSyncCallback_ = std::move(callback);
    }
    
    void setGetLatestBlockCallback(std::function<json()> callback) {
        getLatestBlockCallback_ = std::move(callback);
    }
    
    void setGetPendingTransactionsCallback(std::function<std::vector<json>()> callback) {
        getPendingTransactionsCallback_ = std::move(callback);
    }
    
    void setValidateBlockCallback(std::function<bool(const json&)> callback) {
        validateBlockCallback_ = std::move(callback);
    }
    
    void setValidateTransactionCallback(std::function<bool(const json&)> callback) {
        validateTransactionCallback_ = std::move(callback);
    }
    
    // ----- Status and Statistics -----
    
    size_t getPeerCount() const {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        return peers_.size();
    }
    
    size_t getOutboundPeerCount() const {
        return outboundConnections_;
    }
    
    size_t getInboundPeerCount() const {
        return inboundConnections_;
    }
    
    json getNetworkStats() const {
        auto uptime = duration_cast<seconds>(system_clock::now() - startTime_).count();
        
        return {
            {"node_id", nodeId_},
            {"version", version_},
            {"uptime_seconds", uptime},
            {"peer_count", getPeerCount()},
            {"outbound_peers", outboundConnections_.load()},
            {"inbound_peers", inboundConnections_.load()},
            {"messages_received", messagesReceived_.load()},
            {"messages_sent", messagesSent_.load()},
            {"bytes_received", bytesReceived_.load()},
            {"bytes_sent", bytesSent_.load()},
            {"known_addresses", addressManager_->getKnownCount()},
            {"tried_addresses", addressManager_->getTriedCount()}
        };
    }
    
    std::vector<json> getPeerInfo() const {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        std::vector<json> peerInfo;
        
        for (const auto& [id, peer] : peers_) {
            auto lastActivity = duration_cast<seconds>(
                system_clock::now() - peer->getLastActivity()).count();
            
            peerInfo.push_back({
                {"id", id},
                {"address", peer->getAddress().toString()},
                {"peer_id", peer->getPeerId()},
                {"version", peer->getVersion()},
                {"outbound", peer->isOutbound()},
                {"connected", peer->isConnected()},
                {"handshake_complete", peer->isHandshakeComplete()},
                {"last_activity_seconds", lastActivity}
            });
        }
        
        return peerInfo;
    }
    
    // ----- Address Management -----
    
    void addBootstrapNode(const NetworkAddress& address) {
        addressManager_->addBootstrapNode(address);
    }
    
    void addKnownAddress(const NetworkAddress& address) {
        addressManager_->addAddress(address);
    }
    
private:
    // ----- Internal Methods -----
    
    bool createServerSocket() {
        serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket_ < 0) return false;
        
        // Set socket options
        int opt = 1;
        setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        
        // Bind to port
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(listenPort_);
        
        if (bind(serverSocket_, (sockaddr*)&address, sizeof(address)) < 0) {
            close(serverSocket_);
            return false;
        }
        
        // Start listening
        if (listen(serverSocket_, SOMAXCONN) < 0) {
            close(serverSocket_);
            return false;
        }
        
        return true;
    }
    
    void serverLoop() {
        std::cout << "Server loop started" << std::endl;
        
        while (running_) {
            if (inboundConnections_ >= (MAX_PEERS - MAX_OUTBOUND_PEERS)) {
                std::this_thread::sleep_for(milliseconds(100));
                continue;
            }
            
            sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket < 0) {
                if (running_) {
                    std::this_thread::sleep_for(milliseconds(100));
                }
                continue;
            }
            
            // Get client IP
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            uint16_t clientPort = ntohs(clientAddr.sin_port);
            
            NetworkAddress clientAddress(clientIP, clientPort);
            std::string peerId = clientAddress.toString();
            
            // Create peer connection for incoming connection
            auto peer = std::make_shared<PeerConnection>(clientAddress, false);
            
            // Set the socket (bypass connect since it's already connected)
            // This is a bit hacky - in a real implementation you'd have a better way
            
            std::cout << "Accepted connection from: " << clientAddress.toString() << std::endl;
            
            // Add to peer list
            {
                std::unique_lock<std::shared_mutex> lock(peersMutex_);
                peers_[peerId] = peer;
            }
            
            inboundConnections_++;
            
            // Start processing this peer
            std::thread peerThread(&BlockchainP2PNode::processPeer, this, peer);
            peerThread.detach();
        }
        
        std::cout << "Server loop ended" << std::endl;
    }
    
    void processPeer(std::shared_ptr<PeerConnection> peer) {
        std::string peerId = peer->getAddress().toString();
        
        // Perform handshake for inbound connections
        if (!peer->isOutbound()) {
            if (!peer->performHandshake(nodeId_, version_)) {
                disconnectPeer(peerId);
                return;
            }
        }
        
        std::cout << "Processing peer: " << peerId << std::endl;
        
        // Send initial messages
        sendPing(peer);
        requestAddresses(peer);
        
        // Main message processing loop
        while (running_ && peer->isConnected()) {
            auto message = peer->receiveMessage();
            if (!message) {
                // Check if peer timed out
                auto timeSinceActivity = duration_cast<seconds>(
                    system_clock::now() - peer->getLastActivity()).count();
                
                if (timeSinceActivity > PEER_TIMEOUT_SECONDS) {
                    std::cout << "Peer " << peerId << " timed out" << std::endl;
                    break;
                }
                
                std::this_thread::sleep_for(milliseconds(100));
                continue;
            }
            
            messagesReceived_++;
            bytesReceived_ += message->payload.size();
            
            // Handle the message
            try {
                messageHandler_->handleMessage(peer, *message);
            } catch (const std::exception& e) {
                std::cerr << "Error handling message from " << peerId 
                         << ": " << e.what() << std::endl;
            }
        }
        
        disconnectPeer(peerId);
    }
    
    void workerLoop() {
        while (running_) {
            // Perform periodic tasks
            std::this_thread::sleep_for(seconds(1));
            
            // Add any background processing here
            // e.g., message queue processing, cleanup tasks, etc.
        }
    }
    
    void maintenanceLoop() {
        auto lastPing = system_clock::now();
        auto lastPeerDiscovery = system_clock::now();
        
        while (running_) {
            auto now = system_clock::now();
            
            // Send periodic pings
            if (duration_cast<seconds>(now - lastPing).count() >= PING_INTERVAL_SECONDS) {
                sendPingToAllPeers();
                lastPing = now;
            }
            
            // Periodic peer discovery
            if (duration_cast<seconds>(now - lastPeerDiscovery).count() >= 300) { // 5 minutes
                if (getPeerCount() < MAX_OUTBOUND_PEERS) {
                    connectToRandomPeers();
                }
                lastPeerDiscovery = now;
            }
            
            // Clean up disconnected peers
            cleanupDisconnectedPeers();
            
            std::this_thread::sleep_for(seconds(10));
        }
    }
    
    void connectToBootstrapPeers() {
        auto bootstrapAddresses = addressManager_->getRandomAddresses(5);
        
        for (const auto& address : bootstrapAddresses) {
            if (outboundConnections_ >= MAX_OUTBOUND_PEERS) break;
            
            std::thread connectThread([this, address]() {
                connectToPeer(address);
            });
            connectThread.detach();
            
            std::this_thread::sleep_for(milliseconds(100));
        }
    }
    
    void connectToRandomPeers() {
        auto randomAddresses = addressManager_->getRandomAddresses(3);
        
        for (const auto& address : randomAddresses) {
            if (outboundConnections_ >= MAX_OUTBOUND_PEERS) break;
            
            std::thread connectThread([this, address]() {
                connectToPeer(address);
            });
            connectThread.detach();
            
            std::this_thread::sleep_for(milliseconds(100));
        }
    }
    
    void broadcastMessage(const Message& message) {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        
        for (const auto& [id, peer] : peers_) {
            if (peer->isConnected() && peer->isHandshakeComplete()) {
                std::thread sendThread([peer, message]() {
                    peer->sendMessage(message);
                });
                sendThread.detach();
            }
        }
        
        messagesSent_ += peers_.size();
        bytesSent_ += message.payload.size() * peers_.size();
    }
    
    void sendPing(std::shared_ptr<PeerConnection> peer) {
        Message ping(MessageType::PING);
        
        // Add timestamp to ping payload
        auto timestamp = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
        std::string timestampStr = std::to_string(timestamp);
        ping.payload.assign(timestampStr.begin(), timestampStr.end());
        
        peer->sendMessage(ping);
    }
    
    void sendPingToAllPeers() {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        
        for (const auto& [id, peer] : peers_) {
            if (peer->isConnected() && peer->isHandshakeComplete()) {
                std::thread pingThread([this, peer]() {
                    sendPing(peer);
                });
                pingThread.detach();
            }
        }
    }
    
    void requestAddresses(std::shared_ptr<PeerConnection> peer) {
        Message getAddr(MessageType::GETADDR);
        peer->sendMessage(getAddr);
    }
    
    void cleanupDisconnectedPeers() {
        std::vector<std::string> toRemove;
        
        {
            std::shared_lock<std::shared_mutex> lock(peersMutex_);
            for (const auto& [id, peer] : peers_) {
                if (!peer->isConnected()) {
                    toRemove.push_back(id);
                }
            }
        }
        
        for (const auto& id : toRemove) {
            disconnectPeer(id);
        }
    }
    
    void setupMessageHandlers() {
        // Set up message handlers for blockchain integration
        messageHandler_->setBlockHandler([this](const json& block) {
            if (validateBlockCallback_ && validateBlockCallback_(block)) {
                if (blockchainSyncCallback_) {
                    blockchainSyncCallback_(block);
                }
                std::cout << "Received valid block from peer" << std::endl;
            } else {
                std::cout << "Received invalid block from peer" << std::endl;
            }
        });
        
        messageHandler_->setTransactionHandler([this](const json& tx) {
            if (validateTransactionCallback_ && validateTransactionCallback_(tx)) {
                // Add to pending transactions or mempool
                std::cout << "Received valid transaction from peer" << std::endl;
            } else {
                std::cout << "Received invalid transaction from peer" << std::endl;
            }
        });
        
        messageHandler_->setAddressHandler([this](const std::vector<NetworkAddress>& addresses) {
            addressManager_->addAddresses(addresses);
            std::cout << "Received " << addresses.size() << " addresses from peer" << std::endl;
        });
    }
};

// ----- P2P Network Manager (Integration with Blockchain Core) -----
class P2PNetworkManager {
private:
    std::unique_ptr<BlockchainP2PNode> node_;
    std::function<void(const json&)> onBlockReceived_;
    std::function<void(const json&)> onTransactionReceived_;
    
public:
    P2PNetworkManager(uint16_t port = DEFAULT_P2P_PORT) {
        node_ = std::make_unique<BlockchainP2PNode>(port);
    }
    
    ~P2PNetworkManager() {
        stop();
    }
    
    bool start() {
        return node_->start();
    }
    
    void stop() {
        if (node_) {
            node_->stop();
        }
    }
    
    // Integration with blockchain core
    void connectToBlockchain(
        std::function<void(const json&)> onBlockReceived,
        std::function<void(const json&)> onTransactionReceived,
        std::function<json()> getLatestBlock,
        std::function<std::vector<json>()> getPendingTransactions,
        std::function<bool(const json&)> validateBlock,
        std::function<bool(const json&)> validateTransaction
    ) {
        onBlockReceived_ = std::move(onBlockReceived);
        onTransactionReceived_ = std::move(onTransactionReceived);
        
        node_->setBlockchainSyncCallback(onBlockReceived_);
        node_->setGetLatestBlockCallback(std::move(getLatestBlock));
        node_->setGetPendingTransactionsCallback(std::move(getPendingTransactions));
        node_->setValidateBlockCallback(std::move(validateBlock));
        node_->setValidateTransactionCallback(std::move(validateTransaction));
    }
    
    // Public interface for blockchain operations
    void broadcastBlock(const json& block) {
        if (node_) {
            node_->broadcastBlock(block);
        }
    }
    
    void broadcastTransaction(const json& transaction) {
        if (node_) {
            node_->broadcastTransaction(transaction);
        }
    }
    
    void requestSync() {
        if (node_) {
            node_->requestBlockchainSync();
        }
    }
    
    void addBootstrapNode(const std::string& ip, uint16_t port) {
        if (node_) {
            node_->addBootstrapNode(NetworkAddress(ip, port));
        }
    }
    
    json getNetworkStatus() const {
        return node_ ? node_->getNetworkStats() : json{};
    }
    
    std::vector<json> getPeerList() const {
        return node_ ? node_->getPeerInfo() : std::vector<json>{};
    }
    
    size_t getPeerCount() const {
        return node_ ? node_->getPeerCount() : 0;
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_NODE_MANAGER_HPP