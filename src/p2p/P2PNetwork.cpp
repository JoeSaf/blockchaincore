#include "p2p/P2PNetwork.h"
#include "utils/Crypto.h"
#include <spdlog/spdlog.h>
#include <random>

// NetworkMessage implementations
nlohmann::json NetworkMessage::toJson() const {
    nlohmann::json json;
    json["type"] = static_cast<int>(type);
    json["messageId"] = messageId;
    json["senderId"] = senderId;
    json["timestamp"] = timestamp;
    json["payload"] = payload;
    json["ttl"] = ttl;
    return json;
}

void NetworkMessage::fromJson(const nlohmann::json& json) {
    type = static_cast<MessageType>(json["type"]);
    messageId = json["messageId"];
    senderId = json["senderId"];
    timestamp = json["timestamp"];
    payload = json["payload"];
    ttl = json["ttl"];
}

std::string NetworkMessage::serialize() const {
    return toJson().dump();
}

NetworkMessage NetworkMessage::deserialize(const std::string& data) {
    NetworkMessage message;
    try {
        nlohmann::json json = nlohmann::json::parse(data);
        message.fromJson(json);
    } catch (const std::exception& e) {
        spdlog::error("Failed to deserialize message: {}", e.what());
    }
    return message;
}

// PeerInfo implementations
nlohmann::json PeerInfo::toJson() const {
    nlohmann::json json;
    json["peerId"] = peerId;
    json["ipAddress"] = ipAddress;
    json["port"] = port;
    json["chainHeight"] = chainHeight;
    json["lastSeen"] = lastSeen;
    json["isConnected"] = isConnected;
    return json;
}

void PeerInfo::fromJson(const nlohmann::json& json) {
    peerId = json["peerId"];
    ipAddress = json["ipAddress"];
    port = json["port"];
    chainHeight = json["chainHeight"];
    lastSeen = json["lastSeen"];
    isConnected = json["isConnected"];
}

// P2PNetwork implementation
P2PNetwork::P2PNetwork(uint16_t tcpPort, uint16_t udpPort)
    : tcpPort_(tcpPort), udpPort_(udpPort), chainHeight_(0)
    , maxPeers_(50), heartbeatInterval_(30), messageTTL_(10)
    , running_(false), messagesSent_(0), messagesReceived_(0), bytesTransferred_(0) {
    
    nodeId_ = generateNodeId();
    spdlog::info("P2P Network initialized - Node ID: {}, TCP: {}, UDP: {}", 
                 nodeId_, tcpPort_, udpPort_);
}

P2PNetwork::~P2PNetwork() {
    stop();
}

bool P2PNetwork::start() {
    if (running_) {
        spdlog::warn("P2P Network is already running");
        return false;
    }
    
    try {
        // Initialize ASIO components
        tcpAcceptor_ = std::make_unique<tcp::acceptor>(ioContext_, tcp::endpoint(tcp::v4(), tcpPort_));
        udpSocket_ = std::make_unique<udp::socket>(ioContext_, udp::endpoint(udp::v4(), udpPort_));
        
        running_ = true;
        
        // Start network threads
        networkThreads_.emplace_back(&P2PNetwork::networkMainLoop, this);
        networkThreads_.emplace_back(&P2PNetwork::heartbeatLoop, this);
        networkThreads_.emplace_back(&P2PNetwork::peerCleanupLoop, this);
        
        // Start servers
        startTcpServer();
        startUdpListener();
        
        spdlog::info("P2P Network started successfully");
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to start P2P Network: {}", e.what());
        running_ = false;
        return false;
    }
}

void P2PNetwork::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    try {
        // Stop ASIO context
        ioContext_.stop();
        
        // Join all threads
        for (auto& thread : networkThreads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        // Close sockets
        if (tcpAcceptor_) {
            tcpAcceptor_->close();
        }
        if (udpSocket_) {
            udpSocket_->close();
        }
        
        // Clear peers
        {
            std::lock_guard<std::mutex> lock(peersMutex_);
            peers_.clear();
        }
        
        spdlog::info("P2P Network stopped");
        
    } catch (const std::exception& e) {
        spdlog::error("Error stopping P2P Network: {}", e.what());
    }
}

void P2PNetwork::discoverPeers() {
    if (!running_) {
        return;
    }
    
    try {
        // Create discovery message
        nlohmann::json payload;
        payload["nodeId"] = nodeId_;
        payload["tcpPort"] = tcpPort_;
        payload["chainHeight"] = chainHeight_;
        
        NetworkMessage message = createMessage(MessageType::PEER_DISCOVERY, payload);
        
        // Broadcast to local network
        udp::endpoint broadcastEndpoint(asio::ip::address_v4::broadcast(), udpPort_);
        sendUdpMessage(message, broadcastEndpoint);
        
        spdlog::debug("Peer discovery message broadcasted");
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to discover peers: {}", e.what());
    }
}

bool P2PNetwork::connectToPeer(const std::string& ipAddress, uint16_t port) {
    if (!running_) {
        return false;
    }
    
    try {
        auto socket = std::make_shared<tcp::socket>(ioContext_);
        tcp::endpoint endpoint(asio::ip::make_address(ipAddress), port);
        
        socket->connect(endpoint);
        
        // Generate peer ID and add to peers
        std::string peerId = generateNodeId();
        PeerInfo peer;
        peer.peerId = peerId;
        peer.ipAddress = ipAddress;
        peer.port = port;
        peer.chainHeight = 0;
        peer.lastSeen = std::time(nullptr);
        peer.isConnected = true;
        peer.socket = socket;
        
        addPeer(peer);
        
        // Start handling this peer connection
        std::thread(&P2PNetwork::handlePeerConnection, this, socket, peerId).detach();
        
        spdlog::info("Connected to peer: {}:{}", ipAddress, port);
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to connect to peer {}:{} - {}", ipAddress, port, e.what());
        return false;
    }
}

void P2PNetwork::disconnectPeer(const std::string& peerId) {
    removePeer(peerId);
}

std::vector<PeerInfo> P2PNetwork::getConnectedPeers() const {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    std::vector<PeerInfo> connectedPeers;
    for (const auto& [id, peer] : peers_) {
        if (peer.isConnected) {
            connectedPeers.push_back(peer);
        }
    }
    
    return connectedPeers;
}

uint32_t P2PNetwork::getPeerCount() const {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    uint32_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer.isConnected) {
            count++;
        }
    }
    
    return count;
}

void P2PNetwork::broadcastBlock(const Block& block) {
    nlohmann::json payload;
    payload["block"] = block.toJson();
    
    NetworkMessage message = createMessage(MessageType::BLOCK_BROADCAST, payload);
    forwardMessage(message);
    
    spdlog::debug("Block {} broadcasted to network", block.getIndex());
}

void P2PNetwork::broadcastTransaction(const Transaction& transaction) {
    nlohmann::json payload;
    payload["transaction"] = transaction.toJson();
    
    NetworkMessage message = createMessage(MessageType::TRANSACTION_BROADCAST, payload);
    forwardMessage(message);
    
    spdlog::debug("Transaction {} broadcasted to network", transaction.getId());
}

void P2PNetwork::requestChainSync() {
    nlohmann::json payload;
    payload["fromHeight"] = chainHeight_;
    
    NetworkMessage message = createMessage(MessageType::CHAIN_SYNC_REQUEST, payload);
    forwardMessage(message);
    
    spdlog::debug("Chain sync requested from height {}", chainHeight_);
}

void P2PNetwork::sendHeartbeat() {
    nlohmann::json payload;
    payload["nodeId"] = nodeId_;
    payload["chainHeight"] = chainHeight_;
    payload["timestamp"] = std::time(nullptr);
    
    NetworkMessage message = createMessage(MessageType::HEARTBEAT, payload);
    forwardMessage(message);
}

void P2PNetwork::setBlockReceivedCallback(std::function<void(const Block&, const std::string&)> callback) {
    blockReceivedCallback_ = callback;
}

void P2PNetwork::setTransactionReceivedCallback(std::function<void(const Transaction&, const std::string&)> callback) {
    transactionReceivedCallback_ = callback;
}

void P2PNetwork::setChainSyncRequestCallback(std::function<std::vector<Block>(uint32_t)> callback) {
    chainSyncRequestCallback_ = callback;
}

void P2PNetwork::setPeerConnectedCallback(std::function<void(const PeerInfo&)> callback) {
    peerConnectedCallback_ = callback;
}

void P2PNetwork::setPeerDisconnectedCallback(std::function<void(const std::string&)> callback) {
    peerDisconnectedCallback_ = callback;
}

void P2PNetwork::startTcpServer() {
    auto socket = std::make_shared<tcp::socket>(ioContext_);
    
    tcpAcceptor_->async_accept(*socket,
        [this, socket](std::error_code ec) {
            if (!ec && running_) {
                handleNewConnection(socket);
                startTcpServer(); // Accept next connection
            }
        });
}

void P2PNetwork::startUdpListener() {
    auto buffer = std::make_shared<std::array<char, 1024>>();
    auto senderEndpoint = std::make_shared<udp::endpoint>();
    
    udpSocket_->async_receive_from(asio::buffer(*buffer), *senderEndpoint,
        [this, buffer, senderEndpoint](std::error_code ec, std::size_t length) {
            if (!ec && running_) {
                std::string data(buffer->data(), length);
                handleUdpMessage(data, *senderEndpoint);
                startUdpListener(); // Continue listening
            }
        });
}

void P2PNetwork::handleNewConnection(std::shared_ptr<tcp::socket> socket) {
    std::string peerId = generateNodeId();
    
    PeerInfo peer;
    peer.peerId = peerId;
    peer.ipAddress = socket->remote_endpoint().address().to_string();
    peer.port = socket->remote_endpoint().port();
    peer.chainHeight = 0;
    peer.lastSeen = std::time(nullptr);
    peer.isConnected = true;
    peer.socket = socket;
    
    addPeer(peer);
    
    // Handle peer connection in separate thread
    std::thread(&P2PNetwork::handlePeerConnection, this, socket, peerId).detach();
    
    spdlog::info("New peer connected: {}", peerId);
}

void P2PNetwork::handlePeerConnection(std::shared_ptr<tcp::socket> socket, const std::string& peerId) {
    try {
        while (running_ && socket->is_open()) {
            // Read message from peer
            asio::streambuf buffer;
            asio::read_until(*socket, buffer, "\n");
            
            std::istream stream(&buffer);
            std::string messageData;
            std::getline(stream, messageData);
            
            if (!messageData.empty()) {
                NetworkMessage message = NetworkMessage::deserialize(messageData);
                processMessage(message, peerId);
                messagesReceived_++;
                bytesTransferred_ += messageData.size();
            }
        }
    } catch (const std::exception& e) {
        spdlog::debug("Peer connection error for {}: {}", peerId, e.what());
    }
    
    // Clean up disconnected peer
    removePeer(peerId);
}

void P2PNetwork::handleUdpMessage(const std::string& data, const udp::endpoint& senderEndpoint) {
    try {
        NetworkMessage message = NetworkMessage::deserialize(data);
        
        if (message.type == MessageType::PEER_DISCOVERY) {
            handlePeerDiscovery(message, senderEndpoint);
        }
        
        messagesReceived_++;
        bytesTransferred_ += data.size();
        
    } catch (const std::exception& e) {
        spdlog::debug("UDP message error: {}", e.what());
    }
}

void P2PNetwork::processMessage(const NetworkMessage& message, const std::string& senderId) {
    if (!isMessageSeen(message.messageId)) {
        markMessageSeen(message.messageId);
        
        switch (message.type) {
            case MessageType::BLOCK_BROADCAST:
                handleBlockBroadcast(message, senderId);
                break;
            case MessageType::TRANSACTION_BROADCAST:
                handleTransactionBroadcast(message, senderId);
                break;
            case MessageType::CHAIN_SYNC_REQUEST:
                handleChainSyncRequest(message, senderId);
                break;
            case MessageType::CHAIN_SYNC_RESPONSE:
                handleChainSyncResponse(message, senderId);
                break;
            case MessageType::HEARTBEAT:
                handleHeartbeat(message, senderId);
                break;
            default:
                spdlog::debug("Unknown message type received: {}", static_cast<int>(message.type));
                break;
        }
        
        // Forward message to other peers if TTL > 1
        if (message.ttl > 1) {
            NetworkMessage forwardMsg = message;
            forwardMsg.ttl--;
            forwardMessage(forwardMsg, senderId);
        }
    }
}

void P2PNetwork::handlePeerDiscovery(const NetworkMessage& message, const udp::endpoint& senderEndpoint) {
    if (message.senderId == nodeId_) {
        return; // Ignore our own discovery message
    }
    
    // Extract peer information
    std::string peerId = message.payload["nodeId"];
    uint16_t tcpPort = message.payload["tcpPort"];
    uint32_t peerChainHeight = message.payload["chainHeight"];
    
    // Send discovery response
    nlohmann::json responsePayload;
    responsePayload["nodeId"] = nodeId_;
    responsePayload["tcpPort"] = tcpPort_;
    responsePayload["chainHeight"] = chainHeight_;
    
    NetworkMessage response = createMessage(MessageType::PEER_DISCOVERY_RESPONSE, responsePayload);
    sendUdpMessage(response, senderEndpoint);
    
    // Try to connect to the peer via TCP
    std::string peerIp = senderEndpoint.address().to_string();
    connectToPeer(peerIp, tcpPort);
    
    spdlog::debug("Responded to peer discovery from {}", peerId);
}

void P2PNetwork::handleBlockBroadcast(const NetworkMessage& message, const std::string& senderId) {
    try {
        Block block(message.payload["block"]);
        
        if (blockReceivedCallback_) {
            blockReceivedCallback_(block, senderId);
        }
        
        updatePeerLastSeen(senderId);
        
    } catch (const std::exception& e) {
        spdlog::error("Error handling block broadcast: {}", e.what());
    }
}

void P2PNetwork::handleTransactionBroadcast(const NetworkMessage& message, const std::string& senderId) {
    try {
        Transaction transaction(message.payload["transaction"]);
        
        if (transactionReceivedCallback_) {
            transactionReceivedCallback_(transaction, senderId);
        }
        
        updatePeerLastSeen(senderId);
        
    } catch (const std::exception& e) {
        spdlog::error("Error handling transaction broadcast: {}", e.what());
    }
}

void P2PNetwork::handleChainSyncRequest(const NetworkMessage& message, const std::string& senderId) {
    try {
        uint32_t fromHeight = message.payload["fromHeight"];
        
        if (chainSyncRequestCallback_) {
            std::vector<Block> blocks = chainSyncRequestCallback_(fromHeight);
            
            // Send response with blocks
            nlohmann::json responsePayload;
            responsePayload["blocks"] = nlohmann::json::array();
            
            for (const auto& block : blocks) {
                responsePayload["blocks"].push_back(block.toJson());
            }
            
            NetworkMessage response = createMessage(MessageType::CHAIN_SYNC_RESPONSE, responsePayload);
            sendMessageToPeer(response, senderId);
        }
        
        updatePeerLastSeen(senderId);
        
    } catch (const std::exception& e) {
        spdlog::error("Error handling chain sync request: {}", e.what());
    }
}

void P2PNetwork::handleChainSyncResponse(const NetworkMessage& message, const std::string& senderId) {
    try {
        // Process received blocks - this would typically involve blockchain validation
        auto blocksJson = message.payload["blocks"];
        
        spdlog::info("Received {} blocks from peer {}", blocksJson.size(), senderId);
        updatePeerLastSeen(senderId);
        
    } catch (const std::exception& e) {
        spdlog::error("Error handling chain sync response: {}", e.what());
    }
}

void P2PNetwork::handleHeartbeat(const NetworkMessage& message, const std::string& senderId) {
    try {
        uint32_t peerChainHeight = message.payload["chainHeight"];
        
        // Update peer information
        {
            std::lock_guard<std::mutex> lock(peersMutex_);
            auto it = peers_.find(senderId);
            if (it != peers_.end()) {
                it->second.chainHeight = peerChainHeight;
                it->second.lastSeen = std::time(nullptr);
            }
        }
        
        // Send heartbeat response
        nlohmann::json responsePayload;
        responsePayload["nodeId"] = nodeId_;
        responsePayload["chainHeight"] = chainHeight_;
        responsePayload["timestamp"] = std::time(nullptr);
        
        NetworkMessage response = createMessage(MessageType::HEARTBEAT_RESPONSE, responsePayload);
        sendMessageToPeer(response, senderId);
        
    } catch (const std::exception& e) {
        spdlog::error("Error handling heartbeat: {}", e.what());
    }
}

void P2PNetwork::forwardMessage(const NetworkMessage& message, const std::string& excludePeerId) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    for (const auto& [peerId, peer] : peers_) {
        if (peer.isConnected && peerId != excludePeerId) {
            sendMessageToPeer(message, peerId);
        }
    }
}

bool P2PNetwork::isMessageSeen(const std::string& messageId) const {
    std::lock_guard<std::mutex> lock(messagesMutex_);
    return seenMessages_.count(messageId) > 0;
}

void P2PNetwork::markMessageSeen(const std::string& messageId) {
    std::lock_guard<std::mutex> lock(messagesMutex_);
    seenMessages_.insert(messageId);
    
    // Clean up old messages to prevent memory growth
    if (seenMessages_.size() > 10000) {
        seenMessages_.clear();
    }
}

NetworkMessage P2PNetwork::createMessage(MessageType type, const nlohmann::json& payload) {
    NetworkMessage message;
    message.type = type;
    message.messageId = generateMessageId();
    message.senderId = nodeId_;
    message.timestamp = std::time(nullptr);
    message.payload = payload;
    message.ttl = messageTTL_;
    
    return message;
}

void P2PNetwork::sendMessageToPeer(const NetworkMessage& message, const std::string& peerId) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    auto it = peers_.find(peerId);
    if (it != peers_.end() && it->second.isConnected && it->second.socket) {
        try {
            std::string data = message.serialize() + "\n";
            asio::write(*it->second.socket, asio::buffer(data));
            
            messagesSent_++;
            bytesTransferred_ += data.size();
            
        } catch (const std::exception& e) {
            spdlog::debug("Failed to send message to peer {}: {}", peerId, e.what());
            // Mark peer as disconnected
            it->second.isConnected = false;
        }
    }
}

void P2PNetwork::sendUdpMessage(const NetworkMessage& message, const udp::endpoint& endpoint) {
    try {
        std::string data = message.serialize();
        udpSocket_->send_to(asio::buffer(data), endpoint);
        
        messagesSent_++;
        bytesTransferred_ += data.size();
        
    } catch (const std::exception& e) {
        spdlog::debug("Failed to send UDP message: {}", e.what());
    }
}

void P2PNetwork::addPeer(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    if (peers_.size() >= maxPeers_) {
        spdlog::warn("Maximum peer limit reached, not adding new peer");
        return;
    }
    
    peers_[peer.peerId] = peer;
    
    if (peerConnectedCallback_) {
        peerConnectedCallback_(peer);
    }
    
    spdlog::debug("Added peer: {} ({}:{})", peer.peerId, peer.ipAddress, peer.port);
}

void P2PNetwork::removePeer(const std::string& peerId) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    auto it = peers_.find(peerId);
    if (it != peers_.end()) {
        if (it->second.socket && it->second.socket->is_open()) {
            it->second.socket->close();
        }
        
        peers_.erase(it);
        
        if (peerDisconnectedCallback_) {
            peerDisconnectedCallback_(peerId);
        }
        
        spdlog::debug("Removed peer: {}", peerId);
    }
}

void P2PNetwork::updatePeerLastSeen(const std::string& peerId) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    auto it = peers_.find(peerId);
    if (it != peers_.end()) {
        it->second.lastSeen = std::time(nullptr);
    }
}

void P2PNetwork::cleanupInactivePeers() {
    std::lock_guard<std::mutex> lock(peersMutex_);
    
    std::time_t now = std::time(nullptr);
    const std::time_t PEER_TIMEOUT = 300; // 5 minutes
    
    auto it = peers_.begin();
    while (it != peers_.end()) {
        if (now - it->second.lastSeen > PEER_TIMEOUT) {
            spdlog::debug("Removing inactive peer: {}", it->first);
            
            if (it->second.socket && it->second.socket->is_open()) {
                it->second.socket->close();
            }
            
            if (peerDisconnectedCallback_) {
                peerDisconnectedCallback_(it->first);
            }
            
            it = peers_.erase(it);
        } else {
            ++it;
        }
    }
}

void P2PNetwork::heartbeatLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(heartbeatInterval_));
        
        if (running_) {
            sendHeartbeat();
        }
    }
}

void P2PNetwork::peerCleanupLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(60)); // Run every minute
        
        if (running_) {
            cleanupInactivePeers();
        }
    }
}

void P2PNetwork::networkMainLoop() {
    try {
        ioContext_.run();
    } catch (const std::exception& e) {
        spdlog::error("Network main loop error: {}", e.what());
    }
}

std::string P2PNetwork::generateNodeId() {
    return Crypto::generateRandomString(16);
}

std::string P2PNetwork::generateMessageId() {
    return Crypto::generateRandomString(32);
}

std::vector<std::string> P2PNetwork::getLocalIpAddresses() {
    // This would implement getting local IP addresses
    // For now, return a placeholder
    return {"127.0.0.1"};
}