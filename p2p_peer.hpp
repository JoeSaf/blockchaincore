// p2p_peer.hpp - Enhanced Peer Management
#ifndef P2P_PEER_HPP
#define P2P_PEER_HPP

#include "p2p_types.hpp"
#include "p2p_message.hpp"
#include <thread>
#include <atomic>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <asio.hpp>

namespace blockchain {
namespace p2p {

// ----- Enhanced Peer Connection -----
class PeerConnection {
private:
    std::shared_ptr<asio::ip::tcp::socket> socket_;
    asio::io_context& ioContext_;
    PeerInfo peerInfo_;
    
    // Message handling
    MessageQueue incomingMessages_;
    MessageQueue outgoingMessages_;
    
    // Threading
    std::thread receiveThread_;
    std::thread sendThread_;
    std::atomic<bool> running_{false};
    
    // Callbacks
    MessageHandler messageHandler_;
    PeerEventHandler eventHandler_;
    
    // Connection state
    std::mutex stateMutex_;
    std::chrono::system_clock::time_point lastHeartbeat_;
    std::atomic<bool> handshakeCompleted_{false};
    
    // Buffer for receiving data
    std::vector<uint8_t> receiveBuffer_;
    std::mutex receiveMutex_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    
public:
    PeerConnection(asio::io_context& ioContext, std::shared_ptr<asio::ip::tcp::socket> socket)
        : socket_(socket), ioContext_(ioContext), receiveBuffer_(MAX_MESSAGE_SIZE) {
        
        peerInfo_.connectionTime = std::chrono::system_clock::now();
        peerInfo_.lastActivity = peerInfo_.connectionTime;
        updateConnectionInfo();
    }
    
    PeerConnection(asio::io_context& ioContext, const std::string& address, uint16_t port)
        : socket_(std::make_shared<asio::ip::tcp::socket>(ioContext)), 
          ioContext_(ioContext), receiveBuffer_(MAX_MESSAGE_SIZE) {
        
        peerInfo_.address = address;
        peerInfo_.port = port;
        peerInfo_.outbound = true;
        peerInfo_.connectionTime = std::chrono::system_clock::now();
        peerInfo_.lastActivity = peerInfo_.connectionTime;
    }
    
    ~PeerConnection() {
        disconnect();
    }
    
    // ----- Connection Management -----
    
    bool connect(std::chrono::seconds timeout = std::chrono::seconds(10)) {
        if (isConnected()) return true;
        
        try {
            asio::ip::tcp::resolver resolver(ioContext_);
            auto endpoints = resolver.resolve(peerInfo_.address, std::to_string(peerInfo_.port));
            
            std::error_code ec;
            asio::connect(*socket_, endpoints, ec);
            
            if (ec) {
                peerInfo_.status = PeerInfo::Status::FAILED;
                triggerEvent(PeerEvent::ERROR_OCCURRED, "Connection failed: " + ec.message());
                return false;
            }
            
            peerInfo_.connected = true;
            peerInfo_.status = PeerInfo::Status::CONNECTED;
            updateConnectionInfo();
            
            // Start communication threads
            startCommunication();
            
            triggerEvent(PeerEvent::CONNECTED, "Successfully connected");
            return true;
            
        } catch (const std::exception& e) {
            peerInfo_.status = PeerInfo::Status::FAILED;
            triggerEvent(PeerEvent::ERROR_OCCURRED, "Connection exception: " + std::string(e.what()));
            return false;
        }
    }
    
    void disconnect() {
        if (!running_) return;
        
        running_ = false;
        peerInfo_.connected = false;
        peerInfo_.status = PeerInfo::Status::DISCONNECTING;
        
        // Close socket
        if (socket_ && socket_->is_open()) {
            std::error_code ec;
            socket_->close(ec);
        }
        
        // Join threads
        if (receiveThread_.joinable()) receiveThread_.join();
        if (sendThread_.joinable()) sendThread_.join();
        
        peerInfo_.status = PeerInfo::Status::DISCONNECTED;
        triggerEvent(PeerEvent::DISCONNECTED, "Connection closed");
    }
    
    // ----- Message Handling -----
    
    bool sendMessage(const P2PMessage& message) {
        if (!isConnected()) return false;
        
        // Add to outgoing queue
        if (!outgoingMessages_.push(message)) {
            return false; // Queue full
        }
        
        updateStats(true, message.getTotalSize());
        return true;
    }
    
    bool receiveMessage(P2PMessage& message, std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) {
        return incomingMessages_.pop(message, timeout);
    }
    
    // ----- Handshake Protocol -----
    
    bool performHandshake(const std::string& ourPeerId, const std::string& ourVersion, uint16_t listeningPort) {
        if (handshakeCompleted_) return true;
        
        try {
            if (peerInfo_.outbound) {
                // We initiated the connection, send handshake first
                auto handshakeMsg = P2PMessage::createHandshake(ourPeerId, listeningPort);
                if (!sendMessage(handshakeMsg)) {
                    return false;
                }
                
                // Wait for handshake acknowledgment
                P2PMessage response;
                auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(HANDSHAKE_TIMEOUT_SECONDS);
                
                while (std::chrono::steady_clock::now() < timeout) {
                    if (receiveMessage(response, std::chrono::milliseconds(100))) {
                        if (response.getType() == MessageType::HANDSHAKE_ACK) {
                            auto payload = response.getJsonPayload();
                            if (payload.value("accepted", false)) {
                                completeHandshake(response);
                                return true;
                            } else {
                                triggerEvent(PeerEvent::ERROR_OCCURRED, "Handshake rejected");
                                return false;
                            }
                        }
                    }
                }
                
                triggerEvent(PeerEvent::TIMEOUT, "Handshake timeout");
                return false;
                
            } else {
                // They initiated the connection, wait for their handshake
                P2PMessage handshake;
                auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(HANDSHAKE_TIMEOUT_SECONDS);
                
                while (std::chrono::steady_clock::now() < timeout) {
                    if (receiveMessage(handshake, std::chrono::milliseconds(100))) {
                        if (handshake.getType() == MessageType::HANDSHAKE) {
                            // Send acknowledgment
                            auto ackMsg = P2PMessage::createHandshakeAck(ourPeerId, true);
                            if (sendMessage(ackMsg)) {
                                completeHandshake(handshake);
                                return true;
                            }
                            return false;
                        }
                    }
                }
                
                triggerEvent(PeerEvent::TIMEOUT, "Handshake timeout");
                return false;
            }
            
        } catch (const std::exception& e) {
            triggerEvent(PeerEvent::ERROR_OCCURRED, "Handshake error: " + std::string(e.what()));
            return false;
        }
    }
    
    // ----- Status and Information -----
    
    bool isConnected() const {
        return running_ && peerInfo_.connected && socket_ && socket_->is_open();
    }
    
    bool isHandshakeCompleted() const {
        return handshakeCompleted_;
    }
    
    const PeerInfo& getPeerInfo() const {
        std::lock_guard<std::mutex> lock(statsMutex_);
        return peerInfo_;
    }
    
    json getConnectionStats() const {
        std::lock_guard<std::mutex> lock(statsMutex_);
        return {
            {"peer_info", peerInfo_.toJson()},
            {"incoming_queue_size", incomingMessages_.size()},
            {"outgoing_queue_size", outgoingMessages_.size()},
            {"handshake_completed", handshakeCompleted_.load()},
            {"last_heartbeat_seconds", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - lastHeartbeat_).count()}
        };
    }
    
    // ----- Event Handling -----
    
    void setMessageHandler(MessageHandler handler) {
        messageHandler_ = handler;
    }
    
    void setPeerEventHandler(PeerEventHandler handler) {
        eventHandler_ = handler;
    }
    
    // ----- Heartbeat -----
    
    void sendHeartbeat() {
        if (!isConnected()) return;
        
        auto pingMsg = P2PMessage::createPing(peerInfo_.peerId);
        sendMessage(pingMsg);
        lastHeartbeat_ = std::chrono::system_clock::now();
    }
    
    bool isHeartbeatAlive() const {
        auto now = std::chrono::system_clock::now();
        auto timeSinceHeartbeat = std::chrono::duration_cast<std::chrono::seconds>(
            now - lastHeartbeat_).count();
        return timeSinceHeartbeat < (HEARTBEAT_INTERVAL_SECONDS * 3);
    }

private:
    void startCommunication() {
        running_ = true;
        receiveThread_ = std::thread(&PeerConnection::receiveLoop, this);
        sendThread_ = std::thread(&PeerConnection::sendLoop, this);
    }
    
    void receiveLoop() {
        while (running_) {
            try {
                std::vector<uint8_t> headerBuffer(MessageHeader::HEADER_SIZE);
                
                // Read message header
                std::error_code ec;
                size_t headerBytesRead = asio::read(*socket_, asio::buffer(headerBuffer), ec);
                
                if (ec || headerBytesRead != MessageHeader::HEADER_SIZE) {
                    if (running_) {
                        triggerEvent(PeerEvent::ERROR_OCCURRED, "Failed to read message header");
                    }
                    break;
                }
                
                // Parse header to get payload size
                MessageHeader header;
                std::memcpy(&header, headerBuffer.data(), MessageHeader::HEADER_SIZE);
                
                if (!header.isValid()) {
                    triggerEvent(PeerEvent::ERROR_OCCURRED, "Invalid message header");
                    continue;
                }
                
                // Read payload
                std::vector<uint8_t> payloadBuffer(header.payloadSize);
                size_t payloadBytesRead = asio::read(*socket_, asio::buffer(payloadBuffer), ec);
                
                if (ec || payloadBytesRead != header.payloadSize) {
                    triggerEvent(PeerEvent::ERROR_OCCURRED, "Failed to read message payload");
                    break;
                }
                
                // Combine header and payload
                std::vector<uint8_t> fullMessage;
                fullMessage.reserve(MessageHeader::HEADER_SIZE + header.payloadSize);
                fullMessage.insert(fullMessage.end(), headerBuffer.begin(), headerBuffer.end());
                fullMessage.insert(fullMessage.end(), payloadBuffer.begin(), payloadBuffer.end());
                
                // Deserialize message
                P2PMessage message = P2PMessage::deserialize(fullMessage);
                
                // Update activity
                updateActivity();
                updateStats(false, message.getTotalSize());
                
                // Handle special messages
                handleSpecialMessages(message);
                
                // Add to incoming queue
                if (!incomingMessages_.push(message)) {
                    triggerEvent(PeerEvent::ERROR_OCCURRED, "Incoming message queue full");
                }
                
                // Trigger message received event
                if (messageHandler_) {
                    messageHandler_(peerInfo_.peerId, message.getType(), message.getPayload());
                }
                
                triggerEvent(PeerEvent::MESSAGE_RECEIVED, message.toString());
                
            } catch (const std::exception& e) {
                if (running_) {
                    triggerEvent(PeerEvent::ERROR_OCCURRED, "Receive error: " + std::string(e.what()));
                }
                break;
            }
        }
    }
    
    void sendLoop() {
        while (running_) {
            try {
                P2PMessage message;
                if (outgoingMessages_.pop(message, std::chrono::milliseconds(100))) {
                    auto serialized = message.serialize();
                    
                    std::error_code ec;
                    size_t bytesWritten = asio::write(*socket_, asio::buffer(serialized), ec);
                    
                    if (ec || bytesWritten != serialized.size()) {
                        if (running_) {
                            triggerEvent(PeerEvent::ERROR_OCCURRED, "Failed to send message");
                        }
                        break;
                    }
                    
                    updateActivity();
                }
            } catch (const std::exception& e) {
                if (running_) {
                    triggerEvent(PeerEvent::ERROR_OCCURRED, "Send error: " + std::string(e.what()));
                }
                break;
            }
        }
    }
    
    void handleSpecialMessages(const P2PMessage& message) {
        switch (message.getType()) {
            case MessageType::PING: {
                // Respond with PONG
                auto pongMsg = P2PMessage::createPong(peerInfo_.peerId, message.getMessageId());
                sendMessage(pongMsg);
                break;
            }
            case MessageType::PONG: {
                // Update last activity
                updateActivity();
                break;
            }
            case MessageType::DISCONNECT: {
                running_ = false;
                break;
            }
            default:
                break;
        }
    }
    
    void completeHandshake(const P2PMessage& handshakeMessage) {
        auto payload = handshakeMessage.getJsonPayload();
        peerInfo_.peerId = payload.value("peer_id", "");
        peerInfo_.version = payload.value("version", "");
        
        if (payload.contains("capabilities")) {
            peerInfo_.capabilities = payload["capabilities"];
        }
        
        handshakeCompleted_ = true;
        peerInfo_.status = PeerInfo::Status::CONNECTED;
        triggerEvent(PeerEvent::HANDSHAKE_COMPLETED, "Handshake successful");
    }
    
    void updateConnectionInfo() {
        if (socket_ && socket_->is_open()) {
            try {
                auto remoteEndpoint = socket_->remote_endpoint();
                if (peerInfo_.address.empty()) {
                    peerInfo_.address = remoteEndpoint.address().to_string();
                }
                if (peerInfo_.port == 0) {
                    peerInfo_.port = remoteEndpoint.port();
                }
            } catch (...) {
                // Ignore errors in getting endpoint info
            }
        }
    }
    
    void updateActivity() {
        std::lock_guard<std::mutex> lock(statsMutex_);
        peerInfo_.lastActivity = std::chrono::system_clock::now();
    }
    
    void updateStats(bool sent, size_t bytes) {
        std::lock_guard<std::mutex> lock(statsMutex_);
        if (sent) {
            peerInfo_.messagesSent++;
            peerInfo_.bytesSent += bytes;
        } else {
            peerInfo_.messagesReceived++;
            peerInfo_.bytesReceived += bytes;
        }
    }
    
    void triggerEvent(PeerEvent event, const std::string& data) {
        if (eventHandler_) {
            eventHandler_(peerInfo_.peerId, event, data);
        }
    }
};

// ----- Peer Manager -----
class PeerManager {
private:
    asio::io_context& ioContext_;
    std::map<std::string, std::shared_ptr<PeerConnection>> peers_;
    mutable std::shared_mutex peersMutex_;
    
    NetworkConfig config_;
    MessageHandler messageHandler_;
    PeerEventHandler eventHandler_;
    
    // Bootstrap nodes
    std::vector<BootstrapNode> bootstrapNodes_;
    mutable std::mutex bootstrapMutex_;
    
public:
    explicit PeerManager(asio::io_context& ioContext, const NetworkConfig& config = NetworkConfig{})
        : ioContext_(ioContext), config_(config) {}
    
    // ----- Peer Management -----
    
    std::shared_ptr<PeerConnection> addPeer(const std::string& address, uint16_t port) {
        std::string peerId = generatePeerId(address, port);
        
        std::unique_lock<std::shared_mutex> lock(peersMutex_);
        if (peers_.find(peerId) != peers_.end()) {
            return peers_[peerId]; // Already exists
        }
        
        if (peers_.size() >= config_.maxPeers) {
            return nullptr; // Peer limit reached
        }
        
        auto peer = std::make_shared<PeerConnection>(ioContext_, address, port);
        peer->setMessageHandler(messageHandler_);
        peer->setPeerEventHandler(eventHandler_);
        
        peers_[peerId] = peer;
        return peer;
    }
    
    std::shared_ptr<PeerConnection> addIncomingPeer(std::shared_ptr<asio::ip::tcp::socket> socket) {
        std::unique_lock<std::shared_mutex> lock(peersMutex_);
        if (peers_.size() >= config_.maxPeers) {
            return nullptr; // Peer limit reached
        }
        
        auto peer = std::make_shared<PeerConnection>(ioContext_, socket);
        peer->setMessageHandler(messageHandler_);
        peer->setPeerEventHandler(eventHandler_);
        
        std::string peerId = generateTempPeerId();
        peers_[peerId] = peer;
        return peer;
    }
    
    void removePeer(const std::string& peerId) {
        std::unique_lock<std::shared_mutex> lock(peersMutex_);
        auto it = peers_.find(peerId);
        if (it != peers_.end()) {
            it->second->disconnect();
            peers_.erase(it);
        }
    }
    
    std::shared_ptr<PeerConnection> getPeer(const std::string& peerId) {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        auto it = peers_.find(peerId);
        return it != peers_.end() ? it->second : nullptr;
    }
    
    std::vector<std::shared_ptr<PeerConnection>> getAllPeers() {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        std::vector<std::shared_ptr<PeerConnection>> result;
        result.reserve(peers_.size());
        
        for (const auto& [peerId, peer] : peers_) {
            result.push_back(peer);
        }
        
        return result;
    }
    
    size_t getPeerCount() const {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        return peers_.size();
    }
    
    // ----- Bootstrap Management -----
    
    void addBootstrapNode(const std::string& address, uint16_t port, bool trusted = false) {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        bootstrapNodes_.push_back({address, port, trusted, 0});
    }
    
    std::vector<BootstrapNode> getBootstrapNodes() const {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        return bootstrapNodes_;
    }
    
    // ----- Event Handling -----
    
    void setMessageHandler(MessageHandler handler) {
        messageHandler_ = handler;
        
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        for (auto& [peerId, peer] : peers_) {
            peer->setMessageHandler(handler);
        }
    }
    
    void setPeerEventHandler(PeerEventHandler handler) {
        eventHandler_ = handler;
        
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        for (auto& [peerId, peer] : peers_) {
            peer->setPeerEventHandler(handler);
        }
    }
    
    // ----- Broadcasting -----
    
    void broadcastMessage(const P2PMessage& message, const std::string& excludePeerId = "") {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        for (const auto& [peerId, peer] : peers_) {
            if (peerId != excludePeerId && peer->isConnected() && peer->isHandshakeCompleted()) {
                peer->sendMessage(message);
            }
        }
    }
    
    // ----- Statistics -----
    
    json getStats() const {
        std::shared_lock<std::shared_mutex> lock(peersMutex_);
        
        size_t connectedCount = 0;
        size_t handshakeCompletedCount = 0;
        uint64_t totalMessagesSent = 0;
        uint64_t totalMessagesReceived = 0;
        
        for (const auto& [peerId, peer] : peers_) {
            if (peer->isConnected()) connectedCount++;
            if (peer->isHandshakeCompleted()) handshakeCompletedCount++;
            
            auto stats = peer->getConnectionStats();
            auto peerInfo = stats["peer_info"];
            totalMessagesSent += peerInfo.value("messages_sent", 0);
            totalMessagesReceived += peerInfo.value("messages_received", 0);
        }
        
        return {
            {"total_peers", peers_.size()},
            {"connected_peers", connectedCount},
            {"handshake_completed", handshakeCompletedCount},
            {"total_messages_sent", totalMessagesSent},
            {"total_messages_received", totalMessagesReceived},
            {"bootstrap_nodes", bootstrapNodes_.size()}
        };
    }

private:
    std::string generatePeerId(const std::string& address, uint16_t port) {
        return address + ":" + std::to_string(port);
    }
    
    std::string generateTempPeerId() {
        static std::atomic<uint64_t> counter{0};
        return "temp_" + std::to_string(counter++);
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_PEER_HPP