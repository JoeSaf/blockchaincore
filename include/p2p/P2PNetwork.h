#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include "../blockchain/Block.h"
#include "../blockchain/Transaction.h"

using asio::ip::tcp;
using asio::ip::udp;

enum class MessageType {
    PEER_DISCOVERY,
    PEER_DISCOVERY_RESPONSE,
    BLOCK_BROADCAST,
    TRANSACTION_BROADCAST,
    CHAIN_SYNC_REQUEST,
    CHAIN_SYNC_RESPONSE,
    HEARTBEAT,
    HEARTBEAT_RESPONSE
};

struct NetworkMessage {
    MessageType type;
    std::string messageId;
    std::string senderId;
    std::time_t timestamp;
    nlohmann::json payload;
    uint32_t ttl;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    std::string serialize() const;
    static NetworkMessage deserialize(const std::string& data);
};



struct PeerInfo {
    std::string peerId;
    std::string ipAddress;
    uint16_t port;
    uint32_t chainHeight;
    std::time_t lastSeen;
    bool isConnected;
    std::shared_ptr<tcp::socket> socket;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

class P2PNetwork {
public:
    // Constructor
    P2PNetwork(uint16_t tcpPort = 8333, uint16_t udpPort = 8334);
    
    // Destructor
    ~P2PNetwork();
    
    // Network lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    
    // Peer management
    void discoverPeers();
    bool connectToPeer(const std::string& ipAddress, uint16_t port);
    void disconnectPeer(const std::string& peerId);
    std::vector<PeerInfo> getConnectedPeers() const;
    uint32_t getPeerCount() const;
    
    // Message broadcasting
    void broadcastBlock(const Block& block);
    void broadcastTransaction(const Transaction& transaction);
    void requestChainSync();
    void sendHeartbeat();
    
    // Message handling callbacks
    void setBlockReceivedCallback(std::function<void(const Block&, const std::string&)> callback);
    void setTransactionReceivedCallback(std::function<void(const Transaction&, const std::string&)> callback);
    void setChainSyncRequestCallback(std::function<std::vector<Block>(uint32_t)> callback);
    void setPeerConnectedCallback(std::function<void(const PeerInfo&)> callback);
    void setPeerDisconnectedCallback(std::function<void(const std::string&)> callback);
    
    // Node identification
    const std::string& getNodeId() const { return nodeId_; }
    void setChainHeight(uint32_t height) { chainHeight_ = height; }
    uint32_t getChainHeight() const { return chainHeight_; }
    
    // Network statistics
    uint64_t getMessagesSent() const { return messagesSent_; }
    uint64_t getMessagesReceived() const { return messagesReceived_; }
    uint64_t getBytesTransferred() const { return bytesTransferred_; }
    
    // Configuration
    void setMaxPeers(uint32_t maxPeers) { maxPeers_ = maxPeers; }
    void setHeartbeatInterval(uint32_t seconds) { heartbeatInterval_ = seconds; }
    void setMessageTTL(uint32_t ttl) { messageTTL_ = ttl; }

private:
    // Network configuration
    std::string nodeId_;
    uint16_t tcpPort_;
    uint16_t udpPort_;
    uint32_t chainHeight_;
    uint32_t maxPeers_;
    uint32_t heartbeatInterval_;
    uint32_t messageTTL_;
    
    // ASIO components
    asio::io_context ioContext_;
    std::unique_ptr<tcp::acceptor> tcpAcceptor_;
    std::unique_ptr<udp::socket> udpSocket_;
    std::vector<std::thread> networkThreads_;
    
    // State management
    std::atomic<bool> running_;
    mutable std::mutex peersMutex_;
    mutable std::mutex messagesMutex_;
    
    // Peer management
    std::unordered_map<std::string, PeerInfo> peers_;
    std::unordered_set<std::string> seenMessages_;
    
    // Statistics
    std::atomic<uint64_t> messagesSent_;
    std::atomic<uint64_t> messagesReceived_;
    std::atomic<uint64_t> bytesTransferred_;
    
    // Callbacks
    std::function<void(const Block&, const std::string&)> blockReceivedCallback_;
    std::function<void(const Transaction&, const std::string&)> transactionReceivedCallback_;
    std::function<std::vector<Block>(uint32_t)> chainSyncRequestCallback_;
    std::function<void(const PeerInfo&)> peerConnectedCallback_;
    std::function<void(const std::string&)> peerDisconnectedCallback_;
    
    // Network operations
    void startTcpServer();
    void startUdpListener();
    void handleNewConnection(std::shared_ptr<tcp::socket> socket);
    void handlePeerConnection(std::shared_ptr<tcp::socket> socket, const std::string& peerId);
    void handleUdpMessage(const std::string& data, const udp::endpoint& senderEndpoint);
    
    // Message handling
    void processMessage(const NetworkMessage& message, const std::string& senderId);
    void handlePeerDiscovery(const NetworkMessage& message, const udp::endpoint& senderEndpoint);
    void handleBlockBroadcast(const NetworkMessage& message, const std::string& senderId);
    void handleTransactionBroadcast(const NetworkMessage& message, const std::string& senderId);
    void handleChainSyncRequest(const NetworkMessage& message, const std::string& senderId);
    void handleChainSyncResponse(const NetworkMessage& message, const std::string& senderId);
    void handleHeartbeat(const NetworkMessage& message, const std::string& senderId);
    
    // Message utilities
    void forwardMessage(const NetworkMessage& message, const std::string& excludePeerId = "");
    bool isMessageSeen(const std::string& messageId) const;
    void markMessageSeen(const std::string& messageId);
    NetworkMessage createMessage(MessageType type, const nlohmann::json& payload);
    void sendMessageToPeer(const NetworkMessage& message, const std::string& peerId);
    void sendUdpMessage(const NetworkMessage& message, const udp::endpoint& endpoint);
    
    // Peer utilities
    void addPeer(const PeerInfo& peer);
    void removePeer(const std::string& peerId);
    void updatePeerLastSeen(const std::string& peerId);
    void cleanupInactivePeers();
    
    // Background tasks
    void heartbeatLoop();
    void peerCleanupLoop();
    void networkMainLoop();
    
    // Utility functions
    std::string generateNodeId();
    std::string generateMessageId();
    std::vector<std::string> getLocalIpAddresses();
};
