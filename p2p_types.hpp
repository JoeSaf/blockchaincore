// p2p_types.hpp - Core P2P Data Structures
#ifndef P2P_TYPES_HPP
#define P2P_TYPES_HPP

#include <string>
#include <chrono>
#include <vector>
#include <map>
#include <atomic>
#include <cstdint>
#include "blockchain_core.hpp"

namespace blockchain {
namespace p2p {

// ----- Constants -----
constexpr uint16_t DEFAULT_P2P_PORT = 8333;
constexpr size_t MAX_MESSAGE_SIZE = 32 * 1024 * 1024; // 32MB
constexpr const char* PROTOCOL_VERSION = "1.0.0";
constexpr size_t MAX_PEERS = 100;
constexpr uint32_t HEARTBEAT_INTERVAL_SECONDS = 30;
constexpr uint32_t CONNECTION_TIMEOUT_SECONDS = 10;
constexpr uint32_t HANDSHAKE_TIMEOUT_SECONDS = 5;

// ----- Message Types -----
enum class MessageType : uint8_t {
    // Connection management
    PING = 0x01,
    PONG = 0x02,
    HANDSHAKE = 0x03,
    HANDSHAKE_ACK = 0x04,
    DISCONNECT = 0x05,
    
    // Blockchain synchronization
    BLOCK_ANNOUNCEMENT = 0x10,
    BLOCK_REQUEST = 0x11,
    BLOCK_RESPONSE = 0x12,
    CHAIN_REQUEST = 0x13,
    CHAIN_RESPONSE = 0x14,
    
    // Transaction management
    TRANSACTION = 0x20,
    MEMPOOL_REQUEST = 0x21,
    MEMPOOL_RESPONSE = 0x22,
    
    // Network coordination
    SYNC_REQUEST = 0x30,
    SYNC_RESPONSE = 0x31,
    PEER_LIST_REQUEST = 0x32,
    PEER_LIST_RESPONSE = 0x33,
    
    // Custom/Extended
    CUSTOM = 0xFF
};

// ----- Network Configuration -----
struct NetworkConfig {
    size_t maxPeers = MAX_PEERS;
    uint32_t connectionTimeout = CONNECTION_TIMEOUT_SECONDS;
    uint32_t handshakeTimeout = HANDSHAKE_TIMEOUT_SECONDS;
    uint32_t heartbeatInterval = HEARTBEAT_INTERVAL_SECONDS;
    size_t maxMessageSize = MAX_MESSAGE_SIZE;
    bool enableEncryption = false;
    std::string protocolVersion = PROTOCOL_VERSION;
    bool enableLogging = true;
    bool allowInboundConnections = true;
    bool enablePeerDiscovery = true;
    
    // Network limits
    size_t maxInboundConnections = 50;
    size_t maxOutboundConnections = 50;
    uint32_t reconnectInterval = 60; // seconds
    uint32_t maxReconnectAttempts = 3;
    
    // Message handling
    uint32_t messageQueueSize = 1000;
    uint32_t messageProcessingThreads = 4;
    
    // Validation
    bool isValid() const {
        return maxPeers > 0 && 
               maxPeers <= 10000 &&
               connectionTimeout > 0 && 
               connectionTimeout <= 300 &&
               maxMessageSize > 0 && 
               maxMessageSize <= 100 * 1024 * 1024;
    }
};

// ----- Peer Information -----
struct PeerInfo {
    std::string peerId;
    std::string address;
    uint16_t port;
    std::string version = PROTOCOL_VERSION;
    bool connected = false;
    bool outbound = false;
    std::chrono::system_clock::time_point lastActivity;
    std::chrono::system_clock::time_point connectionTime;
    
    // Statistics
    uint64_t messagesSent = 0;
    uint64_t messagesReceived = 0;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    
    // Connection state
    enum class Status {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKING,
        CONNECTED,
        DISCONNECTING,
        FAILED
    } status = Status::DISCONNECTED;
    
    // Capabilities
    std::vector<std::string> capabilities;
    
    // Helper methods
    std::string getAddress() const {
        return address + ":" + std::to_string(port);
    }
    
    bool isActive() const {
        auto now = std::chrono::system_clock::now();
        auto inactive_duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - lastActivity).count();
        return connected && inactive_duration < (HEARTBEAT_INTERVAL_SECONDS * 3);
    }
    
    uint64_t getUptimeSeconds() const {
        if (!connected) return 0;
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(
            now - connectionTime).count();
    }
    
    // Convert to JSON for serialization
    json toJson() const {
        return {
            {"peer_id", peerId},
            {"address", address},
            {"port", port},
            {"version", version},
            {"connected", connected},
            {"outbound", outbound},
            {"last_activity_seconds", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - lastActivity).count()},
            {"uptime_seconds", getUptimeSeconds()},
            {"messages_sent", messagesSent},
            {"messages_received", messagesReceived},
            {"bytes_sent", bytesSent},
            {"bytes_received", bytesReceived},
            {"capabilities", capabilities}
        };
    }
    
    // Create from JSON
    static PeerInfo fromJson(const json& j) {
        PeerInfo info;
        info.peerId = j.value("peer_id", "");
        info.address = j.value("address", "");
        info.port = j.value("port", 0);
        info.version = j.value("version", PROTOCOL_VERSION);
        info.connected = j.value("connected", false);
        info.outbound = j.value("outbound", false);
        info.capabilities = j.value("capabilities", std::vector<std::string>{});
        return info;
    }
};

// ----- Network Statistics -----
struct NetworkStats {
    // Connection stats
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> connectionAttempts{0};
    std::atomic<uint64_t> successfulConnections{0};
    std::atomic<uint64_t> failedConnections{0};
    
    // Timing
    std::chrono::system_clock::time_point startTime;
    
    // Current state
    std::atomic<size_t> peerCount{0};
    std::atomic<size_t> inboundConnections{0};
    std::atomic<size_t> outboundConnections{0};
    
    // Message type breakdown
    std::map<MessageType, uint64_t> messageTypeStats;
    
    NetworkStats() : startTime(std::chrono::system_clock::now()) {}
    
    uint64_t getUptimeSeconds() const {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(
            now - startTime).count();
    }
    
    double getConnectionSuccessRate() const {
        uint64_t attempts = connectionAttempts.load();
        return attempts > 0 ? 
            static_cast<double>(successfulConnections.load()) / attempts * 100.0 : 0.0;
    }
    
    double getAverageMessageRate() const {
        uint64_t uptime = getUptimeSeconds();
        return uptime > 0 ? 
            static_cast<double>(messagesReceived.load()) / uptime : 0.0;
    }
    
    json toJson() const {
        return {
            {"messages_sent", messagesSent.load()},
            {"messages_received", messagesReceived.load()},
            {"bytes_sent", bytesSent.load()},
            {"bytes_received", bytesReceived.load()},
            {"connection_attempts", connectionAttempts.load()},
            {"successful_connections", successfulConnections.load()},
            {"failed_connections", failedConnections.load()},
            {"uptime_seconds", getUptimeSeconds()},
            {"peer_count", peerCount.load()},
            {"inbound_connections", inboundConnections.load()},
            {"outbound_connections", outboundConnections.load()},
            {"connection_success_rate", getConnectionSuccessRate()},
            {"average_message_rate", getAverageMessageRate()}
        };
    }
};

// ----- Connection Event Types -----
enum class PeerEvent {
    CONNECTED,
    DISCONNECTED,
    HANDSHAKE_COMPLETED,
    MESSAGE_RECEIVED,
    ERROR_OCCURRED,
    TIMEOUT
};

// ----- Event Callbacks -----
using MessageHandler = std::function<void(const std::string& peerId, MessageType type, const std::string& payload)>;
using PeerEventHandler = std::function<void(const std::string& peerId, PeerEvent event, const std::string& data)>;
using BlockchainEventHandler = std::function<void(const json& data)>;

// ----- Network Discovery -----
struct BootstrapNode {
    std::string address;
    uint16_t port;
    bool trusted = false;
    uint32_t priority = 0; // Lower is higher priority
    
    std::string getAddress() const {
        return address + ":" + std::to_string(port);
    }
    
    json toJson() const {
        return {
            {"address", address},
            {"port", port},
            {"trusted", trusted},
            {"priority", priority}
        };
    }
    
    static BootstrapNode fromJson(const json& j) {
        BootstrapNode node;
        node.address = j.value("address", "");
        node.port = j.value("port", 0);
        node.trusted = j.value("trusted", false);
        node.priority = j.value("priority", 0);
        return node;
    }
};

// ----- Message Priority -----
enum class MessagePriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// ----- Network Error Types -----
enum class NetworkError {
    NONE,
    CONNECTION_FAILED,
    HANDSHAKE_FAILED,
    MESSAGE_TOO_LARGE,
    INVALID_MESSAGE,
    PEER_LIMIT_REACHED,
    TIMEOUT,
    PROTOCOL_MISMATCH,
    AUTHENTICATION_FAILED,
    NETWORK_UNREACHABLE,
    UNKNOWN
};

// ----- Helper Functions -----
inline std::string messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::PING: return "PING";
        case MessageType::PONG: return "PONG";
        case MessageType::HANDSHAKE: return "HANDSHAKE";
        case MessageType::HANDSHAKE_ACK: return "HANDSHAKE_ACK";
        case MessageType::DISCONNECT: return "DISCONNECT";
        case MessageType::BLOCK_ANNOUNCEMENT: return "BLOCK_ANNOUNCEMENT";
        case MessageType::BLOCK_REQUEST: return "BLOCK_REQUEST";
        case MessageType::BLOCK_RESPONSE: return "BLOCK_RESPONSE";
        case MessageType::CHAIN_REQUEST: return "CHAIN_REQUEST";
        case MessageType::CHAIN_RESPONSE: return "CHAIN_RESPONSE";
        case MessageType::TRANSACTION: return "TRANSACTION";
        case MessageType::MEMPOOL_REQUEST: return "MEMPOOL_REQUEST";
        case MessageType::MEMPOOL_RESPONSE: return "MEMPOOL_RESPONSE";
        case MessageType::SYNC_REQUEST: return "SYNC_REQUEST";
        case MessageType::SYNC_RESPONSE: return "SYNC_RESPONSE";
        case MessageType::PEER_LIST_REQUEST: return "PEER_LIST_REQUEST";
        case MessageType::PEER_LIST_RESPONSE: return "PEER_LIST_RESPONSE";
        case MessageType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

inline MessageType stringToMessageType(const std::string& str) {
    static const std::map<std::string, MessageType> typeMap = {
        {"PING", MessageType::PING},
        {"PONG", MessageType::PONG},
        {"HANDSHAKE", MessageType::HANDSHAKE},
        {"HANDSHAKE_ACK", MessageType::HANDSHAKE_ACK},
        {"DISCONNECT", MessageType::DISCONNECT},
        {"BLOCK_ANNOUNCEMENT", MessageType::BLOCK_ANNOUNCEMENT},
        {"BLOCK_REQUEST", MessageType::BLOCK_REQUEST},
        {"BLOCK_RESPONSE", MessageType::BLOCK_RESPONSE},
        {"CHAIN_REQUEST", MessageType::CHAIN_REQUEST},
        {"CHAIN_RESPONSE", MessageType::CHAIN_RESPONSE},
        {"TRANSACTION", MessageType::TRANSACTION},
        {"MEMPOOL_REQUEST", MessageType::MEMPOOL_REQUEST},
        {"MEMPOOL_RESPONSE", MessageType::MEMPOOL_RESPONSE},
        {"SYNC_REQUEST", MessageType::SYNC_REQUEST},
        {"SYNC_RESPONSE", MessageType::SYNC_RESPONSE},
        {"PEER_LIST_REQUEST", MessageType::PEER_LIST_REQUEST},
        {"PEER_LIST_RESPONSE", MessageType::PEER_LIST_RESPONSE},
        {"CUSTOM", MessageType::CUSTOM}
    };
    
    auto it = typeMap.find(str);
    return it != typeMap.end() ? it->second : MessageType::CUSTOM;
}

inline std::string peerEventToString(PeerEvent event) {
    switch (event) {
        case PeerEvent::CONNECTED: return "CONNECTED";
        case PeerEvent::DISCONNECTED: return "DISCONNECTED";
        case PeerEvent::HANDSHAKE_COMPLETED: return "HANDSHAKE_COMPLETED";
        case PeerEvent::MESSAGE_RECEIVED: return "MESSAGE_RECEIVED";
        case PeerEvent::ERROR_OCCURRED: return "ERROR_OCCURRED";
        case PeerEvent::TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

inline std::string networkErrorToString(NetworkError error) {
    switch (error) {
        case NetworkError::NONE: return "NONE";
        case NetworkError::CONNECTION_FAILED: return "CONNECTION_FAILED";
        case NetworkError::HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
        case NetworkError::MESSAGE_TOO_LARGE: return "MESSAGE_TOO_LARGE";
        case NetworkError::INVALID_MESSAGE: return "INVALID_MESSAGE";
        case NetworkError::PEER_LIMIT_REACHED: return "PEER_LIMIT_REACHED";
        case NetworkError::TIMEOUT: return "TIMEOUT";
        case NetworkError::PROTOCOL_MISMATCH: return "PROTOCOL_MISMATCH";
        case NetworkError::AUTHENTICATION_FAILED: return "AUTHENTICATION_FAILED";
        case NetworkError::NETWORK_UNREACHABLE: return "NETWORK_UNREACHABLE";
        default: return "UNKNOWN";
    }
}

} // namespace p2p
} // namespace blockchain

#endif // P2P_TYPES_HPP