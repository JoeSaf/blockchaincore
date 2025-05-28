#include "p2p/P2PNetwork.h"
#include <spdlog/spdlog.h>

// MessageHandler implementation is integrated into P2PNetwork class
// This file serves as a placeholder for future message handling extensions

namespace MessageHandler {
    
    // Utility functions for message validation
    bool isValidMessageType(MessageType type) {
        switch (type) {
            case MessageType::PEER_DISCOVERY:
            case MessageType::PEER_DISCOVERY_RESPONSE:
            case MessageType::BLOCK_BROADCAST:
            case MessageType::TRANSACTION_BROADCAST:
            case MessageType::CHAIN_SYNC_REQUEST:
            case MessageType::CHAIN_SYNC_RESPONSE:
            case MessageType::HEARTBEAT:
            case MessageType::HEARTBEAT_RESPONSE:
                return true;
            default:
                return false;
        }
    }
    
    // Message size validation
    bool isValidMessageSize(const std::string& message) {
        const size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB
        return message.size() <= MAX_MESSAGE_SIZE;
    }
    
    // Message format validation
    bool isValidMessageFormat(const NetworkMessage& message) {
        if (!isValidMessageType(message.type)) {
            spdlog::warn("Invalid message type received");
            return false;
        }
        
        if (message.messageId.empty() || message.senderId.empty()) {
            spdlog::warn("Message missing required fields");
            return false;
        }
        
        if (message.ttl == 0) {
            spdlog::warn("Message TTL expired");
            return false;
        }
        
        return true;
    }
    
    // Get string representation of message type
    std::string messageTypeToString(MessageType type) {
        switch (type) {
            case MessageType::PEER_DISCOVERY: return "PEER_DISCOVERY";
            case MessageType::PEER_DISCOVERY_RESPONSE: return "PEER_DISCOVERY_RESPONSE";
            case MessageType::BLOCK_BROADCAST: return "BLOCK_BROADCAST";
            case MessageType::TRANSACTION_BROADCAST: return "TRANSACTION_BROADCAST";
            case MessageType::CHAIN_SYNC_REQUEST: return "CHAIN_SYNC_REQUEST";
            case MessageType::CHAIN_SYNC_RESPONSE: return "CHAIN_SYNC_RESPONSE";
            case MessageType::HEARTBEAT: return "HEARTBEAT";
            case MessageType::HEARTBEAT_RESPONSE: return "HEARTBEAT_RESPONSE";
            default: return "UNKNOWN";
        }
    }
    
} // namespace MessageHandler
