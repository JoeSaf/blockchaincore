// p2p_message.hpp - P2P Message System
#ifndef P2P_MESSAGE_HPP
#define P2P_MESSAGE_HPP

#include "p2p_types.hpp"
#include "blockchain_core.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <queue>
#include <condition_variable>
namespace blockchain {
namespace p2p {

// ----- Message Header Structure -----
struct MessageHeader {
    uint32_t magic = 0xDEADBEEF;           // Protocol magic number
    MessageType type;                       // Message type
    uint32_t payloadSize;                   // Payload size in bytes
    uint32_t checksum;                      // CRC32 of payload
    uint64_t timestamp;                     // Unix timestamp
    char senderId[64];                      // Sender peer ID
    char messageId[32];                     // Unique message ID
    uint8_t version = 1;                    // Message format version
    uint8_t priority = static_cast<uint8_t>(MessagePriority::NORMAL);
    uint8_t flags = 0;                      // Message flags
    uint8_t reserved = 0;                   // Reserved for future use
    
    static constexpr size_t HEADER_SIZE = sizeof(MessageHeader);
    
    bool isValid() const {
        return magic == 0xDEADBEEF && 
               payloadSize <= MAX_MESSAGE_SIZE &&
               version >= 1;
    }
};

// ----- P2P Message Class -----
class P2PMessage {
private:
    MessageHeader header_;
    std::string payload_;
    json jsonPayload_;
    bool isJsonPayload_;
    
    // Generate unique message ID
    std::string generateMessageId() const {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << dis(gen);
        }
        return ss.str();
    }
    
    // Calculate CRC32 checksum
    uint32_t calculateChecksum(const std::string& data) const {
        uint32_t crc = 0xFFFFFFFF;
        const uint32_t polynomial = 0xEDB88320;
        
        for (char byte : data) {
            crc ^= static_cast<uint32_t>(byte);
            for (int i = 0; i < 8; ++i) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                } else {
                    crc >>= 1;
                }
            }
        }
        return ~crc;
    }
    
public:
    // ----- Constructors -----
    
    P2PMessage() : isJsonPayload_(false) {
        std::memset(&header_, 0, sizeof(header_));
        header_.magic = 0xDEADBEEF;
        header_.version = 1;
        header_.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        std::string msgId = generateMessageId();
        std::strncpy(header_.messageId, msgId.c_str(), sizeof(header_.messageId) - 1);
    }
    
    P2PMessage(MessageType type, const std::string& payload) : P2PMessage() {
        header_.type = type;
        payload_ = payload;
        isJsonPayload_ = false;
        updateHeader();
    }
    
    P2PMessage(MessageType type, const json& jsonPayload) : P2PMessage() {
        header_.type = type;
        jsonPayload_ = jsonPayload;
        payload_ = jsonPayload.dump();
        isJsonPayload_ = true;
        updateHeader();
    }
    
    // ----- Getters -----
    
    MessageType getType() const { return header_.type; }
    const std::string& getPayload() const { return payload_; }
    const json& getJsonPayload() const { return jsonPayload_; }
    bool isJsonMessage() const { return isJsonPayload_; }
    
    std::string getSenderId() const { 
        return std::string(header_.senderId, strnlen(header_.senderId, sizeof(header_.senderId))); 
    }
    
    uint64_t getTimestamp() const { return header_.timestamp; }
    
    std::string getMessageId() const { 
        return std::string(header_.messageId, strnlen(header_.messageId, sizeof(header_.messageId))); 
    }
    
    MessagePriority getPriority() const { 
        return static_cast<MessagePriority>(header_.priority); 
    }
    
    uint32_t getPayloadSize() const { return header_.payloadSize; }
    uint32_t getChecksum() const { return header_.checksum; }
    size_t getTotalSize() const { return MessageHeader::HEADER_SIZE + payload_.size(); }
    
    // ----- Setters -----
    
    void setSenderId(const std::string& senderId) {
        std::memset(header_.senderId, 0, sizeof(header_.senderId));
        std::strncpy(header_.senderId, senderId.c_str(), sizeof(header_.senderId) - 1);
    }
    
    void setPriority(MessagePriority priority) {
        header_.priority = static_cast<uint8_t>(priority);
    }
    
    void setFlags(uint8_t flags) {
        header_.flags = flags;
    }
    
    // ----- Validation -----
    
    bool isValid() const {
        if (!header_.isValid()) return false;
        if (payload_.size() != header_.payloadSize) return false;
        if (calculateChecksum(payload_) != header_.checksum) return false;
        return true;
    }
    
    bool hasExpired(uint32_t maxAgeSeconds = 300) const {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return (now - header_.timestamp) > maxAgeSeconds;
    }
    
    // ----- Serialization -----
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        result.reserve(MessageHeader::HEADER_SIZE + payload_.size());
        
        // Serialize header
        const uint8_t* headerBytes = reinterpret_cast<const uint8_t*>(&header_);
        result.insert(result.end(), headerBytes, headerBytes + MessageHeader::HEADER_SIZE);
        
        // Serialize payload
        result.insert(result.end(), payload_.begin(), payload_.end());
        
        return result;
    }
    
    static P2PMessage deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < MessageHeader::HEADER_SIZE) {
            throw std::runtime_error("Invalid message: too small");
        }
        
        P2PMessage message;
        
        // Deserialize header
        std::memcpy(&message.header_, data.data(), MessageHeader::HEADER_SIZE);
        
        if (!message.header_.isValid()) {
            throw std::runtime_error("Invalid message header");
        }
        
        if (data.size() < MessageHeader::HEADER_SIZE + message.header_.payloadSize) {
            throw std::runtime_error("Invalid message: payload too small");
        }
        
        // Deserialize payload
        message.payload_.assign(
            data.begin() + MessageHeader::HEADER_SIZE,
            data.begin() + MessageHeader::HEADER_SIZE + message.header_.payloadSize
        );
        
        // Try to parse as JSON
        try {
            message.jsonPayload_ = json::parse(message.payload_);
            message.isJsonPayload_ = true;
        } catch (...) {
            message.isJsonPayload_ = false;
        }
        
        if (!message.isValid()) {
            throw std::runtime_error("Message validation failed");
        }
        
        return message;
    }
    
    // ----- Utility Methods -----
    
    json toJson() const {
        return {
            {"type", messageTypeToString(header_.type)},
            {"sender_id", getSenderId()},
            {"message_id", getMessageId()},
            {"timestamp", header_.timestamp},
            {"payload_size", header_.payloadSize},
            {"checksum", header_.checksum},
            {"priority", static_cast<int>(getPriority())},
            {"flags", header_.flags},
            {"is_json", isJsonPayload_},
            {"payload", isJsonPayload_ ? jsonPayload_ : json(payload_)}
        };
    }
    
    std::string toString() const {
        std::stringstream ss;
        ss << "P2PMessage{type=" << messageTypeToString(header_.type)
           << ", sender=" << getSenderId()
           << ", size=" << payload_.size()
           << ", id=" << getMessageId()
           << "}";
        return ss.str();
    }
    
    // ----- Factory Methods -----
    
    static P2PMessage createPing(const std::string& senderId) {
        P2PMessage msg(MessageType::PING, json{
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"version", PROTOCOL_VERSION}
        });
        msg.setSenderId(senderId);
        return msg;
    }
    
    static P2PMessage createPong(const std::string& senderId, const std::string& originalMessageId) {
        P2PMessage msg(MessageType::PONG, json{
            {"original_message_id", originalMessageId},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        return msg;
    }
    
    static P2PMessage createHandshake(const std::string& senderId, uint16_t listeningPort) {
        P2PMessage msg(MessageType::HANDSHAKE, json{
            {"peer_id", senderId},
            {"version", PROTOCOL_VERSION},
            {"listening_port", listeningPort},
            {"capabilities", std::vector<std::string>{"blockchain", "sync", "mempool"}},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        msg.setPriority(MessagePriority::HIGH);
        return msg;
    }
    
    static P2PMessage createHandshakeAck(const std::string& senderId, bool accepted) {
        P2PMessage msg(MessageType::HANDSHAKE_ACK, json{
            {"accepted", accepted},
            {"peer_id", senderId},
            {"version", PROTOCOL_VERSION},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        msg.setPriority(MessagePriority::HIGH);
        return msg;
    }
    
    static P2PMessage createBlockAnnouncement(const std::string& senderId, const json& blockData) {
        P2PMessage msg(MessageType::BLOCK_ANNOUNCEMENT, json{
            {"block", blockData},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        msg.setPriority(MessagePriority::HIGH);
        return msg;
    }
    
    static P2PMessage createTransaction(const std::string& senderId, const json& transactionData) {
        P2PMessage msg(MessageType::TRANSACTION, json{
            {"transaction", transactionData},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        msg.setPriority(MessagePriority::NORMAL);
        return msg;
    }
    
    static P2PMessage createSyncRequest(const std::string& senderId, size_t fromBlock = 0) {
        P2PMessage msg(MessageType::SYNC_REQUEST, json{
            {"from_block", fromBlock},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        msg.setPriority(MessagePriority::HIGH);
        return msg;
    }
    
    static P2PMessage createPeerListRequest(const std::string& senderId) {
        P2PMessage msg(MessageType::PEER_LIST_REQUEST, json{
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        });
        msg.setSenderId(senderId);
        return msg;
    }
    
private:
    void updateHeader() {
        header_.payloadSize = static_cast<uint32_t>(payload_.size());
        header_.checksum = calculateChecksum(payload_);
        header_.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ----- Message Queue -----
class MessageQueue {
private:
    std::queue<P2PMessage> queue_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    size_t maxSize_;
    
public:
    explicit MessageQueue(size_t maxSize = 1000) : maxSize_(maxSize) {}
    
    bool push(const P2PMessage& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= maxSize_) {
            return false; // Queue full
        }
        queue_.push(message);
        condition_.notify_one();
        return true;
    }
    
    bool pop(P2PMessage& message, std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (condition_.wait_for(lock, timeout, [this] { return !queue_.empty(); })) {
            message = queue_.front();
            queue_.pop();
            return true;
        }
        return false;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::queue<P2PMessage> empty;
        queue_.swap(empty);
    }
};

// ----- Message Batch Processing -----
class MessageBatch {
private:
    std::vector<P2PMessage> messages_;
    size_t maxBatchSize_;
    
public:
    explicit MessageBatch(size_t maxBatchSize = 100) : maxBatchSize_(maxBatchSize) {
        messages_.reserve(maxBatchSize);
    }
    
    bool addMessage(const P2PMessage& message) {
        if (messages_.size() >= maxBatchSize_) {
            return false;
        }
        messages_.push_back(message);
        return true;
    }
    
    const std::vector<P2PMessage>& getMessages() const {
        return messages_;
    }
    
    size_t size() const {
        return messages_.size();
    }
    
    bool empty() const {
        return messages_.empty();
    }
    
    void clear() {
        messages_.clear();
    }
    
    bool isFull() const {
        return messages_.size() >= maxBatchSize_;
    }
    
    // Serialize batch as single message
    std::vector<uint8_t> serialize() const {
        json batchJson = json::array();
        for (const auto& msg : messages_) {
            batchJson.push_back(msg.toJson());
        }
        
        std::string payload = batchJson.dump();
        P2PMessage batchMessage(MessageType::CUSTOM, payload);
        return batchMessage.serialize();
    }
    
    // Deserialize batch from message
    static MessageBatch deserialize(const P2PMessage& message) {
        MessageBatch batch;
        
        if (message.getType() != MessageType::CUSTOM) {
            throw std::runtime_error("Invalid batch message type");
        }
        
        try {
            json batchJson = json::parse(message.getPayload());
            for (const auto& msgJson : batchJson) {
                // Reconstruct individual messages from JSON
                MessageType type = stringToMessageType(msgJson["type"]);
                json payload = msgJson["payload"];
                
                P2PMessage msg(type, payload);
                msg.setSenderId(msgJson["sender_id"]);
                batch.addMessage(msg);
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to deserialize message batch: " + std::string(e.what()));
        }
        
        return batch;
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_MESSAGE_HPP