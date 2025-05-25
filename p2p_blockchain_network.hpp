// p2p_blockchain_network.hpp
#ifndef P2P_BLOCKCHAIN_NETWORK_HPP
#define P2P_BLOCKCHAIN_NETWORK_HPP

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <queue>
#include <future>
#include <condition_variable>
#include <memory>
#include <functional>
#include <random>
#include <algorithm>

// Network includes
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// Cryptography includes
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// JSON for message serialization
#include <nlohmann/json.hpp>

namespace blockchain {
namespace p2p {

using json = nlohmann::json;
using namespace std::chrono;

// Forward declarations
class BlockchainP2PNode;
class PeerConnection;
class MessageHandler;

// ----- Constants -----
constexpr uint16_t DEFAULT_P2P_PORT = 8333;
constexpr size_t MAX_PEERS = 125;
constexpr size_t MAX_OUTBOUND_PEERS = 8;
constexpr size_t MAX_MESSAGE_SIZE = 32 * 1024 * 1024; // 32MB
constexpr int PING_INTERVAL_SECONDS = 30;
constexpr int PEER_TIMEOUT_SECONDS = 90;
constexpr int BOOTSTRAP_RETRY_SECONDS = 60;

// ----- Message Types -----
enum class MessageType : uint8_t {
    VERSION = 1,
    VERACK = 2,
    PING = 3,
    PONG = 4,
    ADDR = 5,
    GETADDR = 6,
    INV = 7,        // Inventory
    GETDATA = 8,    // Request specific data
    BLOCK = 9,      // Block data
    TX = 10,        // Transaction data
    GETBLOCKS = 11, // Request block hashes
    GETHEADERS = 12,// Request block headers
    HEADERS = 13,   // Block headers
    REJECT = 14,    // Rejection message
    MEMPOOL = 15,   // Request mempool
    FILTERLOAD = 16,// Bloom filter
    FILTERADD = 17, // Add to bloom filter
    FILTERCLEAR = 18,// Clear bloom filter
    NOTFOUND = 19,  // Requested data not found
    BLOCKCHAIN_SYNC = 20, // Custom blockchain sync
    PEER_DISCOVERY = 21,  // Enhanced peer discovery
    ENCRYPTED_DATA = 22   // Encrypted payload
};

// ----- Network Address -----
struct NetworkAddress {
    std::string ip;
    uint16_t port;
    uint64_t services;
    system_clock::time_point timestamp;
    
    NetworkAddress() : port(0), services(0), timestamp(system_clock::now()) {}
    NetworkAddress(const std::string& ip_, uint16_t port_, uint64_t services_ = 0)
        : ip(ip_), port(port_), services(services_), timestamp(system_clock::now()) {}
    
    std::string toString() const {
        return ip + ":" + std::to_string(port);
    }
    
    bool operator==(const NetworkAddress& other) const {
        return ip == other.ip && port == other.port;
    }
    
    bool operator<(const NetworkAddress& other) const {
        if (ip != other.ip) return ip < other.ip;
        return port < other.port;
    }
};

} // namespace p2p
} // namespace blockchain

// Hash specialization for NetworkAddress
namespace std {
template<>
struct hash<blockchain::p2p::NetworkAddress> {
    size_t operator()(const blockchain::p2p::NetworkAddress& addr) const {
        return std::hash<std::string>{}(addr.ip) ^ 
               (std::hash<uint16_t>{}(addr.port) << 1);
    }
};
}

namespace blockchain {
namespace p2p {

// ----- Message Structure -----
struct Message {
    MessageType type;
    std::vector<uint8_t> payload;
    std::string checksum;
    bool encrypted;
    
    Message(MessageType t = MessageType::PING) 
        : type(t), encrypted(false) {}
    
    // Serialize message to wire format
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        
        // Magic bytes (4 bytes)
        uint32_t magic = 0xD9B4BEF9; // Bitcoin-style magic
        result.insert(result.end(), (uint8_t*)&magic, (uint8_t*)&magic + 4);
        
        // Message type (1 byte)
        result.push_back(static_cast<uint8_t>(type));
        
        // Encrypted flag (1 byte)
        result.push_back(encrypted ? 1 : 0);
        
        // Payload length (4 bytes)
        uint32_t payloadLen = payload.size();
        result.insert(result.end(), (uint8_t*)&payloadLen, (uint8_t*)&payloadLen + 4);
        
        // Checksum (32 bytes SHA256)
        std::vector<uint8_t> checksumBytes(32, 0);
        if (!checksum.empty()) {
            for (size_t i = 0; i < std::min(checksum.length() / 2, size_t(32)); ++i) {
                uint8_t byte = std::stoul(checksum.substr(i * 2, 2), nullptr, 16);
                checksumBytes[i] = byte;
            }
        }
        result.insert(result.end(), checksumBytes.begin(), checksumBytes.end());
        
        // Payload
        result.insert(result.end(), payload.begin(), payload.end());
        
        return result;
    }
    
    // Deserialize message from wire format
    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 42) return nullptr; // Minimum header size
        
        // Check magic bytes
        uint32_t magic = *reinterpret_cast<const uint32_t*>(data.data());
        if (magic != 0xD9B4BEF9) return nullptr;
        
        auto msg = std::make_unique<Message>();
        size_t offset = 4;
        
        // Message type
        msg->type = static_cast<MessageType>(data[offset++]);
        
        // Encrypted flag
        msg->encrypted = data[offset++] != 0;
        
        // Payload length
        uint32_t payloadLen = *reinterpret_cast<const uint32_t*>(&data[offset]);
        offset += 4;
        
        if (payloadLen > MAX_MESSAGE_SIZE) return nullptr;
        
        // Checksum (skip for now, but we could verify)
        offset += 32;
        
        // Payload
        if (offset + payloadLen > data.size()) return nullptr;
        msg->payload.assign(data.begin() + offset, data.begin() + offset + payloadLen);
        
        return msg;
    }
};

// ----- Cryptographic Utils -----
class CryptoUtils {
public:
    static std::string generatePeerId() {
        std::vector<uint8_t> randomBytes(20);
        RAND_bytes(randomBytes.data(), 20);
        
        std::string result;
        for (uint8_t byte : randomBytes) {
            char hex[3];
            sprintf(hex, "%02x", byte);
            result += hex;
        }
        return result;
    }
    
    static std::string sha256(const std::vector<uint8_t>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.data(), data.size());
        SHA256_Final(hash, &sha256);
        
        std::string result;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            char hex[3];
            sprintf(hex, "%02x", hash[i]);
            result += hex;
        }
        return result;
    }
    
    static std::vector<uint8_t> encryptAES(const std::vector<uint8_t>& plaintext, 
                                          const std::vector<uint8_t>& key) {
        // AES-256-CBC encryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(16);
        RAND_bytes(iv.data(), 16);
        
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
        
        std::vector<uint8_t> ciphertext;
        ciphertext.insert(ciphertext.end(), iv.begin(), iv.end()); // Prepend IV
        
        int len;
        int ciphertext_len;
        ciphertext.resize(iv.size() + plaintext.size() + AES_BLOCK_SIZE);
        
        EVP_EncryptUpdate(ctx, ciphertext.data() + iv.size(), &len, 
                         plaintext.data(), plaintext.size());
        ciphertext_len = len;
        
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + iv.size() + len, &len);
        ciphertext_len += len;
        
        ciphertext.resize(iv.size() + ciphertext_len);
        
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
    
    static std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& ciphertext, 
                                          const std::vector<uint8_t>& key) {
        if (ciphertext.size() < 16) return {};
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 16);
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
        
        std::vector<uint8_t> plaintext(ciphertext.size() - 16);
        int len;
        int plaintext_len;
        
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                         ciphertext.data() + 16, ciphertext.size() - 16);
        plaintext_len = len;
        
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;
        
        plaintext.resize(plaintext_len);
        
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
};

// ----- Peer Connection -----
class PeerConnection {
private:
    NetworkAddress address_;
    int sockfd_;
    std::atomic<bool> connected_;
    std::atomic<bool> handshakeComplete_;
    std::mutex sendMutex_;
    std::mutex receiveMutex_;
    std::string peerId_;
    std::string version_;
    uint64_t services_;
    system_clock::time_point lastActivity_;
    std::vector<uint8_t> encryptionKey_;
    bool isOutbound_;
    
public:
    PeerConnection(const NetworkAddress& addr, bool outbound = true)
        : address_(addr), sockfd_(-1), connected_(false), 
          handshakeComplete_(false), services_(0), 
          lastActivity_(system_clock::now()), isOutbound_(outbound) {}
    
    ~PeerConnection() {
        disconnect();
    }
    
    bool connect() {
        if (connected_) return true;
        
        sockfd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sockfd_ < 0) return false;
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(address_.port);
        if (inet_pton(AF_INET, address_.ip.c_str(), &addr.sin_addr) <= 0) {
            close(sockfd_);
            return false;
        }
        
        int result = ::connect(sockfd_, (sockaddr*)&addr, sizeof(addr));
        if (result < 0 && errno != EINPROGRESS) {
            close(sockfd_);
            return false;
        }
        
        // Wait for connection to complete (with timeout)
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sockfd_, &writefds);
        
        timeval timeout{5, 0}; // 5 seconds
        if (select(sockfd_ + 1, nullptr, &writefds, nullptr, &timeout) <= 0) {
            close(sockfd_);
            return false;
        }
        
        // Check if connection succeeded
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            close(sockfd_);
            return false;
        }
        
        connected_ = true;
        lastActivity_ = system_clock::now();
        return true;
    }
    
    void disconnect() {
        connected_ = false;
        handshakeComplete_ = false;
        if (sockfd_ >= 0) {
            close(sockfd_);
            sockfd_ = -1;
        }
    }
    
    bool sendMessage(const Message& msg) {
        if (!connected_) return false;
        
        std::lock_guard<std::mutex> lock(sendMutex_);
        
        auto serialized = msg.serialize();
        size_t totalSent = 0;
        
        while (totalSent < serialized.size()) {
            ssize_t sent = send(sockfd_, serialized.data() + totalSent, 
                              serialized.size() - totalSent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(milliseconds(10));
                    continue;
                }
                return false;
            }
            totalSent += sent;
        }
        
        lastActivity_ = system_clock::now();
        return true;
    }
    
    std::unique_ptr<Message> receiveMessage() {
        if (!connected_) return nullptr;
        
        std::lock_guard<std::mutex> lock(receiveMutex_);
        
        // First, read the header to get message size
        std::vector<uint8_t> header(42); // Minimum header size
        size_t totalReceived = 0;
        
        while (totalReceived < header.size()) {
            ssize_t received = recv(sockfd_, header.data() + totalReceived, 
                                  header.size() - totalReceived, MSG_DONTWAIT);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(milliseconds(10));
                    continue;
                }
                return nullptr;
            }
            if (received == 0) return nullptr; // Connection closed
            
            totalReceived += received;
        }
        
        // Parse header to get payload length
        if (header.size() < 42) return nullptr;
        uint32_t payloadLen = *reinterpret_cast<uint32_t*>(&header[10]);
        
        if (payloadLen > MAX_MESSAGE_SIZE) return nullptr;
        
        // Read the payload
        std::vector<uint8_t> fullMessage = header;
        if (payloadLen > 0) {
            size_t oldSize = fullMessage.size();
            fullMessage.resize(oldSize + payloadLen);
            totalReceived = 0;
            
            while (totalReceived < payloadLen) {
                ssize_t received = recv(sockfd_, fullMessage.data() + oldSize + totalReceived, 
                                      payloadLen - totalReceived, MSG_DONTWAIT);
                if (received < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        std::this_thread::sleep_for(milliseconds(10));
                        continue;
                    }
                    return nullptr;
                }
                if (received == 0) return nullptr;
                
                totalReceived += received;
            }
        }
        
        lastActivity_ = system_clock::now();
        return Message::deserialize(fullMessage);
    }
    
    bool performHandshake(const std::string& ourPeerId, const std::string& ourVersion) {
        if (!connected_ || handshakeComplete_) return handshakeComplete_;
        
        // Send VERSION message
        json versionData = {
            {"version", ourVersion},
            {"services", 1}, // NODE_NETWORK
            {"timestamp", duration_cast<seconds>(system_clock::now().time_since_epoch()).count()},
            {"addr_recv", {{"ip", address_.ip}, {"port", address_.port}}},
            {"addr_from", {{"ip", "0.0.0.0"}, {"port", 0}}},
            {"nonce", std::to_string(std::random_device{}())},
            {"user_agent", "BlockchainP2P/1.0"},
            {"start_height", 0},
            {"relay", true}
        };
        
        Message versionMsg(MessageType::VERSION);
        std::string versionStr = versionData.dump();
        versionMsg.payload.assign(versionStr.begin(), versionStr.end());
        versionMsg.checksum = CryptoUtils::sha256(versionMsg.payload);
        
        if (!sendMessage(versionMsg)) return false;
        
        // Wait for VERSION response
        auto response = receiveMessage();
        if (!response || response->type != MessageType::VERSION) return false;
        
        // Parse peer's version info
        try {
            std::string responseStr(response->payload.begin(), response->payload.end());
            json peerVersion = json::parse(responseStr);
            peerId_ = peerVersion.value("nonce", "unknown");
            version_ = peerVersion.value("version", "unknown");
            services_ = peerVersion.value("services", 0);
        } catch (...) {
            return false;
        }
        
        // Send VERACK
        Message verackMsg(MessageType::VERACK);
        if (!sendMessage(verackMsg)) return false;
        
        // Wait for VERACK
        response = receiveMessage();
        if (!response || response->type != MessageType::VERACK) return false;
        
        handshakeComplete_ = true;
        return true;
    }
    
    // Getters
    const NetworkAddress& getAddress() const { return address_; }
    bool isConnected() const { return connected_; }
    bool isHandshakeComplete() const { return handshakeComplete_; }
    const std::string& getPeerId() const { return peerId_; }
    const std::string& getVersion() const { return version_; }
    uint64_t getServices() const { return services_; }
    bool isOutbound() const { return isOutbound_; }
    
    system_clock::time_point getLastActivity() const { return lastActivity_; }
    
    void updateActivity() { lastActivity_ = system_clock::now(); }
};

// ----- Address Manager -----
class AddressManager {
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<NetworkAddress, system_clock::time_point> knownAddresses_;
    std::unordered_set<NetworkAddress> triedAddresses_;
    std::vector<NetworkAddress> bootstrapNodes_;
    std::random_device rd_;
    mutable std::mt19937 gen_;
    
public:
    AddressManager() : gen_(rd_()) {
        // Default bootstrap nodes
        bootstrapNodes_ = {
            {"127.0.0.1", 8333},
            {"localhost", 8334}
        };
    }
    
    void addBootstrapNode(const NetworkAddress& addr) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        bootstrapNodes_.push_back(addr);
    }
    
    void addAddress(const NetworkAddress& addr) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        knownAddresses_[addr] = system_clock::now();
    }
    
    void addAddresses(const std::vector<NetworkAddress>& addresses) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto now = system_clock::now();
        for (const auto& addr : addresses) {
            knownAddresses_[addr] = now;
        }
    }
    
    void markTried(const NetworkAddress& addr) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        triedAddresses_.insert(addr);
    }
    
    std::vector<NetworkAddress> getRandomAddresses(size_t count) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        std::vector<NetworkAddress> candidates;
        
        // Add bootstrap nodes if we don't have many addresses
        if (knownAddresses_.size() < 10) {
            for (const auto& bootstrap : bootstrapNodes_) {
                candidates.push_back(bootstrap);
            }
        }
        
        // Add known addresses
        for (const auto& [addr, timestamp] : knownAddresses_) {
            candidates.push_back(addr);
        }
        
        if (candidates.empty()) return {};
        
        // Shuffle and return requested count
        std::shuffle(candidates.begin(), candidates.end(), gen_);
        if (candidates.size() > count) {
            candidates.resize(count);
        }
        
        return candidates;
    }
    
    std::vector<NetworkAddress> getAllAddresses() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<NetworkAddress> result;
        for (const auto& [addr, timestamp] : knownAddresses_) {
            result.push_back(addr);
        }
        return result;
    }
    
    size_t getKnownCount() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return knownAddresses_.size();
    }
    
    size_t getTriedCount() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return triedAddresses_.size();
    }
};

// ----- Message Handler -----
class MessageHandler {
private:
    std::function<void(const json&)> onBlockReceived_;
    std::function<void(const json&)> onTransactionReceived_;
    std::function<void(const std::vector<NetworkAddress>&)> onAddressesReceived_;
    
public:
    void setBlockHandler(std::function<void(const json&)> handler) {
        onBlockReceived_ = std::move(handler);
    }
    
    void setTransactionHandler(std::function<void(const json&)> handler) {
        onTransactionReceived_ = std::move(handler);
    }
    
    void setAddressHandler(std::function<void(const std::vector<NetworkAddress>&)> handler) {
        onAddressesReceived_ = std::move(handler);
    }
    
    void handleMessage(std::shared_ptr<PeerConnection> peer, const Message& msg) {
        switch (msg.type) {
            case MessageType::PING:
                handlePing(peer, msg);
                break;
            case MessageType::PONG:
                handlePong(peer, msg);
                break;
            case MessageType::ADDR:
                handleAddr(peer, msg);
                break;
            case MessageType::GETADDR:
                handleGetAddr(peer, msg);
                break;
            case MessageType::BLOCK:
                handleBlock(peer, msg);
                break;
            case MessageType::TX:
                handleTransaction(peer, msg);
                break;
            case MessageType::INV:
                handleInventory(peer, msg);
                break;
            case MessageType::GETDATA:
                handleGetData(peer, msg);
                break;
            default:
                std::cout << "Unhandled message type: " 
                         << static_cast<int>(msg.type) << std::endl;
                break;
        }
    }
    
private:
    void handlePing(std::shared_ptr<PeerConnection> peer, const Message& msg) {
        // Respond with PONG
        Message pong(MessageType::PONG);
        pong.payload = msg.payload; // Echo the ping payload
        peer->sendMessage(pong);
    }
    
    void handlePong(std::shared_ptr<PeerConnection> peer, const Message& /*msg*/) {
        // Update peer activity
        peer->updateActivity();
    }
    
    void handleAddr(std::shared_ptr<PeerConnection> /*peer*/, const Message& msg) {
        try {
            std::string payloadStr(msg.payload.begin(), msg.payload.end());
            json addrData = json::parse(payloadStr);
            
            std::vector<NetworkAddress> addresses;
            for (const auto& addr : addrData["addresses"]) {
                NetworkAddress netAddr(addr["ip"], addr["port"]);
                addresses.push_back(netAddr);
            }
            
            if (onAddressesReceived_) {
                onAddressesReceived_(addresses);
            }
        } catch (...) {
            std::cerr << "Error parsing ADDR message" << std::endl;
        }
    }
    
    void handleGetAddr(std::shared_ptr<PeerConnection> peer, const Message& /*msg*/) {
        // This would be implemented by the node to send known addresses
        // For now, send empty response
        Message addrMsg(MessageType::ADDR);
        json addrData = {{"addresses", json::array()}};
        std::string addrStr = addrData.dump();
        addrMsg.payload.assign(addrStr.begin(), addrStr.end());
        peer->sendMessage(addrMsg);
    }
    
    void handleBlock(std::shared_ptr<PeerConnection> /*peer*/, const Message& msg) {
        try {
            std::string payloadStr(msg.payload.begin(), msg.payload.end());
            json blockData = json::parse(payloadStr);
            
            if (onBlockReceived_) {
                onBlockReceived_(blockData);
            }
        } catch (...) {
            std::cerr << "Error parsing BLOCK message" << std::endl;
        }
    }
    
    void handleTransaction(std::shared_ptr<PeerConnection> /*peer*/, const Message& msg) {
        try {
            std::string payloadStr(msg.payload.begin(), msg.payload.end());
            json txData = json::parse(payloadStr);
            
            if (onTransactionReceived_) {
                onTransactionReceived_(txData);
            }
        } catch (...) {
            std::cerr << "Error parsing TX message" << std::endl;
        }
    }
    
    void handleInventory(std::shared_ptr<PeerConnection> peer, const Message& msg) {
        // Handle inventory announcements
        try {
            std::string payloadStr(msg.payload.begin(), msg.payload.end());
            json invData = json::parse(payloadStr);
            
            // Request the data we're interested in
            Message getDataMsg(MessageType::GETDATA);
            getDataMsg.payload = msg.payload; // Request the same items
            peer->sendMessage(getDataMsg);
        } catch (...) {
            std::cerr << "Error parsing INV message" << std::endl;
        }
    }
    
    void handleGetData(std::shared_ptr<PeerConnection> /*peer*/, const Message& /*msg*/) {
        // Handle requests for specific data
        // This would be implemented to serve blocks/transactions from local storage
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_BLOCKCHAIN_NETWORK_HPP