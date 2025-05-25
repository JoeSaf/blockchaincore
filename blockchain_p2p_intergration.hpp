// blockchain_p2p_integration.hpp
#ifndef BLOCKCHAIN_P2P_INTEGRATION_HPP
#define BLOCKCHAIN_P2P_INTEGRATION_HPP

#include "blockchain_core.hpp"
#include "p2p_node_manager.hpp"
#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace blockchain {

// ----- Enhanced Blockchain Core with P2P Integration -----
class NetworkedBlockchainCore {
private:
    std::unique_ptr<BlockchainCore> blockchainCore_;
    std::unique_ptr<p2p::P2PNetworkManager> networkManager_;
    
    // Transaction mempool
    std::queue<json> pendingTransactions_;
    mutable std::mutex mempoolMutex_;
    std::condition_variable mempoolCondition_;
    
    // Sync management
    std::atomic<bool> syncInProgress_;
    std::mutex syncMutex_;
    
    // Background processing
    std::thread mempoolProcessor_;
    std::thread syncManager_;
    std::atomic<bool> running_;
    
    // Configuration
    uint16_t p2pPort_;
    bool enableP2P_;
    
public:
    NetworkedBlockchainCore(uint16_t p2pPort = p2p::DEFAULT_P2P_PORT) 
        : p2pPort_(p2pPort), enableP2P_(true), syncInProgress_(false), running_(false) {
        
        blockchainCore_ = std::make_unique<BlockchainCore>(BlockchainCore::get_instance());
        
        if (enableP2P_) {
            networkManager_ = std::make_unique<p2p::P2PNetworkManager>(p2pPort_);
            setupP2PIntegration();
        }
    }
    
    ~NetworkedBlockchainCore() {
        stop();
    }
    
    // ----- Core Blockchain Operations (Delegated) -----
    
    bool initialize() {
        if (!blockchainCore_->initialize()) {
            return false;
        }
        
        if (enableP2P_) {
            return startP2PNetwork();
        }
        
        return true;
    }
    
    bool registerUser(const std::string& username, const std::string& role, const std::string& password) {
        return blockchainCore_->register_user(username, role, password);
    }
    
    std::pair<std::string, std::string> authenticate(const std::string& username, const std::string& password) {
        return blockchainCore_->authenticate(username, password);
    }
    
    std::vector<std::string> listUsers() const {
        return blockchainCore_->list_users();
    }
    
    bool verifyBlockchain() const {
        return blockchainCore_->verify_blockchain();
    }
    
    size_t getChainLength() const {
        return blockchainCore_->get_chain_length();
    }
    
    json getBlockchainData() const {
        return blockchainCore_->get_blockchain_data();
    }
    
    // ----- Enhanced Network Operations -----
    
    bool addBlock(const json& blockData, bool broadcast = true) {
        // Add block to local blockchain
        if (!blockchainCore_->add_custom_block(blockData)) {
            return false;
        }
        
        // Broadcast to network if enabled
        if (enableP2P_ && broadcast && networkManager_) {
            networkManager_->broadcastBlock(blockData);
            std::cout << "Block added and broadcasted to network" << std::endl;
        }
        
        return true;
    }
    
    bool addTransaction(const json& transaction, bool broadcast = true) {
        // Validate transaction first
        if (!validateTransaction(transaction)) {
            std::cerr << "Invalid transaction rejected" << std::endl;
            return false;
        }
        
        // Add to local mempool
        {
            std::lock_guard<std::mutex> lock(mempoolMutex_);
            pendingTransactions_.push(transaction);
        }
        mempoolCondition_.notify_one();
        
        // Broadcast to network if enabled
        if (enableP2P_ && broadcast && networkManager_) {
            networkManager_->broadcastTransaction(transaction);
            std::cout << "Transaction added to mempool and broadcasted" << std::endl;
        }
        
        return true;
    }
    
    void requestNetworkSync() {
        if (enableP2P_ && networkManager_) {
            std::cout << "Requesting blockchain sync from network..." << std::endl;
            networkManager_->requestSync();
        }
    }
    
    void addBootstrapNode(const std::string& ip, uint16_t port) {
        if (enableP2P_ && networkManager_) {
            networkManager_->addBootstrapNode(ip, port);
            std::cout << "Added bootstrap node: " << ip << ":" << port << std::endl;
        }
    }
    
    // ----- P2P Network Management -----
    
    bool startP2PNetwork() {
        if (!enableP2P_ || !networkManager_) {
            return true; // Not an error if P2P is disabled
        }
        
        if (!networkManager_->start()) {
            std::cerr << "Failed to start P2P network" << std::endl;
            return false;
        }
        
        running_ = true;
        
        // Start background processing threads
        mempoolProcessor_ = std::thread(&NetworkedBlockchainCore::processMempoolLoop, this);
        syncManager_ = std::thread(&NetworkedBlockchainCore::syncManagerLoop, this);
        
        std::cout << "P2P network started on port " << p2pPort_ << std::endl;
        return true;
    }
    
    void stopP2PNetwork() {
        running_ = false;
        
        if (networkManager_) {
            networkManager_->stop();
        }
        
        // Wake up and join background threads
        mempoolCondition_.notify_all();
        
        if (mempoolProcessor_.joinable()) {
            mempoolProcessor_.join();
        }
        
        if (syncManager_.joinable()) {
            syncManager_.join();
        }
        
        std::cout << "P2P network stopped" << std::endl;
    }
    
    void stop() {
        stopP2PNetwork();
        
        if (blockchainCore_) {
            blockchainCore_->stop_block_adjuster();
        }
    }
    
    // ----- Network Status and Statistics -----
    
    json getNetworkStatus() const {
        json status = {
            {"p2p_enabled", enableP2P_},
            {"p2p_port", p2pPort_},
            {"sync_in_progress", syncInProgress_.load()},
            {"mempool_size", getMempoolSize()},
            {"blockchain_height", getChainLength()}
        };
        
        if (enableP2P_ && networkManager_) {
            auto networkStats = networkManager_->getNetworkStatus();
            status["network"] = networkStats;
            status["peer_count"] = networkManager_->getPeerCount();
        } else {
            status["network"] = nullptr;
            status["peer_count"] = 0;
        }
        
        return status;
    }
    
    std::vector<json> getPeerList() const {
        if (enableP2P_ && networkManager_) {
            return networkManager_->getPeerList();
        }
        return {};
    }
    
    size_t getPeerCount() const {
        if (enableP2P_ && networkManager_) {
            return networkManager_->getPeerCount();
        }
        return 0;
    }
    
    size_t getMempoolSize() const {
        std::lock_guard<std::mutex> lock(mempoolMutex_);
        return pendingTransactions_.size();
    }
    
    std::vector<json> getPendingTransactions() const {
        std::lock_guard<std::mutex> lock(mempoolMutex_);
        std::vector<json> transactions;
        
        auto tempQueue = pendingTransactions_;
        while (!tempQueue.empty()) {
            transactions.push_back(tempQueue.front());
            tempQueue.pop();
        }
        
        return transactions;
    }
    
    // ----- Configuration -----
    
    void enableP2PNetworking(bool enable) {
        if (enableP2P_ != enable) {
            enableP2P_ = enable;
            
            if (enable && !networkManager_) {
                networkManager_ = std::make_unique<p2p::P2PNetworkManager>(p2pPort_);
                setupP2PIntegration();
            } else if (!enable && networkManager_) {
                stopP2PNetwork();
                networkManager_.reset();
            }
        }
    }
    
    void setP2PPort(uint16_t port) {
        if (p2pPort_ != port) {
            bool wasRunning = (enableP2P_ && networkManager_);
            
            if (wasRunning) {
                stopP2PNetwork();
            }
            
            p2pPort_ = port;
            
            if (wasRunning) {
                networkManager_ = std::make_unique<p2p::P2PNetworkManager>(p2pPort_);
                setupP2PIntegration();
                startP2PNetwork();
            }
        }
    }
    
    // ----- Advanced Features -----
    
    bool createAndBroadcastBlock(const std::vector<json>& transactions = {}) {
        // Create a new block with pending transactions
        auto latestBlock = getLatestBlock();
        
        json newBlockData = {
            {"index", getChainLength()},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"previous_hash", latestBlock.value("hash", "0")},
            {"transactions", transactions.empty() ? getPendingTransactions() : transactions},
            {"nonce", 0}  // For proof-of-work if implemented
        };
        
        // Add mining/proof-of-work here if needed
        // For now, just create the block
        
        return addBlock(newBlockData, true);
    }
    
    void clearMempool() {
        std::lock_guard<std::mutex> lock(mempoolMutex_);
        std::queue<json> empty;
        pendingTransactions_.swap(empty);
        std::cout << "Mempool cleared" << std::endl;
    }
    
    json getLatestBlock() const {
        auto chainData = getBlockchainData();
        if (!chainData.empty()) {
            return chainData.back();
        }
        return json{};
    }
    
    // ----- Blockchain Analysis -----
    
    json getBlockchainStats() const {
        auto chainData = getBlockchainData();
        
        size_t totalTransactions = 0;
        size_t totalBlocks = chainData.size();
        std::map<std::string, size_t> actionCounts;
        
        for (const auto& block : chainData) {
            if (block.contains("data")) {
                const auto& data = block["data"];
                
                if (data.contains("action")) {
                    std::string action = data["action"];
                    actionCounts[action]++;
                }
                
                if (data.contains("transactions")) {
                    totalTransactions += data["transactions"].size();
                }
            }
        }
        
        return {
            {"total_blocks", totalBlocks},
            {"total_transactions", totalTransactions},
            {"action_counts", actionCounts},
            {"chain_valid", verifyBlockchain()},
            {"latest_block", totalBlocks > 0 ? chainData.back() : json{}},
            {"genesis_block", totalBlocks > 0 ? chainData.front() : json{}}
        };
    }
    
private:
    // ----- Internal Methods -----
    
    void setupP2PIntegration() {
        if (!networkManager_) return;
        
        // Connect P2P callbacks to blockchain operations
        networkManager_->connectToBlockchain(
            // On block received
            [this](const json& block) {
                handleReceivedBlock(block);
            },
            // On transaction received
            [this](const json& transaction) {
                handleReceivedTransaction(transaction);
            },
            // Get latest block
            [this]() -> json {
                return getLatestBlock();
            },
            // Get pending transactions
            [this]() -> std::vector<json> {
                return getPendingTransactions();
            },
            // Validate block
            [this](const json& block) -> bool {
                return validateBlock(block);
            },
            // Validate transaction
            [this](const json& transaction) -> bool {
                return validateTransaction(transaction);
            }
        );
    }
    
    void handleReceivedBlock(const json& block) {
        std::lock_guard<std::mutex> lock(syncMutex_);
        
        std::cout << "Received block from network: " << block.value("index", -1) << std::endl;
        
        // Validate the block
        if (!validateBlock(block)) {
            std::cerr << "Received invalid block from network" << std::endl;
            return;
        }
        
        // Check if this block extends our chain
        auto latestBlock = getLatestBlock();
        size_t expectedIndex = getChainLength();
        
        if (block.value("index", 0) == expectedIndex) {
            // This block extends our chain
            if (addBlock(block, false)) { // Don't re-broadcast
                std::cout << "Added block " << expectedIndex << " to blockchain" << std::endl;
                
                // Remove transactions from mempool that are in this block
                if (block.contains("transactions")) {
                    removeTransactionsFromMempool(block["transactions"]);
                }
            }
        } else if (block.value("index", 0) > expectedIndex) {
            // We're behind, request sync
            if (!syncInProgress_) {
                syncInProgress_ = true;
                std::cout << "Chain behind, requesting sync..." << std::endl;
                networkManager_->requestSync();
            }
        }
        // If block index < expectedIndex, it's an old block, ignore it
    }
    
    void handleReceivedTransaction(const json& transaction) {
        std::cout << "Received transaction from network" << std::endl;
        
        // Add to mempool (will validate internally)
        addTransaction(transaction, false); // Don't re-broadcast
    }
    
    bool validateBlock(const json& block) const {
        // Basic block validation
        if (!block.contains("index") || !block.contains("timestamp") || 
            !block.contains("previous_hash") || !block.contains("hash")) {
            return false;
        }
        
        // Check if block index is sequential
        size_t expectedIndex = getChainLength();
        if (block["index"] != expectedIndex && block["index"] != 0) { // Allow genesis block
            return false;
        }
        
        // Validate previous hash (except for genesis)
        if (block["index"] != 0) {
            auto latestBlock = getLatestBlock();
            if (block["previous_hash"] != latestBlock.value("hash", "")) {
                return false;
            }
        }
        
        // Additional validation can be added here
        // - Hash verification
        // - Transaction validation
        // - Proof-of-work verification
        
        return true;
    }
    
    bool validateTransaction(const json& transaction) const {
        // Basic transaction validation
        if (!transaction.contains("type") || !transaction.contains("timestamp")) {
            return false;
        }
        
        // Add more sophisticated validation here
        // - Signature verification
        // - Balance checking
        // - Double-spend prevention
        
        return true;
    }
    
    void removeTransactionsFromMempool(const json& blockTransactions) {
        std::lock_guard<std::mutex> lock(mempoolMutex_);
        
        // This is a simplified implementation
        // In practice, you'd want more efficient transaction matching
        std::queue<json> newMempool;
        
        while (!pendingTransactions_.empty()) {
            auto tx = pendingTransactions_.front();
            pendingTransactions_.pop();
            
            // Check if this transaction is in the block
            bool found = false;
            for (const auto& blockTx : blockTransactions) {
                if (tx == blockTx) { // Simple comparison, could be improved
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                newMempool.push(tx);
            }
        }
        
        pendingTransactions_ = std::move(newMempool);
    }
    
    void processMempoolLoop() {
        std::cout << "Mempool processor started" << std::endl;
        
        while (running_) {
            std::unique_lock<std::mutex> lock(mempoolMutex_);
            
            // Wait for transactions or shutdown
            mempoolCondition_.wait(lock, [this] {
                return !pendingTransactions_.empty() || !running_;
            });
            
            if (!running_) break;
            
            // Process transactions (could implement batching here)
            size_t mempoolSize = pendingTransactions_.size();
            lock.unlock();
            
            if (mempoolSize > 0) {
                std::cout << "Processing mempool with " << mempoolSize << " transactions" << std::endl;
                
                // Auto-create blocks when mempool reaches certain size
                if (mempoolSize >= 10) { // Configurable threshold
                    createAndBroadcastBlock();
                    clearMempool();
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        
        std::cout << "Mempool processor stopped" << std::endl;
    }
    
    void syncManagerLoop() {
        std::cout << "Sync manager started" << std::endl;
        
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
            if (!running_) break;
            
            // Periodic sync checks
            if (getPeerCount() > 0 && !syncInProgress_) {
                // Could implement more sophisticated sync logic here
                // For now, just reset the sync flag periodically
                syncInProgress_ = false;
            }
        }
        
        std::cout << "Sync manager stopped" << std::endl;
    }
};

// ----- Factory Functions -----

std::unique_ptr<NetworkedBlockchainCore> createNetworkedBlockchain(uint16_t p2pPort = p2p::DEFAULT_P2P_PORT) {
    return std::make_unique<NetworkedBlockchainCore>(p2pPort);
}

// ----- CLI Interface for P2P Operations -----
class P2PCommandInterface {
private:
    NetworkedBlockchainCore& blockchain_;
    
public:
    P2PCommandInterface(NetworkedBlockchainCore& blockchain) : blockchain_(blockchain) {}
    
    void showNetworkStatus() {
        auto status = blockchain_.getNetworkStatus();
        std::cout << "\n=== Network Status ===" << std::endl;
        std::cout << "P2P Enabled: " << (status["p2p_enabled"] ? "Yes" : "No") << std::endl;
        std::cout << "P2P Port: " << status["p2p_port"] << std::endl;
        std::cout << "Peer Count: " << status["peer_count"] << std::endl;
        std::cout << "Sync in Progress: " << (status["sync_in_progress"] ? "Yes" : "No") << std::endl;
        std::cout << "Mempool Size: " << status["mempool_size"] << std::endl;
        std::cout << "Blockchain Height: " << status["blockchain_height"] << std::endl;
        
        if (status["network"] != nullptr) {
            auto network = status["network"];
            std::cout << "Node ID: " << network["node_id"] << std::endl;
            std::cout << "Uptime: " << network["uptime_seconds"] << " seconds" << std::endl;
            std::cout << "Messages Sent: " << network["messages_sent"] << std::endl;
            std::cout << "Messages Received: " << network["messages_received"] << std::endl;
        }
    }
    
    void showPeerList() {
        auto peers = blockchain_.getPeerList();
        std::cout << "\n=== Peer List ===" << std::endl;
        
        if (peers.empty()) {
            std::cout << "No peers connected" << std::endl;
            return;
        }
        
        for (const auto& peer : peers) {
            std::cout << "Peer: " << peer["address"] << std::endl;
            std::cout << "  ID: " << peer["peer_id"] << std::endl;
            std::cout << "  Version: " << peer["version"] << std::endl;
            std::cout << "  Outbound: " << (peer["outbound"] ? "Yes" : "No") << std::endl;
            std::cout << "  Connected: " << (peer["connected"] ? "Yes" : "No") << std::endl;
            std::cout << "  Last Activity: " << peer["last_activity_seconds"] << " seconds ago" << std::endl;
            std::cout << std::endl;
        }
    }
    
    void showBlockchainStats() {
        auto stats = blockchain_.getBlockchainStats();
        std::cout << "\n=== Blockchain Statistics ===" << std::endl;
        std::cout << "Total Blocks: " << stats["total_blocks"] << std::endl;
        std::cout << "Total Transactions: " << stats["total_transactions"] << std::endl;
        std::cout << "Chain Valid: " << (stats["chain_valid"] ? "Yes" : "No") << std::endl;
        
        if (stats.contains("action_counts")) {
            std::cout << "\nAction Counts:" << std::endl;
            for (const auto& [action, count] : stats["action_counts"].items()) {
                std::cout << "  " << action << ": " << count << std::endl;
            }
        }
    }
    
    void addBootstrapNode() {
        std::string ip;
        uint16_t port;
        
        std::cout << "Enter bootstrap node IP: ";
        std::cin >> ip;
        std::cout << "Enter bootstrap node port: ";
        std::cin >> port;
        
        blockchain_.addBootstrapNode(ip, port);
        std::cout << "Bootstrap node added: " << ip << ":" << port << std::endl;
    }
    
    void requestSync() {
        blockchain_.requestNetworkSync();
        std::cout << "Blockchain sync requested from network" << std::endl;
    }
    
    void createBlock() {
        if (blockchain_.createAndBroadcastBlock()) {
            std::cout << "Block created and broadcasted successfully" << std::endl;
        } else {
            std::cout << "Failed to create block" << std::endl;
        }
    }
    
    void showMempoolTransactions() {
        auto transactions = blockchain_.getPendingTransactions();
        std::cout << "\n=== Mempool Transactions ===" << std::endl;
        std::cout << "Count: " << transactions.size() << std::endl;
        
        for (size_t i = 0; i < transactions.size() && i < 10; ++i) { // Show first 10
            std::cout << "TX " << (i + 1) << ": " << transactions[i].dump() << std::endl;
        }
        
        if (transactions.size() > 10) {
            std::cout << "... and " << (transactions.size() - 10) << " more" << std::endl;
        }
    }
};

} // namespace blockchain

#endif // BLOCKCHAIN_P2P_INTEGRATION_HPP