// blockchain_core.hpp
#ifndef BLOCKCHAIN_CORE_HPP
#define BLOCKCHAIN_CORE_HPP

#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <algorithm>
#include <filesystem>
#include <thread>

// JSON library
#include <nlohmann/json.hpp>

// OpenSSL includes
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

namespace blockchain {

using json = nlohmann::json;
namespace fs = std::filesystem;

// Utility functions
class CryptoUtils {
public:
    static std::string sha256(const std::string& data);
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
    static std::pair<std::string, std::string> generate_rsa_keypair();
    static std::string encrypt_private_key(const std::string& private_key, const std::string& password);
    static std::string decrypt_private_key(const std::string& encrypted_key, const std::string& password);
    static std::string sign_message(const std::string& message, const std::string& private_key);
    static bool verify_signature(const std::string& message, const std::string& signature, const std::string& public_key);
};

// Forward declarations
class Blockchain;
class AuthSystem;

// Block class
class Block {
private:
    size_t index_;
    double timestamp_;
    json data_;
    std::string previous_hash_;
    std::string hash_;

public:
    Block(size_t index, double timestamp, const json& data, const std::string& previous_hash);
    
    std::string calculate_hash() const;
    json to_json() const;
    static std::unique_ptr<Block> from_json(const json& j);
    
    // Getters
    size_t get_index() const { return index_; }
    double get_timestamp() const { return timestamp_; }
    const json& get_data() const { return data_; }
    const std::string& get_hash() const { return hash_; }
    const std::string& get_previous_hash() const { return previous_hash_; }
    
    // Setters
    void set_index(size_t index) { index_ = index; }
    void set_previous_hash(const std::string& hash) { previous_hash_ = hash; }
    void recalculate_hash() { hash_ = calculate_hash(); }
};

// User class
class User {
private:
    std::string username_;
    std::string role_;
    std::string public_key_;
    std::string private_key_;

public:
    User(const std::string& username, const std::string& role, const std::string& password = "");
    User(const std::string& username, const std::string& role, 
         const std::string& public_key, const std::string& private_key);
    
    std::string get_public_key_pem() const { return public_key_; }
    std::string get_private_key_pem(const std::string& password = "") const;
    std::string sign_message(const std::string& message) const;
    bool verify_password(const std::string& password) const;
    
    void initialize_user_folder() const;
    std::string store_user_item(const std::string& item_name, const json& item_data) const;
    
    const std::string& get_username() const { return username_; }
    const std::string& get_role() const { return role_; }
};

// Blockchain class
class Blockchain {
private:
    std::vector<std::unique_ptr<Block>> chain_;
    std::string db_file_;
    mutable std::shared_mutex chain_mutex_;
    std::atomic<bool> integrity_compromised_{false};

public:
    Blockchain(const std::string& db_file = "blockchain_db.json");
    
    void add_block(std::unique_ptr<Block> block);
    bool is_chain_valid() const;
    void save_chain() const;
    bool load_chain();
    void rehash_chain();
    
    const Block& get_latest_block() const;
    size_t get_chain_length() const;
    json to_json() const;
    
    // Thread-safe block operations
    void safely_reorder_blocks(size_t start_index, size_t count);
    std::unique_ptr<Block> create_genesis_block() const;
    
    // Security response
    void trigger_fallback_response(const std::string& reason);
    
    // Block adjuster integration
    void start_block_adjuster(int interval_seconds = 300);
    void stop_block_adjuster();

private:
    std::unique_ptr<std::thread> adjuster_thread_;
    std::atomic<bool> adjuster_running_{false};
    
    void block_adjuster_loop(int interval_seconds);
    bool safe_chain_valid() const;
};

// AuthSystem class
class AuthSystem {
private:
    std::unique_ptr<Blockchain> blockchain_;
    std::unordered_map<std::string, std::unique_ptr<User>> users_;
    mutable std::shared_mutex users_mutex_;

public:
    AuthSystem();
    ~AuthSystem() = default;
    
    bool register_user(const std::string& username, const std::string& role, const std::string& password);
    std::pair<std::string, std::string> authenticate(const std::string& username, const std::string& password);
    
    std::vector<std::string> list_users() const;
    bool verify_blockchain() const;
    void load_users_from_blockchain();
    
    // Getters
    Blockchain& get_blockchain() { return *blockchain_; }
    const Blockchain& get_blockchain() const { return *blockchain_; }
    
    // User management
    bool user_exists(const std::string& username) const;
    std::string get_user_role(const std::string& username) const;
    
private:
    std::string get_previous_user(const std::string& current_user) const;
    void initialize_system();
};

// Blockchain Core API - Main interface
class BlockchainCore {
private:
    std::unique_ptr<AuthSystem> auth_system_;
    static std::unique_ptr<BlockchainCore> instance_;
    static std::mutex instance_mutex_;

public:
    BlockchainCore();
    ~BlockchainCore();
    
    // Singleton pattern
    static BlockchainCore& get_instance();
    
    // Core operations
    bool initialize();
    bool register_user(const std::string& username, const std::string& role, const std::string& password);
    std::pair<std::string, std::string> authenticate(const std::string& username, const std::string& password);
    std::vector<std::string> list_users() const;
    bool verify_blockchain() const;
    
    // Blockchain operations
    json get_blockchain_data() const;
    bool add_custom_block(const json& data);
    size_t get_chain_length() const;
    
    // System management
    void start_block_adjuster(int interval_seconds = 300);
    void stop_block_adjuster();
    bool save_state() const;
    bool load_state();
    
    // Directory management
    void setup_directories() const;
    
    AuthSystem& get_auth_system() { return *auth_system_; }
};

} // namespace blockchain

//=============================================================================
// IMPLEMENTATION
//=============================================================================

namespace blockchain {

// Static member definitions
std::unique_ptr<BlockchainCore> BlockchainCore::instance_ = nullptr;
std::mutex BlockchainCore::instance_mutex_;

// CryptoUtils implementation
std::string CryptoUtils::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    SHA256_Final(hash, &sha256);
    
    std::string result;
    result.reserve(64);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }
    return result;
}

std::string CryptoUtils::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(bio, &buffer);
    
    std::string result(buffer->data, buffer->length);
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> CryptoUtils::base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    std::vector<uint8_t> result(encoded.length());
    int decoded_length = BIO_read(bio, result.data(), static_cast<int>(encoded.length()));
    
    BIO_free_all(bio);
    
    if (decoded_length > 0) {
        result.resize(decoded_length);
    } else {
        result.clear();
    }
    
    return result;
}

std::pair<std::string, std::string> CryptoUtils::generate_rsa_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return {"", ""};
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {"", ""};
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {"", ""};
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {"", ""};
    }
    
    // Extract public key
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, pkey);
    BUF_MEM* pub_mem;
    BIO_get_mem_ptr(pub_bio, &pub_mem);
    std::string public_key(pub_mem->data, pub_mem->length);
    BIO_free(pub_bio);
    
    // Extract private key
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* priv_mem;
    BIO_get_mem_ptr(priv_bio, &priv_mem);
    std::string private_key(priv_mem->data, priv_mem->length);
    BIO_free(priv_bio);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return {public_key, private_key};
}

std::string CryptoUtils::encrypt_private_key(const std::string& private_key, const std::string& password) {
    if (password.empty()) return private_key;
    
    BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) return "";
    
    BIO* encrypted_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(encrypted_bio, pkey, EVP_aes_256_cbc(), 
                            reinterpret_cast<const unsigned char*>(password.c_str()), 
                            static_cast<int>(password.length()), nullptr, nullptr);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(encrypted_bio, &mem);
    std::string result(mem->data, mem->length);
    
    BIO_free(encrypted_bio);
    EVP_PKEY_free(pkey);
    
    return result;
}

std::string CryptoUtils::decrypt_private_key(const std::string& encrypted_key, const std::string& password) {
    BIO* bio = BIO_new_mem_buf(encrypted_key.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, 
                                           const_cast<char*>(password.c_str()));
    BIO_free(bio);
    
    if (!pkey) return "";
    
    BIO* decrypted_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(decrypted_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(decrypted_bio, &mem);
    std::string result(mem->data, mem->length);
    
    BIO_free(decrypted_bio);
    EVP_PKEY_free(pkey);
    
    return result;
}

std::string CryptoUtils::sign_message(const std::string& message, const std::string& private_key) {
    BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) return "";
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return base64_encode(signature);
}

bool CryptoUtils::verify_signature(const std::string& message, const std::string& signature, const std::string& public_key) {
    BIO* bio = BIO_new_mem_buf(public_key.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) return false;
    
    auto sig_data = base64_decode(signature);
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    int result = EVP_DigestVerifyFinal(ctx, sig_data.data(), sig_data.size());
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return result == 1;
}

// Block implementation
Block::Block(size_t index, double timestamp, const json& data, const std::string& previous_hash)
    : index_(index), timestamp_(timestamp), data_(data), previous_hash_(previous_hash) {
    hash_ = calculate_hash();
}

std::string Block::calculate_hash() const {
    json block_data = {
        {"index", index_},
        {"timestamp", timestamp_},
        {"data", data_},
        {"previous_hash", previous_hash_}
    };
    return CryptoUtils::sha256(block_data.dump());
}

json Block::to_json() const {
    return {
        {"index", index_},
        {"timestamp", timestamp_},
        {"data", data_},
        {"previous_hash", previous_hash_},
        {"hash", hash_}
    };
}

std::unique_ptr<Block> Block::from_json(const json& j) {
    auto block = std::make_unique<Block>(
        j["index"].get<size_t>(),
        j["timestamp"].get<double>(),
        j["data"],
        j["previous_hash"].get<std::string>()
    );
    block->hash_ = j["hash"].get<std::string>();
    return block;
}

// User implementation
User::User(const std::string& username, const std::string& role, const std::string& password)
    : username_(username), role_(role) {
    auto keypair = CryptoUtils::generate_rsa_keypair();
    public_key_ = keypair.first;
    private_key_ = CryptoUtils::encrypt_private_key(keypair.second, password);
    initialize_user_folder();
}

User::User(const std::string& username, const std::string& role, 
           const std::string& public_key, const std::string& private_key)
    : username_(username), role_(role), public_key_(public_key), private_key_(private_key) {
}

std::string User::get_private_key_pem(const std::string& password) const {
    if (password.empty()) return private_key_;
    return CryptoUtils::decrypt_private_key(private_key_, password);
}

std::string User::sign_message(const std::string& message) const {
    std::string decrypted_key = CryptoUtils::decrypt_private_key(private_key_, "");
    return CryptoUtils::sign_message(message, decrypted_key);
}

bool User::verify_password(const std::string& password) const {
    std::string decrypted = CryptoUtils::decrypt_private_key(private_key_, password);
    return !decrypted.empty();
}

void User::initialize_user_folder() const {
    fs::path user_folder = fs::path("userData") / username_;
    
    if (!fs::exists(user_folder)) {
        fs::create_directories(user_folder);
        std::cout << "Created user folder for " << username_ << std::endl;
    }
    
    // Create user info file
    json user_info = {
        {"username", username_},
        {"role", role_},
        {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"public_key", public_key_}
    };
    
    std::ofstream file(user_folder / "user_info.json");
    file << user_info.dump(4);
}

std::string User::store_user_item(const std::string& item_name, const json& item_data) const {
    fs::path user_folder = fs::path("userData") / username_;
    
    if (!fs::exists(user_folder)) {
        initialize_user_folder();
    }
    
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::string filename = item_name + "_" + std::to_string(timestamp) + ".json";
    fs::path item_path = user_folder / filename;
    
    std::ofstream file(item_path);
    file << item_data.dump(4);
    
    std::cout << "Stored item '" << item_name << "' for user " << username_ << std::endl;
    return item_path.string();
}

// Blockchain implementation
Blockchain::Blockchain(const std::string& db_file) : db_file_(db_file) {
    if (fs::exists(db_file_)) {
        if (!load_chain()) {
            std::cerr << "Error loading blockchain, creating new one" << std::endl;
            chain_.clear();
            chain_.push_back(create_genesis_block());
            save_chain();
        }
    } else {
        chain_.push_back(create_genesis_block());
        save_chain();
    }
}

std::unique_ptr<Block> Blockchain::create_genesis_block() const {
    json genesis_data = {
        {"action", "genesis"},
        {"message", "Genesis Block"}
    };
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return std::make_unique<Block>(0, static_cast<double>(now), genesis_data, "0");
}

void Blockchain::add_block(std::unique_ptr<Block> block) {
    std::unique_lock<std::shared_mutex> lock(chain_mutex_);
    
    block->set_previous_hash(chain_.back()->get_hash());
    block->recalculate_hash();
    chain_.push_back(std::move(block));
    
    lock.unlock();
    save_chain();
}

bool Blockchain::is_chain_valid() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    
    for (size_t i = 1; i < chain_.size(); ++i) {
        const auto& current_block = chain_[i];
        const auto& previous_block = chain_[i - 1];
        
        if (current_block->get_hash() != current_block->calculate_hash()) {
            lock.unlock();
            const_cast<Blockchain*>(this)->trigger_fallback_response("Hash mismatch detected");
            return false;
        }
        
        if (current_block->get_previous_hash() != previous_block->get_hash()) {
            lock.unlock();
            const_cast<Blockchain*>(this)->trigger_fallback_response("Chain continuity broken");
            return false;
        }
    }
    
    return true;
}

bool Blockchain::safe_chain_valid() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    
    for (size_t i = 1; i < chain_.size(); ++i) {
        const auto& current_block = chain_[i];
        const auto& previous_block = chain_[i - 1];
        
        if (current_block->get_hash() != current_block->calculate_hash()) {
            std::cout << "Hash mismatch detected but security response suppressed" << std::endl;
            return false;
        }
        
        if (current_block->get_previous_hash() != previous_block->get_hash()) {
            std::cout << "Chain continuity compromised but security response suppressed" << std::endl;
            return false;
        }
    }
    
    return true;
}

void Blockchain::trigger_fallback_response(const std::string& reason) {
    std::cout << "WARNING: Blockchain integrity compromised - " << reason << std::endl;
    std::cout << "Initiating security response..." << std::endl;
    
    integrity_compromised_ = true;
    
    json fallback_data = {
        {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"breach_reason", reason},
        {"users", json::object()}
    };
    
    // Extract user data from blockchain
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    for (const auto& block : chain_) {
        const auto& data = block->get_data();
        if (data.contains("action") && data["action"] == "register") {
            std::string username = data.value("username", "");
            if (!username.empty()) {
                fallback_data["users"][username] = {
                    {"role", data.value("role", "user")},
                    {"private_key", data.value("private_key", "")},
                    {"public_key", data.value("public_key", "")},
                    {"migrated_at", std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count()}
                };
            }
        }
    }
    lock.unlock();
    
    // Save fallback database
    std::ofstream fallback_file("fallback_db.json");
    fallback_file << fallback_data.dump(4);
    
    std::cout << "\nSecurity measures completed:" << std::endl;
    std::cout << "- Created fallback database: fallback_db.json" << std::endl;
    std::cout << "- Migrated " << fallback_data["users"].size() << " users to fallback database" << std::endl;
    std::cout << "- System will now use the fallback database" << std::endl;
    
    rehash_chain();
    std::cout << "- Blockchain rehashed to restore integrity" << std::endl;
}

void Blockchain::rehash_chain() {
    std::unique_lock<std::shared_mutex> lock(chain_mutex_);
    
    if (chain_.size() < 2) {
        std::cout << "WARNING: Chain size seems unexpectedly low. Aborting rehash to prevent data loss." << std::endl;
        return;
    }
    
    for (size_t i = 1; i < chain_.size(); ++i) {
        chain_[i]->set_previous_hash(chain_[i - 1]->get_hash());
        chain_[i]->recalculate_hash();
    }
    
    std::cout << "Chain rehashed successfully" << std::endl;
    lock.unlock();
    save_chain();
    
    integrity_compromised_ = false;
}

void Blockchain::save_chain() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    
    json chain_json = json::array();
    for (const auto& block : chain_) {
        chain_json.push_back(block->to_json());
    }
    
    lock.unlock();
    
    std::ofstream file(db_file_);
    file << chain_json.dump(4);
}

bool Blockchain::load_chain() {
    std::ifstream file(db_file_);
    if (!file.is_open()) return false;
    
    json chain_json;
    file >> chain_json;
    
    std::unique_lock<std::shared_mutex> lock(chain_mutex_);
    chain_.clear();
    
    for (const auto& block_json : chain_json) {
        chain_.push_back(Block::from_json(block_json));
    }
    
    return !chain_.empty();
}

const Block& Blockchain::get_latest_block() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    return *chain_.back();
}

size_t Blockchain::get_chain_length() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    return chain_.size();
}

json Blockchain::to_json() const {
    std::shared_lock<std::shared_mutex> lock(chain_mutex_);
    
    json result = json::array();
    for (const auto& block : chain_) {
        result.push_back(block->to_json());
    }
    
    return result;
}

void Blockchain::safely_reorder_blocks(size_t start_index, size_t count) {
    std::unique_lock<std::shared_mutex> lock(chain_mutex_);
    
    if (start_index + count > chain_.size()) {
        std::cout << "[Adjuster] Not enough blocks for reordering" << std::endl;
        return;
    }
    
    std::cout << "[Adjuster] Safely reordering blocks " << start_index 
              << " to " << (start_index + count - 1) << "..." << std::endl;
    
    // Create a copy of blocks to reorder
    std::vector<std::unique_ptr<Block>> blocks_to_reorder;
    for (size_t i = start_index; i < start_index + count; ++i) {
        json block_json = chain_[i]->to_json();
        blocks_to_reorder.push_back(Block::from_json(block_json));
    }
    
    // Shuffle the blocks
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(blocks_to_reorder.begin(), blocks_to_reorder.end(), g);
    
    // Rebuild the chain with proper hash links
    for (size_t i = 0; i < blocks_to_reorder.size(); ++i) {
        size_t chain_index = start_index + i;
        
        if (i == 0) {
            // Link first shuffled block to previous block
            blocks_to_reorder[i]->set_previous_hash(chain_[start_index - 1]->get_hash());
        } else {
            // Link to previous shuffled block
            blocks_to_reorder[i]->set_previous_hash(blocks_to_reorder[i - 1]->get_hash());
        }
        
        blocks_to_reorder[i]->set_index(chain_index);
        blocks_to_reorder[i]->recalculate_hash();
        
        // Replace in chain
        chain_[chain_index] = std::move(blocks_to_reorder[i]);
    }
    
    // Fix remaining blocks if any
    for (size_t i = start_index + count; i < chain_.size(); ++i) {
        chain_[i]->set_previous_hash(chain_[i - 1]->get_hash());
        chain_[i]->set_index(i);
        chain_[i]->recalculate_hash();
    }
    
    lock.unlock();
    
    if (safe_chain_valid()) {
        std::cout << "[Adjuster] Reordering successful, blockchain integrity maintained" << std::endl;
        save_chain();
    } else {
        std::cout << "[Adjuster] Warning: Reordered chain is invalid" << std::endl;
    }
}

void Blockchain::start_block_adjuster(int interval_seconds) {
    if (adjuster_running_) {
        std::cout << "[Adjuster] Block adjuster already running" << std::endl;
        return;
    }
    
    adjuster_running_ = true;
    adjuster_thread_ = std::make_unique<std::thread>(&Blockchain::block_adjuster_loop, this, interval_seconds);
    std::cout << "[Adjuster] Block adjuster timer started, interval: " << interval_seconds << " seconds" << std::endl;
}

void Blockchain::stop_block_adjuster() {
    adjuster_running_ = false;
    if (adjuster_thread_ && adjuster_thread_->joinable()) {
        adjuster_thread_->join();
    }
    std::cout << "[Adjuster] Block adjuster stopped" << std::endl;
}

void Blockchain::block_adjuster_loop(int interval_seconds) {
    while (adjuster_running_) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
        
        if (!adjuster_running_) break;
        
        // Reorder blocks 1-11 to preserve genesis block
        size_t chain_len = get_chain_length();
        if (chain_len > 12) {
            safely_reorder_blocks(1, 11);
        }
    }
}

// AuthSystem implementation
AuthSystem::AuthSystem() : blockchain_(std::make_unique<Blockchain>()) {
    load_users_from_blockchain();
}

bool AuthSystem::register_user(const std::string& username, const std::string& role, const std::string& password) {
    std::unique_lock<std::shared_mutex> lock(users_mutex_);
    
    if (users_.find(username) != users_.end()) {
        std::cout << "User already exists!" << std::endl;
        return false;
    }
    
    // Create new user
    auto user = std::make_unique<User>(username, role, password);
    
    // Store user data in blockchain
    json block_data = {
        {"action", "register"},
        {"username", username},
        {"role", role},
        {"public_key", user->get_public_key_pem()},
        {"private_key", user->get_private_key_pem(password)},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"previous", get_previous_user(username)}
    };
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    auto new_block = std::make_unique<Block>(blockchain_->get_chain_length(), 
                                           static_cast<double>(now), block_data, "");
    
    // Store user in memory
    users_[username] = std::move(user);
    
    lock.unlock();
    
    // Add block to blockchain
    blockchain_->add_block(std::move(new_block));
    
    std::cout << "User added successfully and recorded in blockchain." << std::endl;
    return true;
}

std::pair<std::string, std::string> AuthSystem::authenticate(const std::string& username, const std::string& password) {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        std::cout << "User not found!" << std::endl;
        return {"", ""};
    }
    
    // Verify password
    if (!it->second->verify_password(password)) {
        std::cout << "Authentication failed - incorrect password!" << std::endl;
        return {"", ""};
    }
    
    std::string role = it->second->get_role();
    lock.unlock();
    
    // Log authentication in blockchain
    json block_data = {
        {"action", "authenticate"},
        {"username", username},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    auto auth_block = std::make_unique<Block>(blockchain_->get_chain_length(),
                                            static_cast<double>(now), block_data, "");
    
    blockchain_->add_block(std::move(auth_block));
    
    // Verify blockchain integrity
    if (!blockchain_->is_chain_valid()) {
        return {"", ""};
    }
    
    std::cout << "Welcome, " << username << " (" << role << ")!" << std::endl;
    return {username, role};
}

std::vector<std::string> AuthSystem::list_users() const {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    
    std::vector<std::string> user_list;
    for (const auto& [username, user] : users_) {
        user_list.push_back(username + " (" + user->get_role() + ")");
    }
    
    return user_list;
}

bool AuthSystem::verify_blockchain() const {
    bool is_valid = blockchain_->is_chain_valid();
    if (is_valid) {
        std::cout << "Blockchain integrity verified - all blocks are valid." << std::endl;
    } else {
        std::cout << "WARNING: Blockchain integrity compromised - chain validation failed!" << std::endl;
    }
    return is_valid;
}

void AuthSystem::load_users_from_blockchain() {
    std::unique_lock<std::shared_mutex> lock(users_mutex_);
    users_.clear();
    
    auto chain_data = blockchain_->to_json();
    
    for (const auto& block_json : chain_data) {
        if (block_json.contains("data") && block_json["data"].contains("action")) {
            const auto& data = block_json["data"];
            if (data["action"] == "register") {
                std::string username = data.value("username", "");
                std::string role = data.value("role", "user");
                std::string public_key = data.value("public_key", "");
                std::string private_key = data.value("private_key", "");
                
                if (!username.empty()) {
                    users_[username] = std::make_unique<User>(username, role, public_key, private_key);
                }
            }
        }
    }
}

bool AuthSystem::user_exists(const std::string& username) const {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    return users_.find(username) != users_.end();
}

std::string AuthSystem::get_user_role(const std::string& username) const {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    auto it = users_.find(username);
    return (it != users_.end()) ? it->second->get_role() : "";
}

std::string AuthSystem::get_previous_user(const std::string& current_user) const {
    auto latest_block_json = blockchain_->get_latest_block().to_json();
    
    if (latest_block_json.contains("data") && latest_block_json["data"].contains("username")) {
        return latest_block_json["data"]["username"];
    }
    
    return "";
}

void AuthSystem::initialize_system() {
    // This will be called during first-time setup
    std::cout << "Initializing blockchain authentication system..." << std::endl;
}

// BlockchainCore implementation
BlockchainCore::BlockchainCore() : auth_system_(std::make_unique<AuthSystem>()) {
}

BlockchainCore::~BlockchainCore() {
    if (auth_system_) {
        auth_system_->get_blockchain().stop_block_adjuster();
    }
}

BlockchainCore& BlockchainCore::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::unique_ptr<BlockchainCore>(new BlockchainCore());
    }
    return *instance_;
}

bool BlockchainCore::initialize() {
    setup_directories();
    
    // Check if this is first-time initialization
    if (auth_system_->get_blockchain().get_chain_length() <= 1) {
        std::cout << "Initializing system with admin user..." << std::endl;
        std::cout << "Create admin password: ";
        std::string admin_password;
        std::getline(std::cin, admin_password);
        
        if (!register_user("admin", "admin", admin_password)) {
            std::cerr << "Failed to create admin user" << std::endl;
            return false;
        }
        
        std::cout << "Admin user created. System ready." << std::endl;
    }
    
    return true;
}

bool BlockchainCore::register_user(const std::string& username, const std::string& role, const std::string& password) {
    return auth_system_->register_user(username, role, password);
}

std::pair<std::string, std::string> BlockchainCore::authenticate(const std::string& username, const std::string& password) {
    return auth_system_->authenticate(username, password);
}

std::vector<std::string> BlockchainCore::list_users() const {
    return auth_system_->list_users();
}

bool BlockchainCore::verify_blockchain() const {
    return auth_system_->verify_blockchain();
}

json BlockchainCore::get_blockchain_data() const {
    return auth_system_->get_blockchain().to_json();
}

bool BlockchainCore::add_custom_block(const json& data) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    auto block = std::make_unique<Block>(auth_system_->get_blockchain().get_chain_length(),
                                       static_cast<double>(now), data, "");
    
    auth_system_->get_blockchain().add_block(std::move(block));
    return true;
}

size_t BlockchainCore::get_chain_length() const {
    return auth_system_->get_blockchain().get_chain_length();
}

void BlockchainCore::start_block_adjuster(int interval_seconds) {
    auth_system_->get_blockchain().start_block_adjuster(interval_seconds);
}

void BlockchainCore::stop_block_adjuster() {
    auth_system_->get_blockchain().stop_block_adjuster();
}

bool BlockchainCore::save_state() const {
    auth_system_->get_blockchain().save_chain();
    return true;
}

bool BlockchainCore::load_state() {
    return auth_system_->get_blockchain().load_chain();
}

void BlockchainCore::setup_directories() const {
    std::vector<std::string> directories = {"userData", "databases", "security_logs"};
    
    for (const auto& dir : directories) {
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
            std::cout << "Created directory: " << dir << std::endl;
        }
    }
}

} // namespace blockchain

#endif // BLOCKCHAIN_CORE_HPP
