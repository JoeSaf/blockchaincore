#include "utils/Crypto.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <spdlog/spdlog.h>

namespace {
    bool openSSLInitialized = false;
}

std::string Crypto::sha256(const std::string& input) {
    ensureOpenSSLInit();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string Crypto::sha256(const std::vector<uint8_t>& input) {
    ensureOpenSSLInit();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.data(), input.size());
    SHA256_Final(hash, &sha256);
    
    return bytesToHex(std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH));
}

std::string Crypto::doubleSha256(const std::string& input) {
    return sha256(sha256(input));
}

std::pair<std::string, std::string> Crypto::generateKeyPair() {
    ensureOpenSSLInit();
    
    EC_KEY* ecKey = createECKey();
    if (!ecKey) {
        spdlog::error("Failed to create EC key");
        return {"", ""};
    }
    
    // Generate key pair
    if (EC_KEY_generate_key(ecKey) != 1) {
        spdlog::error("Failed to generate EC key pair");
        EC_KEY_free(ecKey);
        return {"", ""};
    }
    
    std::string privateKey = ecKeyToString(ecKey, true);
    std::string publicKey = ecKeyToString(ecKey, false);
    
    EC_KEY_free(ecKey);
    
    spdlog::debug("Generated new key pair");
    return {privateKey, publicKey};
}

std::string Crypto::signData(const std::string& data, const std::string& privateKey) {
    ensureOpenSSLInit();
    
    if (privateKey.empty()) {
        spdlog::error("Cannot sign with empty private key");
        return "";
    }
    
    // For simplicity, we'll use a basic signing approach
    // In a real implementation, this would use proper ECDSA signing
    std::string hash = sha256(data + privateKey);
    
    spdlog::debug("Signed data with hash: {}", hash.substr(0, 16) + "...");
    return hash;
}

bool Crypto::verifySignature(const std::string& data, const std::string& signature, 
                            const std::string& publicKey) {
    ensureOpenSSLInit();
    
    // For simplicity, we'll do basic verification
    // In a real implementation, this would use proper ECDSA verification
    if (signature.empty()) {
        return false;
    }
    
    // This is a placeholder implementation
    return signature.length() == 64; // SHA256 hex length
}

std::string Crypto::generateAddress(const std::string& publicKey) {
    if (publicKey.empty()) {
        return generateRandomAddress();
    }
    
    // Simple address generation from public key
    std::string hash = sha256(publicKey);
    return "1" + hash.substr(0, 33); // Bitcoin-style address prefix
}

std::string Crypto::generateRandomAddress() {
    std::string randomData = generateRandomString(32);
    return generateAddress(randomData);
}

std::string Crypto::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> Crypto::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string Crypto::base64Encode(const std::vector<uint8_t>& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, input.data(), static_cast<int>(input.size()));
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> Crypto::base64Decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.length()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    std::vector<uint8_t> result(input.length());
    int decodedLength = BIO_read(bio, result.data(), static_cast<int>(result.size()));
    
    BIO_free_all(bio);
    
    if (decodedLength > 0) {
        result.resize(decodedLength);
    } else {
        result.clear();
    }
    
    return result;
}

std::string Crypto::generateRandomString(size_t length) {
    ensureOpenSSLInit();
    
    std::vector<uint8_t> randomBytes(length);
    if (RAND_bytes(randomBytes.data(), static_cast<int>(length)) != 1) {
        // Fallback to C++ random if OpenSSL fails
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < length; ++i) {
            randomBytes[i] = static_cast<uint8_t>(dis(gen));
        }
    }
    
    return bytesToHex(randomBytes);
}

uint64_t Crypto::generateRandomNumber() {
    ensureOpenSSLInit();
    
    uint64_t result;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1) {
        // Fallback to C++ random
        std::random_device rd;
        std::mt19937_64 gen(rd());
        result = gen();
    }
    
    return result;
}

bool Crypto::isValidHash(const std::string& hash) {
    if (hash.length() != 64) { // SHA256 hex length
        return false;
    }
    
    return std::all_of(hash.begin(), hash.end(), [](char c) {
        return std::isxdigit(c);
    });
}

bool Crypto::hasValidProofOfWork(const std::string& hash, uint32_t difficulty) {
    if (!isValidHash(hash)) {
        return false;
    }
    
    std::string target(difficulty, '0');
    return hash.substr(0, difficulty) == target;
}

std::string Crypto::calculateMerkleRoot(const std::vector<std::string>& hashes) {
    if (hashes.empty()) {
        return sha256("empty");
    }
    
    if (hashes.size() == 1) {
        return hashes[0];
    }
    
    std::vector<std::string> currentLevel = hashes;
    
    while (currentLevel.size() > 1) {
        std::vector<std::string> nextLevel;
        
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            if (i + 1 < currentLevel.size()) {
                nextLevel.push_back(sha256(currentLevel[i] + currentLevel[i + 1]));
            } else {
                nextLevel.push_back(sha256(currentLevel[i] + currentLevel[i]));
            }
        }
        
        currentLevel = std::move(nextLevel);
    }
    
    return currentLevel[0];
}

void Crypto::ensureOpenSSLInit() {
    if (!openSSLInitialized) {
        EVP_add_digest(EVP_sha256());
        openSSLInitialized = true;
        spdlog::debug("OpenSSL initialized");
    }
}

EC_KEY* Crypto::createECKey() {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        spdlog::error("Failed to create EC key with secp256k1 curve");
        return nullptr;
    }
    
    return ecKey;
}

std::string Crypto::ecKeyToString(EC_KEY* key, bool isPrivate) {
    BIO* bio = BIO_new(BIO_s_mem());
    
    if (isPrivate) {
        PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        PEM_write_bio_EC_PUBKEY(bio, key);
    }
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free(bio);
    
    return result;
}

EC_KEY* Crypto::stringToECKey(const std::string& keyStr, bool isPrivate) {
    BIO* bio = BIO_new_mem_buf(keyStr.c_str(), static_cast<int>(keyStr.length()));
    EC_KEY* key = nullptr;
    
    if (isPrivate) {
        key = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    } else {
        key = PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr);
    }
    
    BIO_free(bio);
    return key;
}
