// p2p_crypto_utils.hpp - Crypto Utilities for P2P
#ifndef P2P_CRYPTO_UTILS_HPP
#define P2P_CRYPTO_UTILS_HPP

#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

namespace blockchain {
namespace p2p {

class CryptoUtils {
public:
    // ----- Peer ID Generation -----
    
    static std::string generatePeerId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        std::stringstream ss;
        ss << "peer_";
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
        }
        
        return ss.str();
    }
    
    // ----- SHA256 Hashing -----
    
    static std::string sha256(const std::string& input) {
        return sha256(std::vector<unsigned char>(input.begin(), input.end()));
    }
    
    static std::string sha256(const std::vector<unsigned char>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        
        // Use modern OpenSSL EVP interface instead of deprecated SHA256_* functions
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP context");
        }
        
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize SHA256");
        }
        
        if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update SHA256");
        }
        
        unsigned int hash_len;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize SHA256");
        }
        
        EVP_MD_CTX_free(ctx);
        
        // Convert to hex string
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        
        return ss.str();
    }
    
    // ----- AES Encryption/Decryption -----
    
    static std::vector<unsigned char> encryptAES(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    ) {
        if (key.size() != 32) { // AES-256
            throw std::invalid_argument("Key must be 32 bytes for AES-256");
        }
        if (iv.size() != 16) { // AES block size
            throw std::invalid_argument("IV must be 16 bytes");
        }
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len;
        int ciphertext_len;
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }
    
    static std::vector<unsigned char> decryptAES(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    ) {
        if (key.size() != 32) {
            throw std::invalid_argument("Key must be 32 bytes for AES-256");
        }
        if (iv.size() != 16) {
            throw std::invalid_argument("IV must be 16 bytes");
        }
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len;
        int plaintext_len;
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    // ----- String overloads for convenience -----
    
    static std::string encryptAES(
        const std::string& plaintext,
        const std::string& key,
        const std::string& iv
    ) {
        std::vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
        std::vector<unsigned char> keyVec(key.begin(), key.end());
        std::vector<unsigned char> ivVec(iv.begin(), iv.end());
        
        auto encrypted = encryptAES(plaintextVec, keyVec, ivVec);
        return std::string(encrypted.begin(), encrypted.end());
    }
    
    static std::string decryptAES(
        const std::string& ciphertext,
        const std::string& key,
        const std::string& iv
    ) {
        std::vector<unsigned char> ciphertextVec(ciphertext.begin(), ciphertext.end());
        std::vector<unsigned char> keyVec(key.begin(), key.end());
        std::vector<unsigned char> ivVec(iv.begin(), iv.end());
        
        auto decrypted = decryptAES(ciphertextVec, keyVec, ivVec);
        return std::string(decrypted.begin(), decrypted.end());
    }
    
    // ----- Random Generation -----
    
    static std::vector<unsigned char> generateRandomBytes(size_t length) {
        std::vector<unsigned char> buffer(length);
        
        if (RAND_bytes(buffer.data(), static_cast<int>(length)) != 1) {
            throw std::runtime_error("Failed to generate random bytes");
        }
        
        return buffer;
    }
    
    static std::string generateRandomKey(size_t length = 32) {
        auto bytes = generateRandomBytes(length);
        std::stringstream ss;
        for (unsigned char byte : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        return ss.str();
    }
    
    static std::string generateRandomIV() {
        return generateRandomKey(16); // AES block size
    }
    
    // ----- Digital Signatures (simplified) -----
    
    static std::string signMessage(const std::string& message, const std::string& privateKey) {
        // Simplified signature - in production, use proper ECDSA/RSA
        return sha256(message + privateKey);
    }
    
    static bool verifySignature(
        const std::string& message,
        const std::string& signature,
        const std::string& publicKey
    ) {
        // Simplified verification - in production, use proper ECDSA/RSA
        std::string expectedSignature = sha256(message + publicKey);
        return signature == expectedSignature;
    }
    
    // ----- Network Security Helpers -----
    
    static std::string generateSessionToken() {
        return generateRandomKey(16);
    }
    
    static std::string hashPassword(const std::string& password, const std::string& salt) {
        return sha256(password + salt);
    }
    
    static bool validateHash(const std::string& data, const std::string& expectedHash) {
        return sha256(data) == expectedHash;
    }
    
    // ----- Utility Functions -----
    
    static std::string bytesToHex(const std::vector<unsigned char>& bytes) {
        std::stringstream ss;
        for (unsigned char byte : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        return ss.str();
    }
    
    static std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        bytes.reserve(hex.length() / 2);
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }
    
    // ----- Network Address Validation -----
    
    static bool isValidIPv4(const std::string& ip) {
        // Simple IPv4 validation
        std::stringstream ss(ip);
        std::string segment;
        int segmentCount = 0;
        
        while (std::getline(ss, segment, '.')) {
            if (segment.empty()) return false;
            
            try {
                int value = std::stoi(segment);
                if (value < 0 || value > 255) return false;
                segmentCount++;
            } catch (...) {
                return false;
            }
        }
        
        return segmentCount == 4;
    }
    
    static bool isValidPort(uint16_t port) {
        return port > 0 && port <= 65535;
    }
    
    static bool isPrivateIP(const std::string& ip) {
        // Check for private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if (!isValidIPv4(ip)) return false;
        
        std::stringstream ss(ip);
        std::string segment;
        std::vector<int> octets;
        
        while (std::getline(ss, segment, '.')) {
            octets.push_back(std::stoi(segment));
        }
        
        if (octets.size() != 4) return false;
        
        // 10.0.0.0/8
        if (octets[0] == 10) return true;
        
        // 172.16.0.0/12
        if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return true;
        
        // 192.168.0.0/16
        if (octets[0] == 192 && octets[1] == 168) return true;
        
        // 127.0.0.0/8 (localhost)
        if (octets[0] == 127) return true;
        
        return false;
    }
};

} // namespace p2p
} // namespace blockchain

#endif // P2P_CRYPTO_UTILS_HPP