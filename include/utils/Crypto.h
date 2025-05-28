#pragma once

#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>

class Crypto {
public:
    // SHA-256 hashing
    static std::string sha256(const std::string& input);
    static std::string sha256(const std::vector<uint8_t>& input);
    
    // Double SHA-256 (Bitcoin-style)
    static std::string doubleSha256(const std::string& input);
    
    // ECDSA key generation
    static std::pair<std::string, std::string> generateKeyPair();
    
    // Digital signatures
    static std::string signData(const std::string& data, const std::string& privateKey);
    static bool verifySignature(const std::string& data, const std::string& signature, 
                               const std::string& publicKey);
    
    // Address generation
    static std::string generateAddress(const std::string& publicKey);
    static std::string generateRandomAddress();
    
    // Utility functions
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
    static std::string base64Encode(const std::vector<uint8_t>& input);
    static std::vector<uint8_t> base64Decode(const std::string& input);
    
    // Random number generation
    static std::string generateRandomString(size_t length);
    static uint64_t generateRandomNumber();
    
    // Hash validation
    static bool isValidHash(const std::string& hash);
    static bool hasValidProofOfWork(const std::string& hash, uint32_t difficulty);
    
    // Merkle tree operations
    static std::string calculateMerkleRoot(const std::vector<std::string>& hashes);
    
private:
    // Internal utility functions
    static void ensureOpenSSLInit();
    static EC_KEY* createECKey();
    static std::string ecKeyToString(EC_KEY* key, bool isPrivate);
    static EC_KEY* stringToECKey(const std::string& keyStr, bool isPrivate);
};
