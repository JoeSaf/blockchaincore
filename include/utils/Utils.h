#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>

class Utils {
public:
    // File operations
    static bool fileExists(const std::string& filename);
    static bool writeFile(const std::string& filename, const std::string& content);
    static std::string readFile(const std::string& filename);
    static bool deleteFile(const std::string& filename);
    
    // JSON operations
    static bool writeJsonFile(const std::string& filename, const nlohmann::json& json);
    static nlohmann::json readJsonFile(const std::string& filename);
    
    // String operations
    static std::string trim(const std::string& str);
    static std::vector<std::string> split(const std::string& str, char delimiter);
    static std::string join(const std::vector<std::string>& strings, const std::string& delimiter);
    static std::string toLower(const std::string& str);
    static std::string toUpper(const std::string& str);
    
    // Time operations
    static std::string getCurrentTimestamp();
    static std::string formatTimestamp(std::time_t timestamp);
    static std::time_t parseTimestamp(const std::string& timestamp);
    
    // Network operations
    static std::vector<std::string> getLocalIpAddresses();
    static bool isValidIpAddress(const std::string& ip);
    static bool isValidPort(uint16_t port);
    
    // System operations
    static std::string getHostname();
    static uint64_t getCurrentMemoryUsage();
    static double getCpuUsage();
    
    // Validation
    static bool isValidUuid(const std::string& uuid);
    static bool isValidEmail(const std::string& email);
    static bool isAlphanumeric(const std::string& str);
    
    // Encoding/Decoding
    static std::string urlEncode(const std::string& value);
    static std::string urlDecode(const std::string& value);
    
private:
    // Helper functions
    static char fromHex(char ch);
    static char toHex(char code);
};
