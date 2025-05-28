#include "utils/Utils.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <unistd.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

bool Utils::fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

bool Utils::writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << content;
        file.close();
        return true;
    }
    return false;
}

std::string Utils::readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }
    return "";
}

bool Utils::deleteFile(const std::string& filename) {
    return (std::remove(filename.c_str()) == 0);
}

bool Utils::writeJsonFile(const std::string& filename, const nlohmann::json& json) {
    try {
        std::string content = json.dump(4); // Pretty print with 4 spaces
        return writeFile(filename, content);
    } catch (const std::exception& e) {
        spdlog::error("Failed to write JSON file {}: {}", filename, e.what());
        return false;
    }
}

nlohmann::json Utils::readJsonFile(const std::string& filename) {
    try {
        std::string content = readFile(filename);
        if (!content.empty()) {
            return nlohmann::json::parse(content);
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to read JSON file {}: {}", filename, e.what());
    }
    return nlohmann::json();
}

std::string Utils::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> Utils::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string Utils::join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) {
        return "";
    }
    
    std::stringstream ss;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) {
            ss << delimiter;
        }
        ss << strings[i];
    }
    
    return ss.str();
}

std::string Utils::toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string Utils::toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string Utils::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}

std::string Utils::formatTimestamp(std::time_t timestamp) {
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&timestamp), "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}

std::time_t Utils::parseTimestamp(const std::string& timestamp) {
    std::tm tm = {};
    std::stringstream ss(timestamp);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    return std::mktime(&tm);
}

std::vector<std::string> Utils::getLocalIpAddresses() {
    std::vector<std::string> addresses;
    
    struct ifaddrs *ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return addresses;
    }
    
    for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            char addr_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr_in->sin_addr), addr_buf, INET_ADDRSTRLEN);
            addresses.emplace_back(addr_buf);
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return addresses;
}

bool Utils::isValidIpAddress(const std::string& ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return result != 0;
}

bool Utils::isValidPort(uint16_t port) {
    return port > 0 && port <= 65535;
}

std::string Utils::getHostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
}

uint64_t Utils::getCurrentMemoryUsage() {
    // Simple memory usage reading from /proc/self/status
    std::ifstream file("/proc/self/status");
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.substr(0, 6) == "VmRSS:") {
            std::stringstream ss(line);
            std::string label, value, unit;
            ss >> label >> value >> unit;
            return std::stoull(value) * 1024; // Convert from KB to bytes
        }
    }
    
    return 0;
}

double Utils::getCpuUsage() {
    // Simplified CPU usage - in a real implementation this would be more sophisticated
    return 0.0;
}

bool Utils::isValidUuid(const std::string& uuid) {
    std::regex uuid_regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
    return std::regex_match(uuid, uuid_regex);
}

bool Utils::isValidEmail(const std::string& email) {
    std::regex email_regex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return std::regex_match(email, email_regex);
}

bool Utils::isAlphanumeric(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isalnum(c);
    });
}

std::string Utils::urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }
    
    return escaped.str();
}

std::string Utils::urlDecode(const std::string& value) {
    std::string result;
    result.reserve(value.length());
    
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            char hex1 = value[i + 1];
            char hex2 = value[i + 2];
            char decoded = fromHex(hex1) * 16 + fromHex(hex2);
            result += decoded;
            i += 2;
        } else if (value[i] == '+') {
            result += ' ';
        } else {
            result += value[i];
        }
    }
    
    return result;
}

char Utils::fromHex(char ch) {
    return std::isdigit(ch) ? ch - '0' : std::tolower(ch) - 'a' + 10;
}

char Utils::toHex(char code) {
    static const char hex[] = "0123456789abcdef";
    return hex[code & 15];
}
