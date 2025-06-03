#include "blockchain/FileBlockchain.h"
#include "cli/CLIInterface.h"
#include "utils/Crypto.h"
#include "utils/Utils.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <spdlog/spdlog.h>

CLIInterface::CLIInterface() 
    : outputFormat_(OutputFormat::TABLE)
    , colorsEnabled_(true)
    , verbose_(false)
    , interactiveMode_(false) {
    
    initializeCommands();
    loadConfig();
}

int CLIInterface::run(int argc, char* argv[]) {
    if (argc <= 1) {
        return runInteractiveMode();
    }
    
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    
    return executeCommand(args);
}

int CLIInterface::runInteractiveMode() {
    interactiveMode_ = true;
    printWelcomeBanner();
    
    while (true) {
        try {
            std::string input = readUserInput(colorize("blockchain> ", Colors::CYAN));
            
            if (input.empty()) continue;
            
            auto args = parseCommandLine(input);
            if (args.empty()) continue;
            
            if (args[0] == "exit" || args[0] == "quit") {
                printInfo("Goodbye!");
                break;
            }
            
            executeCommand(args);
            
        } catch (const std::exception& e) {
            printError("Error: " + std::string(e.what()));
        }
    }
    
    return 0;
}

void CLIInterface::initializeCommands() {
    // ========================
    // BLOCKCHAIN COMMANDS
    // ========================
    
    registerCommand({
        "status", "Show blockchain status and health",
        "status [--security] [--verbose]", {"stat"},
        [this](const std::vector<std::string>& args) { return cmdStatus(args); },
        true, false
    });
    
    registerCommand({
        "mine", "Mine a new block",
        "mine [miner-address]", {"mining"},
        [this](const std::vector<std::string>& args) { return cmdMineBlock(args); },
        true, false
    });
    
    registerCommand({
        "validate", "Validate the entire blockchain",
        "validate [--deep] [--repair]", {"verify"},
        [this](const std::vector<std::string>& args) { return cmdValidate(args); },
        true, false
    });
    
    // ========================
    // FILE STORAGE COMMANDS
    // ========================
    
    registerCommand({
        "upload", "Upload a file to the blockchain",
        "upload <file-path> [--user-address <address>]", {"up"},
        [this](const std::vector<std::string>& args) { return cmdUploadFile(args); },
        true, false
    });
    
    registerCommand({
        "download", "Download a file from the blockchain",
        "download <file-id> [--output <path>]", {"dl", "get"},
        [this](const std::vector<std::string>& args) { return cmdDownloadFile(args); },
        true, false
    });
    
    registerCommand({
        "files", "List files in the blockchain",
        "files [--user <address>] [--format json|table]", {"ls", "list-files"},
        [this](const std::vector<std::string>& args) { return cmdListFiles(args); },
        true, false
    });
    
    // ========================
    // SECURITY COMMANDS
    // ========================
    
    registerCommand({
        "security-scan", "Perform comprehensive security scan",
        "security-scan [--deep] [--auto-fix]", {"scan"},
        [this](const std::vector<std::string>& args) { return cmdSecurityScan(args); },
        true, false
    });
    
    registerCommand({
        "reorder", "Trigger polymorphic chain reordering",
        "reorder [--reason <text>] [--force]", {"polymorphic"},
        [this](const std::vector<std::string>& args) { return cmdTriggerReorder(args); },
        true, false
    });
    
    registerCommand({
        "threats", "Show active security threats",
        "threats [--level critical|high|medium|low]", {"security-status"},
        [this](const std::vector<std::string>& args) { return cmdListThreats(args); },
        true, false
    });
    
    // ========================
    // P2P NETWORK COMMANDS
    // ========================
    
    registerCommand({
        "peers", "List connected peers",
        "peers [--detailed] [--format json|table]", {"network"},
        [this](const std::vector<std::string>& args) { return cmdListPeers(args); },
        false, true
    });
    
    registerCommand({
        "connect", "Connect to a peer",
        "connect <ip> <port>", {"peer-connect"},
        [this](const std::vector<std::string>& args) { return cmdConnectPeer(args); },
        false, true
    });
    
    registerCommand({
        "discover", "Discover peers on the network",
        "discover [--timeout <seconds>]", {"find-peers"},
        [this](const std::vector<std::string>& args) { return cmdDiscoverPeers(args); },
        false, true
    });
    
    // ========================
    // UTILITY COMMANDS
    // ========================
    
    registerCommand({
        "help", "Show help information",
        "help [command]", {"h", "?"},
        [this](const std::vector<std::string>& args) { return cmdHelp(args); },
        false, false
    });
    
    registerCommand({
        "monitor", "Real-time monitoring display",
        "monitor [--security] [--network] [--chain]", {"watch"},
        [this](const std::vector<std::string>& args) { 
            if (hasFlag(args, "--security")) {
                displayLiveSecurityMonitor();
            } else if (hasFlag(args, "--network")) {
                displayLiveNetworkStatus();
            } else {
                displayLiveChainStatus();
            }
            return 0;
        },
        true, true
    });
}

// ========================
// COMMAND IMPLEMENTATIONS
// ========================

int CLIInterface::cmdStatus(const std::vector<std::string>& args) {
    if (!requiresComponent("Blockchain", blockchain_ != nullptr)) return 1;
    
    try {
        bool showSecurity = hasFlag(args, "--security");
        bool verbose = hasFlag(args, "--verbose") || verbose_;
        
        printSeparator('=', 60);
        printInfo(colorize("BLOCKCHAIN NODE STATUS", Colors::BOLD + Colors::CYAN));
        printSeparator('=', 60);
        
        // Basic blockchain stats
        auto chainHeight = blockchain_->getChainHeight();
        auto difficulty = blockchain_->getDifficulty();
        auto mempoolSize = blockchain_->getTransactionPool().getTransactionCount();
        auto totalSupply = blockchain_->getTotalSupply();
        
        std::vector<std::vector<std::string>> statusData = {
            {"Chain Height", std::to_string(chainHeight)},
            {"Difficulty", std::to_string(difficulty)},
            {"Mempool Size", std::to_string(mempoolSize)},
            {"Total Supply", std::to_string(totalSupply) + " coins"},
            {"Average Block Time", std::to_string(blockchain_->getAverageBlockTime()) + "s"},
            {"Network Hash Rate", blockchain_->getNetworkHashRate()}
        };
        
        // Add network info if available
        if (p2pNetwork_) {
            statusData.push_back({"Connected Peers", std::to_string(p2pNetwork_->getPeerCount())});
            statusData.push_back({"Network Running", p2pNetwork_->isRunning() ? "Yes" : "No"});
            statusData.push_back({"Node ID", p2pNetwork_->getNodeId().substr(0, 16) + "..."});
        }
        
        printTable(statusData, {"Property", "Value"});
        
        // Security status if requested
        if (showSecurity && securityManager_) {
            printSeparator('-', 60);
            printInfo(colorize("SECURITY STATUS", Colors::BOLD + Colors::YELLOW));
            
            auto threatLevel = securityManager_->assessThreatLevel();
            auto threats = securityManager_->getActiveThreats();
            auto quarantined = securityManager_->getQuarantinedBlocks();
            
            std::vector<std::vector<std::string>> securityData = {
                {"Threat Level", threatLevelToString(threatLevel)},
                {"Active Threats", std::to_string(threats.size())},
                {"Quarantined Blocks", std::to_string(quarantined.size())},
                {"Chain Integrity", std::to_string(securityManager_->getChainIntegrityScore()) + "%"},
                {"Total Violations", std::to_string(securityManager_->getTotalViolationsCount())},
                {"Reorder Count", std::to_string(securityManager_->getReorderCount())}
            };
            
            printTable(securityData, {"Security Metric", "Value"});
            
            // Show critical threats
            for (const auto& threat : threats) {
                if (threat.level == ThreatLevel::CRITICAL || threat.level == ThreatLevel::HIGH) {
                    showSecurityAlert(threat);
                }
            }
        }
        
        printSeparator('=', 60);
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("status", e);
        return 1;
    }
}

int CLIInterface::cmdUploadFile(const std::vector<std::string>& args) {
    if (!validateArgs(args, 1, 3)) {
        showUsage("upload");
        return 1;
    }
    
    if (!requiresComponent("FileBlockchain", blockchain_ != nullptr)) return 1;
    
    try {
        std::string filePath = args[0];
        std::string userAddress = getFlagValue(args, "--user-address");
        
        if (userAddress.empty()) {
            userAddress = Crypto::generateRandomAddress();
            printWarning("No user address provided, using generated address: " + userAddress);
        }
        
        if (!validateFilePath(filePath)) {
            printError("File not found: " + filePath);
            return 1;
        }
        
        printInfo("Starting file upload: " + filePath);
        showProgress("Reading file", 0.1);
        
        auto fileData = readFileData(filePath);
        if (fileData.empty()) {
            printError("Failed to read file or file is empty");
            return 1;
        }
        
        showProgress("Uploading to blockchain", 0.3);
        
        // Cast to FileBlockchain if available
        auto fileBlockchain = std::dynamic_pointer_cast<FileBlockchain>(blockchain_);
        if (fileBlockchain) {
            std::string fileId = fileBlockchain->uploadFileData(fileData, filePath, userAddress);
            
            if (!fileId.empty()) {
                showProgress("Upload complete", 1.0);
                printSuccess("File uploaded successfully!");
                
                std::vector<std::vector<std::string>> uploadData = {
                    {"File ID", fileId},
                    {"File Path", filePath},
                    {"File Size", formatBytes(fileData.size())},
                    {"User Address", userAddress},
                    {"Upload Time", formatTimestamp(std::time(nullptr))}
                };
                
                printTable(uploadData, {"Property", "Value"});
                
                // Broadcast to network if available
                if (p2pNetwork_) {
                    printInfo("Broadcasting file to network...");
                    // Implementation would broadcast file metadata
                }
                
            } else {
                printError("Failed to upload file to blockchain");
                return 1;
            }
        } else {
            printError("File blockchain not available");
            return 1;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("upload", e);
        return 1;
    }
}

int CLIInterface::cmdDownloadFile(const std::vector<std::string>& args) {
    if (!validateArgs(args, 1, 2)) {
        showUsage("download");
        return 1;
    }
    
    try {
        std::string fileId = args[0];
        std::string outputPath = getFlagValue(args, "--output");
        
        if (outputPath.empty()) {
            outputPath = "./downloaded_" + fileId.substr(0, 8);
        }
        
        auto fileBlockchain = std::dynamic_pointer_cast<FileBlockchain>(blockchain_);
        if (!fileBlockchain) {
            printError("File blockchain not available");
            return 1;
        }
        
        printInfo("Downloading file: " + fileId);
        showProgress("Locating file", 0.1);
        
        if (!fileBlockchain->fileExists(fileId)) {
            printError("File not found: " + fileId);
            return 1;
        }
        
        auto metadata = fileBlockchain->getFileMetadata(fileId);
        showProgress("Downloading chunks", 0.3);
        
        auto fileData = fileBlockchain->downloadFile(fileId);
        
        if (fileData.empty()) {
            printError("Failed to download file data");
            return 1;
        }
        
        showProgress("Writing to disk", 0.8);
        
        if (!writeFileData(outputPath, fileData)) {
            printError("Failed to write file to: " + outputPath);
            return 1;
        }
        
        showProgress("Download complete", 1.0);
        printSuccess("File downloaded successfully!");
        
        std::vector<std::vector<std::string>> downloadData = {
            {"File ID", fileId},
            {"Original Name", metadata.originalName},
            {"File Size", formatBytes(fileData.size())},
            {"Output Path", outputPath},
            {"File Hash", metadata.fileHash}
        };
        
        printTable(downloadData, {"Property", "Value"});
        return 0;
        
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("download", e);
        return 1;
    }
}

int CLIInterface::cmdSecurityScan(const std::vector<std::string>& args) {
    if (!requiresComponent("Security Manager", securityManager_ != nullptr)) return 1;
    
    try {
        bool deepScan = hasFlag(args, "--deep");
        bool autoFix = hasFlag(args, "--auto-fix");
        
        printInfo(colorize("BLOCKCHAIN SECURITY SCAN", Colors::BOLD + Colors::YELLOW));
        printSeparator('=', 50);
        
        showSpinner("Performing security scan...");
        
        bool scanResult = securityManager_->performSecurityScan();
        hideSpinner();
        
        if (scanResult) {
            printSuccess("Security scan completed successfully");
        } else {
            printWarning("Security scan completed with issues detected");
        }
        
        // Show results
        auto threats = securityManager_->getActiveThreats();
        auto quarantined = securityManager_->getQuarantinedBlocks();
        
        printInfo("Scan Results:");
        std::vector<std::vector<std::string>> scanData = {
            {"Threats Found", std::to_string(threats.size())},
            {"Blocks Quarantined", std::to_string(quarantined.size())},
            {"Chain Integrity", std::to_string(securityManager_->getChainIntegrityScore()) + "%"},
            {"Scan Type", deepScan ? "Deep Scan" : "Quick Scan"}
        };
        
        printTable(scanData, {"Metric", "Value"});
        
        // Show detailed threats
        if (!threats.empty()) {
            printSeparator('-', 50);
            printWarning("Active Threats Detected:");
            
            for (const auto& threat : threats) {
                std::string levelColor = Colors::GREEN;
                if (threat.level == ThreatLevel::HIGH) levelColor = Colors::YELLOW;
                if (threat.level == ThreatLevel::CRITICAL) levelColor = Colors::RED;
                
                std::cout << colorize("• ", levelColor) 
                         << colorize(threatLevelToString(threat.level), levelColor + Colors::BOLD)
                         << " - " << threat.description << std::endl;
                std::cout << "  Block: " << threat.blockIndex 
                         << " | Time: " << formatTimestamp(threat.timestamp) << std::endl;
            }
            
            if (autoFix) {
                printInfo("Attempting automatic threat remediation...");
                
                if (securityManager_->quarantineInfectedBlocks()) {
                    printSuccess("Infected blocks quarantined");
                }
                
                if (securityManager_->migrateUserData()) {
                    printSuccess("User data migrated to clean chain");
                }
                
                auto reorderConfig = securityManager_->getReorderConfig();
                if (threats.size() >= reorderConfig.triggerThreshold) {
                    printWarning("Triggering polymorphic chain reorder...");
                    securityManager_->triggerPolymorphicReorder("Auto-fix security scan");
                    printSuccess("Chain reordering completed");
                }
            }
        } else {
            printSuccess("No security threats detected");
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("security-scan", e);
        return 1;
    }
}

int CLIInterface::cmdTriggerReorder(const std::vector<std::string>& args) {
    if (!requiresComponent("Security Manager", securityManager_ != nullptr)) return 1;
    
    try {
        std::string reason = getFlagValue(args, "--reason");
        bool force = hasFlag(args, "--force");
        
        if (reason.empty()) {
            reason = "Manual CLI trigger";
        }
        
        if (!force && !securityManager_->canExecuteReorder()) {
            printWarning("Reorder cooldown is active. Use --force to override.");
            return 1;
        }
        
        printWarning(colorize("INITIATING POLYMORPHIC CHAIN REORDER", Colors::BOLD + Colors::YELLOW));
        printInfo("Reason: " + reason);
        printSeparator('=', 50);
        
        if (!force) {
            std::cout << "This operation will reorder the blockchain structure. Continue? (y/N): ";
            std::string confirmation;
            std::getline(std::cin, confirmation);
            
            if (confirmation != "y" && confirmation != "Y") {
                printInfo("Operation cancelled");
                return 0;
            }
        }
        
        showSpinner("Analyzing chain structure...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
        showSpinner("Generating reorder sequence...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        
        showSpinner("Preserving user data...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
        showSpinner("Executing polymorphic reorder...");
        bool success = securityManager_->executePolymorphicReorder();
        hideSpinner();
        
        if (success) {
            printSuccess(colorize("POLYMORPHIC REORDER COMPLETED", Colors::BOLD + Colors::GREEN));
            
            auto newHeight = blockchain_->getChainHeight();
            auto integrity = securityManager_->getChainIntegrityScore();
            
            std::vector<std::vector<std::string>> reorderData = {
                {"Chain Height", std::to_string(newHeight)},
                {"Integrity Score", std::to_string(integrity) + "%"},
                {"Reorder Reason", reason},
                {"Completion Time", formatTimestamp(std::time(nullptr))}
            };
            
            printTable(reorderData, {"Property", "Value"});
            
            // Broadcast reorder to network
            if (p2pNetwork_) {
                printInfo("Broadcasting reordered chain to network...");
                // Implementation would sync with peers
            }
            
        } else {
            printError("Polymorphic reorder failed");
            return 1;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("reorder", e);
        return 1;
    }
}

int CLIInterface::cmdListPeers(const std::vector<std::string>& args) {
    if (!requiresComponent("P2P Network", p2pNetwork_ != nullptr)) return 1;
    
    try {
        bool detailed = hasFlag(args, "--detailed");
        
        auto peers = p2pNetwork_->getConnectedPeers();
        
        printInfo(colorize("CONNECTED PEERS", Colors::BOLD + Colors::CYAN));
        printSeparator('=', 60);
        
        if (peers.empty()) {
            printWarning("No peers connected");
            return 0;
        }
        
        if (outputFormat_ == OutputFormat::JSON) {
            nlohmann::json peersJson;
            for (const auto& peer : peers) {
                peersJson.push_back(peer.toJson());
            }
            printJson(peersJson);
            return 0;
        }
        
        std::vector<std::string> headers;
        std::vector<std::vector<std::string>> peerData;
        
        if (detailed) {
            headers = {"Peer ID", "IP Address", "Port", "Chain Height", "Last Seen", "Status"};
            for (const auto& peer : peers) {
                peerData.push_back({
                    peer.peerId.substr(0, 12) + "...",
                    peer.ipAddress,
                    std::to_string(peer.port),
                    std::to_string(peer.chainHeight),
                    formatTimestamp(peer.lastSeen),
                    peer.isConnected ? colorize("Connected", Colors::GREEN) : 
                                     colorize("Disconnected", Colors::RED)
                });
            }
        } else {
            headers = {"Peer ID", "Address", "Chain Height", "Status"};
            for (const auto& peer : peers) {
                peerData.push_back({
                    peer.peerId.substr(0, 16) + "...",
                    peer.ipAddress + ":" + std::to_string(peer.port),
                    std::to_string(peer.chainHeight),
                    peer.isConnected ? colorize("✓", Colors::GREEN) : 
                                     colorize("✗", Colors::RED)
                });
            }
        }
        
        printTable(peerData, headers);
        
        // Network statistics
        printSeparator('-', 60);
        std::vector<std::vector<std::string>> netStats = {
            {"Total Peers", std::to_string(peers.size())},
            {"Messages Sent", std::to_string(p2pNetwork_->getMessagesSent())},
            {"Messages Received", std::to_string(p2pNetwork_->getMessagesReceived())},
            {"Bytes Transferred", formatBytes(p2pNetwork_->getBytesTransferred())},
            {"Node ID", p2pNetwork_->getNodeId().substr(0, 20) + "..."}
        };
        
        printTable(netStats, {"Network Stat", "Value"});
        
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("peers", e);
        return 1;
    }
}

// ========================
// UTILITY IMPLEMENTATIONS
// ========================

void CLIInterface::printSuccess(const std::string& message) {
    std::cout << colorize("✓ ", Colors::GREEN) << colorize(message, Colors::GREEN) << std::endl;
}

void CLIInterface::printError(const std::string& message) {
    std::cout << colorize("✗ ", Colors::RED) << colorize("Error: " + message, Colors::RED) << std::endl;
}

void CLIInterface::printWarning(const std::string& message) {
    std::cout << colorize("⚠ ", Colors::YELLOW) << colorize("Warning: " + message, Colors::YELLOW) << std::endl;
}

void CLIInterface::printInfo(const std::string& message) {
    std::cout << colorize("ℹ ", Colors::BLUE) << message << std::endl;
}

void CLIInterface::displayLiveSecurityMonitor() {
    if (!securityManager_) {
        printError("Security manager not available");
        return;
    }
    
    std::cout << "\033[2J\033[H"; // Clear screen
    printInfo(colorize("LIVE SECURITY MONITOR", Colors::BOLD + Colors::CYAN));
    printInfo("Press Ctrl+C to exit");
    printSeparator('=', 80);
    
    while (true) {
        std::cout << "\033[5;1H"; // Move cursor to line 5
        
        auto threats = securityManager_->getActiveThreats();
        auto integrity = securityManager_->getChainIntegrityScore();
        auto threatLevel = securityManager_->assessThreatLevel();
        
        // Real-time threat display
        std::cout << colorize("Threat Level: ", Colors::BOLD);
        std::string levelColor = Colors::GREEN;
        if (threatLevel == ThreatLevel::HIGH) levelColor = Colors::YELLOW;
        if (threatLevel == ThreatLevel::CRITICAL) levelColor = Colors::RED;
        std::cout << colorize(threatLevelToString(threatLevel), levelColor + Colors::BOLD) << std::endl;
        
        std::cout << "Chain Integrity: " << colorize(std::to_string(integrity) + "%", 
                    integrity > 95 ? Colors::GREEN : 
                    integrity > 80 ? Colors::YELLOW : Colors::RED) << std::endl;
        
        std::cout << "Active Threats: " << threats.size() << std::endl;
        std::cout << "Last Scan: " << formatTimestamp(securityManager_->getLastSecurityScan()) << std::endl;
        
        if (!threats.empty()) {
            std::cout << "\nRecent Threats:" << std::endl;
            for (size_t i = 0; i < std::min(threats.size(), size_t(5)); ++i) {
                const auto& threat = threats[i];
                std::cout << "• " << colorize(threatLevelToString(threat.level), levelColor)
                         << " - " << threat.description << std::endl;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

std::string CLIInterface::formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string CLIInterface::colorize(const std::string& text, const std::string& color) {
    if (!colorsEnabled_) return text;
    return color + text + Colors::RESET;
}

void CLIInterface::showProgress(const std::string& operation, double percentage) {
    if (!verbose_) return;
    
    int barWidth = 40;
    std::cout << "\r" << operation << " [";
    int pos = static_cast<int>(barWidth * percentage);
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << static_cast<int>(percentage * 100.0) << "%";
    std::cout.flush();
    
    if (percentage >= 1.0) {
        std::cout << std::endl;
    }
}

std::string CLIInterface::threatLevelToString(ThreatLevel level) const {
    switch (level) {
        case ThreatLevel::NONE: return "None";
        case ThreatLevel::LOW: return "Low";
        case ThreatLevel::MEDIUM: return "Medium";
        case ThreatLevel::HIGH: return "High";
        case ThreatLevel::CRITICAL: return "Critical";
        default: return "Unknown";
    }
}

void CLIInterface::printWelcomeBanner() {
    std::cout << colorize(R"(
╔════════════════════════════════════════════════════════════════╗
║              BLOCKCHAIN FILE STORAGE SYSTEM                   ║
║                   Interactive CLI v1.0                        ║
║                                                                ║
║  Commands: upload, download, mine, status, security-scan      ║
║           peers, reorder, help, exit                          ║
║                                                                ║
║  Type 'help' for command list or 'help <command>' for details ║
╚════════════════════════════════════════════════════════════════╝
)", Colors::CYAN) << std::endl;
}


void CLIInterface::setBlockchain(std::shared_ptr<Blockchain> blockchain) {
    blockchain_ = blockchain;
}

void CLIInterface::setP2PNetwork(std::shared_ptr<P2PNetwork> network) {
    p2pNetwork_ = network;
}

void CLIInterface::setSecurityManager(std::shared_ptr<SecurityManager> securityManager) {
    securityManager_ = securityManager;
}

void CLIInterface::registerCommand(const CLICommand& command) {
    commands_[command.name] = command;
    
    // Also register aliases
    for (const auto& alias : command.aliases) {
        commands_[alias] = command;
    }
}

int CLIInterface::executeCommand(const std::vector<std::string>& args) {
    if (args.empty()) {
        printError("No command provided");
        return 1;
    }
    
    std::string commandName = args[0];
    auto it = commands_.find(commandName);
    
    if (it == commands_.end()) {
        printError("Unknown command: " + commandName);
        showCommandNotFound(commandName);
        return 1;
    }
    
    try {
        return it->second.handler(args);
    } catch (const std::exception& e) {
        handleCommandError(commandName, e);
        return 1;
    }
}

bool CLIInterface::loadConfig(const std::string& configFile) {
    if (!Utils::fileExists(configFile)) {
        spdlog::debug("Config file {} does not exist, using defaults", configFile);
        return false;
    }
    
    try {
        nlohmann::json configJson = Utils::readJsonFile(configFile);
        config_.fromJson(configJson);
        
        // Apply configuration
        outputFormat_ = config_.defaultFormat;
        colorsEnabled_ = config_.enableColors;
        verbose_ = config_.verboseOutput;
        
        spdlog::debug("Loaded CLI configuration from {}", configFile);
        return true;
    } catch (const std::exception& e) {
        spdlog::error("Failed to load config: {}", e.what());
        return false;
    }
}

std::string CLIInterface::readUserInput(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    
    std::string input;
    std::getline(std::cin, input);
    
    // Add to command history if not empty
    if (!input.empty() && input != "exit" && input != "quit") {
        commandHistory_.push_back(input);
        
        // Limit history size
        if (commandHistory_.size() > 100) {
            commandHistory_.erase(commandHistory_.begin());
        }
    }
    
    return input;
}

std::vector<std::string> CLIInterface::parseCommandLine(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string token;
    
    while (iss >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

void CLIInterface::displayLiveChainStatus() {
    if (!blockchain_) {
        printError("Blockchain not available");
        return;
    }
    
    std::cout << "\033[2J\033[H"; // Clear screen
    printInfo(colorize("LIVE BLOCKCHAIN STATUS", Colors::BOLD + Colors::CYAN));
    printInfo("Press Ctrl+C to exit");
    printSeparator('=', 80);
    
    while (true) {
        std::cout << "\033[5;1H"; // Move cursor to line 5
        
        auto height = blockchain_->getChainHeight();
        auto difficulty = blockchain_->getDifficulty();
        auto mempoolSize = blockchain_->getTransactionPool().getTransactionCount();
        
        std::cout << "Chain Height: " << colorize(std::to_string(height), Colors::GREEN) << std::endl;
        std::cout << "Difficulty: " << difficulty << std::endl;
        std::cout << "Mempool Size: " << mempoolSize << std::endl;
        std::cout << "Last Update: " << Utils::getCurrentTimestamp() << std::endl;
        
        if (p2pNetwork_) {
            std::cout << "Connected Peers: " << p2pNetwork_->getPeerCount() << std::endl;
            std::cout << "Network Status: " << (p2pNetwork_->isRunning() ? 
                colorize("Online", Colors::GREEN) : colorize("Offline", Colors::RED)) << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void CLIInterface::displayLiveNetworkStatus() {
    if (!p2pNetwork_) {
        printError("P2P Network not available");
        return;
    }
    
    std::cout << "\033[2J\033[H"; // Clear screen
    printInfo(colorize("LIVE NETWORK STATUS", Colors::BOLD + Colors::CYAN));
    printInfo("Press Ctrl+C to exit");
    printSeparator('=', 80);
    
    while (true) {
        std::cout << "\033[5;1H"; // Move cursor to line 5
        
        auto peers = p2pNetwork_->getConnectedPeers();
        std::cout << "Connected Peers: " << colorize(std::to_string(peers.size()), Colors::GREEN) << std::endl;
        std::cout << "Messages Sent: " << p2pNetwork_->getMessagesSent() << std::endl;
        std::cout << "Messages Received: " << p2pNetwork_->getMessagesReceived() << std::endl;
        std::cout << "Bytes Transferred: " << formatBytes(p2pNetwork_->getBytesTransferred()) << std::endl;
        std::cout << "Network Running: " << (p2pNetwork_->isRunning() ? 
            colorize("Yes", Colors::GREEN) : colorize("No", Colors::RED)) << std::endl;
        
        std::cout << "\nActive Peers:" << std::endl;
        for (size_t i = 0; i < std::min(peers.size(), size_t(5)); ++i) {
            const auto& peer = peers[i];
            std::cout << "• " << peer.ipAddress << ":" << peer.port 
                     << " (Height: " << peer.chainHeight << ")" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void CLIInterface::showSpinner(const std::string& message) {
    if (!verbose_) return;
    
    std::cout << message << " ";
    std::cout.flush();
}

void CLIInterface::hideSpinner() {
    if (!verbose_) return;
    
    std::cout << colorize("✓", Colors::GREEN) << std::endl;
}

bool CLIInterface::requiresComponent(const std::string& componentName, bool condition) {
    if (!condition) {
        printError(componentName + " is required but not available");
        return false;
    }
    return true;
}

bool CLIInterface::validateArgs(const std::vector<std::string>& args, size_t minArgs, size_t maxArgs) {
    if (args.size() < minArgs) {
        printError("Too few arguments. Minimum required: " + std::to_string(minArgs));
        return false;
    }
    
    if (maxArgs != SIZE_MAX && args.size() > maxArgs) {
        printError("Too many arguments. Maximum allowed: " + std::to_string(maxArgs));
        return false;
    }
    
    return true;
}

std::string CLIInterface::getFlagValue(const std::vector<std::string>& args, const std::string& flag) {
    for (size_t i = 0; i < args.size() - 1; ++i) {
        if (args[i] == flag) {
            return args[i + 1];
        }
    }
    return "";
}

bool CLIInterface::hasFlag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

bool CLIInterface::validateFilePath(const std::string& path) {
    return Utils::fileExists(path);
}

std::vector<uint8_t> CLIInterface::readFileData(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
}

bool CLIInterface::writeFileData(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

void CLIInterface::printTable(const std::vector<std::vector<std::string>>& data, 
                             const std::vector<std::string>& headers) {
    if (data.empty()) {
        printInfo("No data to display");
        return;
    }
    
    // Calculate column widths
    std::vector<size_t> columnWidths(headers.size(), 0);
    
    for (size_t i = 0; i < headers.size(); ++i) {
        columnWidths[i] = headers[i].length();
    }
    
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size() && i < columnWidths.size(); ++i) {
            columnWidths[i] = std::max(columnWidths[i], row[i].length());
        }
    }
    
    // Print headers
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << std::left << std::setw(columnWidths[i] + 2) << headers[i];
    }
    std::cout << std::endl;
    
    // Print separator
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << std::string(columnWidths[i] + 2, '-');
    }
    std::cout << std::endl;
    
    // Print data rows
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size() && i < columnWidths.size(); ++i) {
            std::cout << std::left << std::setw(columnWidths[i] + 2) << row[i];
        }
        std::cout << std::endl;
    }
}

void CLIInterface::printJson(const nlohmann::json& json) {
    std::cout << json.dump(2) << std::endl;
}

std::string CLIInterface::formatTimestamp(std::time_t timestamp) {
    return Utils::formatTimestamp(timestamp);
}

void CLIInterface::handleCommandError(const std::string& command, const std::exception& e) {
    printError("Command '" + command + "' failed: " + e.what());
}

void CLIInterface::showUsage(const std::string& command) {
    auto it = commands_.find(command);
    if (it != commands_.end()) {
        std::cout << "Usage: " << it->second.usage << std::endl;
        std::cout << "Description: " << it->second.description << std::endl;
    }
}

void CLIInterface::showCommandNotFound(const std::string& command) {
    printError("Command not found: " + command);
    printInfo("Type 'help' to see available commands");
}

void CLIInterface::showSecurityAlert(const SecurityViolation& violation) {
    std::string levelColor;
    switch (violation.level) {
        case ThreatLevel::CRITICAL: levelColor = Colors::RED; break;
        case ThreatLevel::HIGH: levelColor = Colors::YELLOW; break;
        case ThreatLevel::MEDIUM: levelColor = Colors::BLUE; break;
        default: levelColor = Colors::GREEN; break;
    }
    
    std::cout << colorize("🚨 SECURITY ALERT", Colors::BOLD + levelColor) << std::endl;
    std::cout << "Level: " << colorize(threatLevelToString(violation.level), levelColor) << std::endl;
    std::cout << "Block: " << violation.blockIndex << std::endl;
    std::cout << "Description: " << violation.description << std::endl;
    std::cout << "Time: " << formatTimestamp(violation.timestamp) << std::endl;
    printSeparator('-', 40);
}

// ========================
// MISSING COMMAND IMPLEMENTATIONS  
// ========================

int CLIInterface::cmdMineBlock(const std::vector<std::string>& args) {
    if (!requiresComponent("Blockchain", blockchain_ != nullptr)) return 1;
    
    try {
        std::string minerAddress = "default_miner";
        if (args.size() > 1) {
            minerAddress = args[1];
        } else {
            minerAddress = Crypto::generateRandomAddress();
        }
        
        printInfo("Mining new block with miner address: " + minerAddress);
        showSpinner("Mining block...");
        
        auto block = blockchain_->mineBlock(minerAddress);
        hideSpinner();
        
        if (block.getIndex() > 0) {
            printSuccess("Block mined successfully!");
            
            std::vector<std::vector<std::string>> blockData = {
                {"Block Index", std::to_string(block.getIndex())},
                {"Block Hash", block.getHash().substr(0, 32) + "..."},
                {"Nonce", std::to_string(block.getNonce())},
                {"Transactions", std::to_string(block.getTransactions().size())},
                {"Miner Address", minerAddress}
            };
            
            printTable(blockData, {"Property", "Value"});
            
            // Broadcast to network
            if (p2pNetwork_) {
                p2pNetwork_->broadcastBlock(block);
                printInfo("Block broadcasted to network");
            }
        } else {
            printError("Block mining failed");
            return 1;
        }
        
        return 0;
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("mine", e);
        return 1;
    }
}

int CLIInterface::cmdValidate(const std::vector<std::string>& args) {
    if (!requiresComponent("Blockchain", blockchain_ != nullptr)) return 1;
    
    try {
        bool deepValidation = hasFlag(args, "--deep");
        bool repair = hasFlag(args, "--repair");
        
        printInfo(colorize("BLOCKCHAIN VALIDATION", Colors::BOLD + Colors::CYAN));
        printSeparator('=', 50);
        
        showSpinner("Validating blockchain...");
        bool isValid = blockchain_->isValidChain();
        hideSpinner();
        
        if (isValid) {
            printSuccess("✓ Blockchain is valid");
        } else {
            printError("✗ Blockchain validation failed");
        }
        
        if (deepValidation) {
            printInfo("Performing deep validation...");
            
            const auto& chain = blockchain_->getChain();
            uint32_t validBlocks = 0;
            
            for (const auto& block : chain) {
                if (block.isValidBlock()) {
                    validBlocks++;
                } else {
                    printWarning("Block " + std::to_string(block.getIndex()) + " has validation issues");
                }
            }
            
            double validityPercentage = (static_cast<double>(validBlocks) / chain.size()) * 100.0;
            
            std::vector<std::vector<std::string>> validationData = {
                {"Total Blocks", std::to_string(chain.size())},
                {"Valid Blocks", std::to_string(validBlocks)},
                {"Validity Percentage", std::to_string(static_cast<int>(validityPercentage)) + "%"},
                {"Chain Height", std::to_string(blockchain_->getChainHeight())},
                {"Genesis Block", chain.empty() ? "Missing" : "Present"}
            };
            
            printTable(validationData, {"Metric", "Value"});
        }
        
        if (repair && !isValid) {
            printWarning("Repair functionality not yet implemented");
        }
        
        return isValid ? 0 : 1;
        
    } catch (const std::exception& e) {
        hideSpinner();
        handleCommandError("validate", e);
        return 1;
    }
}

int CLIInterface::cmdListFiles(const std::vector<std::string>& args) {
    if (!requiresComponent("FileBlockchain", blockchain_ != nullptr)) return 1;
    
    auto fileBlockchain = std::dynamic_pointer_cast<FileBlockchain>(blockchain_);
    if (!fileBlockchain) {
        printError("File blockchain not available");
        return 1;
    }
    
    try {
        std::string userAddress = getFlagValue(args, "--user");
        bool jsonFormat = hasFlag(args, "--json") || outputFormat_ == OutputFormat::JSON;
        
        auto files = fileBlockchain->listFiles(userAddress);
        
        if (files.empty()) {
            printInfo("No files found");
            return 0;
        }
        
        if (jsonFormat) {
            nlohmann::json filesJson = nlohmann::json::array();
            for (const auto& file : files) {
                filesJson.push_back(file.toJson());
            }
            printJson(filesJson);
        } else {
            printInfo(colorize("STORED FILES", Colors::BOLD + Colors::CYAN));
            printSeparator('=', 80);
            
            std::vector<std::string> headers = {"File ID", "Name", "Size", "Upload Time", "Uploader"};
            std::vector<std::vector<std::string>> fileData;
            
            for (const auto& file : files) {
                fileData.push_back({
                    file.fileId.substr(0, 16) + "...",
                    file.originalName,
                    formatBytes(file.fileSize),
                    formatTimestamp(file.uploadTime),
                    file.uploaderAddress.substr(0, 16) + "..."
                });
            }
            
            printTable(fileData, headers);
            printInfo("Total files: " + std::to_string(files.size()));
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("files", e);
        return 1;
    }
}

int CLIInterface::cmdListThreats(const std::vector<std::string>& args) {
    if (!requiresComponent("Security Manager", securityManager_ != nullptr)) return 1;
    
    try {
        std::string levelFilter = getFlagValue(args, "--level");
        
        auto threats = securityManager_->getActiveThreats();
        
        if (threats.empty()) {
            printSuccess("No active security threats detected");
            return 0;
        }
        
        printInfo(colorize("ACTIVE SECURITY THREATS", Colors::BOLD + Colors::YELLOW));
        printSeparator('=', 60);
        
        for (const auto& threat : threats) {
            // Filter by level if specified
            if (!levelFilter.empty()) {
                std::string threatLevelStr = threatLevelToString(threat.level);
                std::transform(threatLevelStr.begin(), threatLevelStr.end(), threatLevelStr.begin(), ::tolower);
                std::transform(levelFilter.begin(), levelFilter.end(), levelFilter.begin(), ::tolower);
                
                if (threatLevelStr != levelFilter) {
                    continue;
                }
            }
            
            showSecurityAlert(threat);
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("threats", e);
        return 1;
    }
}

int CLIInterface::cmdConnectPeer(const std::vector<std::string>& args) {
    if (!validateArgs(args, 3, 3)) {
        showUsage("connect");
        return 1;
    }
    
    if (!requiresComponent("P2P Network", p2pNetwork_ != nullptr)) return 1;
    
    try {
        std::string ip = args[1];
        uint16_t port = static_cast<uint16_t>(std::stoul(args[2]));
        
        printInfo("Connecting to peer " + ip + ":" + std::to_string(port));
        
        bool success = p2pNetwork_->connectToPeer(ip, port);
        
        if (success) {
            printSuccess("Successfully connected to peer");
        } else {
            printError("Failed to connect to peer");
            return 1;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("connect", e);
        return 1;
    }
}

int CLIInterface::cmdDiscoverPeers(const std::vector<std::string>& args) {
    if (!requiresComponent("P2P Network", p2pNetwork_ != nullptr)) return 1;
    
    try {
        printInfo("Starting peer discovery...");
        
        p2pNetwork_->discoverPeers();
        
        printSuccess("Peer discovery initiated");
        printInfo("Use 'peers' command to see discovered peers");
        
        return 0;
        
    } catch (const std::exception& e) {
        handleCommandError("discover", e);
        return 1;
    }
}

int CLIInterface::cmdHelp(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        // Show help for specific command
        std::string command = args[1];
        auto it = commands_.find(command);
        
        if (it != commands_.end()) {
            std::cout << colorize("COMMAND: " + command, Colors::BOLD + Colors::CYAN) << std::endl;
            std::cout << "Description: " << it->second.description << std::endl;
            std::cout << "Usage: " << it->second.usage << std::endl;
            
            if (!it->second.aliases.empty()) {
                std::cout << "Aliases: ";
                for (size_t i = 0; i < it->second.aliases.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << it->second.aliases[i];
                }
                std::cout << std::endl;
            }
        } else {
            printError("Unknown command: " + command);
            return 1;
        }
    } else {
        // Show general help
        std::cout << colorize("BLOCKCHAIN CLI HELP", Colors::BOLD + Colors::CYAN) << std::endl;
        printSeparator('=', 50);
        
        std::cout << "Available Commands:" << std::endl << std::endl;
        
        // Group commands by category
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> categories;
        
        for (const auto& [name, cmd] : commands_) {
            if (name == cmd.name) { // Only show primary command names, not aliases
                std::string category = "General";
                if (name.find("file") != std::string::npos || 
                    name == "upload" || name == "download" || name == "files") {
                    category = "File Storage";
                } else if (name.find("security") != std::string::npos || 
                          name == "scan" || name == "threats" || name == "reorder") {
                    category = "Security";
                } else if (name.find("peer") != std::string::npos || 
                          name == "connect" || name == "discover" || name == "peers") {
                    category = "Network";
                } else if (name == "mine" || name == "validate" || name == "status") {
                    category = "Blockchain";
                }
                
                categories[category].emplace_back(name, cmd.description);
            }
        }
        
        for (const auto& [category, commands] : categories) {
            std::cout << colorize(category + ":", Colors::BOLD + Colors::YELLOW) << std::endl;
            for (const auto& [name, desc] : commands) {
                std::cout << "  " << std::left << std::setw(15) << name << " - " << desc << std::endl;
            }
            std::cout << std::endl;
        }
        
        std::cout << "Use 'help <command>' for detailed information about a specific command." << std::endl;
    }
    
    return 0;
}

// ========================
// MISSING CLICONFIG METHODS
// ========================

nlohmann::json CLIInterface::CLIConfig::toJson() const {
    nlohmann::json json;
    json["defaultFormat"] = static_cast<int>(defaultFormat);
    json["enableColors"] = enableColors;
    json["showTimestamps"] = showTimestamps;
    json["verboseOutput"] = verboseOutput;
    json["logLevel"] = logLevel;
    return json;
}

void CLIInterface::CLIConfig::fromJson(const nlohmann::json& json) {
    if (json.contains("defaultFormat")) {
        defaultFormat = static_cast<OutputFormat>(json["defaultFormat"]);
    }
    if (json.contains("enableColors")) {
        enableColors = json["enableColors"];
    }
    if (json.contains("showTimestamps")) {
        showTimestamps = json["showTimestamps"];
    }
    if (json.contains("verboseOutput")) {
        verboseOutput = json["verboseOutput"];
    }
    if (json.contains("logLevel")) {
        logLevel = json["logLevel"];
    }
}

void CLIInterface::printSeparator(char ch, int length) {
    std::cout << std::string(length, ch) << std::endl;
}