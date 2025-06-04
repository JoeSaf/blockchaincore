#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <iostream>
#include <iomanip>
#include "../blockchain/Blockchain.h"
#include "../p2p/P2PNetwork.h"
#include "../api/RestApiServer.h"
#include "../blockchain/FileBlockchain.h"
#include "../security/SecurityManager.h"

// Forward declarations to avoid circular dependencies
class FileBlockchain;
class SecurityManager;
class MultiChainManager;
enum class ThreatLevel;
struct SecurityViolation;
enum class ChainType;
struct ChainConfig;

// CLI command structure
struct CLICommand {
    std::string name;
    std::string description;
    std::string usage;
    std::vector<std::string> aliases;
    std::function<int(const std::vector<std::string>&)> handler;
    bool requiresBlockchain;
    bool requiresNetwork;
};

// CLI output formatting
enum class OutputFormat {
    TABLE,
    JSON,
    PLAIN,
    DETAILED
};

// CLI color codes for output
namespace Colors {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

class CLIInterface {
public:
    // Constructor
    CLIInterface();
    
    // Destructor
    ~CLIInterface() = default;
    
    // Main CLI operations
    int run(int argc, char* argv[]);
    int runInteractiveMode();
    int executeCommand(const std::vector<std::string>& args);
    
    // Component setup
    void setBlockchain(std::shared_ptr<Blockchain> blockchain);
    void setP2PNetwork(std::shared_ptr<P2PNetwork> network);
    void setApiServer(std::shared_ptr<RestApiServer> apiServer);
    void setSecurityManager(std::shared_ptr<SecurityManager> securityManager);
    void setMultiChainManager(std::shared_ptr<MultiChainManager> manager);
    
    // CLI configuration
    void setOutputFormat(OutputFormat format) { outputFormat_ = format; }
    void enableColors(bool enable) { colorsEnabled_ = enable; }
    void setVerbose(bool verbose) { verbose_ = verbose; }

private:
    // Core components
    std::shared_ptr<Blockchain> blockchain_;
    std::shared_ptr<P2PNetwork> p2pNetwork_;
    std::shared_ptr<RestApiServer> apiServer_;
    std::shared_ptr<SecurityManager> securityManager_;
    std::shared_ptr<MultiChainManager> multiChainManager_;
    
    // CLI configuration
    OutputFormat outputFormat_;
    bool colorsEnabled_;
    bool verbose_;
    bool interactiveMode_;
    
    // Command registry
    std::unordered_map<std::string, CLICommand> commands_;
    std::vector<std::string> commandHistory_;
    
    // Setup and initialization
    void initializeCommands();
    void registerCommand(const CLICommand& command);
    
    // ========================
    // BLOCKCHAIN COMMANDS
    // ========================
    
    // Chain operations
    int cmdStatus(const std::vector<std::string>& args);
    int cmdInfo(const std::vector<std::string>& args);
    int cmdValidate(const std::vector<std::string>& args);
    int cmdStats(const std::vector<std::string>& args);
    
    // Block operations
    int cmdGetBlock(const std::vector<std::string>& args);
    int cmdListBlocks(const std::vector<std::string>& args);
    int cmdMineBlock(const std::vector<std::string>& args);
    int cmdVerifyBlock(const std::vector<std::string>& args);
    
    // Transaction operations
    int cmdCreateTransaction(const std::vector<std::string>& args);
    int cmdListTransactions(const std::vector<std::string>& args);
    int cmdGetTransaction(const std::vector<std::string>& args);
    int cmdMempool(const std::vector<std::string>& args);
    
    // Wallet operations
    int cmdGenerateAddress(const std::vector<std::string>& args);
    int cmdGetBalance(const std::vector<std::string>& args);
    int cmdListAddresses(const std::vector<std::string>& args);
    
    // ========================
    // FILE STORAGE COMMANDS
    // ========================
    
    int cmdUploadFile(const std::vector<std::string>& args);
    int cmdDownloadFile(const std::vector<std::string>& args);
    int cmdListFiles(const std::vector<std::string>& args);
    int cmdVerifyFile(const std::vector<std::string>& args);
    int cmdDeleteFile(const std::vector<std::string>& args);
    
    // ========================
    // P2P NETWORK COMMANDS
    // ========================
    
    int cmdNetworkStatus(const std::vector<std::string>& args);
    int cmdListPeers(const std::vector<std::string>& args);
    int cmdConnectPeer(const std::vector<std::string>& args);
    int cmdDisconnectPeer(const std::vector<std::string>& args);
    int cmdDiscoverPeers(const std::vector<std::string>& args);
    int cmdBroadcast(const std::vector<std::string>& args);
    
    // ========================
    // SECURITY COMMANDS
    // ========================
    
    int cmdSecurityScan(const std::vector<std::string>& args);
    int cmdSecurityStatus(const std::vector<std::string>& args);
    int cmdListThreats(const std::vector<std::string>& args);
    int cmdQuarantineInfo(const std::vector<std::string>& args);
    int cmdTriggerReorder(const std::vector<std::string>& args);
    int cmdSecurityReport(const std::vector<std::string>& args);
    int cmdMigrateData(const std::vector<std::string>& args);
    
    // ========================
    // MULTI-CHAIN COMMANDS
    // ========================
    
    int cmdMultiChain(const std::vector<std::string>& args);
    int cmdMultiChainList(const std::vector<std::string>& args);
    int cmdMultiChainCreate(const std::vector<std::string>& args);
    int cmdMultiChainStart(const std::vector<std::string>& args);
    int cmdMultiChainStop(const std::vector<std::string>& args);
    int cmdMultiChainStatus(const std::vector<std::string>& args);
    int cmdMultiChainTransfer(const std::vector<std::string>& args);
    int cmdMultiChainBridge(const std::vector<std::string>& args);
    int cmdMultiChainConsensus(const std::vector<std::string>& args);
    
    void showMultiChainHelp();
    
    // ========================
    // SYSTEM COMMANDS
    // ========================
    
    int cmdHelp(const std::vector<std::string>& args);
    int cmdVersion(const std::vector<std::string>& args);
    int cmdConfig(const std::vector<std::string>& args);
    int cmdLogs(const std::vector<std::string>& args);
    int cmdExit(const std::vector<std::string>& args);
    
    // ========================
    // API SERVER COMMANDS
    // ========================
    
    int cmdStartApi(const std::vector<std::string>& args);
    int cmdStopApi(const std::vector<std::string>& args);
    int cmdApiStatus(const std::vector<std::string>& args);
    
    // ========================
    // UTILITY FUNCTIONS
    // ========================
    
    // Output formatting
    void printSuccess(const std::string& message);
    void printError(const std::string& message);
    void printWarning(const std::string& message);
    void printInfo(const std::string& message);
    void printTable(const std::vector<std::vector<std::string>>& data, 
                   const std::vector<std::string>& headers);
    void printJson(const nlohmann::json& json);
    void printSeparator(char ch = '=', int length = 60);
    
    // Interactive mode helpers
    std::string readUserInput(const std::string& prompt = "> ");
    std::vector<std::string> parseCommandLine(const std::string& line);
    void printPrompt();
    void printWelcomeBanner();
    void showInteractiveHelp();
    
    // Real-time monitoring displays
    void displayLiveChainStatus();
    void displayLiveNetworkStatus();
    void displayLiveSecurityMonitor();
    void displayLivePeerActivity();
    
    // Security alerts and notifications
    void showSecurityAlert(const SecurityViolation& violation);
    void showRealtimeThreats();
    void showChainIntegrityStatus();
    
    // Progress indicators
    void showProgress(const std::string& operation, double percentage);
    void showSpinner(const std::string& message);
    void hideSpinner();
    
    // Command validation
    bool validateArgs(const std::vector<std::string>& args, size_t minArgs, size_t maxArgs = SIZE_MAX);
    bool requiresComponent(const std::string& componentName, bool condition);
    
    // File operations
    bool validateFilePath(const std::string& path);
    std::vector<uint8_t> readFileData(const std::string& path);
    bool writeFileData(const std::string& path, const std::vector<uint8_t>& data);
    
    // String utilities
    std::string formatBytes(uint64_t bytes);
    std::string formatDuration(uint64_t seconds);
    std::string formatTimestamp(std::time_t timestamp);
    std::string truncateString(const std::string& str, size_t maxLength);
    std::string colorize(const std::string& text, const std::string& color);
    std::string threatLevelToString(ThreatLevel level) const;
    
    // Command parsing
    CLICommand* findCommand(const std::string& name);
    std::vector<std::string> getCommandSuggestions(const std::string& partial);
    bool isFlag(const std::string& arg);
    std::string getFlagValue(const std::vector<std::string>& args, const std::string& flag);
    bool hasFlag(const std::vector<std::string>& args, const std::string& flag);
    
    // Auto-completion helpers
    std::vector<std::string> getCompletionOptions(const std::string& partial);
    void setupAutoComplete();
    
    // Error handling
    void handleCommandError(const std::string& command, const std::exception& e);
    void showUsage(const std::string& command);
    void showCommandNotFound(const std::string& command);
    
    // Configuration management
    struct CLIConfig {
        OutputFormat defaultFormat = OutputFormat::TABLE;
        bool enableColors = true;
        bool showTimestamps = true;
        bool verboseOutput = false;
        std::string logLevel = "info";
        
        nlohmann::json toJson() const;
        void fromJson(const nlohmann::json& json);
    };
    
    CLIConfig config_;
    bool loadConfig(const std::string& configFile = "cli_config.json");
    bool saveConfig(const std::string& configFile = "cli_config.json");
};