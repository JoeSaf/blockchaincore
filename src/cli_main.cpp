#include <iostream>
#include <memory>
#include <csignal>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include "blockchain/Blockchain.h"
#include "p2p/P2PNetwork.h"
#include "security/SecurityManager.h"
#include "blockchain/FileBlockchain.h"
#include "cli/CLIInterface.h"
#include "utils/Crypto.h"

// Global components for clean shutdown
std::shared_ptr<Blockchain> g_blockchain;
std::shared_ptr<FileBlockchain> g_fileBlockchain;
std::shared_ptr<P2PNetwork> g_p2pNetwork;
std::shared_ptr<SecurityManager> g_securityManager;
std::shared_ptr<CLIInterface> g_cli;
std::atomic<bool> g_running(true);

void setupLogging() {
    // Create console sink with colors
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::info);
    
    // Create file sink for detailed logs
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        "blockchain_cli.log", 1024 * 1024 * 5, 3); // 5MB, 3 files
    file_sink->set_level(spdlog::level::debug);
    
    // Create logger with both sinks
    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("blockchain_cli", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::debug);
    
    spdlog::set_default_logger(logger);
    spdlog::info("CLI logging system initialized");
}

void signalHandler(int signal) {
    spdlog::info("Received signal {}, shutting down CLI...", signal);
    g_running = false;
    
    // Graceful shutdown
    if (g_p2pNetwork) {
        g_p2pNetwork->stop();
    }
    
    spdlog::info("CLI shutdown complete");
    exit(0);
}

void setupSignalHandlers() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    #ifndef _WIN32
    signal(SIGQUIT, signalHandler);
    #endif
}

void printCLIBanner() {
    std::cout << R"(
╔════════════════════════════════════════════════════════════════╗
║              BLOCKCHAIN FILE STORAGE CLI v1.0                 ║
║                                                                ║
║  🛡️  Advanced Security     📁  File Storage                    ║
║  🌐  P2P Network          🔄  Polymorphic Reordering          ║
║                                                                ║
║  Type 'help' for commands or use direct CLI arguments         ║
╚════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

bool initializeComponents() {
    try {
        spdlog::info("Initializing blockchain components...");
        
        // Initialize file blockchain (extends regular blockchain)
        g_fileBlockchain = std::make_shared<FileBlockchain>();
        g_blockchain = std::static_pointer_cast<Blockchain>(g_fileBlockchain);
        
        // Try to load existing blockchain
        if (g_blockchain->loadFromFile("blockchain.json")) {
            spdlog::info("Loaded existing blockchain with {} blocks", 
                        g_blockchain->getChainHeight());
        } else {
            spdlog::info("Created new blockchain with genesis block");
        }
        
        // Initialize P2P network
        g_p2pNetwork = std::make_shared<P2PNetwork>(8333, 8334);
        g_p2pNetwork->setChainHeight(g_blockchain->getChainHeight());
        
        // Initialize security manager
        g_securityManager = std::make_shared<SecurityManager>(g_blockchain);
        
        // Initialize CLI interface
        g_cli = std::make_shared<CLIInterface>();
        g_cli->setBlockchain(g_blockchain);
        g_cli->setP2PNetwork(g_p2pNetwork);
        g_cli->setSecurityManager(g_securityManager);
        
        spdlog::info("All components initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize components: {}", e.what());
        return false;
    }
}

bool startNetworkComponents() {
    try {
        // Start P2P network (optional for CLI)
        if (!g_p2pNetwork->start()) {
            spdlog::warn("P2P network failed to start (CLI will work offline)");
            return false;
        }
        
        spdlog::info("P2P network started successfully");
        
        // Discover peers
        g_p2pNetwork->discoverPeers();
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::warn("Network startup failed: {} (CLI will work offline)", e.what());
        return false;
    }
}

void printQuickHelp() {
    std::cout << "\n🚀 Quick Start Commands:\n" << std::endl;
    std::cout << "  blockchain_cli status                    # Show node status\n";
    std::cout << "  blockchain_cli upload myfile.txt        # Upload a file\n";
    std::cout << "  blockchain_cli download <file-id>        # Download a file\n";
    std::cout << "  blockchain_cli files                     # List stored files\n";
    std::cout << "  blockchain_cli mine                      # Mine a new block\n";
    std::cout << "  blockchain_cli security-scan             # Run security scan\n";
    std::cout << "  blockchain_cli peers                     # Show connected peers\n";
    std::cout << "  blockchain_cli reorder                   # Trigger chain reorder\n";
    std::cout << "  blockchain_cli help                      # Show all commands\n";
    std::cout << "\n💡 Run without arguments for interactive mode\n" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        // Setup logging
        setupLogging();
        
        // Print banner
        printCLIBanner();
        
        // Setup signal handlers
        setupSignalHandlers();
        
        // Initialize components
        if (!initializeComponents()) {
            spdlog::error("Failed to initialize blockchain components");
            return 1;
        }
        
        // Start network components (optional for CLI)
        bool networkAvailable = startNetworkComponents();
        if (!networkAvailable) {
            spdlog::info("Running in offline mode (blockchain operations still available)");
        }
        
        // Show quick help if no arguments
        if (argc <= 1) {
            printQuickHelp();
        }
        
        // Run CLI interface
        int result = g_cli->run(argc, argv);
        
        // Save blockchain before exit
        if (g_blockchain) {
            g_blockchain->saveToFile("blockchain.json");
            spdlog::info("Blockchain saved to file");
        }
        
        // Graceful shutdown
        if (g_p2pNetwork) {
            g_p2pNetwork->stop();
        }
        
        spdlog::info("CLI application finished with code {}", result);
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << "CLI Fatal Error: " << e.what() << std::endl;
        spdlog::error("CLI Fatal Error: {}", e.what());
        return 1;
    } catch (...) {
        std::cerr << "CLI Unknown Fatal Error" << std::endl;
        spdlog::error("CLI Unknown Fatal Error");
        return 1;
    }
}

// Additional CLI helper functions that might be useful

namespace CLIHelpers {
    void printSystemInfo() {
        std::cout << "\n=== System Information ===" << std::endl;
        std::cout << "CLI Version: 1.0.0" << std::endl;
        std::cout << "Blockchain Height: " << (g_blockchain ? g_blockchain->getChainHeight() : 0) << std::endl;
        std::cout << "Network Status: " << (g_p2pNetwork && g_p2pNetwork->isRunning() ? "Online" : "Offline") << std::endl;
        std::cout << "Security Manager: " << (g_securityManager ? "Active" : "Disabled") << std::endl;
        std::cout << "File Storage: " << (g_fileBlockchain ? "Available" : "Disabled") << std::endl;
        std::cout << "=========================" << std::endl;
    }
    
    void printNetworkInfo() {
        if (!g_p2pNetwork) {
            std::cout << "P2P Network: Not available" << std::endl;
            return;
        }
        
        std::cout << "\n=== Network Information ===" << std::endl;
        std::cout << "Node ID: " << g_p2pNetwork->getNodeId() << std::endl;
        std::cout << "Connected Peers: " << g_p2pNetwork->getPeerCount() << std::endl;
        std::cout << "Messages Sent: " << g_p2pNetwork->getMessagesSent() << std::endl;
        std::cout << "Messages Received: " << g_p2pNetwork->getMessagesReceived() << std::endl;
        std::cout << "Network Running: " << (g_p2pNetwork->isRunning() ? "Yes" : "No") << std::endl;
        std::cout << "============================" << std::endl;
    }
    
    void printSecurityInfo() {
        if (!g_securityManager) {
            std::cout << "Security Manager: Not available" << std::endl;
            return;
        }
        
        std::cout << "\n=== Security Information ===" << std::endl;
        std::cout << "Total Violations: " << g_securityManager->getTotalViolationsCount() << std::endl;
        std::cout << "Reorder Count: " << g_securityManager->getReorderCount() << std::endl;
        std::cout << "Threat Level: " << static_cast<int>(g_securityManager->assessThreatLevel()) << std::endl;
        std::cout << "Last Scan: " << g_securityManager->getLastSecurityScan() << std::endl;
        std::cout << "=============================" << std::endl;
    }
}