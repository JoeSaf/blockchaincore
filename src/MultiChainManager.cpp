// src/multi_chain_main.cpp
#include <iostream>
#include <memory>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include "MultiChainManager.h"
#include "p2p/P2PNetwork.h"
#include "security/SecurityManager.h"
#include "web/WebInterface.h"
#include "cli/CLIInterface.h"
#include "utils/Crypto.h"

// Global components for clean shutdown
std::shared_ptr<MultiChainManager> g_chainManager;
std::shared_ptr<P2PNetwork> g_p2pNetwork;
std::shared_ptr<SecurityManager> g_securityManager;
std::shared_ptr<WebInterface> g_webInterface;
std::atomic<bool> g_running(true);

void setupLogging() {
    // Create console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::info);
    
    // Create file sink
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        "multi_chain_node.log", 1024 * 1024 * 10, 3);
    file_sink->set_level(spdlog::level::debug);
    
    // Create logger with both sinks
    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("multi_chain", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::debug);
    
    spdlog::set_default_logger(logger);
    spdlog::info("Multi-chain logging system initialized");
}

void signalHandler(int signal) {
    spdlog::info("Received signal {}, initiating multi-chain shutdown...", signal);
    g_running = false;
    
    // Save all chains before shutdown
    if (g_chainManager) {
        spdlog::info("Saving all chains...");
        g_chainManager->saveAllChains();
    }
    
    // Stop web interface
    if (g_webInterface) {
        g_webInterface->stop();
    }
    
    // Stop P2P network
    if (g_p2pNetwork) {
        g_p2pNetwork->stop();
    }
    
    // Shutdown chain manager
    if (g_chainManager) {
        g_chainManager->shutdownChains();
    }
    
    spdlog::info("Multi-chain system shutdown complete");
    exit(0);
}

void setupSignalHandlers() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    #ifndef _WIN32
    signal(SIGQUIT, signalHandler);
    #endif
}

void printStartupBanner() {
    std::cout << R"(
╔════════════════════════════════════════════════════════════════╗
║              MULTI-CHAIN BLOCKCHAIN SYSTEM v2.0                ║
║                                                                ║
║  🔗 Main Chain    - User registration & peer management        ║
║  📁 File Chain    - Secure file storage & retrieval            ║
║  🔐 Auth Chain    - Authentication & permissions               ║
║  👤 Identity Chain - User identity & verification              ║
║                                                                ║
║  🛡️  Advanced Security  🌐  P2P Network  💻  Web Interface     ║
╚════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printSystemInfo() {
    spdlog::info("Multi-Chain System Configuration:");
    spdlog::info("  Main Chain: peer & user management");
    spdlog::info("  File Chain: isolated file storage");
    spdlog::info("  Auth Chain: permissions & sessions");
    spdlog::info("  Identity Chain: user verification");
    spdlog::info("  P2P Ports: TCP 8333, UDP 8334");
    spdlog::info("  Web Interface: http://localhost:8080");
    spdlog::info("  Cross-chain messaging: enabled");
}

bool initializeMultiChainSystem() {
    try {
        g_chainManager = std::make_shared<MultiChainManager>();
        
        if (!g_chainManager->initializeChains()) {
            spdlog::error("Failed to initialize multi-chain system");
            return false;
        }
        
        spdlog::info("Multi-chain system initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain system: {}", e.what());
        return false;
    }
}

bool initializeP2PNetwork() {
    try {
        g_p2pNetwork = std::make_shared<P2PNetwork>(8333, 8334);
        
        // Set callbacks for multi-chain operations
        g_p2pNetwork->setBlockReceivedCallback([](const Block& block, const std::string& peerId) {
            spdlog::info("Received block {} from peer {}", block.getIndex(), peerId);
            
            // Determine which chain this block belongs to based on transactions
            auto mainChain = g_chainManager->getMainChain();
            if (mainChain && mainChain->addBlock(block)) {
                spdlog::info("Added block {} to main chain", block.getIndex());
                g_chainManager->saveAllChains();
            } else {
                spdlog::warn("Rejected invalid block {} from peer {}", block.getIndex(), peerId);
            }
        });
        
        g_p2pNetwork->setTransactionReceivedCallback([](const Transaction& tx, const std::string& peerId) {
            spdlog::info("Received transaction {} from peer {}", tx.getId(), peerId);
            
            // Route transaction to appropriate chain
            auto mainChain = g_chainManager->getMainChain();
            if (mainChain && mainChain->addTransaction(tx)) {
                spdlog::info("Added transaction {} to main chain mempool", tx.getId());
            } else {
                spdlog::warn("Rejected invalid transaction {} from peer {}", tx.getId(), peerId);
            }
        });
        
        g_p2pNetwork->setPeerConnectedCallback([](const PeerInfo& peer) {
            spdlog::info("New peer connected: {} ({}:{})", peer.peerId, peer.ipAddress, peer.port);
            
            // Register peer in main chain
            MainChainTransaction peerTx(MainChainTransaction::MainOperation::PEER_REGISTRATION, peer.peerId);
            peerTx.setPeerInfo(peer);
            
            auto mainChain = g_chainManager->getMainChain();
            if (mainChain) {
                mainChain->addTransaction(peerTx);
            }
        });
        
        g_p2pNetwork->setPeerDisconnectedCallback([](const std::string& peerId) {
            spdlog::info("Peer disconnected: {}", peerId);
        });
        
        // Set chain height from main chain
        auto mainChain = g_chainManager->getMainChain();
        if (mainChain) {
            g_p2pNetwork->setChainHeight(mainChain->getChainHeight());
        }
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize P2P network: {}", e.what());
        return false;
    }
}

bool initializeSecurityManager() {
    try {
        // Use main chain for security management
        auto mainChain = g_chainManager->getMainChain();
        g_securityManager = std::make_shared<SecurityManager>(mainChain);
        
        // Set security callbacks for multi-chain protection
        g_securityManager->setSecurityEventCallback([](const SecurityViolation& violation) {
            spdlog::critical("Security violation detected: {} in block {}", 
                           static_cast<int>(violation.event), violation.blockIndex);
            
            // Handle cross-chain security implications
            if (violation.level == ThreatLevel::CRITICAL) {
                spdlog::warn("Triggering cross-chain security protocols");
                // Could trigger reordering across all chains
            }
        });
        
        // Connect security manager to chain manager
        g_chainManager->setSecurityManager(g_securityManager);
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize security manager: {}", e.what());
        return false;
    }
}

bool initializeWebInterface() {
    try {
        g_webInterface = std::make_shared<WebInterface>(8080);
        
        // Connect to multi-chain system
        g_webInterface->setFileBlockchain(g_chainManager->getFileChain());
        g_webInterface->setP2PNetwork(g_p2pNetwork);
        g_webInterface->setSecurityManager(g_securityManager);
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize web interface: {}", e.what());
        return false;
    }
}

void startServices() {
    spdlog::info("Starting multi-chain services...");
    
    // Start P2P network
    if (!g_p2pNetwork->start()) {
        spdlog::error("Failed to start P2P network");
        return;
    }
    spdlog::info("P2P network started successfully");
    
    // Start web interface
    if (!g_webInterface->start()) {
        spdlog::error("Failed to start web interface");
        return;
    }
    spdlog::info("Web interface started successfully");
    
    // Start peer discovery
    g_p2pNetwork->discoverPeers();
    spdlog::info("Peer discovery initiated");
    
    // Start cross-chain message processing
    std::thread([&]() {
        while (g_running) {
            g_chainManager->processCrossChainMessages();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }).detach();
    
    spdlog::info("Cross-chain message processor started");
}

void runMainLoop() {
    spdlog::info("Multi-chain system is running. Press Ctrl+C to stop.");
    
    auto lastSave = std::chrono::steady_clock::now();
    auto lastStats = std::chrono::steady_clock::now();
    auto lastSecurityScan = std::chrono::steady_clock::now();
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        
        // Save all chains periodically
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastSave).count() >= 5) {
            g_chainManager->saveAllChains();
            lastSave = now;
            spdlog::debug("All chains saved to disk");
        }
        
        // Print system statistics
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastStats).count() >= 2) {
            auto status = g_chainManager->getSystemStatus();
            
            spdlog::info("System Status:");
            spdlog::info("  Main Chain Height: {}", status["chains"]["main"]["height"]);
            spdlog::info("  File Chain Height: {}, Files: {}", 
                        status["chains"]["file"]["height"], 
                        status["chains"]["file"]["file_count"]);
            spdlog::info("  Auth Chain Height: {}", status["chains"]["auth"]["height"]);
            spdlog::info("  Identity Chain Height: {}", status["chains"]["identity"]["height"]);
            spdlog::info("  Connected Peers: {}", g_p2pNetwork->getPeerCount());
            spdlog::info("  Pending Cross-Chain Messages: {}", status["cross_chain"]["pending_messages"]);
            
            lastStats = now;
        }
        
        // Periodic security scan
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastSecurityScan).count() >= 10) {
            spdlog::info("Performing scheduled security scan across all chains...");
            g_chainManager->performSecurityScan();
            lastSecurityScan = now;
        }
        
        // Update P2P network with main chain height
        auto mainChain = g_chainManager->getMainChain();
        if (mainChain) {
            g_p2pNetwork->setChainHeight(mainChain->getChainHeight());
        }
    }
}

void printUsageInstructions() {
    std::cout << "\n=== Multi-Chain System Usage Instructions ===\n" << std::endl;
    
    std::cout << "Web Interface:" << std::endl;
    std::cout << "  http://localhost:8080                      - Main dashboard" << std::endl;
    std::cout << "  http://localhost:8080/api/status           - System status" << std::endl;
    std::cout << "  http://localhost:8080/api/chains           - All chain info" << std::endl;
    std::cout << "" << std::endl;
    
    std::cout << "API Endpoints:" << std::endl;
    std::cout << "  POST /api/auth/register                     - Register new user" << std::endl;
    std::cout << "  POST /api/auth/login                        - User login" << std::endl;
    std::cout << "  POST /api/files/upload                      - Upload file" << std::endl;
    std::cout << "  GET  /api/files/list                        - List user files" << std::endl;
    std::cout << "  GET  /api/files/download/{fileId}           - Download file" << std::endl;
    std::cout << "  GET  /api/security/status                   - Security status" << std::endl;
    std::cout << "" << std::endl;
    
    std::cout << "Example User Registration:" << std::endl;
    std::cout << R"(  curl -X POST http://localhost:8080/api/auth/register \)" << std::endl;
    std::cout << R"(    -H "Content-Type: application/json" \)" << std::endl;
    std::cout << R"(    -d '{"username":"alice","email":"alice@example.com","password":"secret123"}')" << std::endl;
    std::cout << "" << std::endl;
    
    std::cout << "Example File Upload:" << std::endl;
    std::cout << R"(  curl -X POST http://localhost:8080/api/files/upload \)" << std::endl;
    std::cout << R"(    -H "Authorization: Bearer {sessionId}" \)" << std::endl;
    std::cout << R"(    -F "file=@document.pdf")" << std::endl;
    std::cout << "" << std::endl;
    
    std::cout << "Chain Separation:" << std::endl;
    std::cout << "  • Main Chain: Users, peers, coordination" << std::endl;
    std::cout << "  • File Chain: File storage (isolated)" << std::endl;
    std::cout << "  • Auth Chain: Permissions, sessions" << std::endl;
    std::cout << "  • Identity Chain: User verification" << std::endl;
    std::cout << "\n==========================================\n" << std::endl;
}

void demonstrateSystem() {
    std::cout << "\n=== Multi-Chain System Demonstration ===" << std::endl;
    
    try {
        // Register a demo user
        std::string userId = g_chainManager->registerUser("demo_user", "demo@example.com", "demo123");
        if (!userId.empty()) {
            std::cout << "✓ Demo user registered: " << userId << std::endl;
            
            // Create sample file data
            std::string sampleContent = "This is a sample file stored in the isolated file chain!";
            std::vector<uint8_t> fileData(sampleContent.begin(), sampleContent.end());
            
            // Upload file
            std::string fileId = g_chainManager->uploadFile(fileData, "sample.txt", userId);
            if (!fileId.empty()) {
                std::cout << "✓ Sample file uploaded: " << fileId << std::endl;
                
                // Download file
                auto downloadedData = g_chainManager->downloadFile(fileId, userId);
                if (!downloadedData.empty()) {
                    std::cout << "✓ File downloaded successfully" << std::endl;
                    std::cout << "✓ Multi-chain system working correctly!" << std::endl;
                }
            }
        }
        
        // Show system status
        auto status = g_chainManager->getSystemStatus();
        std::cout << "\nSystem Status:" << std::endl;
        std::cout << "  All chains healthy: " << 
            (status["chains"]["main"]["healthy"].get<bool>() &&
             status["chains"]["file"]["healthy"].get<bool>() &&
             status["chains"]["auth"]["healthy"].get<bool>() &&
             status["chains"]["identity"]["healthy"].get<bool>() ? "Yes" : "No") << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Demonstration error: " << e.what() << std::endl;
    }
    
    std::cout << "========================================\n" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        // Setup logging first
        setupLogging();
        
        // Print startup banner
        printStartupBanner();
        
        // Setup signal handlers for clean shutdown
        setupSignalHandlers();
        
        // Print system configuration
        printSystemInfo();
        
        // Initialize multi-chain system
        spdlog::info("Initializing multi-chain blockchain system...");
        
        if (!initializeMultiChainSystem()) {
            spdlog::error("Failed to initialize multi-chain system");
            return 1;
        }
        
        if (!initializeP2PNetwork()) {
            spdlog::error("Failed to initialize P2P network");
            return 1;
        }
        
        if (!initializeSecurityManager()) {
            spdlog::error("Failed to initialize security manager");
            return 1;
        }
        
        if (!initializeWebInterface()) {
            spdlog::error("Failed to initialize web interface");
            return 1;
        }
        
        // Start all services
        startServices();
        
        // Print usage instructions
        printUsageInstructions();
        
        // Run system demonstration
        if (argc > 1 && std::string(argv[1]) == "--demo") {
            demonstrateSystem();
        }
        
        // Run main event loop
        runMainLoop();
        
    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    } catch (...) {
        spdlog::error("Unknown fatal error occurred");
        return 1;
    }
    
    return 0;
}