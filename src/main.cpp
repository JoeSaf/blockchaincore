// =======================================================================================
// Integration of MultiChainManager into Main Components
// =======================================================================================

// Updated src/main.cpp with MultiChainManager integration
#define HTTPLIB_IMPLEMENTATION
#define HTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <iostream>
#include <memory>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include "blockchain/Blockchain.h"
#include "blockchain/FileBlockchain.h"
#include "p2p/P2PNetwork.h"
#include "api/RestApiServer.h"
#include "web/WebInterface.h"
#include "security/SecurityManager.h"
#include "multichain/MultiChainManager.h"
#include "utils/Crypto.h"

// Global variables for clean shutdown - Enhanced with MultiChain
std::shared_ptr<MultiChainManager> g_multiChainManager;
std::shared_ptr<Blockchain> g_blockchain;
std::shared_ptr<FileBlockchain> g_fileBlockchain;
std::shared_ptr<P2PNetwork> g_p2pNetwork;
std::shared_ptr<RestApiServer> g_apiServer;
std::shared_ptr<WebInterface> g_webInterface;
std::shared_ptr<SecurityManager> g_securityManager;
std::atomic<bool> g_running(true);

void setupLogging() {
    // Create console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::info);
    
    // Create file sink
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        "blockchain_node.log", 1024 * 1024 * 10, 3);
    file_sink->set_level(spdlog::level::debug);
    
    // Create logger with both sinks
    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("blockchain", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::debug);
    
    spdlog::set_default_logger(logger);
    spdlog::info("Enhanced multi-chain logging system initialized");
}

void signalHandler(int signal) {
    spdlog::info("Received signal {}, initiating multi-chain shutdown...", signal);
    g_running = false;
    
    // Graceful multi-chain shutdown
    if (g_webInterface) {
        g_webInterface->stop();
    }
    
    if (g_apiServer) {
        g_apiServer->stop();
    }
    
    if (g_p2pNetwork) {
        g_p2pNetwork->stop();
    }
    
    // Stop all chains managed by MultiChainManager
    if (g_multiChainManager) {
        auto chainIds = g_multiChainManager->getAllChainIds();
        for (const auto& chainId : chainIds) {
            g_multiChainManager->stopChain(chainId);
        }
    }
    
    spdlog::info("Multi-chain shutdown complete");
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
║              🌐 MULTI-CHAIN BLOCKCHAIN NODE v2.0 🌐            ║
║                                                                ║
║  Advanced Multi-Chain Blockchain System with:                 ║
║  🔗 Multiple Blockchain Support (Main, File, Identity)        ║
║  🌉 Cross-Chain Bridges & Transactions                        ║
║  🛡️ Coordinated Security Across All Chains                    ║
║  📁 Distributed File Storage System                           ║
║  🌐 P2P Multi-Network Coordination                            ║
║  💻 Enhanced CLI & Web Interfaces                             ║
║  🔄 Polymorphic Chain Reordering                              ║
╚════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printNodeInfo() {
    spdlog::info("Multi-Chain Node Configuration:");
    spdlog::info("  🔗 Main Chain - TCP: 8333, API: 8080");
    spdlog::info("  📁 File Chain - TCP: 8335, API: 8082");
    spdlog::info("  🌐 Web Interface: 8080");
    spdlog::info("  🌉 Cross-Chain Bridges: Enabled");
    spdlog::info("  🛡️ Global Security: Active");
    spdlog::info("  Mining Reward: {} coins per block", Blockchain::MINING_REWARD);
    spdlog::info("  Block Time Target: {} seconds", Blockchain::BLOCK_TIME_TARGET);
}

bool initializeMultiChainSystem() {
    try {
        spdlog::info("Initializing multi-chain blockchain system...");
        
        // Initialize MultiChainManager first
        g_multiChainManager = std::make_shared<MultiChainManager>();
        
        // Get primary chains from MultiChainManager
        auto chainIds = g_multiChainManager->getAllChainIds();
        
        for (const auto& chainId : chainIds) {
            auto config = g_multiChainManager->getChainStatus(chainId);
            spdlog::info("Detected chain: {} - Type: {}", 
                        chainId, config["type"].get<std::string>());
        }
        
        // Get main blockchain reference
        if (!chainIds.empty()) {
            g_blockchain = g_multiChainManager->getChain(chainIds[0]);
            
            // Try to get file blockchain
            g_fileBlockchain = g_multiChainManager->getFileChain(chainIds.size() > 1 ? chainIds[1] : chainIds[0]);
            if (!g_fileBlockchain) {
                // Create file blockchain if not found
                auto fileConfig = ChainFactory::createDefaultConfig(ChainType::FILE_CHAIN, "FileStorage");
                fileConfig.p2pPort = 8335;
                fileConfig.apiPort = 8082;
                std::string fileChainId = g_multiChainManager->createChain(fileConfig);
                g_fileBlockchain = g_multiChainManager->getFileChain(fileChainId);
            }
        }
        
        if (!g_blockchain) {
            spdlog::error("Failed to initialize primary blockchain");
            return false;
        }
        
        // Try to load existing blockchain state
        if (g_blockchain->loadFromFile("blockchain.json")) {
            spdlog::info("Loaded existing main blockchain with {} blocks", 
                        g_blockchain->getChainHeight());
        }
        
        if (g_fileBlockchain && g_fileBlockchain->loadFromFile("file_blockchain.json")) {
            spdlog::info("Loaded existing file blockchain with {} blocks", 
                        g_fileBlockchain->getChainHeight());
        }
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain system: {}", e.what());
        return false;
    }
}

bool initializeP2PNetwork() {
    try {
        // Initialize primary P2P network coordinator
        g_p2pNetwork = std::make_shared<P2PNetwork>(8333, 8334);
        
        // Set up multi-chain callbacks
        g_p2pNetwork->setBlockReceivedCallback([](const Block& block, const std::string& peerId) {
            spdlog::info("Received new block {} from peer {}", block.getIndex(), peerId);
            
            // Add to primary blockchain
            if (g_blockchain && g_blockchain->addBlock(block)) {
                spdlog::info("Added block {} to main chain", block.getIndex());
                g_blockchain->saveToFile("blockchain.json");
                
                // Broadcast to other chains if needed
                if (g_multiChainManager) {
                    g_multiChainManager->performGlobalConsensus();
                }
            }
        });
        
        g_p2pNetwork->setTransactionReceivedCallback([](const Transaction& tx, const std::string& peerId) {
            spdlog::info("Received transaction {} from peer {}", tx.getId(), peerId);
            
            if (g_blockchain && g_blockchain->addTransaction(tx)) {
                spdlog::info("Added transaction {} to main chain mempool", tx.getId());
            }
        });
        
        g_p2pNetwork->setChainSyncRequestCallback([](uint32_t fromHeight) -> std::vector<Block> {
            spdlog::info("Chain sync requested from height {}", fromHeight);
            
            std::vector<Block> blocks;
            if (g_blockchain) {
                const auto& chain = g_blockchain->getChain();
                for (uint32_t i = fromHeight; i < chain.size(); ++i) {
                    blocks.push_back(chain[i]);
                }
            }
            return blocks;
        });
        
        g_p2pNetwork->setPeerConnectedCallback([](const PeerInfo& peer) {
            spdlog::info("Multi-chain peer connected: {} ({}:{})", 
                        peer.peerId, peer.ipAddress, peer.port);
        });
        
        g_p2pNetwork->setPeerDisconnectedCallback([](const std::string& peerId) {
            spdlog::info("Multi-chain peer disconnected: {}", peerId);
        });
        
        // Set current chain height
        if (g_blockchain) {
            g_p2pNetwork->setChainHeight(g_blockchain->getChainHeight());
        }
        
        // Register network coordinator with MultiChainManager
        if (g_multiChainManager) {
            g_multiChainManager->setNetworkCoordinator(g_p2pNetwork);
        }
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain P2P network: {}", e.what());
        return false;
    }
}

bool initializeSecuritySystem() {
    try {
        if (!g_blockchain) {
            spdlog::error("Cannot initialize security without primary blockchain");
            return false;
        }
        
        // Initialize global security manager
        g_securityManager = std::make_shared<SecurityManager>(g_blockchain);
        
        // Set up multi-chain security coordination
        if (g_multiChainManager) {
            g_multiChainManager->setGlobalSecurityManager(g_securityManager);
            
            // Set up security event callbacks
            g_securityManager->setSecurityEventCallback([](const SecurityViolation& violation) {
                spdlog::warn("Multi-chain security event: {} - Block {}", 
                           static_cast<int>(violation.event), violation.blockIndex);
                
                // Handle security events across all chains
                if (g_multiChainManager) {
                    auto chainIds = g_multiChainManager->getAllChainIds();
                    for (const auto& chainId : chainIds) {
                        g_multiChainManager->handleSecurityThreat(chainId, violation);
                    }
                }
            });
            
            g_securityManager->setChainReorderCallback([](const std::vector<Block>& reorderedChain) {
                spdlog::info("Multi-chain polymorphic reorder completed with {} blocks", 
                           reorderedChain.size());
                
                // Coordinate reordering across all chains
                if (g_multiChainManager) {
                    g_multiChainManager->synchronizeAllChains();
                }
            });
        }
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain security system: {}", e.what());
        return false;
    }
}

bool initializeWebInterface() {
    try {
        g_webInterface = std::make_shared<WebInterface>(8080);
        
        // Set primary blockchain
        if (g_fileBlockchain) {
            g_webInterface->setFileBlockchain(g_fileBlockchain);
        }
        
        // Set network and security references
        g_webInterface->setP2PNetwork(g_p2pNetwork);
        g_webInterface->setSecurityManager(g_securityManager);
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain web interface: {}", e.what());
        return false;
    }
}

bool initializeApiServer() {
    try {
        g_apiServer = std::make_shared<RestApiServer>(8080);
        
        // Set primary blockchain reference
        g_apiServer->setBlockchain(g_blockchain);
        g_apiServer->setP2PNetwork(g_p2pNetwork);
        g_apiServer->enableCORS(true);
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize multi-chain API server: {}", e.what());
        return false;
    }
}

void startMultiChainServices() {
    spdlog::info("Starting multi-chain blockchain services...");
    
    // Start all chains in MultiChainManager
    if (g_multiChainManager) {
        auto chainIds = g_multiChainManager->getAllChainIds();
        for (const auto& chainId : chainIds) {
            if (g_multiChainManager->startChain(chainId)) {
                spdlog::info("Started chain: {}", chainId);
            } else {
                spdlog::warn("Failed to start chain: {}", chainId);
            }
        }
    }
    
    // Start P2P network coordinator
    if (g_p2pNetwork && g_p2pNetwork->start()) {
        spdlog::info("Multi-chain P2P network started successfully");
        g_p2pNetwork->discoverPeers();
    } else {
        spdlog::error("Failed to start P2P network coordinator");
    }
    
    // Start Web Interface
    if (g_webInterface && g_webInterface->start()) {
        spdlog::info("Multi-chain web interface started successfully");
    } else {
        spdlog::error("Failed to start web interface");
    }
    
    // Start API server
    if (g_apiServer && g_apiServer->start()) {
        spdlog::info("Multi-chain REST API server started successfully");
    } else {
        spdlog::error("Failed to start REST API server");
    }
    
    spdlog::info("Multi-chain ecosystem fully operational");
}

void runMultiChainMainLoop() {
    spdlog::info("Multi-chain blockchain node is running. Press Ctrl+C to stop.");
    
    auto lastSave = std::chrono::steady_clock::now();
    auto lastStats = std::chrono::steady_clock::now();
    auto lastGlobalConsensus = std::chrono::steady_clock::now();
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        
        // Save blockchain state periodically
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastSave).count() >= 5) {
            if (g_blockchain) {
                g_blockchain->saveToFile("blockchain.json");
            }
            if (g_fileBlockchain) {
                g_fileBlockchain->saveToFile("file_blockchain.json");
            }
            lastSave = now;
            spdlog::debug("Multi-chain state saved to files");
        }
        
        // Print statistics periodically
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastStats).count() >= 1) {
            if (g_multiChainManager) {
                auto metrics = g_multiChainManager->getGlobalMetrics();
                spdlog::info("Multi-Chain Status - Chains: {}, Global Height: {}, Peers: {}, Cross-Chain Txs: {}", 
                           metrics["totalChains"].get<int>(),
                           metrics["maxHeight"].get<int>(),
                           g_p2pNetwork ? g_p2pNetwork->getPeerCount() : 0,
                           metrics["crossChainTransactions"].get<int>());
            }
            lastStats = now;
        }
        
        // Perform global consensus periodically
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastGlobalConsensus).count() >= 2) {
            if (g_multiChainManager) {
                g_multiChainManager->performGlobalConsensus();
            }
            lastGlobalConsensus = now;
        }
        
        // Update network with current chain heights
        if (g_p2pNetwork && g_blockchain) {
            g_p2pNetwork->setChainHeight(g_blockchain->getChainHeight());
        }
    }
}

void printMultiChainUsageInstructions() {
    std::cout << "\n=== Multi-Chain Blockchain Node Usage Instructions ===\n" << std::endl;
    
    std::cout << "🌐 Multi-Chain REST API Endpoints:" << std::endl;
    std::cout << "  GET  http://localhost:8080/api/status                 - Global node status" << std::endl;
    std::cout << "  GET  http://localhost:8080/api/chains                 - List all chains" << std::endl;
    std::cout << "  GET  http://localhost:8080/api/chain/{id}             - Specific chain info" << std::endl;
    std::cout << "  POST http://localhost:8080/api/chain/create           - Create new chain" << std::endl;
    std::cout << "  POST http://localhost:8080/api/bridge/create          - Create cross-chain bridge" << std::endl;
    std::cout << "  POST http://localhost:8080/api/crosschain/transfer    - Cross-chain transfer" << std::endl;
    
    std::cout << "\n🔗 Main Chain Endpoints:" << std::endl;
    std::cout << "  GET  http://localhost:8080/api/blockchain             - Main blockchain" << std::endl;
    std::cout << "  POST http://localhost:8080/api/transactions           - Create transaction" << std::endl;
    std::cout << "  POST http://localhost:8080/api/mine                   - Mine new block" << std::endl;
    
    std::cout << "\n📁 File Chain Endpoints:" << std::endl;
    std::cout << "  GET  http://localhost:8082/api/files                  - List stored files" << std::endl;
    std::cout << "  POST http://localhost:8082/api/files/upload           - Upload file" << std::endl;
    std::cout << "  GET  http://localhost:8082/api/files/download/{id}    - Download file" << std::endl;
    
    std::cout << "\n🛡️ Security Endpoints:" << std::endl;
    std::cout << "  GET  http://localhost:8080/api/security/status        - Security status" << std::endl;
    std::cout << "  POST http://localhost:8080/api/security/scan          - Run security scan" << std::endl;
    std::cout << "  POST http://localhost:8080/api/security/reorder       - Trigger chain reorder" << std::endl;
    
    std::cout << "\n🌉 Cross-Chain Examples:" << std::endl;
    std::cout << R"(  # Create cross-chain transfer)" << std::endl;
    std::cout << R"(  curl -X POST http://localhost:8080/api/crosschain/transfer \)" << std::endl;
    std::cout << R"(    -H "Content-Type: application/json" \)" << std::endl;
    std::cout << R"(    -d '{"sourceChain":"main","targetChain":"file","from":"addr1","to":"addr2","amount":10}')" << std::endl;
    
    std::cout << "\n💻 CLI Commands:" << std::endl;
    std::cout << "  ./bin/blockchain_cli multichain list                  - List all chains" << std::endl;
    std::cout << "  ./bin/blockchain_cli multichain create file MyFiles   - Create file chain" << std::endl;
    std::cout << "  ./bin/blockchain_cli multichain transfer main file addr1 addr2 10 - Cross-chain transfer" << std::endl;
    
    std::cout << "\n🌐 Web Interface:" << std::endl;
    std::cout << "  Multi-Chain Dashboard: http://localhost:8080" << std::endl;
    std::cout << "  File Manager:          http://localhost:8080/files" << std::endl;
    std::cout << "  Chain Explorer:        http://localhost:8080/explorer" << std::endl;
    std::cout << "  Security Monitor:      http://localhost:8080/security" << std::endl;
    
    std::cout << "\n========================================================\n" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        // Setup enhanced logging
        setupLogging();
        
        // Print multi-chain banner
        printStartupBanner();
        
        // Setup signal handlers
        setupSignalHandlers();
        
        // Print node configuration
        printNodeInfo();
        
        // Initialize multi-chain components
        spdlog::info("Initializing advanced multi-chain blockchain system...");
        
        if (!initializeMultiChainSystem()) {
            spdlog::error("Failed to initialize multi-chain system");
            return 1;
        }
        
        if (!initializeP2PNetwork()) {
            spdlog::error("Failed to initialize multi-chain P2P network");
            return 1;
        }
        
        if (!initializeSecuritySystem()) {
            spdlog::error("Failed to initialize multi-chain security system");
            return 1;
        }
        
        if (!initializeWebInterface()) {
            spdlog::error("Failed to initialize multi-chain web interface");
            return 1;
        }
        
        if (!initializeApiServer()) {
            spdlog::error("Failed to initialize multi-chain API server");
            return 1;
        }
        
        // Start all multi-chain services
        startMultiChainServices();
        
        // Print usage instructions
        printMultiChainUsageInstructions();
        
        // Run main event loop
        runMultiChainMainLoop();
        
    } catch (const std::exception& e) {
        spdlog::error("Multi-chain fatal error: {}", e.what());
        return 1;
    } catch (...) {
        spdlog::error("Unknown multi-chain fatal error occurred");
        return 1;
    }
    
    return 0;
}

