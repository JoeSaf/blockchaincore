// p2p_python_bindings.cpp - Complete Enhanced Version
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <pybind11/chrono.h>
#include <pybind11/operators.h>

#include "blockchain_core.hpp"
#include "p2p_types.hpp"
#include "p2p_message.hpp"
#include "p2p_peer.hpp"
#include "p2p_network_manager_enhanced.hpp"
#include "blockchain_p2p_integration.hpp"

namespace py = pybind11;

void add_p2p_bindings(py::module& m) {
    // ----- P2P Network Configuration -----
    
    py::class_<blockchain::p2p::NetworkConfig>(m, "NetworkConfig")
        .def(py::init<>())
        .def_readwrite("max_peers", &blockchain::p2p::NetworkConfig::maxPeers)
        .def_readwrite("connection_timeout", &blockchain::p2p::NetworkConfig::connectionTimeout)
        .def_readwrite("handshake_timeout", &blockchain::p2p::NetworkConfig::handshakeTimeout)
        .def_readwrite("heartbeat_interval", &blockchain::p2p::NetworkConfig::heartbeatInterval)
        .def_readwrite("max_message_size", &blockchain::p2p::NetworkConfig::maxMessageSize)
        .def_readwrite("enable_encryption", &blockchain::p2p::NetworkConfig::enableEncryption)
        .def_readwrite("protocol_version", &blockchain::p2p::NetworkConfig::protocolVersion)
        .def_readwrite("enable_logging", &blockchain::p2p::NetworkConfig::enableLogging)
        .def_readwrite("allow_inbound_connections", &blockchain::p2p::NetworkConfig::allowInboundConnections)
        .def_readwrite("enable_peer_discovery", &blockchain::p2p::NetworkConfig::enablePeerDiscovery)
        .def_readwrite("max_inbound_connections", &blockchain::p2p::NetworkConfig::maxInboundConnections)
        .def_readwrite("max_outbound_connections", &blockchain::p2p::NetworkConfig::maxOutboundConnections)
        .def_readwrite("reconnect_interval", &blockchain::p2p::NetworkConfig::reconnectInterval)
        .def_readwrite("max_reconnect_attempts", &blockchain::p2p::NetworkConfig::maxReconnectAttempts)
        .def_readwrite("message_queue_size", &blockchain::p2p::NetworkConfig::messageQueueSize)
        .def_readwrite("message_processing_threads", &blockchain::p2p::NetworkConfig::messageProcessingThreads)
        .def("isValid", &blockchain::p2p::NetworkConfig::isValid);
    
    // ----- Peer Information -----
    
    py::class_<blockchain::p2p::PeerInfo>(m, "PeerInfo")
        .def(py::init<>())
        .def_readwrite("peer_id", &blockchain::p2p::PeerInfo::peerId)
        .def_readwrite("address", &blockchain::p2p::PeerInfo::address)
        .def_readwrite("port", &blockchain::p2p::PeerInfo::port)
        .def_readwrite("version", &blockchain::p2p::PeerInfo::version)
        .def_readwrite("connected", &blockchain::p2p::PeerInfo::connected)
        .def_readwrite("outbound", &blockchain::p2p::PeerInfo::outbound)
        .def_readwrite("messages_sent", &blockchain::p2p::PeerInfo::messagesSent)
        .def_readwrite("messages_received", &blockchain::p2p::PeerInfo::messagesReceived)
        .def_readwrite("bytes_sent", &blockchain::p2p::PeerInfo::bytesSent)
        .def_readwrite("bytes_received", &blockchain::p2p::PeerInfo::bytesReceived)
        .def_readwrite("capabilities", &blockchain::p2p::PeerInfo::capabilities)
        .def("getAddress", &blockchain::p2p::PeerInfo::getAddress)
        .def("isActive", &blockchain::p2p::PeerInfo::isActive)
        .def("getUptimeSeconds", &blockchain::p2p::PeerInfo::getUptimeSeconds)
        .def("toJson", &blockchain::p2p::PeerInfo::toJson)
        .def_static("fromJson", &blockchain::p2p::PeerInfo::fromJson);
    
    // ----- Network Statistics -----
    
    py::class_<blockchain::p2p::NetworkStats>(m, "NetworkStats")
        .def(py::init<>())
        .def("getUptimeSeconds", &blockchain::p2p::NetworkStats::getUptimeSeconds)
        .def("getConnectionSuccessRate", &blockchain::p2p::NetworkStats::getConnectionSuccessRate)
        .def("getAverageMessageRate", &blockchain::p2p::NetworkStats::getAverageMessageRate)
        .def("toJson", &blockchain::p2p::NetworkStats::toJson)
        .def_property_readonly("messages_sent", [](const blockchain::p2p::NetworkStats& s) { 
            return s.messagesSent.load(); 
        })
        .def_property_readonly("messages_received", [](const blockchain::p2p::NetworkStats& s) { 
            return s.messagesReceived.load(); 
        })
        .def_property_readonly("bytes_sent", [](const blockchain::p2p::NetworkStats& s) { 
            return s.bytesSent.load(); 
        })
        .def_property_readonly("bytes_received", [](const blockchain::p2p::NetworkStats& s) { 
            return s.bytesReceived.load(); 
        })
        .def_property_readonly("peer_count", [](const blockchain::p2p::NetworkStats& s) { 
            return s.peerCount.load(); 
        });
    
    // ----- Message Types -----
    
    py::enum_<blockchain::p2p::MessageType>(m, "MessageType")
        .value("PING", blockchain::p2p::MessageType::PING)
        .value("PONG", blockchain::p2p::MessageType::PONG)
        .value("HANDSHAKE", blockchain::p2p::MessageType::HANDSHAKE)
        .value("HANDSHAKE_ACK", blockchain::p2p::MessageType::HANDSHAKE_ACK)
        .value("DISCONNECT", blockchain::p2p::MessageType::DISCONNECT)
        .value("BLOCK_ANNOUNCEMENT", blockchain::p2p::MessageType::BLOCK_ANNOUNCEMENT)
        .value("BLOCK_REQUEST", blockchain::p2p::MessageType::BLOCK_REQUEST)
        .value("BLOCK_RESPONSE", blockchain::p2p::MessageType::BLOCK_RESPONSE)
        .value("CHAIN_REQUEST", blockchain::p2p::MessageType::CHAIN_REQUEST)
        .value("CHAIN_RESPONSE", blockchain::p2p::MessageType::CHAIN_RESPONSE)
        .value("TRANSACTION", blockchain::p2p::MessageType::TRANSACTION)
        .value("MEMPOOL_REQUEST", blockchain::p2p::MessageType::MEMPOOL_REQUEST)
        .value("MEMPOOL_RESPONSE", blockchain::p2p::MessageType::MEMPOOL_RESPONSE)
        .value("SYNC_REQUEST", blockchain::p2p::MessageType::SYNC_REQUEST)
        .value("SYNC_RESPONSE", blockchain::p2p::MessageType::SYNC_RESPONSE)
        .value("PEER_LIST_REQUEST", blockchain::p2p::MessageType::PEER_LIST_REQUEST)
        .value("PEER_LIST_RESPONSE", blockchain::p2p::MessageType::PEER_LIST_RESPONSE)
        .value("CUSTOM", blockchain::p2p::MessageType::CUSTOM);
    
    // ----- Message Priority -----
    
    py::enum_<blockchain::p2p::MessagePriority>(m, "MessagePriority")
        .value("LOW", blockchain::p2p::MessagePriority::LOW)
        .value("NORMAL", blockchain::p2p::MessagePriority::NORMAL)
        .value("HIGH", blockchain::p2p::MessagePriority::HIGH)
        .value("CRITICAL", blockchain::p2p::MessagePriority::CRITICAL);
    
    // ----- Peer Events -----
    
    py::enum_<blockchain::p2p::PeerEvent>(m, "PeerEvent")
        .value("CONNECTED", blockchain::p2p::PeerEvent::CONNECTED)
        .value("DISCONNECTED", blockchain::p2p::PeerEvent::DISCONNECTED)
        .value("HANDSHAKE_COMPLETED", blockchain::p2p::PeerEvent::HANDSHAKE_COMPLETED)
        .value("MESSAGE_RECEIVED", blockchain::p2p::PeerEvent::MESSAGE_RECEIVED)
        .value("ERROR_OCCURRED", blockchain::p2p::PeerEvent::ERROR_OCCURRED)
        .value("TIMEOUT", blockchain::p2p::PeerEvent::TIMEOUT);
    
    // ----- Network Errors -----
    
    py::enum_<blockchain::p2p::NetworkError>(m, "NetworkError")
        .value("NONE", blockchain::p2p::NetworkError::NONE)
        .value("CONNECTION_FAILED", blockchain::p2p::NetworkError::CONNECTION_FAILED)
        .value("HANDSHAKE_FAILED", blockchain::p2p::NetworkError::HANDSHAKE_FAILED)
        .value("MESSAGE_TOO_LARGE", blockchain::p2p::NetworkError::MESSAGE_TOO_LARGE)
        .value("INVALID_MESSAGE", blockchain::p2p::NetworkError::INVALID_MESSAGE)
        .value("PEER_LIMIT_REACHED", blockchain::p2p::NetworkError::PEER_LIMIT_REACHED)
        .value("TIMEOUT", blockchain::p2p::NetworkError::TIMEOUT)
        .value("PROTOCOL_MISMATCH", blockchain::p2p::NetworkError::PROTOCOL_MISMATCH)
        .value("AUTHENTICATION_FAILED", blockchain::p2p::NetworkError::AUTHENTICATION_FAILED)
        .value("NETWORK_UNREACHABLE", blockchain::p2p::NetworkError::NETWORK_UNREACHABLE)
        .value("UNKNOWN", blockchain::p2p::NetworkError::UNKNOWN);
    
    // ----- P2P Message -----
    
    py::class_<blockchain::p2p::P2PMessage>(m, "P2PMessage")
        .def(py::init<>())
        .def(py::init<blockchain::p2p::MessageType, const std::string&>())
        .def(py::init<blockchain::p2p::MessageType, const blockchain::json&>())
        .def("getType", &blockchain::p2p::P2PMessage::getType)
        .def("getPayload", &blockchain::p2p::P2PMessage::getPayload)
        .def("getJsonPayload", &blockchain::p2p::P2PMessage::getJsonPayload)
        .def("isJsonMessage", &blockchain::p2p::P2PMessage::isJsonMessage)
        .def("getSenderId", &blockchain::p2p::P2PMessage::getSenderId)
        .def("getTimestamp", &blockchain::p2p::P2PMessage::getTimestamp)
        .def("getMessageId", &blockchain::p2p::P2PMessage::getMessageId)
        .def("getPriority", &blockchain::p2p::P2PMessage::getPriority)
        .def("getPayloadSize", &blockchain::p2p::P2PMessage::getPayloadSize)
        .def("getChecksum", &blockchain::p2p::P2PMessage::getChecksum)
        .def("getTotalSize", &blockchain::p2p::P2PMessage::getTotalSize)
        .def("setSenderId", &blockchain::p2p::P2PMessage::setSenderId)
        .def("setPriority", &blockchain::p2p::P2PMessage::setPriority)
        .def("setFlags", &blockchain::p2p::P2PMessage::setFlags)
        .def("isValid", &blockchain::p2p::P2PMessage::isValid)
        .def("hasExpired", &blockchain::p2p::P2PMessage::hasExpired, py::arg("max_age_seconds") = 300)
        .def("serialize", &blockchain::p2p::P2PMessage::serialize)
        .def_static("deserialize", &blockchain::p2p::P2PMessage::deserialize)
        .def("toJson", &blockchain::p2p::P2PMessage::toJson)
        .def("toString", &blockchain::p2p::P2PMessage::toString)
        // Factory methods
        .def_static("createPing", &blockchain::p2p::P2PMessage::createPing)
        .def_static("createPong", &blockchain::p2p::P2PMessage::createPong)
        .def_static("createHandshake", &blockchain::p2p::P2PMessage::createHandshake)
        .def_static("createHandshakeAck", &blockchain::p2p::P2PMessage::createHandshakeAck)
        .def_static("createBlockAnnouncement", &blockchain::p2p::P2PMessage::createBlockAnnouncement)
        .def_static("createTransaction", &blockchain::p2p::P2PMessage::createTransaction)
        .def_static("createSyncRequest", &blockchain::p2p::P2PMessage::createSyncRequest, py::arg("sender_id"), py::arg("from_block") = 0)
        .def_static("createPeerListRequest", &blockchain::p2p::P2PMessage::createPeerListRequest);
    
    // ----- Message Queue -----
    
    py::class_<blockchain::p2p::MessageQueue>(m, "MessageQueue")
        .def(py::init<size_t>(), py::arg("max_size") = 1000)
        .def("push", &blockchain::p2p::MessageQueue::push)
        .def("pop", [](blockchain::p2p::MessageQueue& queue, int timeout_ms) {
            blockchain::p2p::P2PMessage message;
            bool success = queue.pop(message, std::chrono::milliseconds(timeout_ms));
            return std::make_tuple(success, message);
        }, py::arg("timeout_ms") = 100)
        .def("size", &blockchain::p2p::MessageQueue::size)
        .def("empty", &blockchain::p2p::MessageQueue::empty)
        .def("clear", &blockchain::p2p::MessageQueue::clear);
    
    // ----- Message Batch -----
    
    py::class_<blockchain::p2p::MessageBatch>(m, "MessageBatch")
        .def(py::init<size_t>(), py::arg("max_batch_size") = 100)
        .def("addMessage", &blockchain::p2p::MessageBatch::addMessage)
        .def("getMessages", &blockchain::p2p::MessageBatch::getMessages)
        .def("size", &blockchain::p2p::MessageBatch::size)
        .def("empty", &blockchain::p2p::MessageBatch::empty)
        .def("clear", &blockchain::p2p::MessageBatch::clear)
        .def("isFull", &blockchain::p2p::MessageBatch::isFull)
        .def("serialize", &blockchain::p2p::MessageBatch::serialize)
        .def_static("deserialize", &blockchain::p2p::MessageBatch::deserialize);
    
    // ----- Peer Connection -----
    
    py::class_<blockchain::p2p::PeerConnection, std::shared_ptr<blockchain::p2p::PeerConnection>>(m, "PeerConnection")
        .def("connect", &blockchain::p2p::PeerConnection::connect, py::arg("timeout") = std::chrono::seconds(10))
        .def("disconnect", &blockchain::p2p::PeerConnection::disconnect)
        .def("sendMessage", &blockchain::p2p::PeerConnection::sendMessage)
        .def("receiveMessage", [](blockchain::p2p::PeerConnection& conn, int timeout_ms) {
            blockchain::p2p::P2PMessage message;
            bool success = conn.receiveMessage(message, std::chrono::milliseconds(timeout_ms));
            return std::make_tuple(success, message);
        }, py::arg("timeout_ms") = 100)
        .def("performHandshake", &blockchain::p2p::PeerConnection::performHandshake)
        .def("isConnected", &blockchain::p2p::PeerConnection::isConnected)
        .def("isHandshakeCompleted", &blockchain::p2p::PeerConnection::isHandshakeCompleted)
        .def("getPeerInfo", &blockchain::p2p::PeerConnection::getPeerInfo)
        .def("getConnectionStats", &blockchain::p2p::PeerConnection::getConnectionStats)
        .def("setMessageHandler", &blockchain::p2p::PeerConnection::setMessageHandler)
        .def("setPeerEventHandler", &blockchain::p2p::PeerConnection::setPeerEventHandler)
        .def("sendHeartbeat", &blockchain::p2p::PeerConnection::sendHeartbeat)
        .def("isHeartbeatAlive", &blockchain::p2p::PeerConnection::isHeartbeatAlive);
    
    // ----- Peer Manager -----
    
    py::class_<blockchain::p2p::PeerManager>(m, "PeerManager")
        .def("addPeer", &blockchain::p2p::PeerManager::addPeer, py::return_value_policy::reference_internal)
        .def("removePeer", &blockchain::p2p::PeerManager::removePeer)
        .def("getPeer", &blockchain::p2p::PeerManager::getPeer, py::return_value_policy::reference_internal)
        .def("getAllPeers", &blockchain::p2p::PeerManager::getAllPeers)
        .def("getPeerCount", &blockchain::p2p::PeerManager::getPeerCount)
        .def("addBootstrapNode", &blockchain::p2p::PeerManager::addBootstrapNode, 
             py::arg("address"), py::arg("port"), py::arg("trusted") = false)
        .def("getBootstrapNodes", &blockchain::p2p::PeerManager::getBootstrapNodes)
        .def("setMessageHandler", &blockchain::p2p::PeerManager::setMessageHandler)
        .def("setPeerEventHandler", &blockchain::p2p::PeerManager::setPeerEventHandler)
        .def("broadcastMessage", &blockchain::p2p::PeerManager::broadcastMessage, 
             py::arg("message"), py::arg("exclude_peer_id") = "")
        .def("getStats", &blockchain::p2p::PeerManager::getStats);
    
    // ----- P2P Network Manager -----
    
    py::class_<blockchain::p2p::P2PNetworkManager>(m, "P2PNetworkManager")
        .def(py::init<uint16_t>(), py::arg("port") = blockchain::p2p::DEFAULT_P2P_PORT)
        .def(py::init<uint16_t, const blockchain::p2p::NetworkConfig&>())
        .def("start", &blockchain::p2p::P2PNetworkManager::start)
        .def("stop", &blockchain::p2p::P2PNetworkManager::stop)
        .def("isRunning", &blockchain::p2p::P2PNetworkManager::isRunning)
        .def("connectToPeer", &blockchain::p2p::P2PNetworkManager::connectToPeer)
        .def("disconnectFromPeer", &blockchain::p2p::P2PNetworkManager::disconnectFromPeer)
        .def("getPeerCount", &blockchain::p2p::P2PNetworkManager::getPeerCount)
        .def("getPeerList", &blockchain::p2p::P2PNetworkManager::getPeerList)
        .def("getConnectedPeers", &blockchain::p2p::P2PNetworkManager::getConnectedPeers)
        .def("broadcastMessage", &blockchain::p2p::P2PNetworkManager::broadcastMessage)
        .def("sendMessageToPeer", &blockchain::p2p::P2PNetworkManager::sendMessageToPeer)
        .def("broadcastBlock", &blockchain::p2p::P2PNetworkManager::broadcastBlock)
        .def("broadcastTransaction", &blockchain::p2p::P2PNetworkManager::broadcastTransaction)
        .def("requestSync", &blockchain::p2p::P2PNetworkManager::requestSync)
        .def("addBootstrapNode", &blockchain::p2p::P2PNetworkManager::addBootstrapNode)
        .def("removeBootstrapNode", &blockchain::p2p::P2PNetworkManager::removeBootstrapNode)
        .def("connectToBootstrapNodes", &blockchain::p2p::P2PNetworkManager::connectToBootstrapNodes)
        .def("getConfig", &blockchain::p2p::P2PNetworkManager::getConfig)
        .def("updateConfig", &blockchain::p2p::P2PNetworkManager::updateConfig)
        .def("getNetworkStatus", &blockchain::p2p::P2PNetworkManager::getNetworkStatus)
        .def("getNetworkStats", &blockchain::p2p::P2PNetworkManager::getNetworkStats)
        .def("getNodeId", &blockchain::p2p::P2PNetworkManager::getNodeId)
        .def("getListeningPort", &blockchain::p2p::P2PNetworkManager::getListeningPort)
        .def("setMessageHandler", &blockchain::p2p::P2PNetworkManager::setMessageHandler)
        .def("setPeerEventHandler", &blockchain::p2p::P2PNetworkManager::setPeerEventHandler)
        .def("connectToBlockchain", &blockchain::p2p::P2PNetworkManager::connectToBlockchain);
    
    // ----- Networked Blockchain Core -----
    
    py::class_<blockchain::NetworkedBlockchainCore>(m, "NetworkedBlockchainCore")
        .def(py::init<uint16_t>(), py::arg("p2p_port") = blockchain::p2p::DEFAULT_P2P_PORT)
        
        // Core blockchain operations
        .def("initialize", &blockchain::NetworkedBlockchainCore::initialize)
        .def("registerUser", &blockchain::NetworkedBlockchainCore::registerUser)
        .def("authenticate", &blockchain::NetworkedBlockchainCore::authenticate)
        .def("listUsers", &blockchain::NetworkedBlockchainCore::listUsers)
        .def("verifyBlockchain", &blockchain::NetworkedBlockchainCore::verifyBlockchain)
        .def("getChainLength", &blockchain::NetworkedBlockchainCore::getChainLength)
        .def("getBlockchainData", &blockchain::NetworkedBlockchainCore::getBlockchainData)
        
        // Enhanced network operations
        .def("addBlock", &blockchain::NetworkedBlockchainCore::addBlock, 
             py::arg("block_data"), py::arg("broadcast") = true)
        .def("addTransaction", &blockchain::NetworkedBlockchainCore::addTransaction,
             py::arg("transaction"), py::arg("broadcast") = true)
        .def("requestNetworkSync", &blockchain::NetworkedBlockchainCore::requestNetworkSync)
        .def("addBootstrapNode", &blockchain::NetworkedBlockchainCore::addBootstrapNode)
        
        // P2P network management
        .def("startP2PNetwork", &blockchain::NetworkedBlockchainCore::startP2PNetwork)
        .def("stopP2PNetwork", &blockchain::NetworkedBlockchainCore::stopP2PNetwork)
        .def("stop", &blockchain::NetworkedBlockchainCore::stop)
        
        // Network status and statistics
        .def("getNetworkStatus", &blockchain::NetworkedBlockchainCore::getNetworkStatus)
        .def("getPeerList", &blockchain::NetworkedBlockchainCore::getPeerList)
        .def("getPeerCount", &blockchain::NetworkedBlockchainCore::getPeerCount)
        .def("getMempoolSize", &blockchain::NetworkedBlockchainCore::getMempoolSize)
        .def("getPendingTransactions", &blockchain::NetworkedBlockchainCore::getPendingTransactions)
        
        // Configuration
        .def("enableP2PNetworking", &blockchain::NetworkedBlockchainCore::enableP2PNetworking)
        .def("setP2PPort", &blockchain::NetworkedBlockchainCore::setP2PPort)
        
        // Advanced features
        .def("createAndBroadcastBlock", &blockchain::NetworkedBlockchainCore::createAndBroadcastBlock,
             py::arg("transactions") = std::vector<blockchain::json>{})
        .def("clearMempool", &blockchain::NetworkedBlockchainCore::clearMempool)
        .def("getLatestBlock", &blockchain::NetworkedBlockchainCore::getLatestBlock)
        .def("getBlockchainStats", &blockchain::NetworkedBlockchainCore::getBlockchainStats);
    
    // ----- P2P Command Interface -----
    
    py::class_<blockchain::P2PCommandInterface>(m, "P2PCommandInterface")
        .def(py::init<blockchain::NetworkedBlockchainCore&>())
        .def("showNetworkStatus", &blockchain::P2PCommandInterface::showNetworkStatus)
        .def("showPeerList", &blockchain::P2PCommandInterface::showPeerList)
        .def("showBlockchainStats", &blockchain::P2PCommandInterface::showBlockchainStats)
        .def("addBootstrapNode", &blockchain::P2PCommandInterface::addBootstrapNode)
        .def("requestSync", &blockchain::P2PCommandInterface::requestSync)
        .def("createBlock", &blockchain::P2PCommandInterface::createBlock)
        .def("showMempoolTransactions", &blockchain::P2PCommandInterface::showMempoolTransactions);
    
    // ----- Factory Functions -----
    
    m.def("createNetworkedBlockchain", &blockchain::createNetworkedBlockchain,
          py::arg("p2p_port") = blockchain::p2p::DEFAULT_P2P_PORT,
          "Create a new NetworkedBlockchainCore instance");
    
    // ----- Constants -----
    
    m.attr("DEFAULT_P2P_PORT") = blockchain::p2p::DEFAULT_P2P_PORT;
    m.attr("MAX_MESSAGE_SIZE") = blockchain::p2p::MAX_MESSAGE_SIZE;
    m.attr("PROTOCOL_VERSION") = blockchain::p2p::PROTOCOL_VERSION;
    m.attr("MAX_PEERS") = blockchain::p2p::MAX_PEERS;
    m.attr("HEARTBEAT_INTERVAL_SECONDS") = blockchain::p2p::HEARTBEAT_INTERVAL_SECONDS;
    m.attr("CONNECTION_TIMEOUT_SECONDS") = blockchain::p2p::CONNECTION_TIMEOUT_SECONDS;
    m.attr("HANDSHAKE_TIMEOUT_SECONDS") = blockchain::p2p::HANDSHAKE_TIMEOUT_SECONDS;
    
    // ----- Utility Functions -----
    
    m.def("generateNodeId", &blockchain::p2p::CryptoUtils::generatePeerId,
          "Generate a unique node/peer ID");
    
    m.def("validatePeerAddress", [](const std::string& address, uint16_t port) -> bool {
        return !address.empty() && port > 0 && port <= 65535;
    }, "Validate peer address and port");
    
    m.def("formatNetworkAddress", [](const std::string& ip, uint16_t port) -> std::string {
        return ip + ":" + std::to_string(port);
    }, "Format network address as IP:PORT");
    
    m.def("parseNetworkAddress", [](const std::string& address) -> std::pair<std::string, uint16_t> {
        size_t colonPos = address.find_last_of(':');
        if (colonPos == std::string::npos) {
            throw std::invalid_argument("Invalid address format. Expected IP:PORT");
        }
        
        std::string ip = address.substr(0, colonPos);
        uint16_t port = static_cast<uint16_t>(std::stoi(address.substr(colonPos + 1)));
        
        return {ip, port};
    }, "Parse network address from IP:PORT string");
    
    // ----- Helper Functions for Message Types -----
    
    m.def("messageTypeToString", &blockchain::p2p::messageTypeToString,
          "Convert message type to string");
    
    m.def("stringToMessageType", &blockchain::p2p::stringToMessageType,
          "Convert string to message type");
    
    m.def("peerEventToString", &blockchain::p2p::peerEventToString,
          "Convert peer event to string");
    
    m.def("networkErrorToString", &blockchain::p2p::networkErrorToString,
          "Convert network error to string");
    
    // ----- Advanced Message Creation -----
    
    m.def("createCustomMessage", [](blockchain::p2p::MessageType type, const blockchain::json& payload, const std::string& senderId) {
        blockchain::p2p::P2PMessage message(type, payload);
        message.setSenderId(senderId);
        return message;
    }, "Create a custom P2P message with JSON payload");
    
    m.def("createStringMessage", [](blockchain::p2p::MessageType type, const std::string& payload, const std::string& senderId) {
        blockchain::p2p::P2PMessage message(type, payload);
        message.setSenderId(senderId);
        return message;
    }, "Create a P2P message with string payload");
    
    // ----- Network Diagnostics -----
    
    m.def("diagnoseNetworkConnection", [](const std::string& address, uint16_t port) -> blockchain::json {
        // Simple connection test
        try {
            asio::io_context ioContext;
            asio::ip::tcp::socket socket(ioContext);
            asio::ip::tcp::resolver resolver(ioContext);
            
            auto endpoints = resolver.resolve(address, std::to_string(port));
            auto start = std::chrono::steady_clock::now();
            
            std::error_code ec;
            asio::connect(socket, endpoints, ec);
            
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            
            if (ec) {
                return {
                    {"success", false},
                    {"error", ec.message()},
                    {"duration_ms", duration.count()}
                };
            } else {
                socket.close();
                return {
                    {"success", true},
                    {"duration_ms", duration.count()},
                    {"address", address},
                    {"port", port}
                };
            }
        } catch (const std::exception& e) {
            return {
                {"success", false},
                {"error", e.what()}
            };
        }
    }, "Diagnose network connection to a peer");
    
    // ----- Configuration Helpers -----
    
    m.def("createDefaultConfig", []() {
        return blockchain::p2p::NetworkConfig{};
    }, "Create default network configuration");
    
    m.def("createHighPerformanceConfig", []() {
        blockchain::p2p::NetworkConfig config;
        config.maxPeers = 200;
        config.messageProcessingThreads = 8;
        config.messageQueueSize = 2000;
        config.heartbeatInterval = 15;
        config.connectionTimeout = 5;
        return config;
    }, "Create high-performance network configuration");
    
    m.def("createLowResourceConfig", []() {
        blockchain::p2p::NetworkConfig config;
        config.maxPeers = 25;
        config.messageProcessingThreads = 2;
        config.messageQueueSize = 100;
        config.heartbeatInterval = 60;
        config.enableLogging = false;
        return config;
    }, "Create low-resource network configuration");
}

// Main module binding function
PYBIND11_MODULE(blockchain_core, m) {
    m.doc() = "Enhanced Blockchain with Complete P2P Networking Support";
    
    // Add P2P-specific bindings
    add_p2p_bindings(m);
    
    // Module-level documentation and examples
    m.attr("__doc__") = R"pbdoc(
        Enhanced Blockchain with Complete P2P Networking
        
        This module provides a fully-featured blockchain implementation with
        comprehensive peer-to-peer networking capabilities, including:
        
        - Advanced message system with priorities and batching
        - Robust peer management and connection handling
        - Distributed blockchain synchronization
        - Transaction mempool and broadcasting
        - Peer discovery and bootstrap node management
        - Secure message passing with validation
        - Comprehensive network statistics and monitoring
        - Event-driven architecture with callbacks
        - High-performance asynchronous networking
        
        Basic Usage:
        
            import blockchain_p2p
            
            # Create a networked blockchain instance
            blockchain = blockchain_p2p.NetworkedBlockchainCore(port=8333)
            
            # Initialize and start P2P networking
            blockchain.initialize()
            blockchain.startP2PNetwork()
            
            # Add bootstrap nodes to connect to the network
            blockchain.addBootstrapNode("192.168.1.100", 8333)
            
            # Create and broadcast a transaction
            transaction = {
                "type": "transfer",
                "from": "alice",
                "to": "bob",
                "amount": 50,
                "timestamp": int(time.time())
            }
            blockchain.addTransaction(transaction)
            
            # Monitor network status
            status = blockchain.getNetworkStatus()
            print(f"Connected peers: {status['peer_count']}")
            print(f"Mempool size: {status['mempool_size']}")
            
            # Create and broadcast blocks
            blockchain.createAndBroadcastBlock()
            
            # View blockchain statistics
            stats = blockchain.getBlockchainStats()
            print(f"Total blocks: {stats['total_blocks']}")
            
        Advanced Features:
        
            # Configure P2P network settings
            config = blockchain_p2p.NetworkConfig()
            config.max_peers = 100
            config.enable_encryption = True
            config.message_processing_threads = 4
            
            network_manager = blockchain_p2p.P2PNetworkManager(8333, config)
            
            # Set up custom message handlers
            def on_message(peer_id, message_type, payload):
                print(f"Received {message_type} from {peer_id}: {payload}")
            
            def on_peer_event(peer_id, event, data):
                print(f"Peer {peer_id} event: {event} - {data}")
            
            network_manager.setMessageHandler(on_message)
            network_manager.setPeerEventHandler(on_peer_event)
            
            # Manual peer management
            network_manager.connectToPeer("192.168.1.200", 8333)
            peer_list = network_manager.getPeerList()
            
            # Advanced message creation
            message = blockchain_p2p.P2PMessage.createTransaction("node_123", {
                "from": "alice",
                "to": "bob", 
                "amount": 100
            })
            message.setPriority(blockchain_p2p.MessagePriority.HIGH)
            
            # Network diagnostics
            diagnosis = blockchain_p2p.diagnoseNetworkConnection("192.168.1.100", 8333)
            if diagnosis["success"]:
                print(f"Connection successful in {diagnosis['duration_ms']}ms")
            
            # Network statistics and monitoring
            stats = network_manager.getNetworkStats()
            print(f"Messages sent: {stats['messages_sent']}")
            print(f"Bytes received: {stats['bytes_received']}")
            print(f"Connection success rate: {stats['connection_success_rate']}%")
    )pbdoc";
    
    m.attr("__version__") = "2.0.0";
    m.attr("__author__") = "Enhanced Blockchain P2P Team";
}