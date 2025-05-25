// p2p_python_bindings.cpp - Additional bindings for P2P functionality
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include <pybind11/functional.h>
#include <pybind11/iostream.h>
#include "blockchain_core.hpp"
#include "p2p_blockchain_network.hpp"
#include "p2p_node_manager.hpp"
#include "blockchain_p2p_integration.hpp"

namespace py = pybind11;
using namespace blockchain;
using namespace blockchain::p2p;

// Add these bindings to your existing python_bindings.cpp file
// or create this as a separate module

void add_p2p_bindings(py::module& m) {
    // NetworkAddress class
    py::class_<NetworkAddress>(m, "NetworkAddress")
        .def(py::init<>())
        .def(py::init<const std::string&, uint16_t, uint64_t>(),
             py::arg("ip"), py::arg("port"), py::arg("services") = 0)
        .def("toString", &NetworkAddress::toString)
        .def_readwrite("ip", &NetworkAddress::ip)
        .def_readwrite("port", &NetworkAddress::port)
        .def_readwrite("services", &NetworkAddress::services);
    
    // MessageType enum
    py::enum_<MessageType>(m, "MessageType")
        .value("VERSION", MessageType::VERSION)
        .value("VERACK", MessageType::VERACK)
        .value("PING", MessageType::PING)
        .value("PONG", MessageType::PONG)
        .value("ADDR", MessageType::ADDR)
        .value("GETADDR", MessageType::GETADDR)
        .value("INV", MessageType::INV)
        .value("GETDATA", MessageType::GETDATA)
        .value("BLOCK", MessageType::BLOCK)
        .value("TX", MessageType::TX)
        .value("GETBLOCKS", MessageType::GETBLOCKS)
        .value("GETHEADERS", MessageType::GETHEADERS)
        .value("HEADERS", MessageType::HEADERS)
        .value("REJECT", MessageType::REJECT)
        .value("MEMPOOL", MessageType::MEMPOOL)
        .value("BLOCKCHAIN_SYNC", MessageType::BLOCKCHAIN_SYNC)
        .value("PEER_DISCOVERY", MessageType::PEER_DISCOVERY)
        .value("ENCRYPTED_DATA", MessageType::ENCRYPTED_DATA);
    
    // Message class
    py::class_<Message>(m, "Message")
        .def(py::init<MessageType>(), py::arg("type") = MessageType::PING)
        .def("serialize", &Message::serialize)
        .def_static("deserialize", &Message::deserialize)
        .def_readwrite("type", &Message::type)
        .def_readwrite("payload", &Message::payload)
        .def_readwrite("checksum", &Message::checksum)
        .def_readwrite("encrypted", &Message::encrypted);
    
    // CryptoUtils class
    py::class_<CryptoUtils>(m, "P2PCryptoUtils")
        .def_static("generatePeerId", &CryptoUtils::generatePeerId)
        .def_static("sha256", &CryptoUtils::sha256)
        .def_static("encryptAES", &CryptoUtils::encryptAES)
        .def_static("decryptAES", &CryptoUtils::decryptAES);
    
    // PeerConnection class
    py::class_<PeerConnection, std::shared_ptr<PeerConnection>>(m, "PeerConnection")
        .def(py::init<const NetworkAddress&, bool>(), 
             py::arg("address"), py::arg("outbound") = true)
        .def("connect", &PeerConnection::connect)
        .def("disconnect", &PeerConnection::disconnect)
        .def("sendMessage", &PeerConnection::sendMessage)
        .def("receiveMessage", &PeerConnection::receiveMessage)
        .def("performHandshake", &PeerConnection::performHandshake)
        .def("getAddress", &PeerConnection::getAddress, py::return_value_policy::reference_internal)
        .def("isConnected", &PeerConnection::isConnected)
        .def("isHandshakeComplete", &PeerConnection::isHandshakeComplete)
        .def("getPeerId", &PeerConnection::getPeerId)
        .def("getVersion", &PeerConnection::getVersion)
        .def("getServices", &PeerConnection::getServices)
        .def("isOutbound", &PeerConnection::isOutbound)
        .def("updateActivity", &PeerConnection::updateActivity);
    
    // AddressManager class
    py::class_<AddressManager>(m, "AddressManager")
        .def(py::init<>())
        .def("addBootstrapNode", &AddressManager::addBootstrapNode)
        .def("addAddress", &AddressManager::addAddress)
        .def("addAddresses", &AddressManager::addAddresses)
        .def("markTried", &AddressManager::markTried)
        .def("getRandomAddresses", &AddressManager::getRandomAddresses)
        .def("getAllAddresses", &AddressManager::getAllAddresses)
        .def("getKnownCount", &AddressManager::getKnownCount)
        .def("getTriedCount", &AddressManager::getTriedCount);
    
    // BlockchainP2PNode class
    py::class_<BlockchainP2PNode>(m, "BlockchainP2PNode")
        .def(py::init<uint16_t>(), py::arg("port") = DEFAULT_P2P_PORT)
        .def("start", &BlockchainP2PNode::start)
        .def("stop", &BlockchainP2PNode::stop)
        .def("connectToPeer", &BlockchainP2PNode::connectToPeer)
        .def("disconnectPeer", &BlockchainP2PNode::disconnectPeer)
        .def("broadcastBlock", &BlockchainP2PNode::broadcastBlock)
        .def("broadcastTransaction", &BlockchainP2PNode::broadcastTransaction)
        .def("requestBlockchainSync", &BlockchainP2PNode::requestBlockchainSync)
        .def("getPeerCount", &BlockchainP2PNode::getPeerCount)
        .def("getOutboundPeerCount", &BlockchainP2PNode::getOutboundPeerCount)
        .def("getInboundPeerCount", &BlockchainP2PNode::getInboundPeerCount)
        .def("getNetworkStats", &BlockchainP2PNode::getNetworkStats)
        .def("getPeerInfo", &BlockchainP2PNode::getPeerInfo)
        .def("addBootstrapNode", &BlockchainP2PNode::addBootstrapNode)
        .def("addKnownAddress", &BlockchainP2PNode::addKnownAddress)
        .def("setBlockchainSyncCallback", &BlockchainP2PNode::setBlockchainSyncCallback)
        .def("setGetLatestBlockCallback", &BlockchainP2PNode::setGetLatestBlockCallback)
        .def("setGetPendingTransactionsCallback", &BlockchainP2PNode::setGetPendingTransactionsCallback)
        .def("setValidateBlockCallback", &BlockchainP2PNode::setValidateBlockCallback)
        .def("setValidateTransactionCallback", &BlockchainP2PNode::setValidateTransactionCallback);
    
    // P2PNetworkManager class
    py::class_<P2PNetworkManager>(m, "P2PNetworkManager")
        .def(py::init<uint16_t>(), py::arg("port") = DEFAULT_P2P_PORT)
        .def("start", &P2PNetworkManager::start)
        .def("stop", &P2PNetworkManager::stop)
        .def("connectToBlockchain", &P2PNetworkManager::connectToBlockchain)
        .def("broadcastBlock", &P2PNetworkManager::broadcastBlock)
        .def("broadcastTransaction", &P2PNetworkManager::broadcastTransaction)
        .def("requestSync", &P2PNetworkManager::requestSync)
        .def("addBootstrapNode", &P2PNetworkManager::addBootstrapNode)
        .def("getNetworkStatus", &P2PNetworkManager::getNetworkStatus)
        .def("getPeerList", &P2PNetworkManager::getPeerList)
        .def("getPeerCount", &P2PNetworkManager::getPeerCount);
    
    // NetworkedBlockchainCore class
    py::class_<NetworkedBlockchainCore>(m, "NetworkedBlockchainCore")
        .def(py::init<uint16_t>(), py::arg("p2pPort") = DEFAULT_P2P_PORT)
        .def("initialize", &NetworkedBlockchainCore::initialize)
        .def("registerUser", &NetworkedBlockchainCore::registerUser)
        .def("authenticate", &NetworkedBlockchainCore::authenticate)
        .def("listUsers", &NetworkedBlockchainCore::listUsers)
        .def("verifyBlockchain", &NetworkedBlockchainCore::verifyBlockchain)
        .def("getChainLength", &NetworkedBlockchainCore::getChainLength)
        .def("getBlockchainData", &NetworkedBlockchainCore::getBlockchainData)
        .def("addBlock", &NetworkedBlockchainCore::addBlock, 
             py::arg("blockData"), py::arg("broadcast") = true)
        .def("addTransaction", &NetworkedBlockchainCore::addTransaction,
             py::arg("transaction"), py::arg("broadcast") = true)
        .def("requestNetworkSync", &NetworkedBlockchainCore::requestNetworkSync)
        .def("addBootstrapNode", &NetworkedBlockchainCore::addBootstrapNode)
        .def("startP2PNetwork", &NetworkedBlockchainCore::startP2PNetwork)
        .def("stopP2PNetwork", &NetworkedBlockchainCore::stopP2PNetwork)
        .def("stop", &NetworkedBlockchainCore::stop)
        .def("getNetworkStatus", &NetworkedBlockchainCore::getNetworkStatus)
        .def("getPeerList", &NetworkedBlockchainCore::getPeerList)
        .def("getPeerCount", &NetworkedBlockchainCore::getPeerCount)
        .def("getMempoolSize", &NetworkedBlockchainCore::getMempoolSize)
        .def("getPendingTransactions", &NetworkedBlockchainCore::getPendingTransactions)
        .def("enableP2PNetworking", &NetworkedBlockchainCore::enableP2PNetworking)
        .def("setP2PPort", &NetworkedBlockchainCore::setP2PPort)
        .def("createAndBroadcastBlock", &NetworkedBlockchainCore::createAndBroadcastBlock)
        .def("clearMempool", &NetworkedBlockchainCore::clearMempool)
        .def("getLatestBlock", &NetworkedBlockchainCore::getLatestBlock)
        .def("getBlockchainStats", &NetworkedBlockchainCore::getBlockchainStats);
    
    // P2PCommandInterface class
    py::class_<P2PCommandInterface>(m, "P2PCommandInterface")
        .def(py::init<NetworkedBlockchainCore&>())
        .def("showNetworkStatus", &P2PCommandInterface::showNetworkStatus)
        .def("showPeerList", &P2PCommandInterface::showPeerList)
        .def("showBlockchainStats", &P2PCommandInterface::showBlockchainStats)
        .def("addBootstrapNode", &P2PCommandInterface::addBootstrapNode)
        .def("requestSync", &P2PCommandInterface::requestSync)
        .def("createBlock", &P2PCommandInterface::createBlock)
        .def("showMempoolTransactions", &P2PCommandInterface::showMempoolTransactions);
    
    // Factory functions
    m.def("createNetworkedBlockchain", &createNetworkedBlockchain, 
          py::arg("p2pPort") = DEFAULT_P2P_PORT);
    
    // Constants
    m.attr("DEFAULT_P2P_PORT") = DEFAULT_P2P_PORT;
    m.attr("MAX_PEERS") = MAX_PEERS;
    m.attr("MAX_OUTBOUND_PEERS") = MAX_OUTBOUND_PEERS;
    m.attr("MAX_MESSAGE_SIZE") = MAX_MESSAGE_SIZE;
}

// If this is a separate module, define the module here:
// PYBIND11_MODULE(blockchain_p2p, m) {
//     m.doc() = "Blockchain P2P Network Module";
//     add_p2p_bindings(m);
// }

// Or add to your existing blockchain_core module by calling add_p2p_bindings(m) 
// in your main PYBIND11_MODULE definition