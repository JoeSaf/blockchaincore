/*
  File: p2p_torrent.cpp
  Description: Decentralized P2P file-sharing (Torrent-like) in a single-file implementation.
  Build with: g++ p2p_torrent.cpp -std=c++17 -pthread -o p2p_torrent
*/

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <openssl/sha.h>      // For piece hashing
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

// ----- TorrentMeta -----
class TorrentMeta {
public:
    struct Info {
        std::string name;
        uint64_t length;
        uint32_t pieceLength;
        std::vector<std::string> pieceHashes; // hex-encoded SHA1 hashes
    } info;

    TorrentMeta(const std::string& /*path*/, const Info& i): info(i) {}
    const Info& getInfo() const { return info; }
};

// ----- DHTNode -----
class DHTNode {
public:
    DHTNode(const std::vector<std::pair<std::string,uint16_t>>& bootstrap)
        : bootstrapNodes(bootstrap) {}

    void bootstrap() {
        // Ping bootstrap nodes & build routing table
        // (Stub: assume bootstrap success)
    }

    std::vector<std::pair<std::string,uint16_t>> getPeers(const std::string& /*infoHash*/) {
        // DHT lookup for peers advertising this infoHash
        return {{"127.0.0.1", 6881}}; // stub
    }

    void announce(const std::string& /*infoHash*/, const std::pair<std::string,uint16_t>& /*me*/) {
        // DHT announce_peer
    }

private:
    std::vector<std::pair<std::string,uint16_t>> bootstrapNodes;
};

// ----- PeerConnection -----
class PeerConnection {
public:
    PeerConnection(const std::string& ip_, uint16_t port_)
        : ip(ip_), port(port_), sockfd(-1) {}

    bool connectAndHandshake(const std::string& infoHash, const std::string& peerId) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) < 0) return false;

        // Build handshake message
        std::string proto = "\x13BitTorrent protocol";
        std::string reserved(8, 0);
        std::string handshake = proto + reserved + infoHash + peerId;
        send(sockfd, handshake.data(), handshake.size(), 0);

        // Read peer handshake (ignore details in stub)
        char buf[68];
        recv(sockfd, buf, sizeof(buf), 0);
        return true;
    }

    std::vector<bool> fetchBitfield() {
        // Send and recv Bitfield message (stubbed)
        return std::vector<bool>();
    }

    bool requestBlock(int /*pieceIndex*/, int /*offset*/, int /*length*/, std::vector<uint8_t>& /*out*/) {
        // Send request and read piece data
        return false;
    }

    void closeConn() {
        if (sockfd >= 0) close(sockfd);
    }

private:
    std::string ip;
    uint16_t port;
    int sockfd;
};

// ----- PieceManager -----
class PieceManager {
public:
    PieceManager(uint32_t pieceLen, uint64_t total)
        : pieceLength(pieceLen), totalSize(total) {
        numPieces = (totalSize + pieceLen - 1) / pieceLen;
        have.resize(numPieces, false);
    }

    // Rarest-first stub: simply return first missing
    int selectNextPiece(const std::vector<std::vector<bool>>& /*peerBitfields*/) {
        for (int i = 0; i < numPieces; ++i)
            if (!have[i]) return i;
        return -1;
    }

    void addBlock(int pieceIndex, int offset, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> g(mtx);
        // Store data to file buffer (stub skipped)
    }

    bool verifyPiece(int pieceIndex, const std::string& expectedHash) {
        // Read assembled piece from buffer (stub: generate dummy hash)
        unsigned char digest[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)"dummy", 5, digest);
        char hex[41] = {};
        for(int i=0;i<20;++i) sprintf(hex+2*i, "%02x", digest[i]);
        return expectedHash == std::string(hex);
    }

    void markHave(int idx) {
        have[idx] = true;
    }

private:
    uint32_t pieceLength;
    uint64_t totalSize;
    int numPieces;
    std::vector<bool> have;
    std::mutex mtx;
};

// ----- Main -----
int main(int argc, char* argv[]) {
    if (argc < 2) { std::cerr<<"Usage: p2p_torrent <torrent_name>\n"; return 1; }

    // Stub metadata for demonstration
    TorrentMeta::Info metaInfo{ "example.dat", 1024*1024, 16384, { /* hex hashes */ } };
    TorrentMeta meta("dummy.torrent", metaInfo);
    auto info = meta.getInfo();

    // Setup DHT
    DHTNode dht({{"router.bittorrent.com", 6881}});
    dht.bootstrap();
    auto peers = dht.getPeers("info_hash_stub");

    // Setup PieceManager
    PieceManager pm(info.pieceLength, info.length);

    // Connect to peers and download loop
    std::vector<std::thread> threads;
    for (auto& p : peers) {
        threads.emplace_back([&]() {
            PeerConnection pc(p.first, p.second);
            if (!pc.connectAndHandshake("info_hash_stub", "peer_id_12345678")) return;
            // fetch bitfield, then loop piece requests
            pc.closeConn();
        });
    }
    for (auto& t : threads) t.join();

    std::cout << "Download cycle complete (stub)." << std::endl;
    return 0;
}

