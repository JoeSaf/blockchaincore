# 🔗 Blockchain File Storage System

A **decentralized blockchain-based file storage system** with advanced security features, P2P networking, and polymorphic chain reordering capabilities.

## 🚀 Key Features

### 🛡️ **Advanced Security System**
- **Corrupted Block Detection** - Real-time hash integrity verification
- **Chain Integrity Monitoring** - Continuous validation of block connections
- **Automatic Infected Block Quarantine** - Isolates compromised blocks instantly
- **Polymorphic Chain Reordering** - Revolutionary anti-brute-force protection
- **User Data Migration** - Preserves data integrity during security events

### 📁 **File Storage Blockchain**
- **Chunked File Storage** - Efficient handling of large files
- **File Deduplication** - Automatic detection and elimination of duplicates
- **Integrity Verification** - SHA-256 hashing for all file chunks
- **Permission Management** - Granular access control for files
- **Metadata Tracking** - Complete file history and ownership

### 🌐 **True P2P Network**
- **Peer Discovery** - Automatic network node discovery
- **Consensus Mechanisms** - Network-wide agreement on chain state
- **Message Broadcasting** - Efficient block and transaction propagation
- **Network Resilience** - Automatic peer cleanup and connection management

### 💻 **CLI-First Interface**
- **Interactive Mode** - Full-featured command-line interface
- **Real-time Monitoring** - Live security and network status displays
- **Batch Operations** - Script-friendly command structure
- **Colored Output** - Enhanced readability with syntax highlighting

### 🌐 **Simple Web Interface**
- **User Authentication** - Secure login and registration system
- **File Upload/Download** - Drag-and-drop file management
- **Blockchain Explorer** - Visual chain inspection tools
- **Security Dashboard** - Real-time threat monitoring

## 🏗️ Architecture

```
┌─────────────────┐ ┌──────────────────┐ ┌─────────────────┐
│ CLI Interface   │ │ Security Manager │ │ Web Interface   │
│ (Primary UI)    │ │ (Polymorphic)    │ │ (File Upload)   │
└─────────┬───────┘ └─────────┬────────┘ └─────────┬───────┘
          │                   │                    │
          └───────────────────┼────────────────────┘
                              ▼
          ┌──────────────────────────────────────────────┐
          │            File Blockchain Core              │
          │  • Block validation   • File chunking       │
          │  • Transaction pool   • Integrity checks    │
          │  • UTXO management   • Permission system    │
          └─────────────────┬────────────────────────────┘
                            │
          ┌─────────────────▼────────────────────────────┐
          │              P2P Network                     │
          │  • Peer discovery    • Message broadcasting  │
          │  • Consensus logic   • Chain synchronization │
          │  • Network security  • Automatic recovery    │
          └──────────────────────────────────────────────┘
```

## 🛠️ Building from Source

### Prerequisites (Linux)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake git pkg-config libssl-dev libcurl4-openssl-dev wget ninja-build

# Arch Linux
sudo pacman -S base-devel cmake git pkg-config openssl curl wget ninja

# Fedora
sudo dnf groupinstall "Development Tools"
sudo dnf install cmake git openssl-devel libcurl-devel wget ninja-build
```

### Quick Build
```bash
# Clone the repository
git clone <repository-url>
cd blockchain-file-storage

# Use the automated build script
chmod +x build.sh
./build.sh

# Or build manually
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Build Targets
```bash
make blockchain_node     # Full node with all features
make blockchain_cli      # CLI-only tool
make test               # Run test suite
make package            # Create distribution package
make install            # Install to system
```

## 🚀 Quick Start

### 1. Start a Full Node
```bash
./bin/blockchain_node
```
This starts:
- Blockchain core on default settings
- P2P network (TCP: 8333, UDP: 8334)
- REST API server (HTTP: 8080)
- Security monitoring system
- Web interface at http://localhost:8080

### 2. Use the CLI Interface
```bash
# Interactive mode
./bin/blockchain_cli

# Direct commands
./bin/blockchain_cli status --security
./bin/blockchain_cli upload myfile.txt --user-address <address>
./bin/blockchain_cli mine
./bin/blockchain_cli peers --detailed
./bin/blockchain_cli security-scan --deep
./bin/blockchain_cli reorder --reason "Security enhancement"
```

### 3. Web Interface
1. Open http://localhost:8080 in your browser
2. Register a new account or login
3. Upload files via drag-and-drop
4. Monitor blockchain status and security
5. Explore the blockchain and view files

## 📋 CLI Commands Reference

### Blockchain Operations
```bash
blockchain_cli status [--security] [--verbose]     # Node status
blockchain_cli validate [--deep] [--repair]        # Chain validation
blockchain_cli mine [miner-address]                # Mine new block
blockchain_cli stats                               # Chain statistics
```

### File Operations
```bash
blockchain_cli upload <file> [--user-address <addr>]    # Upload file
blockchain_cli download <file-id> [--output <path>]     # Download file
blockchain_cli files [--user <addr>] [--format json]    # List files
blockchain_cli verify-file <file-id>                    # Verify integrity
```

### Security Operations
```bash
blockchain_cli security-scan [--deep] [--auto-fix]      # Security scan
blockchain_cli threats [--level critical|high|medium]   # List threats
blockchain_cli reorder [--reason <text>] [--force]      # Trigger reorder
blockchain_cli quarantine-info                          # Quarantine status
blockchain_cli security-report                          # Generate report
```

### Network Operations
```bash
blockchain_cli peers [--detailed]                       # List peers
blockchain_cli connect <ip> <port>                      # Connect to peer
blockchain_cli discover [--timeout <seconds>]           # Discover peers
blockchain_cli broadcast <message>                      # Broadcast message
```

### Real-time Monitoring
```bash
blockchain_cli monitor [--security|--network|--chain]   # Live monitoring
```

## 🔧 Configuration

### Blockchain Configuration
```json
{
  "mining": {
    "difficulty": 4,
    "blockTimeTarget": 10,
    "miningReward": 50.0
  },
  "network": {
    "tcpPort": 8333,
    "udpPort": 8334,
    "maxPeers": 50
  },
  "security": {
    "reorderThreshold": 5,
    "enableAutoReorder": true,
    "randomnessFactor": 0.7
  },
  "files": {
    "maxChunkSize": 1048576,
    "maxFileSize": 104857600,
    "enableCompression": true,
    "enableDeduplication": true
  }
}
```

## 🛡️ Security Features in Detail

### Polymorphic Chain Reordering
The system can **dynamically reorder blockchain structure** while preserving:
- ✅ Transaction integrity
- ✅ File data consistency  
- ✅ User permissions
- ✅ Chain validation rules

**Triggers:**
- Multiple security violations detected
- Suspected brute force attacks
- Manual admin intervention
- Consensus-based network decision

### Real-time Threat Detection
- **Hash Integrity**: Continuous SHA-256 verification
- **Chain Validation**: Previous/next block consistency
- **Anomaly Detection**: Pattern analysis for suspicious activity
- **Peer Consensus**: Network-wide threat validation

### Automatic Recovery
1. **Threat Detection** → Immediate isolation
2. **Data Preservation** → Extract user files
3. **Chain Reordering** → Randomized restructure
4. **Data Migration** → Restore to clean chain
5. **Network Sync** → Propagate to peers

## 🌐 API Reference

### REST API Endpoints

#### Blockchain
- `GET /api/status` - Node status
- `GET /api/blockchain` - Full chain
- `GET /api/block/{index}` - Specific block
- `POST /api/mine` - Mine new block

#### Files
- `POST /api/files/upload` - Upload file
- `GET /api/files/download/{id}` - Download file
- `GET /api/files/list` - List user files
- `DELETE /api/files/{id}` - Delete file

#### Security
- `GET /api/security/status` - Security status
- `POST /api/security/scan` - Trigger scan
- `GET /api/security/threats` - Active threats
- `POST /api/security/reorder` - Trigger reorder

#### Network
- `GET /api/peers` - Connected peers
- `POST /api/network/connect` - Connect to peer
- `GET /api/network/status` - Network status

## 🔍 Monitoring & Debugging

### Real-time CLI Monitoring
```bash
# Security monitor
blockchain_cli monitor --security

# Network activity
blockchain_cli monitor --network  

# Chain status
blockchain_cli monitor --chain
```

### Log Files
```
blockchain_node.log     # Main application log
security.log           # Security events
p2p_network.log        # Network activity
file_operations.log    # File upload/download
```

### Performance Monitoring
```bash
# Memory usage
blockchain_cli stats --memory

# Network statistics  
blockchain_cli network-stats

# Security metrics
blockchain_cli security-report --detailed
```

## 🧪 Testing

### Run Test Suite
```bash
cd build
make test

# Or run directly
./bin/blockchain_node_test
```

### Manual Testing Scenarios

#### Multi-Node Network
```bash
# Terminal 1: Node A
./blockchain_node --tcp-port 8333 --udp-port 8334

# Terminal 2: Node B  
./blockchain_node --tcp-port 8335 --udp-port 8336

# Terminal 3: Connect nodes
blockchain_cli connect 127.0.0.1 8333
```

#### Security Testing
```bash
# Upload files
blockchain_cli upload test1.txt test2.txt test3.txt

# Trigger security scan
blockchain_cli security-scan --deep

# Simulate attack (for testing)
blockchain_cli reorder --reason "Security test"

# Verify data integrity
blockchain_cli verify-file <file-id>
```

## 📚 Development

### Adding New Features
1. **Core Logic**: Implement in `src/blockchain/`
2. **CLI Commands**: Add to `src/cli/CLIInterface.cpp`
3. **API Endpoints**: Extend `src/api/RestApiServer.cpp`
4. **Security Integration**: Update `src/security/SecurityManager.cpp`
5. **Tests**: Add to `tests/`

### Code Structure
```
src/
├── blockchain/         # Core blockchain logic
├── p2p/               # P2P networking
├── api/               # REST API server
├── cli/               # Command-line interface
├── web/               # Web interface
├── security/          # Security manager
└── utils/             # Utilities and crypto

include/               # Header files
tests/                 # Test suite
docs/                  # Documentation
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

**Build Errors:**
```bash
# Clear build cache
rm -rf build/
./build.sh --clean

# Install missing dependencies
./build.sh --install-deps
```

**Network Issues:**
```bash
# Check firewall settings
sudo ufw allow 8333/tcp
sudo ufw allow 8334/udp

# Test connectivity
blockchain_cli discover --timeout 30
```

**Security Alerts:**
```bash
# Run immediate scan
blockchain_cli security-scan --auto-fix

# Check quarantine status
blockchain_cli quarantine-info

# Manual reorder if needed
blockchain_cli reorder --force
```

### Getting Help
- 📧 **Email**: blockchain-dev@example.com
- 🐛 **Issues**: [GitHub Issues](issues-url)
- 💬 **Discord**: [Community Server](discord-url)
- 📖 **Docs**: [Full Documentation](docs-url)

---

**⚡ Built for the future of decentralized storage ⚡**

*Made with ❤️ by the Blockchain Development Team*