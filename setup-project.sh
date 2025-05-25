#!/bin/bash
# setup-project.sh - Automated setup script for Blockchain Core project structure
# Creates all necessary directories, files, and configurations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="blockchain-core"
CURRENT_DIR="$(pwd)"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}[SETUP]${NC} $1"
}

# Create directory structure
create_directories() {
    log_header "Creating directory structure..."
    
    local dirs=(
        "systemd"
        "scripts"
        "monitoring"
        "tests"
        "docs"
        "config"
        "logs"
        "build"
        "dist"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        else
            log_info "Directory already exists: $dir"
        fi
    done
    
    log_success "Directory structure created"
}

# Create systemd service files
create_systemd_files() {
    log_header "Creating systemd service files..."
    
    # Main system service
    cat > systemd/blockchain-node.service << 'EOF'
[Unit]
Description=Blockchain P2P Node
Documentation=https://github.com/your-username/blockchain-core
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=blockchain
Group=blockchain
WorkingDirectory=/opt/blockchain
ExecStart=/usr/bin/python -m polymorphicblock_p2p --daemon --config /etc/blockchain/node.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
TimeoutStartSec=60
TimeoutStopSec=30

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blockchain-node

# Security hardening
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/opt/blockchain /var/lib/blockchain
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
PrivateMounts=yes

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=10.0.0.0/8
IPAddressAllow=172.16.0.0/12
IPAddressAllow=192.168.0.0/16

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768
MemoryMax=2G
TasksMax=4096

# Environment
Environment=PYTHONPATH=/usr/lib/python3.12/site-packages
Environment=BLOCKCHAIN_CONFIG=/etc/blockchain/node.conf
Environment=BLOCKCHAIN_DATA_DIR=/var/lib/blockchain

[Install]
WantedBy=multi-user.target
EOF

    # Template service for multiple instances
    cat > systemd/blockchain-node@.service << 'EOF'
[Unit]
Description=Blockchain P2P Node (Instance %i)
Documentation=https://github.com/your-username/blockchain-core
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=blockchain
Group=blockchain
WorkingDirectory=/opt/blockchain
ExecStart=/usr/bin/python -m polymorphicblock_p2p --daemon --config /etc/blockchain/node-%i.conf --instance %i
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

# Instance-specific logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blockchain-node-%i

# Security (same as main service)
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/opt/blockchain /var/lib/blockchain/%i
PrivateTmp=yes

# Instance-specific environment
Environment=BLOCKCHAIN_CONFIG=/etc/blockchain/node-%i.conf
Environment=BLOCKCHAIN_DATA_DIR=/var/lib/blockchain/%i
Environment=BLOCKCHAIN_INSTANCE=%i

[Install]
WantedBy=multi-user.target
EOF

    # User service
    cat > systemd/blockchain-node-user.service << 'EOF'
[Unit]
Description=Blockchain P2P Node (User Service)
Documentation=https://github.com/your-username/blockchain-core
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/blockchain-node --user-mode
Restart=always
RestartSec=10
TimeoutStartSec=30

# User service logging
StandardOutput=journal
StandardError=journal

# Minimal security for user service
NoNewPrivileges=yes
PrivateTmp=yes

# User environment
Environment=BLOCKCHAIN_DATA_DIR=%h/.local/share/blockchain
Environment=BLOCKCHAIN_CONFIG=%h/.config/blockchain/node.conf

[Install]
WantedBy=default.target
EOF

    log_success "Systemd service files created"
}

# Create setup script
create_setup_systemd_script() {
    log_header "Creating systemd setup script..."
    
    cat > scripts/setup-systemd.sh << 'EOF'
#!/bin/bash
# setup-systemd.sh - Configure systemd services for Blockchain Core

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Create blockchain user and directories
setup_user_and_dirs() {
    log_info "Setting up blockchain user and directories..."
    
    # Create blockchain user
    if ! id blockchain >/dev/null 2>&1; then
        sudo useradd -r -s /bin/false -d /opt/blockchain blockchain
        log_success "Created blockchain user"
    else
        log_info "Blockchain user already exists"
    fi
    
    # Create directories
    sudo mkdir -p /opt/blockchain
    sudo mkdir -p /var/lib/blockchain
    sudo mkdir -p /etc/blockchain
    sudo mkdir -p /var/log/blockchain
    
    # Set permissions
    sudo chown -R blockchain:blockchain /opt/blockchain
    sudo chown -R blockchain:blockchain /var/lib/blockchain
    sudo chown -R root:blockchain /etc/blockchain
    sudo chmod 750 /etc/blockchain
    
    log_success "Created directories with proper permissions"
}

# Install systemd services
install_services() {
    log_info "Installing systemd services..."
    
    # Copy service files
    sudo cp systemd/blockchain-node.service /etc/systemd/system/
    sudo cp systemd/blockchain-node@.service /etc/systemd/system/
    
    # Set permissions
    sudo chmod 644 /etc/systemd/system/blockchain-node*.service
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    log_success "Systemd services installed"
}

# Create default configuration
create_default_config() {
    log_info "Creating default configuration..."
    
    cat << 'EOFCONFIG' | sudo tee /etc/blockchain/node.conf >/dev/null
# Blockchain Node Configuration
[network]
p2p_port = 8333
max_peers = 125
enable_upnp = false

[bootstrap]
nodes = [
    "seed1.blockchain.example.com:8333",
    "seed2.blockchain.example.com:8333"
]

[security]
enable_encryption = true
require_auth = true

[logging]
level = "INFO"
file = "/var/log/blockchain/node.log"
max_size = "100MB"
max_files = 5

[performance]
worker_threads = 4
cache_size = "512MB"
enable_metrics = true
EOFCONFIG
    
    sudo chown root:blockchain /etc/blockchain/node.conf
    sudo chmod 640 /etc/blockchain/node.conf
    
    log_success "Default configuration created"
}

# Create log rotation
setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat << 'EOFLOGROTATE' | sudo tee /etc/logrotate.d/blockchain >/dev/null
/var/log/blockchain/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 blockchain blockchain
    postrotate
        systemctl reload blockchain-node.service >/dev/null 2>&1 || true
    endscript
}
EOFLOGROTATE
    
    log_success "Log rotation configured"
}

# Main setup function
main() {
    case "${1:-install}" in
        "install")
            setup_user_and_dirs
            install_services
            create_default_config
            setup_logrotate
            
            echo
            log_success "Setup completed successfully!"
            echo
            log_info "Next steps:"
            echo "  1. Enable service: sudo systemctl enable blockchain-node.service"
            echo "  2. Start service: sudo systemctl start blockchain-node.service"
            echo "  3. Check status: sudo systemctl status blockchain-node.service"
            echo "  4. View logs: sudo journalctl -fu blockchain-node.service"
            ;;
        *)
            echo "Usage: $0 {install}"
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    chmod +x scripts/setup-systemd.sh
    log_success "Systemd setup script created and made executable"
}

# Create performance tuning script
create_performance_script() {
    log_header "Creating performance tuning script..."
    
    cat > scripts/arch-performance-tuning.sh << 'EOF'
#!/bin/bash
# arch-performance-tuning.sh - Arch Linux performance optimizations for blockchain nodes

set -euo pipefail

log_info() {
    echo "[INFO] $1"
}

log_warning() {
    echo "[WARNING] $1"
}

# CPU performance tuning
tune_cpu() {
    log_info "Tuning CPU performance..."
    
    # Set CPU governor to performance
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
        log_info "CPU governor set to performance"
    fi
    
    # Enable turbo boost if available
    if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo >/dev/null
        log_info "Intel turbo boost enabled"
    fi
}

# Memory tuning
tune_memory() {
    log_info "Tuning memory performance..."
    
    # Create sysctl config if it doesn't exist
    sudo mkdir -p /etc/sysctl.d
    
    # Optimize swappiness for server workloads
    echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-blockchain.conf >/dev/null
    
    # Increase dirty ratios for better write performance
    cat << 'EOFSYSCTL' | sudo tee -a /etc/sysctl.d/99-blockchain.conf >/dev/null
vm.dirty_ratio=40
vm.dirty_background_ratio=10
vm.dirty_expire_centisecs=3000
vm.dirty_writeback_centisecs=500

# Network buffer tuning
net.core.rmem_max=268435456
net.core.wmem_max=268435456
net.ipv4.tcp_rmem=4096 87380 268435456
net.ipv4.tcp_wmem=4096 65536 268435456
net.ipv4.tcp_congestion_control=bbr
net.core.netdev_max_backlog=5000
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_fastopen=3
EOFSYSCTL
    
    # Apply settings
    sudo sysctl -p /etc/sysctl.d/99-blockchain.conf
    
    log_info "Memory and network tuning applied"
}

# I/O scheduler optimization
tune_io() {
    log_info "Tuning I/O scheduler..."
    
    # Set I/O scheduler to mq-deadline for SSDs, bfq for HDDs
    for disk in /sys/block/sd*; do
        if [[ -f "$disk/queue/scheduler" ]]; then
            # Check if it's an SSD
            if [[ $(cat "$disk/queue/rotational") == "0" ]]; then
                echo mq-deadline | sudo tee "$disk/queue/scheduler" >/dev/null
                log_info "Set mq-deadline scheduler for SSD $(basename "$disk")"
            else
                echo bfq | sudo tee "$disk/queue/scheduler" >/dev/null
                log_info "Set bfq scheduler for HDD $(basename "$disk")"
            fi
        fi
    done
}

# Apply all optimizations
main() {
    echo "Arch Linux Performance Tuning for Blockchain"
    echo "============================================"
    
    tune_cpu
    tune_memory
    tune_io
    
    echo
    log_info "Performance tuning completed!"
    log_warning "Some changes require a reboot to take effect"
    log_info "Monitor performance with: htop, iotop, nethogs"
}

main "$@"
EOF
    
    chmod +x scripts/arch-performance-tuning.sh
    log_success "Performance tuning script created and made executable"
}

# Create monitoring files
create_monitoring_files() {
    log_header "Creating monitoring files..."
    
    # Prometheus exporter
    cat > monitoring/prometheus-exporter.py << 'EOF'
#!/usr/bin/env python3
"""
Prometheus metrics exporter for Blockchain Core
Optimized for Arch Linux deployment
"""

import time
import json
import logging
from typing import Dict, Any
from prometheus_client import start_http_server, Gauge, Counter, Histogram, Info
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BlockchainMetricsExporter:
    def __init__(self, port: int = 9090):
        self.port = port
        self.blockchain_core = None
        
        # System metrics
        self.cpu_usage = Gauge('blockchain_cpu_usage_percent', 'CPU usage percentage')
        self.memory_usage = Gauge('blockchain_memory_usage_bytes', 'Memory usage in bytes')
        self.disk_usage = Gauge('blockchain_disk_usage_bytes', 'Disk usage in bytes')
        
        # Blockchain metrics
        self.blockchain_height = Gauge('blockchain_height', 'Current blockchain height')
        self.peer_count = Gauge('blockchain_peer_count', 'Number of connected peers')
        self.mempool_size = Gauge('blockchain_mempool_size', 'Number of pending transactions')
        self.blocks_total = Counter('blockchain_blocks_total', 'Total number of blocks processed')
        self.transactions_total = Counter('blockchain_transactions_total', 'Total number of transactions')
        
        # Network metrics
        self.messages_received = Counter('blockchain_messages_received_total', 'Total messages received')
        self.messages_sent = Counter('blockchain_messages_sent_total', 'Total messages sent')
        
        # Node info
        self.node_info = Info('blockchain_node_info', 'Static node information')
        
        # Initialize blockchain core
        self._init_blockchain()
    
    def _init_blockchain(self):
        """Initialize blockchain core connection"""
        try:
            import blockchain_core
            
            if hasattr(blockchain_core, 'NetworkedBlockchainCore'):
                self.blockchain_core = blockchain_core.NetworkedBlockchainCore()
                self.blockchain_core.enableP2PNetworking(False)  # Metrics only
                logger.info("Initialized NetworkedBlockchainCore")
            else:
                self.blockchain_core = blockchain_core.BlockchainCore.get_instance()
                logger.info("Initialized basic BlockchainCore")
                
            # Set static node info
            self.node_info.info({
                'version': getattr(blockchain_core, '__version__', '1.0.0'),
                'build_type': 'optimized' if hasattr(blockchain_core, 'NetworkedBlockchainCore') else 'basic',
                'platform': 'arch-linux'
            })
            
        except Exception as e:
            logger.error(f"Failed to initialize blockchain core: {e}")
            self.blockchain_core = None
    
    def collect_system_metrics(self):
        """Collect system resource metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_usage.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.set(memory.used)
            
            # Disk usage for blockchain data
            try:
                disk = psutil.disk_usage('/var/lib/blockchain')
                self.disk_usage.set(disk.used)
            except:
                disk = psutil.disk_usage('.')
                self.disk_usage.set(disk.used)
            
            logger.debug(f"System metrics - CPU: {cpu_percent}%, Memory: {memory.used}")
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def collect_blockchain_metrics(self):
        """Collect blockchain-specific metrics"""
        if not self.blockchain_core:
            return
            
        try:
            # Basic blockchain metrics
            if hasattr(self.blockchain_core, 'getChainLength'):
                chain_length = self.blockchain_core.getChainLength()
                self.blockchain_height.set(chain_length)
            elif hasattr(self.blockchain_core, 'get_chain_length'):
                chain_length = self.blockchain_core.get_chain_length()
                self.blockchain_height.set(chain_length)
            
            # Network metrics (if available)
            if hasattr(self.blockchain_core, 'getNetworkStatus'):
                status = self.blockchain_core.getNetworkStatus()
                
                self.peer_count.set(status.get('peer_count', 0))
                self.mempool_size.set(status.get('mempool_size', 0))
                
                # Network statistics
                network = status.get('network', {})
                if network:
                    self.messages_received._value._value = network.get('messages_received', 0)
                    self.messages_sent._value._value = network.get('messages_sent', 0)
            
            logger.debug(f"Blockchain metrics collected")
            
        except Exception as e:
            logger.error(f"Error collecting blockchain metrics: {e}")
    
    def start_server(self):
        """Start the Prometheus metrics server"""
        start_http_server(self.port)
        logger.info(f"Prometheus metrics server started on port {self.port}")
        
        while True:
            try:
                self.collect_system_metrics()
                self.collect_blockchain_metrics()
                time.sleep(15)  # Collect metrics every 15 seconds
                
            except KeyboardInterrupt:
                logger.info("Metrics collection stopped")
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                time.sleep(5)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Blockchain Prometheus Exporter')
    parser.add_argument('--port', type=int, default=9090, help='Metrics server port')
    parser.add_argument('--log-level', default='INFO', help='Log level')
    
    args = parser.parse_args()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Start exporter
    exporter = BlockchainMetricsExporter(args.port)
    exporter.start_server()

if __name__ == '__main__':
    main()
EOF
    
    chmod +x monitoring/prometheus-exporter.py
    
    # Grafana dashboard
    cat > monitoring/grafana-dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Blockchain Core - Arch Linux",
    "tags": ["blockchain", "arch-linux"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Blockchain Height",
        "type": "stat",
        "targets": [
          {
            "expr": "blockchain_height",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {"mode": "palette-classic"},
            "unit": "short"
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Connected Peers",
        "type": "stat",
        "targets": [
          {
            "expr": "blockchain_peer_count",
            "refId": "A"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "System Resources",
        "type": "graph",
        "targets": [
          {
            "expr": "blockchain_cpu_usage_percent",
            "legendFormat": "CPU Usage %",
            "refId": "A"
          },
          {
            "expr": "blockchain_memory_usage_bytes / 1024 / 1024 / 1024",
            "legendFormat": "Memory Usage GB",
            "refId": "B"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Network Activity",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(blockchain_messages_received_total[5m])",
            "legendFormat": "Messages Received/sec",
            "refId": "A"
          },
          {
            "expr": "rate(blockchain_messages_sent_total[5m])",
            "legendFormat": "Messages Sent/sec",
            "refId": "B"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "10s"
  }
}
EOF
    
    log_success "Monitoring files created"
}

# Create configuration files
create_config_files() {
    log_header "Creating configuration files..."
    
    # Default node configuration
    cat > config/node.conf << 'EOF'
# Blockchain Node Configuration
[network]
p2p_port = 8333
max_peers = 125
enable_upnp = false

[bootstrap]
nodes = [
    "127.0.0.1:8334",
    "localhost:8335"
]

[security]
enable_encryption = true
require_auth = false

[logging]
level = "INFO"
file = "logs/node.log"
max_size = "100MB"
max_files = 5

[performance]
worker_threads = 4
cache_size = "512MB"
enable_metrics = true
metrics_port = 9090
EOF

    # Test configuration
    cat > config/test.conf << 'EOF'
# Test Configuration
[network]
p2p_port = 18333
max_peers = 10

[bootstrap]
nodes = []

[logging]
level = "DEBUG"
file = "logs/test.log"

[performance]
worker_threads = 2
cache_size = "128MB"
EOF

    log_success "Configuration files created"
}

# Create basic test files
create_test_files() {
    log_header "Creating test files..."
    
    # Basic test
    cat > tests/test_basic.py << 'EOF'
#!/usr/bin/env python3
"""Basic tests for blockchain core"""

import sys
import os
import time

def test_import():
    """Test that blockchain_core can be imported"""
    try:
        import blockchain_core
        print("✓ blockchain_core imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Failed to import blockchain_core: {e}")
        return False

def test_basic_operations():
    """Test basic blockchain operations"""
    try:
        import blockchain_core
        
        # Get blockchain instance
        core = blockchain_core.BlockchainCore.get_instance()
        
        # Test chain length
        length = core.get_chain_length()
        print(f"✓ Chain length: {length}")
        
        # Test adding a block
        core.add_custom_block({"test": "data", "timestamp": time.time()})
        new_length = core.get_chain_length()
        
        if new_length > length:
            print("✓ Block addition successful")
            return True
        else:
            print("✗ Block addition failed")
            return False
            
    except Exception as e:
        print(f"✗ Basic operations failed: {e}")
        return False

def test_p2p_availability():
    """Test P2P functionality availability"""
    try:
        import blockchain_core
        
        if hasattr(blockchain_core, 'NetworkedBlockchainCore'):
            print("✓ P2P functionality available")
            
            # Test P2P core creation
            p2p_core = blockchain_core.NetworkedBlockchainCore(19999)
            print("✓ P2P core creation successful")
            return True
        else:
            print("⚠ P2P functionality not available")
            return True  # Not an error
            
    except Exception as e:
        print(f"✗ P2P test failed: {e}")
        return False

def main():
    print("Running Blockchain Core Tests")
    print("=" * 30)
    
    tests = [
        ("Import Test", test_import),
        ("Basic Operations", test_basic_operations),
        ("P2P Availability", test_p2p_availability),
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\nRunning {name}...")
        if test_func():
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF
    
    chmod +x tests/test_basic.py
    
    # Create test runner
    cat > tests/run_tests.sh << 'EOF'
#!/bin/bash
# Test runner script

set -euo pipefail

echo "Blockchain Core Test Suite"
echo "========================="

# Check if blockchain_core is built
if ! python -c "import blockchain_core" 2>/dev/null; then
    echo "ERROR: blockchain_core not found. Please build first:"
    echo "  ./build_arch.sh --build"
    exit 1
fi

# Run basic tests
echo "Running basic tests..."
python tests/test_basic.py

# Run performance test if available
if [[ -f "tests/test_performance.py" ]]; then
    echo -e "\nRunning performance tests..."
    python tests/test_performance.py
fi

echo -e "\nTest suite completed!"
EOF
    
    chmod +x tests/run_tests.sh
    
    log_success "Test files created"
}

# Create documentation
create_docs() {
    log_header "Creating documentation..."
    
    # README
    cat > docs/README.md << 'EOF'
# Blockchain Core - Arch Linux Optimized

High-performance C++ blockchain core with P2P networking, optimized for Arch Linux.

## Quick Start

1. **Install dependencies:**
   ```bash
   sudo pacman -S base-devel cmake ninja openssl python pybind11 nlohmann-json
   ```

2. **Build the project:**
   ```bash
   ./build_arch.sh --all
   ```

3. **Run tests:**
   ```bash
   tests/run_tests.sh
   ```

4. **Start blockchain:**
   ```bash
   python polymorphicblock_p2p.py
   ```

## System Service

Install as systemd service:
```bash
sudo scripts/setup-systemd.sh install
sudo systemctl enable --now blockchain-node.service
```

## Monitoring

Start Prometheus exporter:
```bash
python monitoring/prometheus-exporter.py --port 9090
```

View metrics: http://localhost:9090/metrics

## Performance Tuning

Apply Arch Linux optimizations:
```bash
sudo scripts/arch-performance-tuning.sh
```

## Directory Structure

- `systemd/` - Systemd service files
- `scripts/` - Setup and utility scripts  
- `monitoring/` - Prometheus and Grafana configs
- `config/` - Configuration files
- `tests/` - Test suite
- `docs/` - Documentation
EOF

    # API documentation
    cat > docs/API.md << 'EOF'
# Blockchain Core API

## Python API

### Basic Usage

```python
from polymorphicblock_p2p import NetworkedBlockchain

# Create blockchain instance
blockchain = NetworkedBlockchain(p2p_port=8333)
blockchain.initialize()

# Start P2P networking
blockchain.start_network()

# Add bootstrap nodes
blockchain.add_bootstrap_node("127.0.0.1", 8334)

# Add blocks and transactions
blockchain.add_block({"data": "test"}, broadcast=True)
blockchain.add_transaction({"from": "alice", "to": "bob", "amount": 100})

# Get network status
status = blockchain.get_network_status()
print(f"Peers: {status['peer_count']}")
```

### Advanced Features

```python
# Event handling
def on_block_received(block):
    print(f"New block: {block['index']}")

blockchain.on_block_received(on_block_received)

# Manual block creation
blockchain.create_and_broadcast_block()

# Network synchronization
blockchain.request_sync()
```

## C++ API

Direct C++ usage (for advanced users):

```cpp
#include "blockchain_p2p_integration.hpp"

using namespace blockchain;

// Create networked blockchain
auto blockchain = std::make_unique<NetworkedBlockchainCore>(8333);
blockchain->initialize();

// Add custom block
json block_data = {{"test", "data"}};
blockchain->addBlock(block_data, true);

// Get network status
auto status = blockchain->getNetworkStatus();
```
EOF

    log_success "Documentation created"
}

# Create main setup script that ties everything together
create_main_setup_script() {
    log_header "Creating main setup script..."
    
    cat > setup-all.sh << 'EOF'
#!/bin/bash
# setup-all.sh - Complete project setup and build

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}[SETUP]${NC} $1"
}

# Check if on Arch Linux
check_arch() {
    if ! grep -q "ID=arch" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} Not on Arch Linux. Some optimizations may not apply."
    else
        log_success "Running on Arch Linux - optimizations enabled"
    fi
}

# Install dependencies
install_deps() {
    log_header "Installing dependencies..."
    
    if command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        sudo pacman -S --needed base-devel cmake ninja openssl python python-pip pybind11 nlohmann-json ccache
        pip install --user psutil prometheus-client
    elif command -v apt >/dev/null 2>&1; then
        # Debian/Ubuntu
        sudo apt update
        sudo apt install -y build-essential cmake ninja-build libssl-dev python3-dev python3-pip
        pip3 install pybind11 psutil prometheus-client
    else
        log_info "Please install dependencies manually:"
        echo "  - build-essential/base-devel"
        echo "  - cmake, ninja"
        echo "  - openssl development headers"
        echo "  - python3 development headers"
        echo "  - pybind11, nlohmann-json"
    fi
    
    log_success "Dependencies installed"
}

# Build the project
build_project() {
    log_header "Building project..."
    
    if [[ -f "build_arch.sh" ]]; then
        chmod +x build_arch.sh
        ./build_arch.sh --deps --build --test
    else
        log_info "build_arch.sh not found, using basic build..."
        python setup.py build_ext --inplace
    fi
    
    log_success "Project built successfully"
}

# Set up services
setup_services() {
    log_header "Setting up services..."
    
    if [[ -f "scripts/setup-systemd.sh" ]]; then
        chmod +x scripts/setup-systemd.sh
        
        read -p "Install system-wide systemd services? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo scripts/setup-systemd.sh install
            log_success "System services installed"
        else
            log_info "System services skipped"
        fi
    fi
}

# Performance tuning
apply_tuning() {
    log_header "Applying performance tuning..."
    
    if [[ -f "scripts/arch-performance-tuning.sh" ]]; then
        chmod +x scripts/arch-performance-tuning.sh
        
        read -p "Apply performance optimizations? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo scripts/arch-performance-tuning.sh
            log_success "Performance tuning applied"
        else
            log_info "Performance tuning skipped"
        fi
    fi
}

# Run tests
run_tests() {
    log_header "Running tests..."
    
    if [[ -f "tests/run_tests.sh" ]]; then
        chmod +x tests/run_tests.sh
        tests/run_tests.sh
        log_success "Tests completed"
    else
        # Basic test
        if python -c "import blockchain_core; print('✓ Import successful')" 2>/dev/null; then
            log_success "Basic import test passed"
        else
            echo "✗ Import test failed"
            return 1
        fi
    fi
}

# Start monitoring
start_monitoring() {
    log_header "Starting monitoring..."
    
    if [[ -f "monitoring/prometheus-exporter.py" ]]; then
        chmod +x monitoring/prometheus-exporter.py
        
        read -p "Start Prometheus exporter? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Starting Prometheus exporter on port 9090..."
            python monitoring/prometheus-exporter.py --port 9090 &
            echo $! > .prometheus.pid
            log_success "Prometheus exporter started (PID: $(cat .prometheus.pid))"
            log_info "Metrics available at: http://localhost:9090/metrics"
        fi
    fi
}

# Main function
main() {
    echo -e "${PURPLE}"
    cat << 'BANNER'
╔══════════════════════════════════════════════════════════════╗
║              Blockchain Core Complete Setup                  ║
║                 Arch Linux Optimized                        ║
╚══════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    
    check_arch
    
    case "${1:-all}" in
        "deps")
            install_deps
            ;;
        "build")
            build_project
            ;;
        "services")
            setup_services
            ;;
        "tuning")
            apply_tuning
            ;;
        "test")
            run_tests
            ;;
        "monitor")
            start_monitoring
            ;;
        "all")
            install_deps
            build_project
            run_tests
            setup_services
            apply_tuning
            start_monitoring
            
            echo
            log_success "Complete setup finished!"
            echo
            log_info "Next steps:"
            echo "  • Test: python -c 'import blockchain_core'"
            echo "  • Run: python polymorphicblock_p2p.py"
            echo "  • Monitor: http://localhost:9090/metrics"
            echo "  • Service: sudo systemctl status blockchain-node.service"
            ;;
        *)
            echo "Usage: $0 {deps|build|services|tuning|test|monitor|all}"
            echo
            echo "Commands:"
            echo "  deps     - Install dependencies"
            echo "  build    - Build the project"
            echo "  services - Set up systemd services"
            echo "  tuning   - Apply performance optimizations"
            echo "  test     - Run test suite"
            echo "  monitor  - Start monitoring"
            echo "  all      - Do everything (default)"
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    chmod +x setup-all.sh
    log_success "Main setup script created and made executable"
}

# Create .gitignore
create_gitignore() {
    log_header "Creating .gitignore..."
    
    cat > .gitignore << 'EOF'
# Build directories
build/
dist/
*.egg-info/

# Python cache
__pycache__/
*.pyc
*.pyo
*.pyd

# C++ build artifacts
*.o
*.so
*.dylib
*.dll
*.a
*.lib

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Logs
logs/*.log
*.log

# Configuration (may contain sensitive data)
config/production.conf
config/secrets.conf

# Runtime files
*.pid
.prometheus.pid

# Temporary files
tmp/
temp/

# System files
.DS_Store
Thumbs.db

# Blockchain data (for development)
blockchain_db.json
blockStorage.json
fallback_db.json
userData/

# ccache
.ccache/

# Test artifacts
test_results/
coverage/
EOF
    
    log_success ".gitignore created"
}

# Main execution
main() {
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║          Blockchain Core Project Structure Setup            ║
║                    Automated Installer                      ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log_info "Setting up project structure in: $CURRENT_DIR"
    
    # Create all components
    create_directories
    create_systemd_files
    create_setup_systemd_script
    create_performance_script
    create_monitoring_files
    create_config_files
    create_test_files
    create_docs
    create_main_setup_script
    create_gitignore
    
    echo
    log_success "Project structure setup completed!"
    echo
    log_info "Project structure created:"
    echo "  ├── systemd/              # Service configurations"
    echo "  ├── scripts/              # Setup and utility scripts"
    echo "  ├── monitoring/           # Prometheus and Grafana"
    echo "  ├── config/               # Configuration files"
    echo "  ├── tests/                # Test suite"
    echo "  ├── docs/                 # Documentation"
    echo "  └── setup-all.sh          # Complete setup script"
    echo
    log_info "Next steps:"
    echo "  1. Run complete setup:    ./setup-all.sh"
    echo "  2. Or build only:         ./setup-all.sh build"
    echo "  3. Or install services:   ./setup-all.sh services"
    echo "  4. View documentation:    cat docs/README.md"
    echo
    log_info "Individual scripts:"
    echo "  • System services:        scripts/setup-systemd.sh"
    echo "  • Performance tuning:     scripts/arch-performance-tuning.sh"
    echo "  • Prometheus monitoring:  monitoring/prometheus-exporter.py"
    echo "  • Run tests:              tests/run_tests.sh"
    
    # Make all scripts executable
    find scripts/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    find tests/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    find monitoring/ -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
    
    log_success "All scripts made executable"
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi