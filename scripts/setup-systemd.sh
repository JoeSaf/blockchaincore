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
