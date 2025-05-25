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
            echo "  • Run: python polymorphicblock.py"
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
