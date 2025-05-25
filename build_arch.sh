#!/bin/bash
# build_arch.sh - Comprehensive Arch Linux build script for Blockchain Core
# Optimized for Arch Linux with native performance and modern toolchain

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="${JOBS:-$(nproc)}"
USE_CCACHE="${USE_CCACHE:-true}"
USE_NINJA="${USE_NINJA:-true}"
INSTALL_DEPS="${INSTALL_DEPS:-true}"
RUN_TESTS="${RUN_TESTS:-false}"
CREATE_PACKAGE="${CREATE_PACKAGE:-false}"

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

# Check if running on Arch Linux
check_arch_linux() {
    if ! grep -q "ID=arch" /etc/os-release 2>/dev/null; then
        log_warning "Not running on Arch Linux. Some optimizations may not apply."
        return 1
    fi
    return 0
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    # Core build dependencies
    local CORE_DEPS=(
        "base-devel"
        "cmake"
        "ninja"
        "git"
        "openssl"
        "python"
        "python-pip"
        "python-setuptools"
        "pybind11"
        "nlohmann-json"
    )
    
    # Optional development dependencies
    local DEV_DEPS=(
        "clang"
        "clang-tools-extra"
        "lldb"
        "gdb"
        "valgrind"
        "perf"
        "ccache"
        "cppcheck"
        "doxygen"
        "graphviz"
        "bear"
        "strace"
        "ltrace"
    )
    
    # Check which packages are missing
    local missing_core=()
    local missing_dev=()
    
    for pkg in "${CORE_DEPS[@]}"; do
        if ! pacman -Qi "$pkg" >/dev/null 2>&1; then
            missing_core+=("$pkg")
        fi
    done
    
    for pkg in "${DEV_DEPS[@]}"; do
        if ! pacman -Qi "$pkg" >/dev/null 2>&1; then
            missing_dev+=("$pkg")
        fi
    done
    
    # Install missing core dependencies
    if [[ ${#missing_core[@]} -gt 0 ]]; then
        log_info "Installing core dependencies: ${missing_core[*]}"
        sudo pacman -S --needed "${missing_core[@]}"
    else
        log_success "All core dependencies already installed"
    fi
    
    # Ask about development dependencies
    if [[ ${#missing_dev[@]} -gt 0 ]]; then
        echo
        read -p "Install development dependencies (${missing_dev[*]})? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo pacman -S --needed "${missing_dev[@]}"
            log_success "Development dependencies installed"
        fi
    fi
    
    # Python dependencies
    log_info "Installing Python dependencies..."
    pip install --user pybind11 pytest psutil
}

# Setup build environment
setup_build_env() {
    log_info "Setting up build environment..."
    
    # Set up ccache if available and requested
    if [[ "$USE_CCACHE" == "true" ]] && command -v ccache >/dev/null 2>&1; then
        export CC="ccache gcc"
        export CXX="ccache g++"
        log_success "ccache enabled"
        
        # Configure ccache
        ccache --set-config=max_size=2G
        ccache --set-config=compression=true
        log_info "ccache configured (max 2GB, compression enabled)"
    fi
    
    # Set build flags
    export MAKEFLAGS="-j$JOBS"
    export CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"
    
    # Arch-specific optimizations
    if check_arch_linux; then
        export CFLAGS="-march=native -O3 -pipe -fno-plt -fexceptions"
        export CXXFLAGS="$CFLAGS -fconcepts"
        export LDFLAGS="-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now"
        log_success "Arch Linux optimizations enabled"
    fi
}

# Detect system capabilities
detect_system() {
    log_info "Detecting system capabilities..."
    
    # CPU information
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)
    log_info "CPU: $cpu_model ($cpu_cores cores)"
    
    # Memory information
    local memory_gb=$(free -h | awk '/^Mem:/ {print $2}')
    log_info "Memory: $memory_gb"
    
    # Check for CPU features
    local cpu_features=""
    if grep -q " avx2 " /proc/cpuinfo; then
        cpu_features+="AVX2 "
    fi
    if grep -q " avx512" /proc/cpuinfo; then
        cpu_features+="AVX-512 "
    fi
    if [[ -n "$cpu_features" ]]; then
        log_info "CPU features: $cpu_features"
    fi
    
    # Check compiler versions
    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1)
        log_info "Compiler: $gcc_version"
    fi
    
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1)
        log_info "Alternative: $clang_version"
    fi
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    
    # Remove build directories
    rm -rf build/ dist/ *.egg-info/
    
    # Clean Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    
    # Clean ccache if requested
    if [[ "$USE_CCACHE" == "true" ]] && command -v ccache >/dev/null 2>&1; then
        if [[ "${CLEAN_CCACHE:-false}" == "true" ]]; then
            ccache --clear
            log_info "ccache cleared"
        fi
    fi
    
    log_success "Clean completed"
}

# Build with CMake
build_cmake() {
    log_info "Building with CMake..."
    
    mkdir -p build
    cd build
    
    local cmake_args=(
        "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
        "-DBUILD_TESTS=$RUN_TESTS"
    )
    
    # Use Ninja if available and requested
    if [[ "$USE_NINJA" == "true" ]] && command -v ninja >/dev/null 2>&1; then
        cmake_args+=("-GNinja")
        log_info "Using Ninja build system"
    fi
    
    # Configure
    log_info "Configuring build..."
    cmake "${cmake_args[@]}" ..
    
    # Build
    log_info "Building (using $JOBS parallel jobs)..."
    if [[ "$USE_NINJA" == "true" ]] && command -v ninja >/dev/null 2>&1; then
        ninja -j"$JOBS"
    else
        make -j"$JOBS"
    fi
    
    cd ..
    log_success "CMake build completed"
}

# Build with setuptools
build_setuptools() {
    log_info "Building with setuptools..."
    
    # Set environment for optimal compilation
    export ARCHFLAGS="-arch $(uname -m)"
    
    # Build in-place
    python setup.py build_ext --inplace
    
    log_success "Setuptools build completed"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    # Test Python import
    if python -c "import blockchain_core; print('✓ Import successful')" 2>/dev/null; then
        log_success "Python module import test passed"
    else
        log_error "Python module import test failed"
        return 1
    fi
    
    # Test P2P functionality
    if python -c "import blockchain_core; core = blockchain_core.NetworkedBlockchainCore(); print('✓ P2P core available')" 2>/dev/null; then
        log_success "P2P functionality test passed"
    else
        log_warning "P2P functionality test failed or not available"
    fi
    
    # Run Python tests if available
    if [[ -d "tests" ]] && command -v pytest >/dev/null 2>&1; then
        log_info "Running pytest..."
        pytest tests/ -v
        log_success "pytest completed"
    fi
    
    # Run C++ tests if built
    if [[ -f "build/tests/test_blockchain" ]]; then
        log_info "Running C++ tests..."
        cd build
        ctest --verbose
        cd ..
        log_success "C++ tests completed"
    fi
}

# Performance benchmark
run_benchmark() {
    log_info "Running performance benchmark..."
    
    # Create benchmark script
    cat > benchmark_arch.py << 'EOF'
import time
import psutil
import blockchain_core
import json

def benchmark_performance():
    print("Arch Linux Blockchain Performance Benchmark")
    print("=" * 50)
    
    # System info
    print(f"CPU cores: {psutil.cpu_count()}")
    print(f"Memory: {psutil.virtual_memory().total // (1024**3)} GB")
    
    # Initialize core
    core = blockchain_core.BlockchainCore.get_instance()
    
    # Benchmark block creation
    print("\n1. Block Creation Benchmark")
    start_time = time.perf_counter()
    for i in range(1000):
        core.add_custom_block({
            "test": f"block_{i}", 
            "timestamp": time.time(),
            "data": f"benchmark_data_{i}"
        })
    end_time = time.perf_counter()
    
    blocks_per_sec = 1000 / (end_time - start_time)
    print(f"   Blocks/second: {blocks_per_sec:.2f}")
    
    # Benchmark hash calculation
    print("\n2. Hash Calculation Benchmark")
    start_time = time.perf_counter()
    for i in range(10000):
        blockchain_core.CryptoUtils.sha256(f"test_data_{i}" * 100)
    end_time = time.perf_counter()
    
    hashes_per_sec = 10000 / (end_time - start_time)
    print(f"   Hashes/second: {hashes_per_sec:.2f}")
    
    # Benchmark chain validation
    print("\n3. Chain Validation Benchmark")
    start_time = time.perf_counter()
    for i in range(100):
        core.verify_blockchain()
    end_time = time.perf_counter()
    
    validations_per_sec = 100 / (end_time - start_time)
    print(f"   Validations/second: {validations_per_sec:.2f}")
    
    # Test P2P if available
    if hasattr(blockchain_core, 'NetworkedBlockchainCore'):
        print("\n4. P2P Network Test")
        try:
            p2p_core = blockchain_core.NetworkedBlockchainCore(8999)
            p2p_core.enableP2PNetworking(False)  # Disable actual networking for test
            print("   P2P core: ✓ Available")
        except Exception as e:
            print(f"   P2P core: ✗ Error - {e}")
    
    print(f"\n✓ Benchmark completed on Arch Linux")
    print(f"  Architecture optimizations: {'Enabled' if '-march=native' in str(core) else 'Disabled'}")

if __name__ == "__main__":
    benchmark_performance()
EOF
    
    python benchmark_arch.py
    rm benchmark_arch.py
    
    log_success "Benchmark completed"
}

# Create installation package
create_package() {
    log_info "Creating installation package..."
    
    # Build wheel
    python setup.py bdist_wheel
    
    # Create source distribution
    python setup.py sdist
    
    # Display package info
    if [[ -d "dist" ]]; then
        log_success "Packages created in dist/:"
        ls -la dist/
    fi
    
    # Create PKGBUILD for AUR (optional)
    if [[ "${CREATE_AUR:-false}" == "true" ]]; then
        create_aur_package
    fi
}

# Create AUR package
create_aur_package() {
    log_info "Creating AUR package structure..."
    
    mkdir -p aur-package
    cd aur-package
    
    # Create PKGBUILD
    cat > PKGBUILD << 'EOF'
# Maintainer: Blockchain Core Team <contact@example.com>
pkgname=blockchain-core-git
pkgver=1.0.0.r1
pkgrel=1
pkgdesc="High-performance C++ blockchain core with P2P networking"
arch=('x86_64')
url="https://github.com/your-username/blockchain-core"
license=('MIT')
depends=('openssl' 'python' 'nlohmann-json')
makedepends=('git' 'cmake' 'ninja' 'pybind11' 'base-devel')
provides=('blockchain-core')
conflicts=('blockchain-core')
source=("$pkgname::git+https://github.com/your-username/blockchain-core.git")
sha256sums=('SKIP')

pkgver() {
    cd "$pkgname"
    printf "1.0.0.r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
    cd "$pkgname"
}

build() {
    cd "$pkgname"
    
    # Use Arch optimization flags
    export CFLAGS="$CFLAGS -march=native"
    export CXXFLAGS="$CXXFLAGS -march=native"
    
    # Build with setuptools
    python setup.py build_ext --inplace
    
    # Alternative: Build with CMake
    # mkdir -p build
    # cd build
    # cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ..
    # ninja
}

check() {
    cd "$pkgname"
    python -c "import blockchain_core; print('Import test passed')"
}

package() {
    cd "$pkgname"
    
    # Install Python module
    python setup.py install --root="$pkgdir" --optimize=1 --skip-build
    
    # Install headers
    install -Dm644 blockchain_core.hpp "$pkgdir/usr/include/blockchain_core/blockchain_core.hpp"
    install -Dm644 p2p_blockchain_network.hpp "$pkgdir/usr/include/blockchain_core/p2p_blockchain_network.hpp"
    
    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
    
    # Install systemd service
    install -Dm644 systemd/blockchain-node.service "$pkgdir/usr/lib/systemd/system/blockchain-node.service"
}
EOF
    
    # Create .SRCINFO
    makepkg --printsrcinfo > .SRCINFO
    
    cd ..
    log_success "AUR package created in aur-package/"
}

# Install the built package
install_package() {
    log_info "Installing package..."
    
    # Install in development mode
    pip install --user -e .
    
    # Create desktop entry (optional)
    if [[ "${CREATE_DESKTOP:-false}" == "true" ]]; then
        create_desktop_entry
    fi
    
    # Create systemd service
    create_systemd_service
    
    log_success "Package installed"
}

# Create desktop entry
create_desktop_entry() {
    local desktop_file="$HOME/.local/share/applications/blockchain-core.desktop"
    
    mkdir -p "$(dirname "$desktop_file")"
    
    cat > "$desktop_file" << EOF
[Desktop Entry]
Name=Blockchain Core
Comment=High-performance blockchain with P2P networking
Exec=python -m polymorphicblock_p2p
Icon=network-server
Terminal=true
Type=Application
Categories=Network;Development;
Keywords=blockchain;cryptocurrency;p2p;network;
EOF
    
    update-desktop-database "$HOME/.local/share/applications/" 2>/dev/null || true
    log_info "Desktop entry created"
}

# Create systemd service
create_systemd_service() {
    local service_dir="$HOME/.config/systemd/user"
    local service_file="$service_dir/blockchain-node.service"
    
    mkdir -p "$service_dir"
    
    cat > "$service_file" << EOF
[Unit]
Description=Blockchain P2P Node (User Service)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(which python) -m polymorphicblock_p2p --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=strict
PrivateTmp=yes

# Environment
Environment=PYTHONPATH=%h/.local/lib/python*/site-packages

[Install]
WantedBy=default.target
EOF
    
    # Reload systemd and enable service
    systemctl --user daemon-reload
    
    log_info "Systemd user service created at $service_file"
    log_info "Enable with: systemctl --user enable blockchain-node.service"
    log_info "Start with: systemctl --user start blockchain-node.service"
}

# Display help
show_help() {
    cat << EOF
Arch Linux Blockchain Core Build Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    -c, --clean         Clean previous builds
    -d, --deps          Install dependencies
    -b, --build         Build the project
    -t, --test          Run tests
    -p, --package       Create installation package
    -i, --install       Install the package
    -a, --all           Do everything (clean, build, test, install)
    --benchmark         Run performance benchmark
    --cmake             Use CMake build system
    --setuptools        Use setuptools build system (default)
    --debug             Build in debug mode
    --no-ccache         Disable ccache
    --no-ninja          Disable ninja (use make)
    --aur              Create AUR package

ENVIRONMENT VARIABLES:
    BUILD_TYPE          Build type (Release|Debug) [default: Release]
    JOBS               Number of parallel jobs [default: nproc]
    USE_CCACHE         Enable ccache [default: true]
    USE_NINJA          Enable ninja [default: true]

EXAMPLES:
    $0 --all                    # Full build and installation
    $0 -d -b -t                 # Install deps, build, and test
    $0 --clean --build --cmake  # Clean build with CMake
    BUILD_TYPE=Debug $0 -b      # Debug build

EOF
}

# Main execution
main() {
    # Parse command line arguments
    local do_clean=false
    local do_deps=false
    local do_build=false
    local do_test=false
    local do_package=false
    local do_install=false
    local do_benchmark=false
    local build_system="setuptools"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--clean)
                do_clean=true
                shift
                ;;
            -d|--deps)
                do_deps=true
                shift
                ;;
            -b|--build)
                do_build=true
                shift
                ;;
            -t|--test)
                do_test=true
                shift
                ;;
            -p|--package)
                do_package=true
                shift
                ;;
            -i|--install)
                do_install=true
                shift
                ;;
            -a|--all)
                do_clean=true
                do_build=true
                do_test=true
                do_install=true
                shift
                ;;
            --benchmark)
                do_benchmark=true
                shift
                ;;
            --cmake)
                build_system="cmake"
                shift
                ;;
            --setuptools)
                build_system="setuptools"
                shift
                ;;
            --debug)
                BUILD_TYPE="Debug"
                shift
                ;;
            --no-ccache)
                USE_CCACHE=false
                shift
                ;;
            --no-ninja)
                USE_NINJA=false
                shift
                ;;
            --aur)
                CREATE_AUR=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # If no options specified, show help
    if [[ "$do_clean" == false && "$do_deps" == false && "$do_build" == false && 
          "$do_test" == false && "$do_package" == false && "$do_install" == false && 
          "$do_benchmark" == false ]]; then
        show_help
        exit 0
    fi
    
    # Header
    echo -e "${BLUE}"
    cat << 'EOF'
    ____  _            _     _           _       
   | __ )| | ___   ___| | __| |__   __ _(_)_ __  
   |  _ \| |/ _ \ / __| |/ /| '_ \ / _` | | '_ \ 
   | |_) | | (_) | (__|   < | | | | (_| | | | | |
   |____/|_|\___/ \___|_|\_\|_| |_|\__,_|_|_| |_|
                                                 
    Core P2P Network - Arch Linux Optimized
EOF
    echo -e "${NC}"
    
    # Check if running on Arch
    if check_arch_linux; then
        log_success "Running on Arch Linux - optimizations enabled"
    fi
    
    # Detect system capabilities
    detect_system
    
    # Execute requested operations
    if [[ "$do_deps" == true ]]; then
        if [[ "$INSTALL_DEPS" == true ]]; then
            install_dependencies
        else
            log_info "Dependency installation skipped (INSTALL_DEPS=false)"
        fi
    fi
    
    if [[ "$do_clean" == true ]]; then
        clean_build
    fi
    
    if [[ "$do_build" == true ]]; then
        setup_build_env
        
        case "$build_system" in
            "cmake")
                build_cmake
                ;;
            "setuptools")
                build_setuptools
                ;;
            *)
                log_error "Unknown build system: $build_system"
                exit 1
                ;;
        esac
    fi
    
    if [[ "$do_test" == true ]]; then
        run_tests
    fi
    
    if [[ "$do_benchmark" == true ]]; then
        run_benchmark
    fi
    
    if [[ "$do_package" == true ]]; then
        create_package
    fi
    
    if [[ "$do_install" == true ]]; then
        install_package
    fi
    
    # Final status
    echo
    log_success "Build script completed successfully!"
    
    if [[ "$do_install" == true ]]; then
        echo
        log_info "Next steps:"
        echo "  • Test the installation: python -c 'import blockchain_core'"
        echo "  • Run the blockchain: python -m polymorphicblock_p2p"
        echo "  • Start P2P node: systemctl --user start blockchain-node.service"
        echo "  • Monitor logs: journalctl --user -fu blockchain-node.service"
    fi
    
    # Show ccache stats if used
    if [[ "$USE_CCACHE" == true ]] && command -v ccache >/dev/null 2>&1; then
        echo
        log_info "ccache statistics:"
        ccache --show-stats
    fi
}

# Run main function with all arguments
main "$@"