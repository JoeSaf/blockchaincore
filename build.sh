#!/bin/bash

# Blockchain Node Build Script - Fixed Version
# This script builds the C++ blockchain node with warning suppression

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on supported OS
check_os() {
    print_status "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_success "Linux detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_success "macOS detected"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        print_success "Windows detected"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Install dependencies based on OS
install_dependencies() {
    print_status "Installing dependencies..."
    
    case $OS in
        "linux")
            if command -v pacman &> /dev/null; then
                # Arch Linux / Manjaro
                print_status "Detected Arch Linux - using pacman"
                
                sudo pacman -S --noconfirm \
                    base-devel \
                    cmake \
                    git \
                    pkg-config \
                    openssl \
                    curl \
                    wget \
                    ninja \
                    gdb \
                    valgrind \
                    ccache
                print_success "Arch Linux dependencies installed"
            elif command -v apt-get &> /dev/null; then
                # Debian/Ubuntu
                print_status "Detected Debian/Ubuntu - using apt-get"
                sudo apt-get update
                sudo apt-get install -y \
                    build-essential \
                    cmake \
                    git \
                    pkg-config \
                    libssl-dev \
                    libcurl4-openssl-dev \
                    wget \
                    ninja-build \
                    ccache
                print_success "Debian/Ubuntu dependencies installed"
            elif command -v yum &> /dev/null; then
                # Red Hat/CentOS/Fedora
                print_status "Detected Red Hat/CentOS/Fedora - using yum"
                sudo yum groupinstall -y "Development Tools"
                sudo yum install -y cmake git openssl-devel libcurl-devel wget ninja-build ccache
                print_success "Red Hat/CentOS/Fedora dependencies installed"
            elif command -v dnf &> /dev/null; then
                # Modern Fedora
                print_status "Detected Fedora - using dnf"
                sudo dnf groupinstall -y "Development Tools"
                sudo dnf install -y cmake git openssl-devel libcurl-devel wget ninja-build ccache
                print_success "Fedora dependencies installed"
            else
                print_error "Unsupported package manager. Please install dependencies manually:"
                print_error "Required packages: base-devel cmake git pkg-config openssl curl wget"
                exit 1
            fi
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew not found. Please install Homebrew first:"
                print_error '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                exit 1
            fi
            print_status "Detected macOS - using Homebrew"
            brew update
            brew install cmake openssl curl wget ninja ccache
            print_success "macOS dependencies installed"
            ;;
        "windows")
            print_warning "Windows detected. Please ensure you have:"
            print_warning "1. Visual Studio 2019+ with C++ workload"
            print_warning "2. vcpkg package manager"
            print_warning "3. Git for Windows"
            ;;
    esac
    
    print_success "Dependencies installation completed"
}

# Check for required tools
check_requirements() {
    print_status "Checking build requirements..."
    
    # Check for CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake not found. Please install CMake 3.16 or higher."
        exit 1
    fi
    
    CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
    print_success "CMake found: $CMAKE_VERSION"
    
    # Check for C++ compiler
    if command -v g++ &> /dev/null; then
        GCC_VERSION=$(g++ --version | head -n1)
        print_success "GCC found: $GCC_VERSION"
        COMPILER="gcc"
    elif command -v clang++ &> /dev/null; then
        CLANG_VERSION=$(clang++ --version | head -n1)
        print_success "Clang found: $CLANG_VERSION"
        COMPILER="clang"
    else
        print_error "No C++ compiler found. Please install GCC or Clang."
        exit 1
    fi
    
    # Check for Git
    if ! command -v git &> /dev/null; then
        print_error "Git not found. Please install Git."
        exit 1
    fi
    
    print_success "All requirements satisfied"
}

# Create build directory
setup_build_directory() {
    print_status "Setting up build directory..."
    
    # Clean existing build if it exists and is requested
    if [ -d "build" ]; then
        if [ "$CLEAN" == "1" ] || [ "$1" == "--clean" ]; then
            print_warning "Cleaning existing build directory..."
            rm -rf build
        else
            print_warning "Build directory exists. Use --clean to rebuild from scratch."
        fi
    fi
    
    mkdir -p build
    cd build
    
    print_success "Build directory ready"
}

# Configure with CMake
configure_build() {
    print_status "Configuring build with CMake..."
    
    BUILD_TYPE=${BUILD_TYPE:-Release}
    
    # Set compiler-specific flags to suppress warnings
    CMAKE_ARGS=(
        -DCMAKE_BUILD_TYPE=$BUILD_TYPE
        -DCMAKE_INSTALL_PREFIX=/usr/local
        -DCMAKE_CXX_STANDARD=17
    )
    
    # Add warning suppression flags
    if [ "$COMPILER" == "gcc" ]; then
        CMAKE_ARGS+=(
            -DCMAKE_CXX_FLAGS="-Wall -Wextra -O3 -Wno-dangling-reference -Wno-unused-parameter"
        )
    elif [ "$COMPILER" == "clang" ]; then
        CMAKE_ARGS+=(
            -DCMAKE_CXX_FLAGS="-Wall -Wextra -O3 -Wno-unused-parameter"
        )
    fi
    
    # Use Ninja generator if available for faster builds
    if command -v ninja &> /dev/null; then
        CMAKE_ARGS+=(-G Ninja)
        print_status "Using Ninja build system"
        BUILD_TOOL="ninja"
    else
        print_status "Using Make build system"
        BUILD_TOOL="make"
    fi
    
    # Enable ccache if available
    if command -v ccache &> /dev/null; then
        CMAKE_ARGS+=(
            -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
        )
        print_status "Using ccache for faster rebuilds"
    fi
    
    cmake .. "${CMAKE_ARGS[@]}"
    
    if [ $? -eq 0 ]; then
        print_success "CMake configuration complete"
    else
        print_error "CMake configuration failed"
        print_error "Try installing missing dependencies or check CMakeLists.txt"
        exit 1
    fi
}

# Build the project
build_project() {
    print_status "Building blockchain node..."
    
    # Determine number of CPU cores
    if [[ "$OS" == "linux" ]]; then
        CORES=$(nproc)
    elif [[ "$OS" == "macos" ]]; then
        CORES=$(sysctl -n hw.ncpu)
    else
        CORES=4  # Default for Windows
    fi
    
    print_status "Building with $CORES cores..."
    
    # Build based on the selected build tool
    if [ "$BUILD_TOOL" == "ninja" ]; then
        print_status "Using Ninja build system..."
        ninja -j$CORES
    else
        print_status "Using Make build system..."
        make -j$CORES
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Build completed successfully"
        
        # Show binary information
        if [ -f "bin/blockchain_node" ]; then
            BINARY_SIZE=$(du -h bin/blockchain_node | cut -f1)
            print_success "Binary size: $BINARY_SIZE"
            print_success "Binary location: $(pwd)/bin/blockchain_node"
        fi
    else
        print_error "Build failed"
        print_error "Common issues:"
        print_error "1. Missing dependencies"
        print_error "2. Compiler version too old"
        print_error "3. OpenSSL development headers missing"
        exit 1
    fi
}

# Run tests
run_tests() {
    if [ "$SKIP_TESTS" != "1" ]; then
        print_status "Running tests..."
        
        if [ -f "bin/blockchain_node_test" ]; then
            ./bin/blockchain_node_test
            if [ $? -eq 0 ]; then
                print_success "All tests passed"
            else
                print_error "Some tests failed"
                exit 1
            fi
        else
            print_warning "No test executable found, skipping tests"
        fi
    else
        print_warning "Skipping tests (SKIP_TESTS=1)"
    fi
}

# Install the binary
install_binary() {
    if [ "$INSTALL" == "1" ]; then
        print_status "Installing binary..."
        if [ "$BUILD_TOOL" == "ninja" ]; then
            ninja install
        else
            make install
        fi
        print_success "Binary installed to /usr/local/bin/"
    fi
}

# Print usage information
print_usage() {
    echo "Blockchain Node Build Script - Fixed Version"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help                Show this help message"
    echo "  --install-deps        Install system dependencies"
    echo "  --build-type TYPE     Set build type (Release|Debug|RelWithDebInfo)"
    echo "  --skip-tests          Skip running tests"
    echo "  --install             Install binary after building"
    echo "  --clean               Clean build directory before building"
    echo "  --suppress-warnings   Suppress compiler warnings (default: enabled)"
    echo ""
    echo "Environment variables:"
    echo "  BUILD_TYPE           Build type (default: Release)"
    echo "  SKIP_TESTS           Skip tests if set to 1"
    echo "  INSTALL              Install binary if set to 1"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Standard build with warning suppression"
    echo "  $0 --install-deps                     # Install dependencies first"
    echo "  $0 --build-type Debug                 # Debug build"
    echo "  $0 --skip-tests --install             # Build and install without tests"
    echo ""
}

# Main function
main() {
    echo "════════════════════════════════════════════════════════"
    echo "      Blockchain Node Build Script - Fixed v1.1"
    echo "        (with warning suppression and optimizations)"
    echo "════════════════════════════════════════════════════════"
    echo ""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                print_usage
                exit 0
                ;;
            --install-deps)
                INSTALL_DEPS=1
                shift
                ;;
            --build-type)
                BUILD_TYPE="$2"
                shift 2
                ;;
            --skip-tests)
                SKIP_TESTS=1
                shift
                ;;
            --install)
                INSTALL=1
                shift
                ;;
            --clean)
                CLEAN=1
                shift
                ;;
            --suppress-warnings)
                SUPPRESS_WARNINGS=1
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Check OS
    check_os
    
    # Install dependencies if requested
    if [ "$INSTALL_DEPS" == "1" ]; then
        install_dependencies
    fi
    
    # Check requirements
    check_requirements
    
    # Setup build directory
    setup_build_directory
    
    # Configure build
    configure_build
    
    # Build project
    build_project
    
    # Run tests
    run_tests
    
    # Install if requested
    install_binary
    
    # Success message
    echo ""
    print_success "Build completed successfully!"
    echo ""
    echo "Binary location: $(pwd)/bin/blockchain_node"
    echo "To run the node:  ./bin/blockchain_node"
    echo ""
    echo "API will be available at: http://localhost:8080/api/"
    echo "P2P ports: TCP 8333, UDP 8334"
    echo ""
    print_status "Happy mining! 🚀"
    echo ""
    print_status "Quick test commands:"
    echo "  curl http://localhost:8080/api/status"
    echo "  curl http://localhost:8080/api/blockchain"
    echo ""
}

# Run main function
main "$@"