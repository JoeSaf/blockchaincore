# setup.py - Enhanced for Arch Linux + P2P Networking
"""
Enhanced setup script for the C++ Blockchain Core with P2P networking and Python bindings.
Optimized for Arch Linux with native performance and modern toolchain.
"""

import os
import sys
import subprocess
import platform
import multiprocessing
from pathlib import Path
from pybind11.setup_helpers import Pybind11Extension, build_ext
from pybind11 import get_cmake_dir
import pybind11

from setuptools import setup, Extension, find_packages

# Version information
__version__ = "2.0.0"  # Updated for P2P enhancement
__arch_optimized__ = True
__p2p_enhanced__ = True

def is_arch_linux():
    """Detect if running on Arch Linux"""
    try:
        with open('/etc/os-release', 'r') as f:
            return 'ID=arch' in f.read()
    except FileNotFoundError:
        return False

def get_arch_info():
    """Get Arch-specific system information"""
    arch_info = {
        'is_arch': is_arch_linux(),
        'cpu_count': multiprocessing.cpu_count(),
        'march_native': True,
        'use_lto': True,
        'use_ccache': False
    }
    
    # Check for ccache
    if subprocess.run(['which', 'ccache'], capture_output=True).returncode == 0:
        arch_info['use_ccache'] = True
        print("✓ ccache detected - enabling for faster builds")
    
    # Check CPU features
    try:
        cpuinfo = subprocess.run(['lscpu'], capture_output=True, text=True)
        if 'avx2' in cpuinfo.stdout.lower():
            print("✓ AVX2 support detected")
        if 'avx-512' in cpuinfo.stdout.lower():
            print("✓ AVX-512 support detected")
    except:
        pass
    
    return arch_info

# Get system information
arch_info = get_arch_info()
print(f"Building on Arch Linux: {arch_info['is_arch']}")
print(f"P2P Enhanced Version: {__p2p_enhanced__}")

# Compiler configuration
extra_compile_args = []
extra_link_args = []

if arch_info['is_arch']:
    # Arch Linux optimizations
    extra_compile_args.extend([
        "-std=c++20",
        "-O3",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-fPIC",
        "-DNDEBUG",
        "-DWITH_P2P_ENHANCED",  # Enable enhanced P2P features
        "-DWITH_OPENSSL",
        "-DASIO_STANDALONE",
        "-DASIO_NO_DEPRECATED",
        "-Wno-unused-parameter",  # Suppress warnings in P2P code
        "-Wno-unused-variable",
    ])
    
    if arch_info['march_native']:
        extra_compile_args.append("-march=native")
        print("✓ Native CPU optimization enabled")
    
    if arch_info['use_lto']:
        extra_compile_args.append("-flto")
        extra_link_args.append("-flto")
        print("✓ Link-time optimization enabled")
    
    # Use all CPU cores for compilation
    os.environ['MAKEFLAGS'] = f"-j{arch_info['cpu_count']}"
    
else:
    # Generic Linux/other systems
    extra_compile_args.extend([
        "-std=c++17", 
        "-O3", 
        "-Wall", 
        "-Wextra",
        "-fPIC",
        "-DWITH_P2P_ENHANCED",
        "-DWITH_OPENSSL",
        "-DASIO_STANDALONE",
        "-Wno-unused-parameter",
    ])

# Include directories
include_dirs = [
    pybind11.get_include(),
    ".",  # Current directory for all .hpp files
]

# Enhanced library configuration for P2P
libraries = ["ssl", "crypto", "pthread"]
library_dirs = []

# Check for ASIO (required for enhanced P2P)
def check_asio():
    """Check for ASIO library"""
    asio_found = False
    
    # Check system locations
    asio_paths = [
        "/usr/include/asio.hpp",
        "/usr/local/include/asio.hpp", 
        "/opt/homebrew/include/asio.hpp",
    ]
    
    for path in asio_paths:
        if os.path.exists(path):
            asio_found = True
            print(f"✓ ASIO found at {path}")
            break
    
    if not asio_found:
        if arch_info['is_arch']:
            print("Installing ASIO via pacman...")
            try:
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'asio'], check=True)
                asio_found = True
                print("✓ ASIO installed")
            except subprocess.CalledProcessError:
                print("⚠ Could not install ASIO automatically")
        else:
            print("⚠ ASIO not found - install libasio-dev (Ubuntu) or asio (Arch)")
    
    return asio_found

# Arch-specific package detection
def find_arch_packages():
    """Find packages using Arch's package manager"""
    packages = {}
    
    if arch_info['is_arch']:
        # Check for nlohmann-json
        result = subprocess.run(['pacman', '-Qi', 'nlohmann-json'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            include_dirs.append('/usr/include')
            packages['nlohmann-json'] = '/usr/include/nlohmann'
            print("✓ Using system nlohmann-json")
        
        # Check for OpenSSL
        result = subprocess.run(['pacman', '-Qi', 'openssl'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            packages['openssl'] = True
            print("✓ Using system OpenSSL")
        
        # Check for ASIO
        result = subprocess.run(['pacman', '-Qi', 'asio'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            packages['asio'] = True
            print("✓ Using system ASIO")
        else:
            print("Installing ASIO...")
            try:
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'asio'], check=True)
                packages['asio'] = True
                print("✓ ASIO installed")
            except subprocess.CalledProcessError:
                print("⚠ Could not install ASIO")
    
    return packages

# Detect Arch packages
arch_packages = find_arch_packages()

# Auto-download missing dependencies
def ensure_dependencies():
    """Ensure all dependencies are available"""
    if 'nlohmann-json' not in arch_packages:
        print("Downloading nlohmann/json...")
        try:
            import urllib.request
            os.makedirs("external/nlohmann", exist_ok=True)
            url = "https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp"
            urllib.request.urlretrieve(url, "external/nlohmann/json.hpp")
            include_dirs.append("external")
            print("✓ nlohmann/json downloaded")
        except Exception as e:
            print(f"✗ Failed to download nlohmann/json: {e}")
            sys.exit(1)
    
    # Check ASIO
    if not check_asio():
        print("✗ ASIO is required for enhanced P2P networking")
        print("Install with: sudo pacman -S asio (Arch) or sudo apt install libasio-dev (Ubuntu)")
        sys.exit(1)

# Platform-specific library paths
if platform.system() == "Darwin":  # macOS
    homebrew_prefixes = ["/opt/homebrew", "/usr/local"]
    for prefix in homebrew_prefixes:
        openssl_path = os.path.join(prefix, "opt", "openssl")
        if os.path.exists(openssl_path):
            include_dirs.append(os.path.join(openssl_path, "include"))
            library_dirs.append(os.path.join(openssl_path, "lib"))
            break
            
elif platform.system() == "Windows":
    # Windows OpenSSL paths
    openssl_paths = [
        "C:/Program Files/OpenSSL-Win64",
        "C:/OpenSSL-Win64",
        "C:/vcpkg/installed/x64-windows",
    ]
    for path in openssl_paths:
        if os.path.exists(path):
            include_dirs.append(os.path.join(path, "include"))
            library_dirs.append(os.path.join(path, "lib"))
            break

# Check required source files
def check_required_files():
    """Check that all required source files exist"""
    required_files = [
        "blockchain_core.hpp",
        "p2p_types.hpp",
        "p2p_message.hpp", 
        "p2p_peer.hpp",
        "p2p_network_manager_enhanced.hpp",
        "p2p_crypto_utils.hpp",
        "blockchain_p2p_integration.hpp",
        "python_bindings.cpp",
        "p2p_python_bindings.cpp",
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("✗ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\nPlease ensure all enhanced P2P files are in the project directory.")
        return False
    
    print("✓ All required source files found")
    return True

# Define the extension modules
ext_modules = [
    # Core blockchain module (original)
    Pybind11Extension(
        "blockchain_core",
        sources=[
            "python_bindings.cpp",
        ],
        include_dirs=include_dirs,
        libraries=libraries,
        library_dirs=library_dirs,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        language="c++",
        cxx_std=20 if arch_info['is_arch'] else 17,
    ),
    
    # Enhanced P2P blockchain module (new)
    Pybind11Extension(
        "blockchain_p2p",
        sources=[
            "p2p_python_bindings.cpp",  # Enhanced P2P bindings
        ],
        include_dirs=include_dirs,
        libraries=libraries,
        library_dirs=library_dirs,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        language="c++",
        cxx_std=20 if arch_info['is_arch'] else 17,
    ),
]

# Custom build class
class CustomBuildExt(build_ext):
    def build_extension(self, ext):
        # Pre-build checks
        self.check_system_requirements()
        
        # Check for required files
        if not check_required_files():
            sys.exit(1)
        
        ensure_dependencies()
        
        # Set ccache if available
        if arch_info['use_ccache']:
            os.environ['CXX'] = 'ccache g++'
            os.environ['CC'] = 'ccache gcc'
        
        # Build with enhanced output
        print(f"Building {ext.name} with {arch_info['cpu_count']} parallel jobs...")
        super().build_extension(ext)
        
        # Post-build verification
        self.verify_build(ext)
    
    def check_system_requirements(self):
        """Check system requirements"""
        print("Checking system requirements for enhanced P2P...")
        
        # Check compiler
        try:
            result = subprocess.run(['g++', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                print(f"✓ GCC: {version_line}")
            else:
                raise subprocess.CalledProcessError(result.returncode, 'g++')
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ GCC not found")
            sys.exit(1)
        
        # Check C++ standard support
        try:
            test_cpp = """
            #include <memory>
            #include <thread>
            #include <atomic>
            int main() { return 0; }
            """
            with open('test_cpp_support.cpp', 'w') as f:
                f.write(test_cpp)
            
            result = subprocess.run(['g++', '-std=c++17', '-c', 'test_cpp_support.cpp'], 
                                  capture_output=True)
            os.remove('test_cpp_support.cpp')
            if os.path.exists('test_cpp_support.o'):
                os.remove('test_cpp_support.o')
            
            if result.returncode == 0:
                print("✓ C++17 support confirmed")
            else:
                print("✗ C++17 support required")
                sys.exit(1)
        except Exception as e:
            print(f"⚠ Could not verify C++ support: {e}")
        
        # Check OpenSSL
        try:
            import ssl
            print(f"✓ OpenSSL version: {ssl.OPENSSL_VERSION}")
        except ImportError:
            print("✗ OpenSSL not found")
            sys.exit(1)
        
        # Check pybind11
        try:
            import pybind11
            print(f"✓ pybind11 version: {pybind11.__version__}")
        except ImportError:
            print("✗ pybind11 not found")
            sys.exit(1)
        
        # Check ASIO
        asio_headers = [
            "/usr/include/asio.hpp",
            "/usr/local/include/asio.hpp",
        ]
        asio_found = any(os.path.exists(header) for header in asio_headers)
        if asio_found:
            print("✓ ASIO headers found")
        else:
            print("✗ ASIO headers not found")
            print("Install with: sudo pacman -S asio")
            sys.exit(1)
    
    def verify_build(self, ext):
        """Verify the built extension"""
        try:
            # Test import
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                ext.name, 
                self.get_ext_fullpath(ext.name)
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            print(f"✓ {ext.name} built and importable")
            
            # Check specific features based on module
            if ext.name == "blockchain_core":
                if hasattr(module, 'BlockchainCore'):
                    print("✓ Core blockchain features available")
                else:
                    print("⚠ Core blockchain features not available")
            
            elif ext.name == "blockchain_p2p":
                features = [
                    ('NetworkedBlockchainCore', 'P2P blockchain integration'),
                    ('P2PNetworkManager', 'Advanced network manager'),
                    ('P2PMessage', 'Enhanced message system'),
                    ('NetworkConfig', 'Network configuration'),
                    ('MessageType', 'Message type enums'),
                ]
                
                for attr, desc in features:
                    if hasattr(module, attr):
                        print(f"✓ {desc} available")
                    else:
                        print(f"⚠ {desc} not available")
                
                # Test creating a basic instance
                try:
                    if hasattr(module, 'NetworkedBlockchainCore'):
                        # Just test creation, don't start networking
                        test_instance = module.NetworkedBlockchainCore(8333)
                        print("✓ P2P blockchain instantiation successful")
                except Exception as e:
                    print(f"⚠ P2P blockchain instantiation failed: {e}")
                    
        except Exception as e:
            print(f"✗ Build verification failed: {e}")

# Development dependencies
dev_requirements = [
    "pytest>=6.0",
    "pytest-cov",
    "pytest-benchmark",
    "black",
    "flake8",
    "mypy",
    "pre-commit",
]

if arch_info['is_arch']:
    dev_requirements.extend([
        "gdbgui",  # Available in AUR
        "valgrind",
    ])

# Package setup
setup(
    name="blockchain_core",
    version=__version__,
    author="Enhanced Blockchain P2P Team",
    author_email="",
    description="High-performance C++ blockchain core with enhanced P2P networking - Arch Linux optimized",
    long_description=Path("README.md").read_text() if Path("README.md").exists() else "",
    long_description_content_type="text/markdown",
    ext_modules=ext_modules,
    cmdclass={"build_ext": CustomBuildExt},
    packages=find_packages(),
    python_requires=">=3.9",  # Arch usually has latest Python
    install_requires=[
        "pybind11>=2.6.0",
        "psutil",  # For system monitoring
        "cryptography",  # For additional crypto operations
    ],
    extras_require={
        "dev": dev_requirements,
        "test": [
            "pytest>=6.0",
            "pytest-cov",
            "pytest-benchmark",
            "pytest-asyncio",  # For async P2P testing
        ],
        "monitoring": [
            "prometheus-client",
            "psutil",
            "py-cpuinfo",
        ],
        "p2p": [
            "asyncio",
            "aiohttp",  # For P2P web interfaces
        ],
        "arch": [
            "systemd-python",  # Arch-specific systemd integration
        ] if arch_info['is_arch'] else [],
    },
    entry_points={
        "console_scripts": [
            "blockchain-node=polymorphicblock_p2p:main",
            "blockchain-cli=blockchain_cli:main",
            "blockchain-p2p-node=blockchain_p2p_node:main",  # New P2P node
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C++",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Distributed Computing",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
    keywords="blockchain cryptocurrency p2p networking arch-linux asio enhanced",
    project_urls={
        "Bug Reports": "https://github.com/your-username/blockchain-core/issues",
        "Source": "https://github.com/your-username/blockchain-core",
        "Documentation": "https://blockchain-core.readthedocs.io/",
    },
    zip_safe=False,
    include_package_data=True,
    package_data={
        "blockchain_core": ["*.hpp", "*.h"],
    },
)

# Enhanced Arch Linux specific post-install
if arch_info['is_arch'] and len(sys.argv) > 1 and sys.argv[1] == 'install':
    print("\n" + "="*60)
    print("🚀 ENHANCED P2P BLOCKCHAIN - ARCH LINUX INSTALLATION COMPLETE")
    print("="*60)
    print("\n📦 MODULES INSTALLED:")
    print("  • blockchain_core     - Core blockchain functionality")
    print("  • blockchain_p2p      - Enhanced P2P networking")
    print(f"\n⚡ ARCH OPTIMIZATIONS ENABLED:")
    print(f"  • Native CPU optimization: {arch_info['march_native']}")
    print(f"  • Link-time optimization: {arch_info['use_lto']}")
    print(f"  • ccache acceleration: {arch_info['use_ccache']}")
    print(f"  • Parallel compilation: {arch_info['cpu_count']} jobs")
    print(f"  • C++20 standard: {arch_info['is_arch']}")
    print("\n🌐 P2P FEATURES:")
    print("  • Async networking with ASIO")
    print("  • Advanced message system")
    print("  • Peer discovery and management")
    print("  • Real-time blockchain sync")
    print("  • Network monitoring and stats")
    print("\n🛠️  QUICK START:")
    print("  python -c \"import blockchain_p2p; print('P2P Ready!')\"")
    print("\n📖 SYSTEMD INTEGRATION:")
    print("  sudo systemctl edit --force --full blockchain-node.service")
    print("\n🔧 ADDITIONAL FEATURES:")
    print("  pip install blockchain_core[p2p,monitoring,dev]")
    print("\n📊 TESTING:")
    print("  pytest tests/ --benchmark-only")
    print("="*60)