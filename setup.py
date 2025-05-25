# setup.py - Enhanced for Arch Linux
"""
Enhanced setup script for the C++ Blockchain Core with Python bindings.
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
__version__ = "1.0.0"
__arch_optimized__ = True

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
        "-DNDEBUG"
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
        "-fPIC"
    ])

# Include directories
include_dirs = [
    pybind11.get_include(),
    ".",  # Current directory
]

# Library configuration
libraries = ["ssl", "crypto", "pthread"]
library_dirs = []

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

# Define the extension modules
ext_modules = [
    Pybind11Extension(
        "blockchain_core",
        sources=[
            "python_bindings.cpp",
            "p2p_python_bindings.cpp",
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
        print("Checking system requirements...")
        
        # Check compiler
        try:
            result = subprocess.run(['g++', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ GCC version: {result.stdout.split()[2]}")
            else:
                raise subprocess.CalledProcessError(result.returncode, 'g++')
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ GCC not found")
            sys.exit(1)
        
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
            
            # Check if P2P features are available
            if hasattr(module, 'NetworkedBlockchainCore'):
                print("✓ P2P networking features available")
            else:
                print("⚠ P2P networking features not available")
                
        except Exception as e:
            print(f"✗ Build verification failed: {e}")

# Development dependencies
dev_requirements = [
    "pytest>=6.0",
    "pytest-cov",
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
    author="Blockchain Core Team",
    author_email="",
    description="High-performance C++ blockchain core with P2P networking - Arch Linux optimized",
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
        ],
        "monitoring": [
            "prometheus-client",
            "psutil",
            "py-cpuinfo",
        ],
        "arch": [
            "systemd-python",  # Arch-specific systemd integration
        ] if arch_info['is_arch'] else [],
    },
    entry_points={
        "console_scripts": [
            "blockchain-node=polymorphicblock_p2p:main",
            "blockchain-cli=blockchain_cli:main",
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
    ],
    keywords="blockchain cryptocurrency p2p networking arch-linux",
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

# Arch Linux specific post-install
if arch_info['is_arch'] and len(sys.argv) > 1 and sys.argv[1] == 'install':
    print("\nArch Linux Post-Installation:")
    print("=" * 30)
    print("To create a systemd service:")
    print("  sudo systemctl edit --force --full blockchain-node.service")
    print("\nTo enable performance monitoring:")
    print("  pip install blockchain_core[monitoring]")
    print("\nFor development tools:")
    print("  pip install blockchain_core[dev]")
    print("\nArch-specific optimizations enabled:")
    print(f"  - Native CPU optimization: {arch_info['march_native']}")
    print(f"  - Link-time optimization: {arch_info['use_lto']}")
    print(f"  - ccache acceleration: {arch_info['use_ccache']}")
    print(f"  - Parallel compilation: {arch_info['cpu_count']} jobs")