#!/usr/bin/env python3
"""
Setup Script for Integrated Blockchain System
This script helps set up and test the integrated blockchain system with all components.
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path

def print_banner():
    """Print setup banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║            Integrated Blockchain System Setup               ║
║                                                              ║
║  🔗 C++ Blockchain Node + Python Integration                ║
║  🗄️ Database Management System                              ║
║  🔐 Polymorphic Security & Authentication                   ║
║  📁 Secure File Upload System                              ║
║  🌐 Web Dashboard (Coming Soon)                            ║
╚══════════════════════════════════════════════════════════════╝
""")

def check_dependencies():
    """Check if all dependencies are available"""
    print("🔍 Checking dependencies...")
    
    missing_deps = []
    
    # Check Python packages
    required_packages = [
        'cryptography',
        'requests',
        'tkinter'  # Usually comes with Python
    ]
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            else:
                __import__(package)
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package}")
            missing_deps.append(package)
    
    # Check C++ executable
    cpp_executable = "./build/bin/blockchain_node"
    if os.path.exists(cpp_executable):
        print(f"   ✅ C++ blockchain node: {cpp_executable}")
    else:
        print(f"   ❌ C++ blockchain node: {cpp_executable}")
        missing_deps.append("cpp_blockchain_node")
    
    if missing_deps:
        print(f"\n❌ Missing dependencies: {', '.join(missing_deps)}")
        print("\nTo install missing Python packages:")
        for dep in missing_deps:
            if dep not in ['tkinter', 'cpp_blockchain_node']:
                print(f"   pip install {dep}")
        
        if 'cpp_blockchain_node' in missing_deps:
            print("\nTo build the C++ blockchain node:")
            print("   ./build.sh --clean")
        
        return False
    
    print("✅ All dependencies satisfied!")
    return True

def create_directory_structure():
    """Create necessary directory structure"""
    print("\n📁 Creating directory structure...")
    
    directories = [
        "blockchain_databases",
        "blockchain_databases/databases",
        "security_storage",
        "secure_users",
        "secure_uploads",
        "secure_uploads/quarantine",
        "secure_uploads/approved",
        "secure_uploads/metadata",
        "userData"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   📁 {directory}")
    
    print("✅ Directory structure created!")

def create_default_config():
    """Create default system configuration"""
    print("\n⚙️ Creating default configuration...")
    
    config = {
        "cpp_node": {
            "executable": "./build/bin/blockchain_node",
            "api_url": "http://localhost:8080",
            "tcp_port": 8333,
            "udp_port": 8334
        },
        "storage": {
            "database_root": "blockchain_databases",
            "security_root": "security_storage",
            "upload_root": "secure_uploads"
        },
        "security": {
            "session_timeout": 3600,
            "max_login_attempts": 5,
            "enable_file_scanning": True
        },
        "features": {
            "enable_gui": True,
            "enable_web_dashboard": False,  # Coming soon
            "enable_p2p": True
        }
    }
    
    config_file = "system_config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"   ✅ Configuration saved to {config_file}")

def test_cpp_node():
    """Test if C++ node can start"""
    print("\n🧪 Testing C++ blockchain node...")
    
    cpp_executable = "./build/bin/blockchain_node"
    if not os.path.exists(cpp_executable):
        print(f"   ❌ C++ node not found: {cpp_executable}")
        return False
    
    try:
        # Try to start the node briefly
        print("   🚀 Starting C++ node (this may take a moment)...")
        process = subprocess.Popen([cpp_executable], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE)
        
        # Wait a bit for it to start
        time.sleep(3)
        
        # Check if it's still running
        if process.poll() is None:
            print("   ✅ C++ node started successfully")
            # Terminate the test process
            process.terminate()
            process.wait()
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"   ❌ C++ node failed to start")
            print(f"   Error: {stderr.decode()[:200]}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error testing C++ node: {str(e)}")
        return False

def run_component_tests():
    """Run tests for each component"""
    print("\n🧪 Running component tests...")
    
    # Test imports
    try:
        print("   Testing imports...")
        from blockchain_bridge import BlockchainBridge
        from database_manager import IntegratedDatabaseManager
        from security_auth import PolymorphicSecuritySystem
        from file_upload_system import SecureFileUploader
        print("   ✅ All imports successful")
    except ImportError as e:
        print(f"   ❌ Import error: {str(e)}")
        return False
    
    # Test basic functionality
    try:
        print("   Testing blockchain bridge...")
        bridge = BlockchainBridge()
        print("   ✅ Blockchain bridge initialized")
        
        print("   Testing database manager...")
        db_manager = IntegratedDatabaseManager(bridge)
        print("   ✅ Database manager initialized")
        
        print("   Testing security system...")
        security_system = PolymorphicSecuritySystem(bridge)
        print("   ✅ Security system initialized")
        
        print("   Testing file uploader...")
        file_uploader = SecureFileUploader(db_manager, security_system)
        print("   ✅ File uploader initialized")
        
    except Exception as e:
        print(f"   ❌ Component test error: {str(e)}")
        return False
    
    print("✅ All component tests passed!")
    return True

def create_sample_data():
    """Create some sample data for testing"""
    print("\n📝 Creating sample data...")
    
    # Create a sample text file
    sample_file = "sample_upload.txt"
    with open(sample_file, "w") as f:
        f.write("This is a sample file for testing the blockchain system.\n")
        f.write(f"Created at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("This file can be used to test the file upload functionality.\n")
    
    print(f"   📄 Created sample file: {sample_file}")
    
    # Create a sample JSON file
    sample_json = "sample_data.json"
    data = {
        "message": "Sample JSON data for blockchain system",
        "created_at": time.time(),
        "version": "1.0",
        "test_data": {
            "numbers": [1, 2, 3, 4, 5],
            "strings": ["hello", "world", "blockchain"],
            "boolean": True
        }
    }
    
    with open(sample_json, "w") as f:
        json.dump(data, f, indent=2)
    
    print(f"   📄 Created sample JSON: {sample_json}")
    print("✅ Sample data created!")

def show_usage_instructions():
    """Show usage instructions"""
    print("\n📖 Usage Instructions")
    print("=" * 50)
    print("""
🚀 Starting the System:
   python system_coordinator.py

🧪 Running Demos:
   python system_coordinator.py --demo

🔧 Individual Components:
   python blockchain_bridge.py        # Test C++ integration
   python database_manager.py         # Test database system
   python security_auth.py           # Test security system
   python file_upload_system.py      # Test file uploads

📁 Important Files:
   system_config.json                # System configuration
   blockchain_databases/             # Database storage
   security_storage/                 # Security data
   secure_uploads/                   # File uploads

🔐 Default Admin User:
   When you first run the system, you'll be prompted to create
   an admin user. This user can then create other users and
   manage the system.

🌐 API Access:
   The C++ blockchain node runs on http://localhost:8080
   You can test it with: curl http://localhost:8080/api/status

🆘 Troubleshooting:
   1. Make sure the C++ node is built: ./build.sh --clean
   2. Check that all Python dependencies are installed
   3. Verify ports 8080, 8333, 8334 are available
   4. Check the logs for detailed error messages
""")

def main():
    """Main setup function"""
    print_banner()
    
    print("🛠️ Setting up Integrated Blockchain System...")
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Setup failed due to missing dependencies.")
        return False
    
    # Create directory structure
    create_directory_structure()
    
    # Create default configuration
    create_default_config()
    
    # Test C++ node
    if not test_cpp_node():
        print("\n⚠️ C++ node test failed, but setup can continue.")
        print("   Make sure to build the C++ node with: ./build.sh --clean")
    
    # Run component tests
    if not run_component_tests():
        print("\n❌ Component tests failed.")
        return False
    
    # Create sample data
    create_sample_data()
    
    # Show usage instructions
    show_usage_instructions()
    
    print("\n🎉 Setup completed successfully!")
    print("\n🚀 Ready to start the system with:")
    print("   python system_coordinator.py")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n👋 Setup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Setup error: {str(e)}")
        sys.exit(1)
