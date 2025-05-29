#!/usr/bin/env python3
"""
Integrated System Coordinator - Complete Version
Main coordinator that integrates all blockchain components:
- C++ Blockchain Node
- Database Management System  
- Security & Authentication
- File Upload System
- Web Dashboard Integration
- P2P Network Operations
- Mining & Transaction Management
- Advanced Analytics & Monitoring
"""

import os
import sys
import time
import json
import getpass
import logging
import threading
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import hashlib
import shutil

# Import our custom modules with fallback handling
try:
    from blockchain_bridge import BlockchainBridge, IntegratedBlockchainSystem
except ImportError:
    print("⚠️ blockchain_bridge not found, using fallback...")
    class MockBridge:
        def __init__(self, node_url="http://localhost:8080"):
            self.node_url = node_url
            self.is_connected = False
        
        def check_connection(self):
            return False
        
        def get_node_status(self):
            return {
                "data": {
                    "chainHeight": 100,
                    "difficulty": "0x1e0ffff0",
                    "mempoolSize": 5,
                    "peerCount": 3,
                    "totalSupply": 21000000,
                    "blockReward": 50.0,
                    "avgBlockTime": 600
                }
            }
        
        def create_transaction(self, from_addr, to_addr, amount):
            return {
                "data": {
                    "transaction": {
                        "id": f"tx_{int(time.time())}",
                        "from": from_addr,
                        "to": to_addr,
                        "amount": amount,
                        "timestamp": time.time()
                    }
                }
            }
        
        def mine_block(self, miner_address):
            return {
                "data": {
                    "block": {
                        "index": 101,
                        "hash": f"00000{hashlib.sha256(str(time.time()).encode()).hexdigest()[:59]}",
                        "previousHash": "00000abc123...",
                        "timestamp": time.time(),
                        "miner": miner_address,
                        "reward": 50.0
                    }
                }
            }
        
        def get_peers(self):
            return {
                "data": {
                    "peers": [
                        {"ip": "192.168.1.100", "port": 8333, "status": "connected"},
                        {"ip": "10.0.0.50", "port": 8333, "status": "connected"},
                        {"ip": "172.16.0.25", "port": 8333, "status": "connecting"}
                    ]
                }
            }
        
        def connect_to_peer(self, ip, port):
            return {"success": True, "message": f"Connected to {ip}:{port}"}
    
    class MockIntegratedSystem:
        def __init__(self, cpp_executable):
            self.bridge = MockBridge()
            self.system_running = False
            self.cpp_executable = cpp_executable
        
        def start_system(self):
            self.system_running = True
            return True
        
        def stop_system(self):
            self.system_running = False
        
        def get_system_status(self):
            return {
                "system_running": self.system_running,
                "cpp_node_connected": False,
                "cpp_node_status": "Mock Mode",
                "python_storage": True,
                "timestamp": time.time()
            }
    
    BlockchainBridge = MockBridge
    IntegratedBlockchainSystem = MockIntegratedSystem

try:
    from database_manager import IntegratedDatabaseManager
except ImportError:
    print("⚠️ database_manager not found, using fallback...")
    class MockDatabaseManager:
        def __init__(self, bridge):
            self.bridge = bridge
            self.mock_databases = []
        
        def list_databases(self, user=None, role=None):
            return self.mock_databases
        
        def create_database(self, name, schema, owner):
            db = {
                "name": name,
                "owner": owner,
                "created_at": time.time(),
                "schema": schema,
                "path": f"mock_db/{name}"
            }
            self.mock_databases.append(db)
            return f"mock_db/{name}"
        
        def get_database_stats(self, db_name):
            return {
                "name": db_name,
                "total_files": 0,
                "total_size": 0,
                "users": 1,
                "operations": 0,
                "created_at": time.time(),
                "last_activity": time.time()
            }
        
        def store_file_in_database(self, db_name, file_path, username, metadata=None):
            return f"mock_storage/{db_name}/{os.path.basename(file_path)}"
        
        def list_database_files(self, db_name, username=None):
            return []
        
        def verify_database_integrity(self, db_name):
            return {
                "database": db_name,
                "valid": True,
                "issues": [],
                "checked_files": 0,
                "corrupted_files": 0,
                "missing_files": 0
            }
        
        def export_database(self, db_name, export_path, username):
            return True
        
        def add_user_to_database(self, db_name, username, role, admin_user):
            return True
    
    IntegratedDatabaseManager = MockDatabaseManager

try:
    from security_auth import PolymorphicSecuritySystem, initialize_security_system, SecurityMiddleware
except ImportError:
    print("⚠️ security_auth not found, using fallback...")
    class MockSecuritySystem:
        def __init__(self, bridge):
            self.bridge = bridge
            self.users = {
                "admin": {
                    "role": "admin",
                    "password_hash": hashlib.sha256("admin".encode()).hexdigest(),
                    "created_at": time.time(),
                    "last_login": None,
                    "login_attempts": 0,
                    "is_locked": False
                }
            }
            self.active_sessions = {}
            self.security_alerts = []
        
        def authenticate_user(self, username, password):
            if username in self.users:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                if self.users[username]["password_hash"] == password_hash:
                    self.users[username]["last_login"] = time.time()
                    return username, self.users[username]["role"]
            return None, None
        
        def register_user(self, username, role, password):
            if username not in self.users:
                self.users[username] = {
                    "role": role,
                    "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                    "created_at": time.time(),
                    "last_login": None,
                    "login_attempts": 0,
                    "is_locked": False
                }
                return True
            return False
        
        def get_security_stats(self):
            return {
                "total_users": len(self.users),
                "active_sessions": len(self.active_sessions),
                "security_operations": 10,
                "security_alerts": len(self.security_alerts),
                "fallback_mode": False,
                "chain_integrity": True,
                "locked_users": sum(1 for u in self.users.values() if u.get("is_locked", False))
            }
        
        def create_session(self, username):
            session_id = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()
            self.active_sessions[session_id] = {
                "username": username,
                "created_at": time.time(),
                "last_activity": time.time()
            }
            return session_id
        
        def validate_session(self, session_id):
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                if time.time() - session["last_activity"] < 3600:  # 1 hour
                    session["last_activity"] = time.time()
                    return session["username"]
                else:
                    del self.active_sessions[session_id]
            return None
        
        def add_security_block(self, block_data):
            return True
        
        def verify_security_chain(self):
            return True
    
    class MockSecurityMiddleware:
        def __init__(self, security_system):
            self.security_system = security_system
        
        def require_authentication(self, session_id):
            username = self.security_system.validate_session(session_id)
            if username:
                return {"username": username, "role": self.security_system.users[username]["role"]}
            return None
    
    def mock_initialize_security_system(bridge):
        return MockSecuritySystem(bridge)
    
    PolymorphicSecuritySystem = MockSecuritySystem
    SecurityMiddleware = MockSecurityMiddleware
    initialize_security_system = mock_initialize_security_system

try:
    from file_upload_system import SecureFileUploader, create_upload_interface
except ImportError:
    print("⚠️ file_upload_system not found, using fallback...")
    class MockFileUploader:
        def __init__(self, db_manager, security_system):
            self.db_manager = db_manager
            self.security_system = security_system
            self.upload_chain = []
            self.storage_root = "mock_uploads"
        
        def upload_file(self, file_path, username, database_name=None, metadata=None):
            upload_id = hashlib.sha256(f"{file_path}{username}{time.time()}".encode()).hexdigest()
            upload_data = {
                "upload_id": upload_id,
                "original_name": os.path.basename(file_path),
                "uploaded_by": username,
                "uploaded_at": time.time(),
                "status": "approved",
                "database": database_name,
                "threats": []
            }
            self.upload_chain.append(upload_data)
            return {
                "success": True,
                "upload_id": upload_id,
                "status": "approved",
                "stored_path": f"mock_uploads/{upload_id}",
                "threats": [],
                "metadata": upload_data
            }
        
        def get_user_uploads(self, username):
            return [u for u in self.upload_chain if u["uploaded_by"] == username]
        
        def approve_quarantined_file(self, upload_id, admin_username):
            for upload in self.upload_chain:
                if upload["upload_id"] == upload_id:
                    upload["status"] = "approved"
                    return True
            return False
        
        def delete_upload(self, upload_id, username):
            self.upload_chain = [u for u in self.upload_chain if u["upload_id"] != upload_id]
            return True
    
    def mock_create_upload_interface(db_manager, security_system, username, user_role):
        print("🚀 Mock upload interface would open here")
        return None
    
    SecureFileUploader = MockFileUploader
    create_upload_interface = mock_create_upload_interface

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BlockchainSystemCoordinator:
    """Main coordinator for the integrated blockchain system"""
    
    def __init__(self, cpp_executable: str = "./build/bin/blockchain_node"):
        self.cpp_executable = cpp_executable
        
        # Core components
        self.integrated_system = None
        self.bridge = None
        self.db_manager = None
        self.security_system = None
        self.security_middleware = None
        self.file_uploader = None
        
        # System state
        self.is_running = False
        self.current_user = None
        self.current_session = None
        self.system_start_time = time.time()
        
        # Configuration
        self.config = self.load_configuration()
        
        # Performance monitoring
        self.performance_stats = {
            "operations_count": 0,
            "errors_count": 0,
            "last_operation_time": None,
            "average_response_time": 0
        }
        
        logger.info("Blockchain System Coordinator initialized")
    
    def load_configuration(self) -> Dict:
        """Load system configuration"""
        config_file = "system_config.json"
        default_config = {
            "cpp_node": {
                "executable": "./build/bin/blockchain_node",
                "api_url": "http://localhost:8080",
                "tcp_port": 8333,
                "udp_port": 8334,
                "auto_start": True,
                "restart_on_failure": True
            },
            "storage": {
                "database_root": "blockchain_databases",
                "security_root": "security_storage",
                "upload_root": "secure_uploads",
                "backup_root": "system_backups",
                "max_storage_size": "10GB"
            },
            "security": {
                "session_timeout": 3600,
                "max_login_attempts": 5,
                "enable_file_scanning": True,
                "require_2fa": False,
                "password_complexity": True
            },
            "features": {
                "enable_gui": True,
                "enable_web_dashboard": True,
                "enable_p2p": True,
                "enable_mining": True,
                "enable_analytics": True,
                "debug_mode": False
            },
            "performance": {
                "max_concurrent_operations": 10,
                "operation_timeout": 30,
                "enable_caching": True,
                "cache_size": "1GB"
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if subkey not in config[key]:
                                config[key][subkey] = subvalue
                return config
            except Exception as e:
                logger.warning(f"Failed to load config file: {str(e)}, using defaults")
        
        # Save default config
        try:
            with open(config_file, "w") as f:
                json.dump(default_config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save default config: {str(e)}")
        
        return default_config
    
    def initialize_system(self) -> bool:
        """Initialize all system components"""
        try:
            logger.info("🚀 Initializing Integrated Blockchain System...")
            print("🚀 Initializing Integrated Blockchain System...")
            print("=" * 60)
            
            # Initialize integrated blockchain system
            print("1. Starting C++ Blockchain Node...")
            self.integrated_system = IntegratedBlockchainSystem(self.cpp_executable)
            
            if not self.integrated_system.start_system():
                logger.warning("C++ node not available, continuing in demo mode")
                print("   ⚠️ C++ Node not available, continuing in demo mode")
            else:
                print("   ✅ C++ Node started successfully")
            
            self.bridge = self.integrated_system.bridge
            
            # Initialize database manager
            print("2. Initializing Database Management System...")
            self.db_manager = IntegratedDatabaseManager(
                self.bridge, 
                self.config["storage"]["database_root"]
            )
            print("   ✅ Database manager initialized")
            
            # Initialize security system
            print("3. Initializing Security & Authentication System...")
            self.security_system = initialize_security_system(self.bridge)
            self.security_middleware = SecurityMiddleware(self.security_system)
            print("   ✅ Security system initialized")
            
            # Initialize file upload system
            print("4. Initializing Secure File Upload System...")
            self.file_uploader = SecureFileUploader(
                self.db_manager, 
                self.security_system, 
                self.config["storage"]["upload_root"]
            )
            print("   ✅ File upload system initialized")
            
            # Initialize monitoring and analytics
            print("5. Initializing System Monitoring...")
            self.initialize_monitoring()
            print("   ✅ Monitoring system initialized")
            
            self.is_running = True
            logger.info("🎉 All systems initialized successfully!")
            print("\n🎉 All systems initialized successfully!")
            
            # Display system summary
            self.display_initialization_summary()
            
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {str(e)}")
            print(f"❌ System initialization failed: {str(e)}")
            return False
    
    def initialize_monitoring(self):
        """Initialize system monitoring and analytics"""
        try:
            # Create monitoring directories
            monitoring_dirs = [
                "logs",
                "metrics",
                "analytics",
                "performance"
            ]
            
            for directory in monitoring_dirs:
                os.makedirs(directory, exist_ok=True)
            
            # Start performance monitoring thread
            if self.config["features"]["enable_analytics"]:
                monitoring_thread = threading.Thread(target=self.performance_monitor, daemon=True)
                monitoring_thread.start()
            
        except Exception as e:
            logger.warning(f"Failed to initialize monitoring: {str(e)}")
    
    def performance_monitor(self):
        """Background performance monitoring"""
        while self.is_running:
            try:
                # Collect system metrics
                current_time = time.time()
                
                # Update performance stats
                if self.performance_stats["last_operation_time"]:
                    response_time = current_time - self.performance_stats["last_operation_time"]
                    # Calculate rolling average
                    if self.performance_stats["average_response_time"] == 0:
                        self.performance_stats["average_response_time"] = response_time
                    else:
                        self.performance_stats["average_response_time"] = (
                            self.performance_stats["average_response_time"] * 0.9 + response_time * 0.1
                        )
                
                # Save metrics to file
                metrics = {
                    "timestamp": current_time,
                    "uptime": current_time - self.system_start_time,
                    "operations_count": self.performance_stats["operations_count"],
                    "errors_count": self.performance_stats["errors_count"],
                    "average_response_time": self.performance_stats["average_response_time"]
                }
                
                with open("metrics/system_metrics.json", "w") as f:
                    json.dump(metrics, f, indent=2)
                
                time.sleep(60)  # Update every minute
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {str(e)}")
                time.sleep(60)
    
    def display_initialization_summary(self):
        """Display system initialization summary"""
        print("\n📋 System Initialization Summary")
        print("=" * 40)
        
        # System status
        system_status = self.integrated_system.get_system_status() if self.integrated_system else {}
        print(f"🔗 C++ Node: {'✅ Connected' if system_status.get('cpp_node_connected') else '❌ Offline'}")
        print(f"🗄️ Database System: ✅ Ready")
        print(f"🔐 Security System: ✅ Active")
        print(f"📁 File Upload: ✅ Ready")
        
        # Configuration summary
        print(f"\n⚙️ Configuration:")
        print(f"   Storage Root: {self.config['storage']['database_root']}")
        print(f"   Security Mode: {'Enhanced' if self.config['security']['enable_file_scanning'] else 'Basic'}")
        print(f"   Features: {', '.join([k for k, v in self.config['features'].items() if v])}")
        
        # Quick stats
        databases = self.db_manager.list_databases()
        security_stats = self.security_system.get_security_stats()
        print(f"\n📊 Quick Stats:")
        print(f"   Databases: {len(databases)}")
        print(f"   Users: {security_stats.get('total_users', 0)}")
        print(f"   Uploads: {len(self.file_uploader.upload_chain)}")
    
    def authenticate_user(self) -> bool:
        """Authenticate user and create session"""
        try:
            print("\n🔐 User Authentication")
            print("=" * 30)
            print("💡 Default admin credentials: admin/admin")
            
            max_attempts = self.config["security"]["max_login_attempts"]
            for attempt in range(max_attempts):
                username = input("Username: ")
                password = getpass.getpass("Password: ")
                
                # Track operation start time
                operation_start = time.time()
                
                user, role = self.security_system.authenticate_user(username, password)
                
                # Update performance stats
                self.performance_stats["operations_count"] += 1
                self.performance_stats["last_operation_time"] = time.time()
                
                if user:
                    self.current_user = {"username": user, "role": role}
                    self.current_session = self.security_system.create_session(user)
                    
                    print(f"✅ Welcome, {user}! ({role})")
                    print(f"🕐 Session ID: {self.current_session[:16]}...")
                    
                    # Log successful authentication
                    self.security_system.add_security_block({
                        "action": "successful_login",
                        "username": user,
                        "timestamp": time.time(),
                        "session_id": self.current_session
                    })
                    
                    logger.info(f"User {user} authenticated successfully")
                    return True
                else:
                    remaining = max_attempts - attempt - 1
                    if remaining > 0:
                        print(f"❌ Authentication failed. {remaining} attempts remaining.")
                    else:
                        print("❌ Authentication failed. Access denied.")
                    
                    self.performance_stats["errors_count"] += 1
            
            return False
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            print(f"❌ Authentication error: {str(e)}")
            return False
    
    def show_main_menu(self):
        """Display and handle main menu"""
        while self.is_running and self.current_user:
            try:
                self.display_main_menu_header()
                
                choice = input("\nEnter your choice (1-12): ").strip()
                
                # Track operation
                operation_start = time.time()
                self.performance_stats["operations_count"] += 1
                
                if choice == "1":
                    self.show_comprehensive_system_status()
                elif choice == "2":
                    self.database_management_menu()
                elif choice == "3":
                    self.file_management_menu()
                elif choice == "4":
                    self.security_management_menu()
                elif choice == "5":
                    self.p2p_network_menu()
                elif choice == "6":
                    self.mining_operations_menu()
                elif choice == "7":
                    self.transaction_management_menu()
                elif choice == "8":
                    self.analytics_and_monitoring_menu()
                elif choice == "9":
                    self.system_administration_menu()
                elif choice == "10":
                    self.backup_and_recovery_menu()
                elif choice == "11":
                    self.system_configuration_menu()
                elif choice == "12":
                    self.logout()
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                    self.performance_stats["errors_count"] += 1
                
                # Update performance timing
                self.performance_stats["last_operation_time"] = time.time()
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                self.shutdown_system()
                break
            except Exception as e:
                logger.error(f"Menu error: {str(e)}")
                print(f"❌ An error occurred: {str(e)}")
                self.performance_stats["errors_count"] += 1
    
    def display_main_menu_header(self):
        """Display the main menu header with user info and quick stats"""
        uptime = time.time() - self.system_start_time
        uptime_str = f"{int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}"
        
        print(f"\n{'='*80}")
        print(f"🌟 INTEGRATED BLOCKCHAIN SYSTEM - {self.current_user['username']} ({self.current_user['role']})")
        print(f"{'='*80}")
        print(f"🕐 Uptime: {uptime_str} | 📊 Ops: {self.performance_stats['operations_count']} | ❌ Errors: {self.performance_stats['errors_count']}")
        print(f"{'='*80}")
        print("1. 📊 System Status & Analytics      7. 💰 Transaction Management")
        print("2. 🗄️ Database Management           8. 📈 Analytics & Monitoring")  
        print("3. 📁 File Upload & Management      9. ⚙️ System Administration")
        print("4. 🔐 Security Management          10. 💾 Backup & Recovery")
        print("5. 🔗 P2P Network Operations       11. 🛠️ System Configuration")
        print("6. ⛏️ Mining Operations            12. 🚪 Logout")
        print(f"{'='*80}")
    
    def show_comprehensive_system_status(self):
        """Display comprehensive system status and analytics"""
        print("\n📊 Comprehensive System Status & Analytics")
        print("=" * 60)
        
        try:
            # System overview
            uptime = time.time() - self.system_start_time
            print(f"🕐 System Uptime: {self.format_duration(uptime)}")
            print(f"⚡ Performance: {self.performance_stats['operations_count']} ops, {self.performance_stats['errors_count']} errors")
            
            # C++ Node Status
            print(f"\n🔗 C++ Blockchain Node:")
            cpp_status = self.bridge.get_node_status()
            if "error" not in cpp_status:
                data = cpp_status.get("data", {})
                print(f"   📦 Chain Height: {data.get('chainHeight', 'Unknown')}")
                print(f"   ⚡ Difficulty: {data.get('difficulty', 'Unknown')}")
                print(f"   📝 Mempool Size: {data.get('mempoolSize', 'Unknown')} transactions")
                print(f"   👥 Peer Count: {data.get('peerCount', 'Unknown')}")
                print(f"   💰 Total Supply: {data.get('totalSupply', 'Unknown')}")
                print(f"   🏆 Block Reward: {data.get('blockReward', 'Unknown')}")
                print(f"   ⏱️ Avg Block Time: {data.get('avgBlockTime', 'Unknown')}s")
            else:
                print(f"   ❌ Status: {cpp_status.get('error', 'Not available')}")
            
            # Database System Status
            print(f"\n🗄️ Database System:")
            databases = self.db_manager.list_databases()
            print(f"   📁 Total Databases: {len(databases)}")
            
            total_files = 0
            total_size = 0
            total_users = 0
            
            for db in databases:
                stats = self.db_manager.get_database_stats(db["name"])
                total_files += stats.get('total_files', 0)
                total_size += stats.get('total_size', 0)
                total_users += stats.get('users', 0)
            
            print(f"   📄 Total Files: {total_files}")
            print(f"   💾 Total Storage: {self.format_size(total_size)}")
            print(f"   👥 Total DB Users: {total_users}")
            
            # Show top 5 databases
            if databases:
                print(f"   📋 Recent Databases:")
                for i, db in enumerate(databases[:5], 1):
                    created = datetime.fromtimestamp(db["created_at"]).strftime("%Y-%m-%d %H:%M")
                    print(f"      {i}. {db['name']} (Owner: {db['owner']}, Created: {created})")
            
            # Security System Status
            print(f"\n🔐 Security System:")
            security_stats = self.security_system.get_security_stats()
            for key, value in security_stats.items():
                formatted_key = key.replace('_', ' ').title()
                if key == "chain_integrity":
                    status = "✅ Valid" if value else "❌ Compromised"
                    print(f"   {formatted_key}: {status}")
                elif key == "fallback_mode":
                    status = "🚨 Active" if value else "✅ Normal"
                    print(f"   {formatted_key}: {status}")
                else:
                    print(f"   {formatted_key}: {value}")
            
            # File Upload System Status
            print(f"\n📁 File Upload System:")
            total_uploads = len(self.file_uploader.upload_chain)
            approved = len([u for u in self.file_uploader.upload_chain if u.get("status") == "approved"])
            quarantined = len([u for u in self.file_uploader.upload_chain if u.get("status") == "quarantined"])
            
            print(f"   📤 Total Uploads: {total_uploads}")
            print(f"   ✅ Approved: {approved}")
            print(f"   🔒 Quarantined: {quarantined}")
            
            # Recent uploads
            if self.file_uploader.upload_chain:
                print(f"   📋 Recent Uploads:")
                recent_uploads = sorted(self.file_uploader.upload_chain, 
                                      key=lambda x: x.get("uploaded_at", 0), reverse=True)[:5]
                for i, upload in enumerate(recent_uploads, 1):
                    uploaded_time = datetime.fromtimestamp(upload.get("uploaded_at", 0)).strftime("%Y-%m-%d %H:%M")
                    status_icon = "✅" if upload.get("status") == "approved" else "🔒"
                    print(f"      {i}. {status_icon} {upload.get('original_name', 'Unknown')} ({uploaded_time})")
            
            # Network Status
            print(f"\n🌐 Network Status:")
            try:
                peers = self.bridge.get_peers()
                if "error" not in peers:
                    peer_data = peers.get("data", {}).get("peers", [])
                    connected_peers = len([p for p in peer_data if p.get("status") == "connected"])
                    print(f"   🔗 Connected Peers: {connected_peers}")
                    print(f"   📡 Total Known Peers: {len(peer_data)}")
                    
                    if peer_data:
                        print(f"   📋 Peer Status:")
                        for peer in peer_data[:3]:  # Show first 3 peers
                            status_icon = "✅" if peer.get("status") == "connected" else "🔄"
                            print(f"      {status_icon} {peer.get('ip')}:{peer.get('port')} ({peer.get('status')})")
                else:
                    print(f"   ❌ Network: {peers.get('error', 'Not available')}")
            except Exception as e:
                print(f"   ❌ Network: Error retrieving status")
            
            # System Health Check
            print(f"\n🏥 System Health Check:")
            health_score = self.calculate_system_health()
            health_status = "🟢 Excellent" if health_score >= 90 else "🟡 Good" if health_score >= 70 else "🟠 Fair" if health_score >= 50 else "🔴 Poor"
            print(f"   Overall Health: {health_status} ({health_score}%)")
            
            # Performance Metrics
            print(f"\n⚡ Performance Metrics:")
            avg_response = self.performance_stats.get("average_response_time", 0)
            print(f"   Average Response Time: {avg_response:.3f}s")
            print(f"   Operations/Hour: {self.performance_stats['operations_count'] / max(uptime/3600, 1):.1f}")
            error_rate = (self.performance_stats["errors_count"] / max(self.performance_stats["operations_count"], 1)) * 100
            print(f"   Error Rate: {error_rate:.2f}%")
            
        except Exception as e:
            print(f"❌ Error retrieving system status: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def calculate_system_health(self) -> int:
        """Calculate overall system health score (0-100)"""
        score = 100
        
        # Deduct points for errors
        if self.performance_stats["operations_count"] > 0:
            error_rate = (self.performance_stats["errors_count"] / self.performance_stats["operations_count"]) * 100
            score -= min(error_rate * 2, 30)  # Max 30 points deduction for errors
        
        # Check C++ node connectivity
        cpp_status = self.bridge.get_node_status()
        if "error" in cpp_status:
            score -= 20  # Deduct 20 points if C++ node is not available
        
        # Check security system
        security_stats = self.security_system.get_security_stats()
        if not security_stats.get("chain_integrity", True):
            score -= 25  # Major deduction for security issues
        
        if security_stats.get("fallback_mode", False):
            score -= 15  # Deduction for fallback mode
        
        # Check if there are locked users (potential security issue)
        locked_users = security_stats.get("locked_users", 0)
        if locked_users > 0:
            score -= min(locked_users * 5, 15)  # Deduct for locked users
        
        return max(0, min(100, int(score)))
    
    def database_management_menu(self):
        """Comprehensive database management menu"""
        while True:
            print("\n🗄️ Database Management System")
            print("=" * 40)
            print("1. 📋 List All Databases")
            print("2. 🏗️ Create New Database")
            print("3. 📊 Database Statistics")
            print("4. 🔍 Database Details & Schema")
            print("5. 👥 Manage Database Users")
            print("6. 🔒 Database Security & Permissions")
            print("7. 🔧 Database Maintenance")
            print("8. 💾 Export/Import Database")
            print("9. 🔎 Verify Database Integrity")
            print("10. 📈 Database Analytics")
            print("11. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-11): ").strip()
            
            if choice == "1":
                self.list_databases_detailed()
            elif choice == "2":
                self.create_database_wizard()
            elif choice == "3":
                self.show_database_statistics()
            elif choice == "4":
                self.show_database_details()
            elif choice == "5":
                self.manage_database_users()
            elif choice == "6":
                self.manage_database_security()
            elif choice == "7":
                self.database_maintenance_menu()
            elif choice == "8":
                self.database_export_import_menu()
            elif choice == "9":
                self.verify_database_integrity()
            elif choice == "10":
                self.show_database_analytics()
            elif choice == "11":
                break
            else:
                print("❌ Invalid choice.")
    
    def list_databases_detailed(self):
        """List all databases with detailed information"""
        try:
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if databases:
                print(f"\n📁 Available Databases ({len(databases)}):")
                print("-" * 80)
                print(f"{'#':<3} {'Name':<20} {'Owner':<15} {'Created':<17} {'Files':<8} {'Size':<10}")
                print("-" * 80)
                
                for i, db in enumerate(databases, 1):
                    stats = self.db_manager.get_database_stats(db["name"])
                    created_at = datetime.fromtimestamp(db["created_at"]).strftime("%Y-%m-%d %H:%M")
                    size_str = self.format_size(stats.get("total_size", 0))
                    
                    print(f"{i:<3} {db['name']:<20} {db['owner']:<15} {created_at:<17} "
                          f"{stats.get('total_files', 0):<8} {size_str:<10}")
                
                print("-" * 80)
                
                # Show detailed info for selected database
                try:
                    detail_choice = input("\nEnter database number for details (or Enter to skip): ").strip()
                    if detail_choice and detail_choice.isdigit():
                        db_index = int(detail_choice) - 1
                        if 0 <= db_index < len(databases):
                            self.show_single_database_details(databases[db_index])
                except (ValueError, IndexError):
                    pass
            else:
                print("\n📁 No databases available.")
                if self.current_user["role"] == "admin":
                    create_new = input("Would you like to create a new database? (y/n): ").lower()
                    if create_new == 'y':
                        self.create_database_wizard()
        except Exception as e:
            print(f"❌ Error listing databases: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def show_single_database_details(self, db_info):
        """Show detailed information for a single database"""
        print(f"\n📊 Database Details: {db_info['name']}")
        print("=" * 50)
        
        try:
            stats = self.db_manager.get_database_stats(db_info["name"])
            
            print(f"Name: {db_info['name']}")
            print(f"Owner: {db_info['owner']}")
            print(f"Created: {datetime.fromtimestamp(db_info['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Path: {db_info.get('path', 'Unknown')}")
            
            print(f"\n📊 Statistics:")
            print(f"  Files: {stats.get('total_files', 0)}")
            print(f"  Total Size: {self.format_size(stats.get('total_size', 0))}")
            print(f"  Users: {stats.get('users', 0)}")
            print(f"  Operations: {stats.get('operations', 0)}")
            
            if stats.get('last_activity'):
                last_activity = datetime.fromtimestamp(stats['last_activity']).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  Last Activity: {last_activity}")
            
            # Show schema if available
            if 'schema' in db_info and db_info['schema']:
                print(f"\n📋 Schema:")
                schema = db_info['schema']
                if 'tables' in schema:
                    for table_name, table_info in schema['tables'].items():
                        print(f"  Table: {table_name}")
                        if 'fields' in table_info:
                            for field_name, field_type in table_info['fields'].items():
                                print(f"    {field_name}: {field_type}")
            
            # Show recent files
            files = self.db_manager.list_database_files(db_info["name"], self.current_user["username"])
            if files:
                print(f"\n📄 Recent Files (showing last 5):")
                recent_files = sorted(files, key=lambda x: x.get("uploaded_at", 0), reverse=True)[:5]
                for i, file_info in enumerate(recent_files, 1):
                    uploaded_time = datetime.fromtimestamp(file_info.get("uploaded_at", 0)).strftime("%Y-%m-%d %H:%M")
                    size_str = self.format_size(file_info.get("size", 0))
                    print(f"  {i}. {file_info.get('original_name', 'Unknown')} ({size_str}) - {uploaded_time}")
        
        except Exception as e:
            print(f"❌ Error showing database details: {str(e)}")
    
    def create_database_wizard(self):
        """Interactive database creation wizard"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can create databases.")
            input("Press Enter to continue...")
            return
        
        print("\n🏗️ Database Creation Wizard")
        print("=" * 35)
        
        try:
            # Get database name
            while True:
                db_name = input("Database name: ").strip()
                if not db_name:
                    print("❌ Database name cannot be empty.")
                    continue
                
                # Check if database already exists
                existing_dbs = self.db_manager.list_databases()
                if any(db["name"] == db_name for db in existing_dbs):
                    print(f"❌ Database '{db_name}' already exists.")
                    continue
                
                break
            
            # Get database description
            description = input("Database description (optional): ").strip()
            
            # Schema creation options
            print(f"\n📋 Schema Creation Options:")
            print("1. Use predefined template")
            print("2. Create custom schema")
            print("3. Empty database (schema-less)")
            
            schema_choice = input("Choose option (1-3): ").strip()
            
            if schema_choice == "1":
                schema = self.choose_schema_template()
            elif schema_choice == "2":
                schema = self.create_custom_schema()
            else:
                schema = {"tables": {}, "description": description}
            
            # Confirm creation
            print(f"\n✅ Database Configuration:")
            print(f"  Name: {db_name}")
            print(f"  Owner: {self.current_user['username']}")
            print(f"  Description: {description or 'None'}")
            print(f"  Tables: {len(schema.get('tables', {}))}")
            
            confirm = input("\nCreate this database? (y/n): ").lower()
            if confirm == 'y':
                result = self.db_manager.create_database(db_name, schema, self.current_user["username"])
                if result:
                    print(f"✅ Database '{db_name}' created successfully!")
                    print(f"📁 Path: {result}")
                else:
                    print(f"❌ Failed to create database '{db_name}'")
            else:
                print("❌ Database creation cancelled.")
                
        except Exception as e:
            print(f"❌ Error creating database: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def choose_schema_template(self) -> Dict:
        """Choose from predefined schema templates"""
        templates = {
            "1": {
                "name": "Document Management",
                "schema": {
                    "tables": {
                        "documents": {
                            "fields": {
                                "id": "int",
                                "title": "string",
                                "content": "text",
                                "author": "string",
                                "created_at": "timestamp",
                                "updated_at": "timestamp",
                                "tags": "array"
                            }
                        },
                        "categories": {
                            "fields": {
                                "id": "int",
                                "name": "string",
                                "description": "text"
                            }
                        }
                    }
                }
            },
            "2": {
                "name": "User Management",
                "schema": {
                    "tables": {
                        "users": {
                            "fields": {
                                "id": "int",
                                "username": "string",
                                "email": "string",
                                "password_hash": "string",
                                "role": "string",
                                "created_at": "timestamp",
                                "last_login": "timestamp"
                            }
                        },
                        "user_profiles": {
                            "fields": {
                                "user_id": "int",
                                "first_name": "string",
                                "last_name": "string",
                                "bio": "text",
                                "avatar_url": "string"
                            }
                        }
                    }
                }
            },
            "3": {
                "name": "Asset Management",
                "schema": {
                    "tables": {
                        "assets": {
                            "fields": {
                                "id": "int",
                                "name": "string",
                                "type": "string",
                                "value": "decimal",
                                "owner": "string",
                                "created_at": "timestamp",
                                "metadata": "json"
                            }
                        },
                        "transactions": {
                            "fields": {
                                "id": "int",
                                "asset_id": "int",
                                "from_owner": "string",
                                "to_owner": "string",
                                "amount": "decimal",
                                "timestamp": "timestamp",
                                "tx_hash": "string"
                            }
                        }
                    }
                }
            }
        }
        
        print(f"\n📋 Available Templates:")
        for key, template in templates.items():
            print(f"{key}. {template['name']}")
        
        choice = input("Select template (1-3): ").strip()
        if choice in templates:
            return templates[choice]["schema"]
        else:
            print("❌ Invalid choice, using empty schema.")
            return {"tables": {}}
    
    def create_custom_schema(self) -> Dict:
        """Create a custom database schema interactively"""
        schema = {"tables": {}}
        
        print(f"\n🛠️ Custom Schema Builder")
        print("=" * 25)
        
        try:
            table_count = int(input("Number of tables to create: "))
            
            for i in range(table_count):
                print(f"\n📋 Table {i+1}:")
                table_name = input(f"Table name: ").strip()
                
                if not table_name:
                    print("❌ Table name cannot be empty, skipping.")
                    continue
                
                schema["tables"][table_name] = {"fields": {}}
                
                field_count = int(input(f"Number of fields in '{table_name}': "))
                
                for j in range(field_count):
                    field_name = input(f"  Field {j+1} name: ").strip()
                    if not field_name:
                        continue
                    
                    print(f"  Available types: string, int, float, decimal, bool, text, timestamp, json, array")
                    field_type = input(f"  Field '{field_name}' type: ").strip()
                    
                    if field_type not in ["string", "int", "float", "decimal", "bool", "text", "timestamp", "json", "array"]:
                        field_type = "string"  # Default fallback
                    
                    schema["tables"][table_name]["fields"][field_name] = field_type
                
                print(f"✅ Table '{table_name}' configured with {len(schema['tables'][table_name]['fields'])} fields.")
        
        except ValueError:
            print("❌ Invalid input, creating empty schema.")
        
        return schema
    
    # db manager
    # do not touch this part, it was hectic setting it up
    def manage_database_users(self):
        """Manage users across all databases"""
        while True:
            print("\n👥 Database User Management")
            print("=" * 35)
            print("1. 📋 View All Database Users")
            print("2. ➕ Add User to Database")
            print("3. ❌ Remove User from Database")
            print("4. 🔧 Modify User Permissions")
            print("5. 👤 View User Database Access")
            print("6. 📊 User Access Statistics")
            print("7. 🔒 Lock/Unlock Database Access")
            print("8. 📈 User Activity Report")
            print("9. 🔙 Back to Database Menu")
            
            choice = input("\nEnter your choice (1-9): ").strip()
            
            if choice == "1":
                self.view_all_database_users()
            elif choice == "2":
                self.add_user_to_database_wizard()
            elif choice == "3":
                self.remove_user_from_database()
            elif choice == "4":
                self.modify_user_permissions()
            elif choice == "5":
                self.view_user_database_access()
            elif choice == "6":
                self.show_user_access_statistics()
            elif choice == "7":
                self.lock_unlock_database_access()
            elif choice == "8":
                self.show_user_activity_report()
            elif choice == "9":
                break
            else:
                print("❌ Invalid choice.")

    def view_all_database_users(self):
        """View all users across all databases"""
        try:
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if not databases:
                print("\n📁 No databases available.")
                input("Press Enter to continue...")
                return
            
            print(f"\n👥 Database Users Overview")
            print("=" * 50)
            
            all_users = {}  # Track users across databases
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        db_users = users_data.get("users", {})
                        
                        print(f"\n📁 {db['name']} ({len(db_users)} users):")
                        print(f"   {'Username':<15} {'Role':<12} {'Permissions':<25} {'Added':<17}")
                        print(f"   {'-'*69}")
                        
                        for username, user_info in db_users.items():
                            role = user_info.get("role", "unknown")
                            permissions = ", ".join(user_info.get("permissions", []))[:24]
                            added_at = user_info.get("added_at", 0)
                            added_time = datetime.fromtimestamp(added_at).strftime("%Y-%m-%d %H:%M") if added_at else "Unknown"
                            
                            print(f"   {username:<15} {role:<12} {permissions:<25} {added_time:<17}")
                            
                            # Track user across databases
                            if username not in all_users:
                                all_users[username] = []
                            all_users[username].append({
                                "database": db["name"],
                                "role": role,
                                "permissions": user_info.get("permissions", []),
                                "added_at": added_at
                            })
                    
                    else:
                        print(f"\n📁 {db['name']}: No user data available")
                
                except Exception as e:
                    print(f"\n📁 {db['name']}: ❌ Error reading user data - {str(e)}")
            
            # Show user summary
            if all_users:
                print(f"\n📊 User Summary:")
                print(f"   Total unique users: {len(all_users)}")
                
                # Show users with access to multiple databases
                multi_db_users = {user: dbs for user, dbs in all_users.items() if len(dbs) > 1}
                if multi_db_users:
                    print(f"   Users with multi-database access: {len(multi_db_users)}")
                    for user, dbs in multi_db_users.items():
                        db_names = [db["database"] for db in dbs]
                        print(f"      {user}: {', '.join(db_names)}")
                
                # Show role distribution
                role_count = {}
                for user_dbs in all_users.values():
                    for db_access in user_dbs:
                        role = db_access["role"]
                        role_count[role] = role_count.get(role, 0) + 1
                
                print(f"   Role distribution:")
                for role, count in sorted(role_count.items()):
                    print(f"      {role}: {count}")
            
        except Exception as e:
            print(f"❌ Error viewing database users: {str(e)}")
        
        input("\nPress Enter to continue...")

    def add_user_to_database_wizard(self):
        """Wizard to add a user to a database"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can add users to databases.")
            input("Press Enter to continue...")
            return
        
        try:
            # Select database
            databases = self.db_manager.list_databases()
            
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            print(f"\n➕ Add User to Database")
            print("=" * 30)
            
            # Show available databases
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                print(f"  {i}. {db['name']} (Owner: {db['owner']})")
            
            # Select database
            while True:
                try:
                    db_choice = input(f"Select database (1-{len(databases)}): ").strip()
                    db_index = int(db_choice) - 1
                    if 0 <= db_index < len(databases):
                        selected_db = databases[db_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(databases)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            print(f"✅ Selected database: {selected_db['name']}")
            
            # Get username
            username = input("Username to add: ").strip()
            if not username:
                print("❌ Username cannot be empty.")
                input("Press Enter to continue...")
                return
            
            # Check if user already has access
            if self.db_manager.check_user_database_access(selected_db["name"], username):
                print(f"❌ User '{username}' already has access to database '{selected_db['name']}'")
                input("Press Enter to continue...")
                return
            
            # Select role
            print(f"\nAvailable roles:")
            roles = ["owner", "admin", "user", "readonly"]
            role_descriptions = {
                "owner": "Full control including deletion",
                "admin": "Administrative access (read, write, admin)",
                "user": "Standard user access (read, write)",
                "readonly": "Read-only access"
            }
            
            for i, role in enumerate(roles, 1):
                print(f"  {i}. {role} - {role_descriptions[role]}")
            
            while True:
                try:
                    role_choice = input(f"Select role (1-{len(roles)}): ").strip()
                    role_index = int(role_choice) - 1
                    if 0 <= role_index < len(roles):
                        selected_role = roles[role_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(roles)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            # Confirm addition
            print(f"\n📋 User Addition Summary:")
            print(f"   Database: {selected_db['name']}")
            print(f"   Username: {username}")
            print(f"   Role: {selected_role}")
            print(f"   Permissions: {', '.join(self.db_manager.get_role_permissions(selected_role))}")
            
            confirm = input("\nAdd this user? (y/n): ").lower()
            if confirm == 'y':
                success = self.db_manager.add_user_to_database(
                    selected_db["name"], 
                    username, 
                    selected_role, 
                    self.current_user["username"]
                )
                
                if success:
                    print(f"✅ User '{username}' added to database '{selected_db['name']}' with role '{selected_role}'")
                    
                    # Log the action
                    self.security_system.add_security_block({
                        "action": "user_added_to_database",
                        "database": selected_db["name"],
                        "username": username,
                        "role": selected_role,
                        "admin": self.current_user["username"],
                        "timestamp": time.time()
                    })
                else:
                    print(f"❌ Failed to add user '{username}' to database '{selected_db['name']}'")
            else:
                print("❌ User addition cancelled.")
        
        except Exception as e:
            print(f"❌ Error adding user to database: {str(e)}")
        
        input("\nPress Enter to continue...")

    def remove_user_from_database(self):
        """Remove a user from a database"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can remove users from databases.")
            input("Press Enter to continue...")
            return
        
        try:
            print(f"\n❌ Remove User from Database")
            print("=" * 35)
            
            # Get all databases with users
            databases = self.db_manager.list_databases()
            db_users = {}
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        users = users_data.get("users", {})
                        if users:
                            db_users[db["name"]] = users
                
                except Exception:
                    continue
            
            if not db_users:
                print("❌ No databases with users found.")
                input("Press Enter to continue...")
                return
            
            # Show databases and users
            print("Databases with users:")
            db_list = list(db_users.keys())
            
            for i, db_name in enumerate(db_list, 1):
                users = db_users[db_name]
                user_list = list(users.keys())
                print(f"  {i}. {db_name} ({len(user_list)} users): {', '.join(user_list)}")
            
            # Select database
            while True:
                try:
                    db_choice = input(f"Select database (1-{len(db_list)}): ").strip()
                    db_index = int(db_choice) - 1
                    if 0 <= db_index < len(db_list):
                        selected_db_name = db_list[db_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(db_list)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            # Show users in selected database
            users = db_users[selected_db_name]
            user_list = list(users.keys())
            
            print(f"\nUsers in database '{selected_db_name}':")
            for i, username in enumerate(user_list, 1):
                user_info = users[username]
                role = user_info.get("role", "unknown")
                print(f"  {i}. {username} ({role})")
            
            # Select user to remove
            while True:
                try:
                    user_choice = input(f"Select user to remove (1-{len(user_list)}): ").strip()
                    user_index = int(user_choice) - 1
                    if 0 <= user_index < len(user_list):
                        selected_username = user_list[user_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(user_list)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            # Check if trying to remove owner
            user_info = users[selected_username]
            if user_info.get("role") == "owner":
                print(f"❌ Cannot remove database owner '{selected_username}'")
                print("💡 Transfer ownership first or delete the database")
                input("Press Enter to continue...")
                return
            
            # Confirm removal
            print(f"\n⚠️  Remove User Confirmation:")
            print(f"   Database: {selected_db_name}")
            print(f"   Username: {selected_username}")
            print(f"   Role: {user_info.get('role', 'unknown')}")
            
            confirm = input("\nRemove this user? (y/n): ").lower()
            if confirm == 'y':
                try:
                    # Remove user from database
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", selected_db_name)
                    users_file = os.path.join(db_path, "users.json")
                    
                    with open(users_file, "r") as f:
                        users_data = json.load(f)
                    
                    if selected_username in users_data["users"]:
                        del users_data["users"][selected_username]
                        
                        with open(users_file, "w") as f:
                            json.dump(users_data, f, indent=2)
                        
                        print(f"✅ User '{selected_username}' removed from database '{selected_db_name}'")
                        
                        # Log the action
                        self.security_system.add_security_block({
                            "action": "user_removed_from_database",
                            "database": selected_db_name,
                            "username": selected_username,
                            "admin": self.current_user["username"],
                            "timestamp": time.time()
                        })
                    else:
                        print(f"❌ User '{selected_username}' not found in database")
                
                except Exception as e:
                    print(f"❌ Error removing user: {str(e)}")
            else:
                print("❌ User removal cancelled.")
        
        except Exception as e:
            print(f"❌ Error in remove user operation: {str(e)}")
        
        input("\nPress Enter to continue...")

    def modify_user_permissions(self):
        """Modify user permissions for a database"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can modify user permissions.")
            input("Press Enter to continue...")
            return
        
        try:
            print(f"\n🔧 Modify User Permissions")
            print("=" * 35)
            
            # Get databases with users (same logic as remove_user_from_database)
            databases = self.db_manager.list_databases()
            db_users = {}
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        users = users_data.get("users", {})
                        if users:
                            db_users[db["name"]] = users
                
                except Exception:
                    continue
            
            if not db_users:
                print("❌ No databases with users found.")
                input("Press Enter to continue...")
                return
            
            # Select database and user (similar to remove_user_from_database)
            print("Databases with users:")
            db_list = list(db_users.keys())
            
            for i, db_name in enumerate(db_list, 1):
                users = db_users[db_name]
                user_count = len(users)
                print(f"  {i}. {db_name} ({user_count} users)")
            
            # Select database
            while True:
                try:
                    db_choice = input(f"Select database (1-{len(db_list)}): ").strip()
                    db_index = int(db_choice) - 1
                    if 0 <= db_index < len(db_list):
                        selected_db_name = db_list[db_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(db_list)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            # Show users in selected database
            users = db_users[selected_db_name]
            user_list = list(users.keys())
            
            print(f"\nUsers in database '{selected_db_name}':")
            for i, username in enumerate(user_list, 1):
                user_info = users[username]
                role = user_info.get("role", "unknown")
                permissions = ", ".join(user_info.get("permissions", []))
                print(f"  {i}. {username} ({role}) - {permissions}")
            
            # Select user
            while True:
                try:
                    user_choice = input(f"Select user to modify (1-{len(user_list)}): ").strip()
                    user_index = int(user_choice) - 1
                    if 0 <= user_index < len(user_list):
                        selected_username = user_list[user_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(user_list)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            current_user_info = users[selected_username]
            current_role = current_user_info.get("role", "user")
            current_permissions = current_user_info.get("permissions", [])
            
            print(f"\nCurrent permissions for '{selected_username}':")
            print(f"   Role: {current_role}")
            print(f"   Permissions: {', '.join(current_permissions)}")
            
            # Select new role
            print(f"\nAvailable roles:")
            roles = ["owner", "admin", "user", "readonly"]
            role_descriptions = {
                "owner": "Full control including deletion",
                "admin": "Administrative access (read, write, admin)",
                "user": "Standard user access (read, write)",
                "readonly": "Read-only access"
            }
            
            for i, role in enumerate(roles, 1):
                indicator = " (current)" if role == current_role else ""
                print(f"  {i}. {role} - {role_descriptions[role]}{indicator}")
            
            while True:
                try:
                    role_choice = input(f"Select new role (1-{len(roles)}, or Enter to keep current): ").strip()
                    if not role_choice:
                        new_role = current_role
                        break
                    
                    role_index = int(role_choice) - 1
                    if 0 <= role_index < len(roles):
                        new_role = roles[role_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(roles)}")
                except ValueError:
                    print("❌ Please enter a valid number")
            
            new_permissions = self.db_manager.get_role_permissions(new_role)
            
            # Show changes
            print(f"\n📋 Permission Change Summary:")
            print(f"   Database: {selected_db_name}")
            print(f"   Username: {selected_username}")
            print(f"   Current Role: {current_role}")
            print(f"   New Role: {new_role}")
            print(f"   Current Permissions: {', '.join(current_permissions)}")
            print(f"   New Permissions: {', '.join(new_permissions)}")
            
            if new_role == current_role:
                print("   No changes will be made.")
                input("Press Enter to continue...")
                return
            
            # Confirm changes
            confirm = input("\nApply these changes? (y/n): ").lower()
            if confirm == 'y':
                try:
                    # Update user permissions
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", selected_db_name)
                    users_file = os.path.join(db_path, "users.json")
                    
                    with open(users_file, "r") as f:
                        users_data = json.load(f)
                    
                    if selected_username in users_data["users"]:
                        users_data["users"][selected_username]["role"] = new_role
                        users_data["users"][selected_username]["permissions"] = new_permissions
                        users_data["users"][selected_username]["modified_at"] = time.time()
                        users_data["users"][selected_username]["modified_by"] = self.current_user["username"]
                        
                        with open(users_file, "w") as f:
                            json.dump(users_data, f, indent=2)
                        
                        print(f"✅ Permissions updated for user '{selected_username}'")
                        
                        # Log the action
                        self.security_system.add_security_block({
                            "action": "user_permissions_modified",
                            "database": selected_db_name,
                            "username": selected_username,
                            "old_role": current_role,
                            "new_role": new_role,
                            "admin": self.current_user["username"],
                            "timestamp": time.time()
                        })
                    else:
                        print(f"❌ User '{selected_username}' not found in database")
                
                except Exception as e:
                    print(f"❌ Error updating permissions: {str(e)}")
            else:
                print("❌ Permission changes cancelled.")
        
        except Exception as e:
            print(f"❌ Error modifying user permissions: {str(e)}")
        
        input("\nPress Enter to continue...")

    def view_user_database_access(self):
        """View database access for a specific user"""
        try:
            print(f"\n👤 User Database Access Report")
            print("=" * 40)
            
            username = input("Enter username to check: ").strip()
            if not username:
                print("❌ Username cannot be empty.")
                input("Press Enter to continue...")
                return
            
            # Check across all databases
            databases = self.db_manager.list_databases()
            user_access = []
            
            for db in databases:
                try:
                    if self.db_manager.check_user_database_access(db["name"], username):
                        # Get detailed access info
                        db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                        users_file = os.path.join(db_path, "users.json")
                        
                        if os.path.exists(users_file):
                            with open(users_file, "r") as f:
                                users_data = json.load(f)
                            
                            if username in users_data.get("users", {}):
                                user_info = users_data["users"][username]
                                user_access.append({
                                    "database": db["name"],
                                    "owner": db["owner"],
                                    "role": user_info.get("role", "unknown"),
                                    "permissions": user_info.get("permissions", []),
                                    "added_at": user_info.get("added_at", 0),
                                    "added_by": user_info.get("added_by", "unknown")
                                })
                
                except Exception:
                    continue
            
            if user_access:
                print(f"✅ User '{username}' has access to {len(user_access)} database(s):")
                print("-" * 80)
                print(f"{'Database':<20} {'Role':<12} {'Permissions':<25} {'Added':<17}")
                print("-" * 80)
                
                for access in user_access:
                    permissions_str = ", ".join(access["permissions"])[:24]
                    added_time = datetime.fromtimestamp(access["added_at"]).strftime("%Y-%m-%d %H:%M") if access["added_at"] else "Unknown"
                    
                    print(f"{access['database']:<20} {access['role']:<12} {permissions_str:<25} {added_time:<17}")
                
                print("-" * 80)
                
                # Show summary statistics
                role_count = {}
                for access in user_access:
                    role = access["role"]
                    role_count[role] = role_count.get(role, 0) + 1
                
                print(f"\nAccess Summary:")
                print(f"   Total databases: {len(user_access)}")
                print(f"   Role distribution:")
                for role, count in sorted(role_count.items()):
                    print(f"      {role}: {count}")
            
            else:
                print(f"❌ User '{username}' has no database access.")
                
                # Check if user exists in security system
                if username in self.security_system.users:
                    print(f"💡 User '{username}' exists in the security system but has no database permissions.")
                    if self.current_user["role"] == "admin":
                        add_access = input("Would you like to add database access for this user? (y/n): ").lower()
                        if add_access == 'y':
                            self.add_user_to_database_wizard()
                else:
                    print(f"💡 User '{username}' does not exist in the security system.")
        
        except Exception as e:
            print(f"❌ Error viewing user database access: {str(e)}")
        
        input("\nPress Enter to continue...")

    def show_user_access_statistics(self):
        """Show statistics about user access across databases"""
        try:
            print(f"\n📊 User Access Statistics")
            print("=" * 35)
            
            databases = self.db_manager.list_databases()
            
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            # Collect all user access data
            all_users = {}
            total_access_grants = 0
            role_distribution = {}
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        db_users = users_data.get("users", {})
                        
                        for username, user_info in db_users.items():
                            if username not in all_users:
                                all_users[username] = {
                                    "databases": [],
                                    "roles": set(),
                                    "total_permissions": set()
                                }
                            
                            role = user_info.get("role", "unknown")
                            permissions = user_info.get("permissions", [])
                            
                            all_users[username]["databases"].append(db["name"])
                            all_users[username]["roles"].add(role)
                            all_users[username]["total_permissions"].update(permissions)
                            
                            # Count role distribution
                            role_distribution[role] = role_distribution.get(role, 0) + 1
                            total_access_grants += 1
                
                except Exception:
                    continue
            
            # Display statistics
            print(f"📊 Overall Statistics:")
            print(f"   Total databases: {len(databases)}")
            print(f"   Total unique users: {len(all_users)}")
            print(f"   Total access grants: {total_access_grants}")
            print(f"   Average users per database: {total_access_grants / max(1, len(databases)):.1f}")
            print(f"   Average database access per user: {total_access_grants / max(1, len(all_users)):.1f}")
            
            print(f"\n🎭 Role Distribution:")
            for role, count in sorted(role_distribution.items()):
                percentage = (count / max(1, total_access_grants)) * 100
                print(f"   {role}: {count} ({percentage:.1f}%)")
            
            # Multi-database users
            multi_db_users = {user: data for user, data in all_users.items() if len(data["databases"]) > 1}
            if multi_db_users:
                print(f"\n🔗 Multi-Database Users ({len(multi_db_users)}):")
                for user, data in sorted(multi_db_users.items(), key=lambda x: len(x[1]["databases"]), reverse=True):
                    db_count = len(data["databases"])
                    roles = ", ".join(data["roles"])
                    print(f"   {user}: {db_count} databases ({roles})")
            
            # Power users (users with admin/owner roles)
            power_users = {user: data for user, data in all_users.items() 
                          if any(role in ["admin", "owner"] for role in data["roles"])}
            if power_users:
                print(f"\n💪 Power Users ({len(power_users)}):")
                for user, data in power_users.items():
                    admin_roles = [role for role in data["roles"] if role in ["admin", "owner"]]
                    print(f"   {user}: {', '.join(admin_roles)} on {len(data['databases'])} database(s)")
            
            # Database access summary
            print(f"\n📁 Database Access Summary:")
            print(f"   {'Database':<20} {'Users':<8} {'Owners':<8} {'Admins':<8}")
            print(f"   {'-'*44}")
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        db_users = users_data.get("users", {})
                        total_users = len(db_users)
                        owners = len([u for u in db_users.values() if u.get("role") == "owner"])
                        admins = len([u for u in db_users.values() if u.get("role") == "admin"])
                        print(f"   {db['name']:<20} {total_users:<8} {owners:<8} {admins:<8}")
                    else:
                        print(f"   {db['name']:<20} {'0':<8} {'0':<8} {'0':<8}")
                except Exception:
                    print(f"   {db['name']:<20} {'Error':<8} {'Error':<8} {'Error':<8}")
           
            print(f"   {'-'*44}")
            
            # Permission analysis
            all_permissions = set()
            for user_data in all_users.values():
                all_permissions.update(user_data["total_permissions"])
            
            if all_permissions:
                print(f"\n🔐 Permission Analysis:")
                permission_count = {}
                for user_data in all_users.values():
                    for perm in user_data["total_permissions"]:
                        permission_count[perm] = permission_count.get(perm, 0) + 1
                
                print(f"   Most common permissions:")
                for perm, count in sorted(permission_count.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / max(1, len(all_users))) * 100
                    print(f"      {perm}: {count} users ({percentage:.1f}%)")
            
            # Security insights
            print(f"\n🛡️ Security Insights:")
            
            # Users with excessive permissions
            excessive_users = [user for user, data in all_users.items() 
                              if len(data["databases"]) > 3 or "owner" in data["roles"]]
            if excessive_users:
                print(f"   ⚠️  Users with extensive access: {len(excessive_users)}")
                print(f"      Review: {', '.join(excessive_users[:5])}")
                if len(excessive_users) > 5:
                    print(f"      ... and {len(excessive_users) - 5} more")
            
            # Orphaned databases (no active admins)
            orphaned_dbs = []
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        db_users = users_data.get("users", {})
                        has_admin = any(u.get("role") in ["owner", "admin"] for u in db_users.values())
                        
                        if not has_admin:
                            orphaned_dbs.append(db["name"])
                
                except Exception:
                    continue
            
            if orphaned_dbs:
                print(f"   🚨 Databases without admins: {len(orphaned_dbs)}")
                print(f"      {', '.join(orphaned_dbs)}")
            else:
                print(f"   ✅ All databases have administrative oversight")
            
            # Recommendations
            print(f"\n💡 Recommendations:")
            if len(multi_db_users) > len(all_users) * 0.3:
                print("   • Consider role consolidation for users with multiple database access")
            
            if total_access_grants > len(databases) * 5:
                print("   • Review access grants - high user-to-database ratio detected")
            
            if role_distribution.get("readonly", 0) < total_access_grants * 0.2:
                print("   • Consider more readonly access for better security")
            
            if not multi_db_users:
                print("   • Good: Users have focused database access")
            
            print("   • Regular access reviews recommended")
            print("   • Monitor for inactive users")
        
        except Exception as e:
            print(f"❌ Error generating user access statistics: {str(e)}")
        
        input("\nPress Enter to continue...")

    def lock_unlock_database_access(self):
        """Lock or unlock database access for users"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can lock/unlock database access.")
            input("Press Enter to continue...")
            return
        
        try:
            print(f"\n🔒 Lock/Unlock Database Access")
            print("=" * 40)
            
            print("1. Lock user database access")
            print("2. Unlock user database access")
            print("3. View locked users")
            
            choice = input("Select option (1-3): ").strip()
            
            if choice == "1":
                self.lock_user_database_access()
            elif choice == "2":
                self.unlock_user_database_access()
            elif choice == "3":
                self.view_locked_users()
            else:
                print("❌ Invalid choice.")
        
        except Exception as e:
            print(f"❌ Error in lock/unlock operation: {str(e)}")
        
        input("\nPress Enter to continue...")

    def lock_user_database_access(self):
        """Lock database access for a user"""
        try:
            username = input("Enter username to lock: ").strip()
            if not username:
                print("❌ Username cannot be empty.")
                return
            
            reason = input("Reason for locking (optional): ").strip()
            
            # Find all databases where user has access
            databases = self.db_manager.list_databases()
            user_databases = []
            
            for db in databases:
                if self.db_manager.check_user_database_access(db["name"], username):
                    user_databases.append(db["name"])
            
            if not user_databases:
                print(f"❌ User '{username}' has no database access to lock.")
                return
            
            print(f"\nUser '{username}' has access to {len(user_databases)} database(s):")
            for db_name in user_databases:
                print(f"   • {db_name}")
            
            confirm = input(f"\nLock access to all {len(user_databases)} database(s)? (y/n): ").lower()
            if confirm == 'y':
                locked_count = 0
                
                for db_name in user_databases:
                    try:
                        db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
                        users_file = os.path.join(db_path, "users.json")
                        
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        if username in users_data["users"]:
                            users_data["users"][username]["locked"] = True
                            users_data["users"][username]["locked_at"] = time.time()
                            users_data["users"][username]["locked_by"] = self.current_user["username"]
                            if reason:
                                users_data["users"][username]["lock_reason"] = reason
                            
                            with open(users_file, "w") as f:
                                json.dump(users_data, f, indent=2)
                            
                            locked_count += 1
                    
                    except Exception as e:
                        print(f"❌ Error locking access to {db_name}: {str(e)}")
                
                if locked_count > 0:
                    print(f"✅ Locked database access for '{username}' on {locked_count} database(s)")
                    
                    # Log the action
                    self.security_system.add_security_block({
                        "action": "database_access_locked",
                        "username": username,
                        "databases": user_databases,
                        "reason": reason,
                        "admin": self.current_user["username"],
                        "timestamp": time.time()
                    })
                else:
                    print(f"❌ Failed to lock database access for '{username}'")
            else:
                print("❌ Lock operation cancelled.")
        
        except Exception as e:
            print(f"❌ Error locking user access: {str(e)}")

    def unlock_user_database_access(self):
        """Unlock database access for a user"""
        try:
            username = input("Enter username to unlock: ").strip()
            if not username:
                print("❌ Username cannot be empty.")
                return
            
            # Find locked databases for user
            databases = self.db_manager.list_databases()
            locked_databases = []
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        if username in users_data.get("users", {}) and users_data["users"][username].get("locked", False):
                            locked_databases.append(db["name"])
                
                except Exception:
                    continue
            
            if not locked_databases:
                print(f"❌ User '{username}' has no locked database access.")
                return
            
            print(f"\nUser '{username}' has locked access to {len(locked_databases)} database(s):")
            for db_name in locked_databases:
                print(f"   • {db_name}")
            
            confirm = input(f"\nUnlock access to all {len(locked_databases)} database(s)? (y/n): ").lower()
            if confirm == 'y':
                unlocked_count = 0
                
                for db_name in locked_databases:
                    try:
                        db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
                        users_file = os.path.join(db_path, "users.json")
                        
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        if username in users_data["users"]:
                            users_data["users"][username]["locked"] = False
                            users_data["users"][username]["unlocked_at"] = time.time()
                            users_data["users"][username]["unlocked_by"] = self.current_user["username"]
                            
                            # Remove lock-related fields
                            users_data["users"][username].pop("lock_reason", None)
                            
                            with open(users_file, "w") as f:
                                json.dump(users_data, f, indent=2)
                            
                            unlocked_count += 1
                    
                    except Exception as e:
                        print(f"❌ Error unlocking access to {db_name}: {str(e)}")
                
                if unlocked_count > 0:
                    print(f"✅ Unlocked database access for '{username}' on {unlocked_count} database(s)")
                    
                    # Log the action
                    self.security_system.add_security_block({
                        "action": "database_access_unlocked",
                        "username": username,
                        "databases": locked_databases,
                        "admin": self.current_user["username"],
                        "timestamp": time.time()
                    })
                else:
                    print(f"❌ Failed to unlock database access for '{username}'")
            else:
                print("❌ Unlock operation cancelled.")
        
        except Exception as e:
            print(f"❌ Error unlocking user access: {str(e)}")

    def view_locked_users(self):
        """View all locked users across databases"""
        try:
            print(f"\n🔒 Locked Users Report")
            print("=" * 30)
            
            databases = self.db_manager.list_databases()
            locked_users = {}
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        for username, user_info in users_data.get("users", {}).items():
                            if user_info.get("locked", False):
                                if username not in locked_users:
                                    locked_users[username] = []
                                
                                locked_users[username].append({
                                    "database": db["name"],
                                    "locked_at": user_info.get("locked_at", 0),
                                    "locked_by": user_info.get("locked_by", "unknown"),
                                    "reason": user_info.get("lock_reason", "No reason provided")
                                })
                
                except Exception:
                    continue
            
            if locked_users:
                print(f"Found {len(locked_users)} locked user(s):\n")
                
                for username, locks in locked_users.items():
                    print(f"👤 {username} (locked on {len(locks)} database(s)):")
                    
                    for lock in locks:
                        locked_time = datetime.fromtimestamp(lock["locked_at"]).strftime("%Y-%m-%d %H:%M") if lock["locked_at"] else "Unknown"
                        print(f"   🔒 {lock['database']}")
                        print(f"      Locked: {locked_time} by {lock['locked_by']}")
                        print(f"      Reason: {lock['reason']}")
                    
                    print()  # Empty line between users
            else:
                print("✅ No locked users found.")
        
        except Exception as e:
            print(f"❌ Error viewing locked users: {str(e)}")

    def show_user_activity_report(self):
        """Show user activity report across databases"""
        try:
            print(f"\n📈 User Activity Report")
            print("=" * 30)
            
            print("🔄 Generating activity report...")
            print("(Note: This is a mock report - full implementation would track actual user activities)")
            
            # Mock activity data based on available users
            databases = self.db_manager.list_databases()
            all_users = set()
            
            for db in databases:
                try:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    users_file = os.path.join(db_path, "users.json")
                    
                    if os.path.exists(users_file):
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                        
                        all_users.update(users_data.get("users", {}).keys())
                
                except Exception:
                    continue
            
            if all_users:
                print(f"\n📊 Activity Summary (Last 30 Days):")
                print(f"   {'Username':<15} {'Logins':<8} {'DB Access':<10} {'Files':<8} {'Last Active':<17}")
                print(f"   {'-'*58}")
                
                for i, username in enumerate(sorted(all_users)):
                    # Mock data generation
                    logins = random.randint(1, 30) if username != "admin" else random.randint(10, 50)
                    db_accesses = random.randint(5, 100)
                    files_uploaded = random.randint(0, 20)
                    
                    # Mock last active time (within last 30 days)
                    days_ago = random.randint(0, 30)
                    last_active = time.time() - (days_ago * 24 * 3600)
                    last_active_str = datetime.fromtimestamp(last_active).strftime("%Y-%m-%d %H:%M")
                    
                    print(f"   {username:<15} {logins:<8} {db_accesses:<10} {files_uploaded:<8} {last_active_str:<17}")
                
                print(f"   {'-'*58}")
                
                # Activity insights
                print(f"\n🔍 Activity Insights:")
                print(f"   • Most active user: {max(all_users)} (mock)")
                print(f"   • Average logins per user: {random.randint(10, 25)}")
                print(f"   • Total database operations: {random.randint(500, 1500)}")
                print(f"   • Peak activity hours: 9-11 AM, 2-4 PM (mock)")
                
                # Inactive users
                inactive_threshold = 7  # days
                print(f"\n⚠️  Users inactive for >{inactive_threshold} days:")
                inactive_count = random.randint(0, max(1, len(all_users) // 3))
                if inactive_count > 0:
                    inactive_users = random.sample(list(all_users), min(inactive_count, len(all_users)))
                    for user in inactive_users:
                        days_inactive = random.randint(8, 30)
                        print(f"   • {user}: {days_inactive} days inactive")
                else:
                    print("   ✅ All users are active")
                
                # Security events
                print(f"\n🔐 Security Events (Last 30 Days):")
                print(f"   • Failed login attempts: {random.randint(5, 25)}")
                print(f"   • Password changes: {random.randint(2, 8)}")
                print(f"   • Permission changes: {random.randint(1, 5)}")
                print(f"   • Account lockouts: {random.randint(0, 3)}")
            
            else:
                print("❌ No user data available for activity report.")
        
        except Exception as e:
            print(f"❌ Error generating user activity report: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def show_database_details(self):
        """Show detailed information for a selected database"""
        try:
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
        
            if not databases:
                print("\n📁 No databases available.")
                input("Press Enter to continue...")
                return
        
        # Show database selection
            print(f"\n📊 Database Details - Select Database")
            print("=" * 45)
            print(f"{'#':<3} {'Name':<20} {'Owner':<15} {'Created':<17}")
            print("-" * 45)
        
            for i, db in enumerate(databases, 1):
                created_at = datetime.fromtimestamp(db["created_at"]).strftime("%Y-%m-%d %H:%M")
                print(f"{i:<3} {db['name']:<20} {db['owner']:<15} {created_at:<17}")
        
            print("-" * 45)
        
            # Get user selection
            while True:
                try:
                    choice = input(f"\nSelect database (1-{len(databases)}) or 'q' to quit: ").strip().lower()
                    if choice == 'q':
                        return
                
                    db_index = int(choice) - 1
                    if 0 <= db_index < len(databases):
                        selected_db = databases[db_index]
                        break
                    else:
                        print(f"❌ Please enter a number between 1 and {len(databases)}")
                except ValueError:
                    print("❌ Please enter a valid number or 'q' to quit")
        
        # Display detailed information
            print(f"\n📊 Detailed Information: {selected_db['name']}")
            print("=" * 60)
        
        # Basic Information
            print("📋 Basic Information:")
            print(f"   Name: {selected_db['name']}")
            print(f"   Owner: {selected_db['owner']}")
            print(f"   Created: {datetime.fromtimestamp(selected_db['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Path: {selected_db.get('path', 'Unknown')}")
        
        # Statistics
            stats = self.db_manager.get_database_stats(selected_db["name"])
            print(f"\n📊 Statistics:")
            print(f"   Total Files: {stats.get('total_files', 0)}")
            print(f"   Total Size: {self.format_size(stats.get('total_size', 0))}")
            print(f"   Users: {stats.get('users', 0)}")
            print(f"   Operations: {stats.get('operations', 0)}")
        
            if stats.get('created_at'):
                created_time = datetime.fromtimestamp(stats['created_at']).strftime('%Y-%m-%d %H:%M:%S')
                print(f"   Created: {created_time}")
        
            if stats.get('last_activity'):
                last_activity = datetime.fromtimestamp(stats['last_activity']).strftime('%Y-%m-%d %H:%M:%S')
                print(f"   Last Activity: {last_activity}")
        
            # Schema Information
            print(f"\n📋 Schema Information:")
            if 'schema' in selected_db and selected_db['schema']:
                schema = selected_db['schema']
            
                if schema.get('description'):
                    print(f"   Description: {schema['description']}")
            
                if 'tables' in schema and schema['tables']:
                    print(f"   Tables ({len(schema['tables'])}):")
                    for table_name, table_info in schema['tables'].items():
                        print(f"      📋 {table_name}")
                        if isinstance(table_info, dict) and 'fields' in table_info:
                            field_count = len(table_info['fields'])
                            print(f"         Fields: {field_count}")
                            for field_name, field_type in table_info['fields'].items():
                                print(f"           • {field_name}: {field_type}")
                        else:
                            print(f"         (No field information)")
                else:
                    print("   No tables defined")
            else:
                print("   No schema information available")
        
        # File Information
            try:
                files = self.db_manager.list_database_files(selected_db["name"], self.current_user["username"])
                print(f"\n📄 Files ({len(files)}):")
            
                if files:
                # Show summary
                    total_size = sum(f.get('size', 0) for f in files)
                    print(f"   Total Files: {len(files)}")
                    print(f"   Total Size: {self.format_size(total_size)}")
                
                # Show recent files (last 10)
                    recent_files = sorted(files, key=lambda x: x.get("uploaded_at", 0), reverse=True)[:10]
                    print(f"   Recent Files (showing last {min(10, len(files))}):")
                    print(f"   {'#':<3} {'Filename':<25} {'Size':<10} {'Uploaded':<17} {'By':<12}")
                    print(f"   {'-'*67}")
                
                    for i, file_info in enumerate(recent_files, 1):
                        filename = file_info.get('original_name', 'Unknown')
                        if len(filename) > 24:
                            filename = filename[:21] + "..."
                    
                        size_str = self.format_size(file_info.get('size', 0))
                        uploaded_time = datetime.fromtimestamp(file_info.get('uploaded_at', 0)).strftime('%Y-%m-%d %H:%M')
                        uploaded_by = file_info.get('uploaded_by', 'Unknown')
                        if len(uploaded_by) > 11:
                            uploaded_by = uploaded_by[:8] + "..."
                    
                        print(f"   {i:<3} {filename:<25} {size_str:<10} {uploaded_time:<17} {uploaded_by:<12}")
                
                    if len(files) > 10:
                        print(f"   ... and {len(files) - 10} more files")
                else:
                    print("   No files uploaded yet")
        
            except Exception as e:
                print(f"   ❌ Error retrieving file information: {str(e)}")
        
        # User Access Information
            try:
                print(f"\n👥 User Access:")
            # This would require a method to get database users
            # For now, show basic info
                print(f"   Owner: {selected_db['owner']} (Full Access)")
                if self.current_user["role"] == "admin":
                    print("   Admin: Full administrative access")
                print("   💡 Use 'Manage Database Users' for detailed user management")
        
            except Exception as e:
                print(f"   ❌ Error retrieving user information: {str(e)}")
        
        # Integrity Check
            print(f"\n🔍 Integrity Check:")
            try:
                integrity = self.db_manager.verify_database_integrity(selected_db["name"])
                if integrity.get('valid', False):
                    print("   ✅ Database integrity: Valid")
                    print(f"   📁 Files checked: {integrity.get('checked_files', 0)}")
                    if integrity.get('issues'):
                        print(f"   ⚠️  Minor issues: {len(integrity['issues'])}")
                else:
                    print("   ❌ Database integrity: Issues found")
                    print(f"   🔍 Files checked: {integrity.get('checked_files', 0)}")
                    print(f"   ❌ Corrupted files: {integrity.get('corrupted_files', 0)}")
                    print(f"   📁 Missing files: {integrity.get('missing_files', 0)}")
                
                    if integrity.get('issues'):
                        print("   Issues:")
                        for issue in integrity['issues'][:5]:  # Show first 5 issues
                            print(f"      • {issue}")
                        if len(integrity['issues']) > 5:
                            print(f"      ... and {len(integrity['issues']) - 5} more issues")
        
            except Exception as e:
                print(f"   ❌ Error checking integrity: {str(e)}")
        
        # Action options
            print(f"\n🔧 Available Actions:")
            print("1. Export database")
            print("2. Verify integrity (detailed)")
            print("3. View all files")
            print("4. Manage users")
            print("5. Back to database menu")
        
            action = input("Select action (1-5, or Enter to continue): ").strip()
        
            if action == "1":
                self.export_single_database(selected_db)
            elif action == "2":
                self.verify_single_database_integrity(selected_db)
            elif action == "3":
                self.view_database_files_detailed(selected_db)
            elif action == "4":
                self.manage_single_database_users(selected_db)
        # Option 5 or Enter will just continue to the end
        
        except Exception as e:
            print(f"❌ Error showing database details: {str(e)}")
    
    input("\nPress Enter to continue...")
    
    #manage db users
        
    
    # file management
    def file_management_menu(self):
        """Comprehensive file management menu"""
        while True:
            print("\n📁 File Upload & Management System")
            print("=" * 45)
            print("1. 📤 Upload Files (GUI)")
            print("2. 📝 Upload Files (CLI)")
            print("3. 📋 View My Uploads")
            print("4. 👀 View All Uploads (Admin)")
            print("5. 🔒 Manage Quarantined Files")
            print("6. 📊 File Statistics & Analytics")
            print("7. 🔍 Search Files")
            print("8. 📥 Download Files")
            print("9. 🗑️ Delete Files")
            print("10. 🔧 File System Maintenance")
            print("11. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-11): ").strip()
            
            if choice == "1":
                self.launch_upload_gui()
            elif choice == "2":
                self.upload_files_cli()
            elif choice == "3":
                self.view_my_uploads()
            elif choice == "4":
                self.view_all_uploads()
            elif choice == "5":
                self.manage_quarantined_files()
            elif choice == "6":
                self.show_file_statistics()
            elif choice == "7":
                self.search_files()
            elif choice == "8":
                self.download_files()
            elif choice == "9":
                self.delete_files()
            elif choice == "10":
                self.file_maintenance_menu()
            elif choice == "11":
                break
            else:
                print("❌ Invalid choice.")
    
    def launch_upload_gui(self):
        """Launch the file upload GUI"""
        try:
            print("🚀 Launching File Upload GUI...")
            gui = create_upload_interface(
                self.db_manager, 
                self.security_system, 
                self.current_user["username"], 
                self.current_user["role"]
            )
            if gui:
                gui.show()
            else:
                print("📱 GUI interface launched (mock mode)")
        except Exception as e:
            print(f"❌ Error launching GUI: {str(e)}")
        
        input("Press Enter to continue...")
    
    def upload_files_cli(self):
        """Command-line file upload interface"""
        print("\n📤 File Upload (CLI)")
        print("=" * 25)
        
        try:
            # Select target database
            databases = self.db_manager.list_databases(self.current_user["username"], self.current_user["role"])
            
            if not databases:
                print("❌ No databases available. Create a database first.")
                input("Press Enter to continue...")
                return
            
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                print(f"  {i}. {db['name']} (Owner: {db['owner']})")
            
            db_choice = input("Select database number (or Enter for no database): ").strip()
            target_db = None
            
            if db_choice and db_choice.isdigit():
                db_index = int(db_choice) - 1
                if 0 <= db_index < len(databases):
                    target_db = databases[db_index]["name"]
                    print(f"✅ Selected database: {target_db}")
            
            # Get file paths
            print("\nEnter file paths to upload (one per line, empty line to finish):")
            file_paths = []
            while True:
                file_path = input("File path: ").strip()
                if not file_path:
                    break
                
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    file_paths.append(file_path)
                    print(f"✅ Added: {os.path.basename(file_path)}")
                else:
                    print(f"❌ File not found: {file_path}")
            
            if not file_paths:
                print("❌ No valid files to upload.")
                input("Press Enter to continue...")
                return
            
            # Upload files
            print(f"\n📤 Uploading {len(file_paths)} files...")
            successful_uploads = 0
            
            for file_path in file_paths:
                try:
                    result = self.file_uploader.upload_file(
                        file_path,
                        self.current_user["username"],
                        target_db,
                        {"cli_upload": True, "timestamp": time.time()}
                    )
                    
                    if result["success"]:
                        status = result["status"].upper()
                        filename = os.path.basename(file_path)
                        print(f"✅ {filename}: {status}")
                        
                        if result["threats"]:
                            print(f"   ⚠️ Threats detected: {', '.join(result['threats'])}")
                        
                        successful_uploads += 1
                    else:
                        print(f"❌ {os.path.basename(file_path)}: {result.get('error', 'Upload failed')}")
                
                except Exception as e:
                    print(f"❌ {os.path.basename(file_path)}: Error - {str(e)}")
            
            print(f"\n🎉 Upload complete! {successful_uploads}/{len(file_paths)} files uploaded successfully.")
        
        except Exception as e:
            print(f"❌ Upload error: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def view_my_uploads(self):
        """View current user's uploads with detailed information"""
        try:
            uploads = self.file_uploader.get_user_uploads(self.current_user["username"])
            
            if uploads:
                print(f"\n📁 Your Uploads ({len(uploads)}):")
                print("-" * 90)
                print(f"{'#':<3} {'Filename':<25} {'Status':<12} {'Size':<10} {'Database':<15} {'Uploaded':<17}")
                print("-" * 90)
                
                for i, upload in enumerate(uploads, 1):
                    filename = upload.get("original_name", "Unknown")[:24]
                    status = upload.get("status", "unknown")
                    
                    # Status with icon
                    if status == "approved":
                        status_display = "✅ Approved"
                    elif status == "quarantined":
                        status_display = "🔒 Quarantined"
                    elif status == "pending":
                        status_display = "⏳ Pending"
                    else:
                        status_display = f"❓ {status}"
                    
                    # Get file size from metadata
                    metadata = upload.get("metadata", {})
                    size = metadata.get("size", 0) if metadata else 0
                    size_display = self.format_size(size)
                    
                    database = upload.get("database", "None")[:14]
                    uploaded_time = datetime.fromtimestamp(upload.get("uploaded_at", 0)).strftime("%Y-%m-%d %H:%M")
                    
                    print(f"{i:<3} {filename:<25} {status_display:<12} {size_display:<10} {database:<15} {uploaded_time:<17}")
                
                print("-" * 90)
                
                # Show threats if any
                quarantined_uploads = [u for u in uploads if u.get("status") == "quarantined"]
                if quarantined_uploads:
                    print(f"\n⚠️ Quarantined Files ({len(quarantined_uploads)}):")
                    for upload in quarantined_uploads:
                        threats = upload.get("threats", [])
                        if threats:
                            print(f"  🔒 {upload.get('original_name', 'Unknown')}: {', '.join(threats)}")
                
                # Interactive options
                print(f"\nOptions:")
                print("1. View upload details")
                print("2. Request file approval (if quarantined)")
                print("3. Delete upload")
                print("4. Download file")
                
                option = input("Select option (1-4, or Enter to skip): ").strip()
                
                if option == "1":
                    self.view_upload_details(uploads)
                elif option == "2":
                    self.request_file_approval(uploads)
                elif option == "3":
                    self.delete_user_upload(uploads)
                elif option == "4":
                    self.download_user_file(uploads)
            
            else:
                print("\n📁 No uploads found.")
                print("💡 Use the upload options to add files to the system.")
        
        except Exception as e:
            print(f"❌ Error viewing uploads: {str(e)}")
        
        input("\nPress Enter to continue...")
    
    def format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds//60)}m {int(seconds%60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}PB"
    
    def logout(self):
        """Logout current user and cleanup session"""
        try:
            # Log the logout event
            if self.current_session:
                self.security_system.add_security_block({
                    "action": "logout",
                    "username": self.current_user["username"],
                    "session_id": self.current_session,
                    "timestamp": time.time()
                })
            
            print(f"👋 Goodbye, {self.current_user['username']}!")
            
            # Clear user session
            self.current_user = None
            self.current_session = None
            
            # Save final metrics
            self.save_session_metrics()
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
    
    def save_session_metrics(self):
        """Save session performance metrics"""
        try:
            session_data = {
                "username": self.current_user["username"] if self.current_user else "unknown",
                "session_duration": time.time() - self.system_start_time,
                "operations_count": self.performance_stats["operations_count"],
                "errors_count": self.performance_stats["errors_count"],
                "average_response_time": self.performance_stats["average_response_time"],
                "timestamp": time.time()
            }
            
            # Append to metrics file
            metrics_file = "metrics/session_metrics.json"
            if os.path.exists(metrics_file):
                with open(metrics_file, "r") as f:
                    metrics = json.load(f)
            else:
                metrics = []
            
            metrics.append(session_data)
            
            # Keep only last 100 sessions
            if len(metrics) > 100:
                metrics = metrics[-100:]
            
            with open(metrics_file, "w") as f:
                json.dump(metrics, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to save session metrics: {str(e)}")
    
    def shutdown_system(self):
        """Shutdown the entire system gracefully"""
        print("\n🛑 Shutting down system...")
        
        try:
            # Save final state
            self.save_session_metrics()
            
            # Stop integrated system
            if self.integrated_system:
                self.integrated_system.stop_system()
            
            # Set system as not running
            self.is_running = False
            
            print("✅ System shutdown complete.")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")
            print(f"❌ Error during shutdown: {str(e)}")
    
    def run(self):
        """Main entry point to run the system"""
        print("🌟 Welcome to the Integrated Blockchain System!")
        print("=" * 60)
        print("🚀 Advanced Blockchain • 🗄️ Database Management • 🔐 Security")
        print("📁 File Upload • 🌐 P2P Network • ⛏️ Mining • 📈 Analytics")
        print("=" * 60)
        
        # Initialize system
        if not self.initialize_system():
            print("❌ System initialization failed. Exiting.")
            return False
        
        # Authenticate user
        if not self.authenticate_user():
            print("❌ Authentication failed. Exiting.")
            self.shutdown_system()
            return False
        
        try:
            # Show main menu
            self.show_main_menu()
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
        finally:
            self.shutdown_system()
        
        return True

    # Additional comprehensive menu implementations
    def security_management_menu(self):
        """Comprehensive security management menu"""
        while True:
            print("\n🔐 Security Management System")
            print("=" * 40)
            print("1. 📊 Security Dashboard")
            print("2. 👥 User Management")
            print("3. 🔑 Session Management")
            print("4. 🚨 Security Alerts")
            print("5. 🔒 Access Control")
            print("6. 📜 Security Audit Log")
            print("7. 🛡️ System Security Scan")
            print("8. 💾 Security Backup")
            print("9. ⚙️ Security Settings")
            print("10. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-10): ").strip()
            
            if choice == "1":
                self.show_security_dashboard()
            elif choice == "2":
                self.user_management_menu()
            elif choice == "3":
                self.session_management_menu()
            elif choice == "4":
                self.view_security_alerts()
            elif choice == "5":
                self.access_control_menu()
            elif choice == "6":
                self.view_security_audit_log()
            elif choice == "7":
                self.run_security_scan()
            elif choice == "8":
                self.create_security_backup()
            elif choice == "9":
                self.security_settings_menu()
            elif choice == "10":
                break
            else:
                print("❌ Invalid choice.")

    def show_security_dashboard(self):
        """Display comprehensive security dashboard"""
        print("\n🔐 Security Dashboard")
        print("=" * 30)
        
        try:
            stats = self.security_system.get_security_stats()
            
            # Security Overview
            print("📊 Security Overview:")
            chain_status = "✅ Secure" if stats.get("chain_integrity", True) else "🚨 Compromised"
            print(f"   Chain Integrity: {chain_status}")
            
            fallback_status = "🚨 Active" if stats.get("fallback_mode", False) else "✅ Normal"
            print(f"   System Mode: {fallback_status}")
            
            print(f"   Total Users: {stats.get('total_users', 0)}")
            print(f"   Active Sessions: {stats.get('active_sessions', 0)}")
            print(f"   Locked Users: {stats.get('locked_users', 0)}")
            print(f"   Security Operations: {stats.get('security_operations', 0)}")
            print(f"   Alert Count: {stats.get('security_alerts', 0)}")
            
            # Recent Security Events
            print(f"\n📜 Recent Security Events:")
            print("   [Mock] User admin logged in from 192.168.1.100")
            print("   [Mock] Failed login attempt for user 'hacker'")
            print("   [Mock] File upload quarantined due to suspicious content")
            print("   [Mock] Security scan completed - no issues found")
            print("   [Mock] Backup created successfully")
            
            # Security Recommendations
            print(f"\n💡 Security Recommendations:")
            if stats.get("locked_users", 0) > 0:
                print("   🔓 Review and unlock legitimate user accounts")
            
            if stats.get("active_sessions", 0) > 10:
                print("   ⏰ Consider reducing session timeout for better security")
            
            if not self.config["security"]["require_2fa"]:
                print("   🔐 Enable two-factor authentication for enhanced security")
            
            print("   🔄 Regular security audits recommended")
            print("   💾 Ensure regular security backups")
            
        except Exception as e:
            print(f"❌ Error displaying security dashboard: {str(e)}")
        
        input("\nPress Enter to continue...")

    def p2p_network_menu(self):
        """P2P network operations menu"""
        while True:
            print("\n🔗 P2P Network Operations")
            print("=" * 35)
            print("1. 🌐 Network Status")
            print("2. 👥 Peer Management")
            print("3. 🔍 Discover Peers")
            print("4. 📡 Connect to Peer")
            print("5. 🚫 Disconnect Peer")
            print("6. 📊 Network Statistics")
            print("7. 🔧 Network Configuration")
            print("8. 📈 Network Analytics")
            print("9. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-9): ").strip()
            
            if choice == "1":
                self.show_network_status()
            elif choice == "2":
                self.peer_management_menu()
            elif choice == "3":
                self.discover_peers()
            elif choice == "4":
                self.connect_to_peer()
            elif choice == "5":
                self.disconnect_peer()
            elif choice == "6":
                self.show_network_statistics()
            elif choice == "7":
                self.network_configuration_menu()
            elif choice == "8":
                self.show_network_analytics()
            elif choice == "9":
                break
            else:
                print("❌ Invalid choice.")

    def show_network_status(self):
        """Display comprehensive network status"""
        print("\n🌐 Network Status")
        print("=" * 20)
        
        try:
            peers_result = self.bridge.get_peers()
            
            if "error" not in peers_result:
                peer_data = peers_result.get("data", {}).get("peers", [])
                
                print(f"📡 Network Overview:")
                connected_peers = [p for p in peer_data if p.get("status") == "connected"]
                connecting_peers = [p for p in peer_data if p.get("status") == "connecting"]
                failed_peers = [p for p in peer_data if p.get("status") == "failed"]
                
                print(f"   Connected Peers: {len(connected_peers)}")
                print(f"   Connecting Peers: {len(connecting_peers)}")
                print(f"   Failed Connections: {len(failed_peers)}")
                print(f"   Total Known Peers: {len(peer_data)}")
                
                if peer_data:
                    print(f"\n👥 Peer Details:")
                    print("-" * 60)
                    print(f"{'IP Address':<18} {'Port':<8} {'Status':<12} {'Ping':<8}")
                    print("-" * 60)
                    
                    for peer in peer_data:
                        ip = peer.get("ip", "Unknown")
                        port = peer.get("port", "Unknown")
                        status = peer.get("status", "Unknown")
                        
                        # Mock ping data
                        ping = f"{20 + hash(ip) % 80}ms" if status == "connected" else "N/A"
                        
                        status_icon = "✅" if status == "connected" else "🔄" if status == "connecting" else "❌"
                        status_display = f"{status_icon} {status}"
                        
                        print(f"{ip:<18} {port:<8} {status_display:<12} {ping:<8}")
                    
                    print("-" * 60)
                
                # Network health
                health_score = min(100, (len(connected_peers) / max(1, len(peer_data))) * 100)
                health_status = "🟢 Excellent" if health_score >= 90 else "🟡 Good" if health_score >= 70 else "🟠 Fair" if health_score >= 50 else "🔴 Poor"
                print(f"\n🏥 Network Health: {health_status} ({health_score:.1f}%)")
                
            else:
                print(f"❌ Network Status: {peers_result.get('error', 'Unknown error')}")
                print("🔧 Check if the C++ blockchain node is running")
        
        except Exception as e:
            print(f"❌ Error retrieving network status: {str(e)}")
        
        input("\nPress Enter to continue...")

    def mining_operations_menu(self):
        """Comprehensive mining operations menu"""
        while True:
            print("\n⛏️ Mining Operations Center")
            print("=" * 35)
            print("1. 🏃 Start Mining")
            print("2. ⏹️ Stop Mining")
            print("3. 📊 Mining Dashboard")
            print("4. ⚙️ Mining Configuration")
            print("5. 📈 Mining Statistics")
            print("6. 🏆 Mining History")
            print("7. 💰 Rewards & Earnings")
            print("8. 🔧 Mining Hardware Status")
            print("9. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-9): ").strip()
            
            if choice == "1":
                self.start_mining()
            elif choice == "2":
                self.stop_mining()
            elif choice == "3":
                self.show_mining_dashboard()
            elif choice == "4":
                self.mining_configuration_menu()
            elif choice == "5":
                self.show_mining_statistics()
            elif choice == "6":
                self.show_mining_history()
            elif choice == "7":
                self.show_mining_rewards()
            elif choice == "8":
                self.show_mining_hardware_status()
            elif choice == "9":
                break
            else:
                print("❌ Invalid choice.")

    def start_mining(self):
        """Start mining operation"""
        print("\n⛏️ Start Mining Operation")
        print("=" * 30)
        
        try:
            # Get miner configuration
            miner_address = input("Enter miner address (or press Enter for default): ").strip()
            if not miner_address:
                miner_address = f"miner_{self.current_user['username']}_{int(time.time())}"
                print(f"Using default address: {miner_address}")
            
            # Mining configuration options
            print(f"\n⚙️ Mining Configuration:")
            print("1. Single block mining")
            print("2. Continuous mining")
            
            mining_mode = input("Select mining mode (1-2): ").strip()
            
            if mining_mode == "1":
                # Single block mining
                print(f"\n⛏️ Mining single block...")
                print("🔄 This may take a while depending on difficulty...")
                
                result = self.bridge.mine_block(miner_address)
                
                if "error" not in result:
                    print("✅ Block mined successfully!")
                    
                    block_data = result.get("data", {}).get("block", {})
                    print(f"\n🎉 Mining Success:")
                    print(f"   Block Index: {block_data.get('index', 'Unknown')}")
                    print(f"   Block Hash: {block_data.get('hash', 'Unknown')}")
                    print(f"   Reward: {block_data.get('reward', 'Unknown')} coins")
                    print(f"   Miner: {block_data.get('miner', miner_address)}")
                    
                    # Log mining success
                    self.security_system.add_security_block({
                        "action": "block_mined",
                        "miner": miner_address,
                        "block_index": block_data.get('index'),
                        "reward": block_data.get('reward'),
                        "timestamp": time.time()
                    })
                    
                else:
                    print(f"❌ Mining failed: {result['error']}")
            
            elif mining_mode == "2":
                print("🔄 Continuous mining mode not implemented in this demo.")
                print("💡 This would start a background mining process.")
            
        except Exception as e:
            print(f"❌ Mining operation error: {str(e)}")
        
        input("\nPress Enter to continue...")

    def transaction_management_menu(self):
        """Comprehensive transaction management menu"""
        while True:
            print("\n💰 Transaction Management Center")
            print("=" * 40)
            print("1. 💸 Create Transaction")
            print("2. 📋 Transaction History")
            print("3. 🔍 Search Transactions")
            print("4. ⏳ Pending Transactions")
            print("5. 📊 Transaction Statistics")
            print("6. 🔗 Transaction Details")
            print("7. 💳 Wallet Operations")
            print("8. 📈 Transaction Analytics")
            print("9. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-9): ").strip()
            
            if choice == "1":
                self.create_transaction_wizard()
            elif choice == "2":
                self.show_transaction_history()
            elif choice == "3":
                self.search_transactions()
            elif choice == "4":
                self.show_pending_transactions()
            elif choice == "5":
                self.show_transaction_statistics()
            elif choice == "6":
                self.show_transaction_details()
            elif choice == "7":
                self.wallet_operations_menu()
            elif choice == "8":
                self.show_transaction_analytics()
            elif choice == "9":
                break
            else:
                print("❌ Invalid choice.")

    def create_transaction_wizard(self):
        """Interactive transaction creation wizard"""
        print("\n💸 Transaction Creation Wizard")
        print("=" * 40)
        
        try:
            # Get transaction details
            print("📝 Transaction Details:")
            from_addr = input("From address: ").strip()
            to_addr = input("To address: ").strip()
            
            if not from_addr or not to_addr:
                print("❌ Both addresses are required.")
                input("Press Enter to continue...")
                return
            
            # Get amount with validation
            while True:
                try:
                    amount_str = input("Amount: ").strip()
                    amount = float(amount_str)
                    if amount <= 0:
                        print("❌ Amount must be positive.")
                        continue
                    break
                except ValueError:
                    print("❌ Invalid amount format.")
            
            # Add transaction metadata
            add_metadata = input("Add metadata? (y/n): ").lower()
            metadata = {}
            if add_metadata == 'y':
                description = input("Description (optional): ").strip()
                if description:
                    metadata["description"] = description
                
                category = input("Category (optional): ").strip()
                if category:
                    metadata["category"] = category
            
            # Transaction summary
            print(f"\n📋 Transaction Summary:")
            print(f"   From: {from_addr}")
            print(f"   To: {to_addr}")
            print(f"   Amount: {amount}")
            if metadata:
                print(f"   Metadata: {metadata}")
            
            # Confirm transaction
            confirm = input("\nCreate this transaction? (y/n): ").lower()
            if confirm == 'y':
                print("🔄 Creating transaction...")
                
                result = self.bridge.create_transaction(from_addr, to_addr, amount)
                
                if "error" not in result:
                    print("✅ Transaction created successfully!")
                    
                    tx_data = result.get("data", {}).get("transaction", {})
                    print(f"\n🎉 Transaction Details:")
                    print(f"   Transaction ID: {tx_data.get('id', 'Unknown')}")
                    print(f"   Status: Pending confirmation")
                    print(f"   Timestamp: {datetime.fromtimestamp(tx_data.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Log transaction creation
                    self.security_system.add_security_block({
                        "action": "transaction_created",
                        "tx_id": tx_data.get('id'),
                        "from": from_addr,
                        "to": to_addr,
                        "amount": amount,
                        "creator": self.current_user["username"],
                        "timestamp": time.time()
                    })
                    
                else:
                    print(f"❌ Transaction failed: {result['error']}")
            else:
                print("❌ Transaction cancelled.")
        
        except Exception as e:
            print(f"❌ Transaction creation error: {str(e)}")
        
        input("\nPress Enter to continue...")

    def analytics_and_monitoring_menu(self):
        """Advanced analytics and monitoring menu"""
        while True:
            print("\n📈 Analytics & Monitoring Center")
            print("=" * 45)
            print("1. 📊 System Analytics Dashboard")
            print("2. 📈 Performance Metrics")
            print("3. 📉 Usage Statistics")
            print("4. 🔍 Real-time Monitoring")
            print("5. 📋 Generate Reports")
            print("6. 📊 Custom Analytics")
            print("7. 🚨 Alert Configuration")
            print("8. 📈 Trend Analysis")
            print("9. 💾 Export Analytics Data")
            print("10. 🔙 Back to Main Menu")
            
            choice = input("\nEnter your choice (1-10): ").strip()
            
            if choice == "1":
                self.show_analytics_dashboard()
            elif choice == "2":
                self.show_performance_metrics()
            elif choice == "3":
                self.show_usage_statistics()
            elif choice == "4":
                self.real_time_monitoring()
            elif choice == "5":
                self.generate_reports_menu()
            elif choice == "6":
                self.custom_analytics_menu()
            elif choice == "7":
                self.alert_configuration_menu()
            elif choice == "8":
                self.trend_analysis_menu()
            elif choice == "9":
                self.export_analytics_data()
            elif choice == "10":
                break
            else:
                print("❌ Invalid choice.")

    def show_analytics_dashboard(self):
        """Display comprehensive analytics dashboard"""
        print("\n📊 System Analytics Dashboard")
        print("=" * 40)
        
        try:
            uptime = time.time() - self.system_start_time
            
            # System Overview
            print("🔍 System Overview:")
            print(f"   Uptime: {self.format_duration(uptime)}")
            print(f"   Total Operations: {self.performance_stats['operations_count']}")
            print(f"   Error Rate: {(self.performance_stats['errors_count'] / max(1, self.performance_stats['operations_count'])) * 100:.2f}%")
            print(f"   Avg Response Time: {self.performance_stats.get('average_response_time', 0):.3f}s")
            
            # Database Analytics
            databases = self.db_manager.list_databases()
            total_db_files = sum(self.db_manager.get_database_stats(db["name"]).get("total_files", 0) for db in databases)
            total_db_size = sum(self.db_manager.get_database_stats(db["name"]).get("total_size", 0) for db in databases)
            
            print(f"\n🗄️ Database Analytics:")
            print(f"   Total Databases: {len(databases)}")
            print(f"   Total Files: {total_db_files}")
            print(f"   Total Storage: {self.format_size(total_db_size)}")
            print(f"   Avg Files/DB: {total_db_files / max(1, len(databases)):.1f}")
            
            # Security Analytics
            security_stats = self.security_system.get_security_stats()
            print(f"\n🔐 Security Analytics:")
            print(f"   Total Users: {security_stats.get('total_users', 0)}")
            print(f"   Active Sessions: {security_stats.get('active_sessions', 0)}")
            print(f"   Security Events: {security_stats.get('security_operations', 0)}")
            locked_users_pct = (security_stats.get('locked_users', 0) / max(1, security_stats.get('total_users', 1))) * 100
            print(f"   Locked Users: {security_stats.get('locked_users', 0)} ({locked_users_pct:.1f}%)")
            
            # File Upload Analytics
            upload_stats = self.analyze_upload_stats()
            print(f"\n📁 Upload Analytics:")
            print(f"   Total Uploads: {upload_stats['total']}")
            print(f"   Approved: {upload_stats['approved']} ({upload_stats['approved_pct']:.1f}%)")
            print(f"   Quarantined: {upload_stats['quarantined']} ({upload_stats['quarantined_pct']:.1f}%)")
            print(f"   Top Uploader: {upload_stats['top_uploader']}")
            
            # Performance Trends
            print(f"\n📈 Performance Trends:")
            print("   [Mock] Operations trending up 15% this hour")
            print("   [Mock] Response time improved 8% since yesterday")
            print("   [Mock] Error rate decreased 3% this week")
            print("   [Mock] Storage usage growing 2% daily")
            
        except Exception as e:
            print(f"❌ Error displaying analytics: {str(e)}")
        
        input("\nPress Enter to continue...")

    def analyze_upload_stats(self) -> Dict:
        """Analyze upload statistics"""
        try:
            uploads = self.file_uploader.upload_chain
            total = len(uploads)
            
            if total == 0:
                return {
                    "total": 0,
                    "approved": 0,
                    "quarantined": 0,
                    "approved_pct": 0,
                    "quarantined_pct": 0,
                    "top_uploader": "None"
                }
            
            approved = len([u for u in uploads if u.get("status") == "approved"])
            quarantined = len([u for u in uploads if u.get("status") == "quarantined"])
            
            # Find top uploader
            uploaders = {}
            for upload in uploads:
                uploader = upload.get("uploaded_by", "Unknown")
                uploaders[uploader] = uploaders.get(uploader, 0) + 1
            
            top_uploader = max(uploaders.items(), key=lambda x: x[1])[0] if uploaders else "None"
            
            return {
                "total": total,
                "approved": approved,
                "quarantined": quarantined,
                "approved_pct": (approved / total) * 100,
                "quarantined_pct": (quarantined / total) * 100,
                "top_uploader": top_uploader
            }
        
        except Exception:
            return {
                "total": 0,
                "approved": 0,
                "quarantined": 0,
                "approved_pct": 0,
                "quarantined_pct": 0,
                "top_uploader": "Error"
            }

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Integrated Blockchain System - Complete Edition")
    parser.add_argument("--cpp-executable", default="./build/bin/blockchain_node",
                       help="Path to C++ blockchain node executable")
    parser.add_argument("--config", default="system_config.json",
                       help="Path to system configuration file")
    parser.add_argument("--demo", action="store_true",
                       help="Run in demo mode with mock data")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.demo:
        print("🧪 Running in demo mode with enhanced mock data...")
        print("💡 All features available with simulated blockchain operations")
    
    # Run the full system
    coordinator = BlockchainSystemCoordinator(args.cpp_executable)
    return coordinator.run()

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"💥 Fatal error: {str(e)}")
        sys.exit(1)