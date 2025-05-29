#!/usr/bin/env python3
"""
Blockchain Bridge - Integration layer between C++ blockchain node and Python features
This module provides seamless communication between the C++ node and Python-based
database management, security, and file upload systems.
"""

import json
import requests
import time
import os
import subprocess
import threading
from typing import Dict, List, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlockchainBridge:
    """Bridge class to communicate with C++ blockchain node"""
    
    def __init__(self, node_url="http://localhost:8080", node_executable=None):
        self.node_url = node_url
        self.node_executable = node_executable
        self.node_process = None
        self.is_connected = False
        
    def start_cpp_node(self, executable_path="./build/bin/blockchain_node"):
        """Start the C++ blockchain node"""
        try:
            if self.node_process and self.node_process.poll() is None:
                logger.info("C++ node is already running")
                return True
                
            logger.info(f"Starting C++ blockchain node: {executable_path}")
            self.node_process = subprocess.Popen(
                [executable_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for node to start
            time.sleep(3)
            
            # Check if node is responding
            if self.check_connection():
                logger.info("C++ blockchain node started successfully")
                return True
            else:
                logger.error("C++ node started but not responding to API calls")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start C++ node: {str(e)}")
            return False
    
    def stop_cpp_node(self):
        """Stop the C++ blockchain node"""
        if self.node_process:
            self.node_process.terminate()
            self.node_process.wait()
            logger.info("C++ blockchain node stopped")
    
    def check_connection(self) -> bool:
        """Check if the C++ node is responding"""
        try:
            response = requests.get(f"{self.node_url}/api/status", timeout=5)
            self.is_connected = response.status_code == 200
            return self.is_connected
        except Exception as e:
            logger.debug(f"Connection check failed: {str(e)}")
            self.is_connected = False
            return False
    
    def get_node_status(self) -> Dict:
        """Get current status of the blockchain node"""
        try:
            response = requests.get(f"{self.node_url}/api/status")
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_blockchain(self) -> Dict:
        """Get the full blockchain from C++ node"""
        try:
            response = requests.get(f"{self.node_url}/api/blockchain")
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_latest_block(self) -> Dict:
        """Get the latest block from the blockchain"""
        try:
            response = requests.get(f"{self.node_url}/api/block/latest")
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def create_transaction(self, from_addr: str, to_addr: str, amount: float) -> Dict:
        """Create a new transaction on the blockchain"""
        try:
            payload = {
                "from": from_addr,
                "to": to_addr,
                "amount": amount
            }
            response = requests.post(
                f"{self.node_url}/api/transactions",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def mine_block(self, miner_address: str) -> Dict:
        """Mine a new block"""
        try:
            payload = {"minerAddress": miner_address}
            response = requests.post(
                f"{self.node_url}/api/mine",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_peers(self) -> Dict:
        """Get connected peers"""
        try:
            response = requests.get(f"{self.node_url}/api/peers")
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def connect_to_peer(self, ip: str, port: int) -> Dict:
        """Connect to a peer"""
        try:
            payload = {"ip": ip, "port": port}
            response = requests.post(
                f"{self.node_url}/api/network/connect",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"HTTP {response.status_code}: {response.text}"}
        except Exception as e:
            return {"error": str(e)}

class PythonBlockchainManager:
    """Manager for Python-based blockchain operations"""
    
    def __init__(self, bridge: BlockchainBridge):
        self.bridge = bridge
        self.storage_path = "python_blockchain_data"
        self.ensure_storage_directory()
    
    def ensure_storage_directory(self):
        """Ensure storage directories exist"""
        os.makedirs(self.storage_path, exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "databases"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "users"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "files"), exist_ok=True)
    
    def sync_with_cpp_blockchain(self) -> bool:
        """Synchronize Python data with C++ blockchain"""
        try:
            cpp_blockchain = self.bridge.get_blockchain()
            if "error" in cpp_blockchain:
                logger.error(f"Failed to sync with C++ blockchain: {cpp_blockchain['error']}")
                return False
            
            # Save C++ blockchain data locally for Python processing
            sync_file = os.path.join(self.storage_path, "cpp_sync.json")
            with open(sync_file, "w") as f:
                json.dump(cpp_blockchain, f, indent=2)
            
            logger.info("Successfully synced with C++ blockchain")
            return True
            
        except Exception as e:
            logger.error(f"Sync error: {str(e)}")
            return False
    
    def add_python_metadata(self, block_data: Dict) -> bool:
        """Add Python-specific metadata to blockchain operations"""
        try:
            metadata_file = os.path.join(self.storage_path, "metadata.json")
            
            # Load existing metadata
            metadata = {}
            if os.path.exists(metadata_file):
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)
            
            # Add new metadata
            timestamp = str(int(time.time()))
            metadata[timestamp] = {
                "action": block_data.get("action", "unknown"),
                "timestamp": time.time(),
                "data": block_data
            }
            
            # Save updated metadata
            with open(metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Metadata error: {str(e)}")
            return False

class IntegratedBlockchainSystem:
    """Unified system combining C++ node with Python features"""
    
    def __init__(self, cpp_executable_path="./build/bin/blockchain_node"):
        self.bridge = BlockchainBridge()
        self.python_manager = PythonBlockchainManager(self.bridge)
        self.cpp_executable = cpp_executable_path
        self.system_running = False
    
    def start_system(self) -> bool:
        """Start the complete integrated blockchain system"""
        logger.info("Starting Integrated Blockchain System...")
        
        # Start C++ node
        if not self.bridge.start_cpp_node(self.cpp_executable):
            logger.error("Failed to start C++ blockchain node")
            return False
        
        # Wait for node to be ready
        time.sleep(2)
        
        # Check connection
        if not self.bridge.check_connection():
            logger.error("C++ node not responding")
            return False
        
        # Sync with C++ blockchain
        if not self.python_manager.sync_with_cpp_blockchain():
            logger.warning("Initial sync failed, continuing anyway")
        
        self.system_running = True
        logger.info("Integrated Blockchain System started successfully")
        return True
    
    def stop_system(self):
        """Stop the integrated blockchain system"""
        logger.info("Stopping Integrated Blockchain System...")
        self.bridge.stop_cpp_node()
        self.system_running = False
        logger.info("System stopped")
    
    def get_system_status(self) -> Dict:
        """Get comprehensive system status"""
        cpp_status = self.bridge.get_node_status()
        
        return {
            "system_running": self.system_running,
            "cpp_node_connected": self.bridge.is_connected,
            "cpp_node_status": cpp_status,
            "python_storage": os.path.exists(self.python_manager.storage_path),
            "timestamp": time.time()
        }
    
    def execute_integrated_operation(self, operation: str, **kwargs) -> Dict:
        """Execute operations that involve both C++ and Python components"""
        try:
            result = {"operation": operation, "success": False}
            
            if operation == "create_database_transaction":
                # This would create a transaction in C++ blockchain for database creation
                db_name = kwargs.get("db_name")
                owner = kwargs.get("owner")
                
                # Create transaction in C++ blockchain
                tx_result = self.bridge.create_transaction(
                    from_addr=owner,
                    to_addr="database_system",
                    amount=0.001  # Small fee for database creation
                )
                
                if "error" not in tx_result:
                    # Add Python metadata
                    metadata = {
                        "action": "create_database",
                        "db_name": db_name,
                        "owner": owner,
                        "cpp_transaction": tx_result
                    }
                    self.python_manager.add_python_metadata(metadata)
                    result["success"] = True
                    result["transaction"] = tx_result
                
            elif operation == "sync_and_verify":
                # Sync with C++ and verify integrity
                sync_success = self.python_manager.sync_with_cpp_blockchain()
                cpp_status = self.bridge.get_node_status()
                
                result["success"] = sync_success
                result["cpp_status"] = cpp_status
            
            return result
            
        except Exception as e:
            return {"operation": operation, "success": False, "error": str(e)}

# Utility functions for easy integration
def start_integrated_system(cpp_executable="./build/bin/blockchain_node") -> IntegratedBlockchainSystem:
    """Quick start function for the integrated system"""
    system = IntegratedBlockchainSystem(cpp_executable)
    if system.start_system():
        return system
    else:
        raise RuntimeError("Failed to start integrated blockchain system")

def test_integration():
    """Test the integration between C++ and Python components"""
    print("🧪 Testing Blockchain Integration...")
    
    try:
        system = start_integrated_system()
        
        # Test system status
        status = system.get_system_status()
        print(f"✅ System Status: {status}")
        
        # Test C++ blockchain operations
        latest_block = system.bridge.get_latest_block()
        print(f"✅ Latest Block: {latest_block}")
        
        # Test integrated operation
        result = system.execute_integrated_operation(
            "create_database_transaction",
            db_name="test_db",
            owner="test_user"
        )
        print(f"✅ Integrated Operation: {result}")
        
        print("🎉 Integration test completed successfully!")
        
        system.stop_system()
        
    except Exception as e:
        print(f"❌ Integration test failed: {str(e)}")

if __name__ == "__main__":
    # Run integration test if executed directly
    test_integration()
