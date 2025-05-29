#!/usr/bin/env python3
"""
Integrated Database Manager - Blockchain-based database management
This module provides database operations that are recorded on the C++ blockchain
while maintaining Python-based file storage and management.
"""

import json
import os
import time
import hashlib
import shutil
from typing import Dict, List, Optional, Any
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class DatabaseBlock:
    """Represents a database operation block"""
    
    def __init__(self, index: int, timestamp: float, data: Dict, storage_path: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.storage_path = storage_path
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate hash for the database block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "storage_path": self.storage_path,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert block to dictionary"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "storage_path": self.storage_path,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class IntegratedDatabaseManager:
    """Database manager that integrates with C++ blockchain"""
    
    def __init__(self, blockchain_bridge, storage_root: str = "blockchain_databases"):
        self.bridge = blockchain_bridge
        self.storage_root = storage_root
        self.db_chain_file = os.path.join(storage_root, "db_chain.json")
        self.databases_dir = os.path.join(storage_root, "databases")
        self.chain = []
        
        self.initialize_storage()
        self.load_database_chain()
    
    def initialize_storage(self):
        """Initialize storage directories"""
        os.makedirs(self.storage_root, exist_ok=True)
        os.makedirs(self.databases_dir, exist_ok=True)
        logger.info(f"Database storage initialized at {self.storage_root}")
    
    def load_database_chain(self):
        """Load the database operation chain"""
        if os.path.exists(self.db_chain_file):
            try:
                with open(self.db_chain_file, "r") as f:
                    chain_data = json.load(f)
                
                self.chain = []
                for block_data in chain_data:
                    block = DatabaseBlock(
                        block_data["index"],
                        block_data["timestamp"],
                        block_data["data"],
                        block_data["storage_path"],
                        block_data["previous_hash"]
                    )
                    block.hash = block_data["hash"]
                    self.chain.append(block)
                
                logger.info(f"Loaded {len(self.chain)} database operations from chain")
            except Exception as e:
                logger.error(f"Failed to load database chain: {str(e)}")
                self.chain = [self.create_genesis_block()]
        else:
            self.chain = [self.create_genesis_block()]
        
        self.save_chain()
    
    def create_genesis_block(self) -> DatabaseBlock:
        """Create the genesis block for database operations"""
        return DatabaseBlock(
            index=0,
            timestamp=time.time(),
            data={"action": "genesis", "message": "Database Genesis Block"},
            storage_path="",
            previous_hash="0"
        )
    
    def save_chain(self):
        """Save the database operation chain"""
        try:
            with open(self.db_chain_file, "w") as f:
                json.dump([block.to_dict() for block in self.chain], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save database chain: {str(e)}")
    
    def add_database_block(self, block_data: Dict, storage_path: str) -> bool:
        """Add a new database operation block"""
        try:
            # Create new block
            new_block = DatabaseBlock(
                index=len(self.chain),
                timestamp=time.time(),
                data=block_data,
                storage_path=storage_path,
                previous_hash=self.chain[-1].hash if self.chain else "0"
            )
            
            # Add to chain
            self.chain.append(new_block)
            self.save_chain()
            
            # Also record in C++ blockchain if possible
            try:
                cpp_result = self.bridge.create_transaction(
                    from_addr=block_data.get("owner", "system"),
                    to_addr="database_system",
                    amount=0.001  # Small fee for database operations
                )
                if "error" not in cpp_result:
                    logger.info(f"Database operation recorded in C++ blockchain: {cpp_result}")
            except Exception as e:
                logger.warning(f"Could not record in C++ blockchain: {str(e)}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to add database block: {str(e)}")
            return False
    
    def create_database(self, name: str, schema: Dict, owner: str) -> Optional[str]:
        """Create a new blockchain database"""
        try:
            # Create database directory
            db_path = os.path.join(self.databases_dir, name)
            if os.path.exists(db_path):
                logger.error(f"Database '{name}' already exists")
                return None
            
            os.makedirs(db_path, exist_ok=True)
            
            # Create schema file
            schema_file = os.path.join(db_path, "schema.json")
            with open(schema_file, "w") as f:
                json.dump(schema, f, indent=2)
            
            # Create database metadata
            metadata = {
                "name": name,
                "owner": owner,
                "created_at": time.time(),
                "schema": schema,
                "version": "1.0"
            }
            
            metadata_file = os.path.join(db_path, "metadata.json")
            with open(metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)
            
            # Create users file
            users_data = {
                "users": {
                    owner: {
                        "role": "owner",
                        "added_at": time.time(),
                        "permissions": ["read", "write", "admin"]
                    }
                }
            }
            
            users_file = os.path.join(db_path, "users.json")
            with open(users_file, "w") as f:
                json.dump(users_data, f, indent=2)
            
            # Add to blockchain
            block_data = {
                "action": "create_database",
                "name": name,
                "owner": owner,
                "schema": schema,
                "timestamp": time.time()
            }
            
            if self.add_database_block(block_data, db_path):
                logger.info(f"Database '{name}' created successfully at {db_path}")
                return db_path
            else:
                # Cleanup on failure
                shutil.rmtree(db_path, ignore_errors=True)
                return None
                
        except Exception as e:
            logger.error(f"Failed to create database '{name}': {str(e)}")
            return None
    
    def list_databases(self, user: str = None, role: str = None) -> List[Dict]:
        """List available databases"""
        databases = []
        
        for block in self.chain:
            if block.data.get("action") == "create_database":
                db_info = {
                    "name": block.data.get("name"),
                    "owner": block.data.get("owner"),
                    "created_at": block.timestamp,
                    "path": block.storage_path,
                    "schema": block.data.get("schema", {})
                }
                
                # Check user permissions
                if user and role != "admin":
                    # Check if user has access to this database
                    if not self.check_user_database_access(db_info["name"], user):
                        continue
                
                databases.append(db_info)
        
        return databases
    
    def check_user_database_access(self, db_name: str, username: str) -> bool:
        """Check if user has access to a database"""
        try:
            db_path = os.path.join(self.databases_dir, db_name)
            users_file = os.path.join(db_path, "users.json")
            
            if not os.path.exists(users_file):
                return False
            
            with open(users_file, "r") as f:
                users_data = json.load(f)
            
            return username in users_data.get("users", {})
            
        except Exception as e:
            logger.error(f"Error checking database access: {str(e)}")
            return False
    
    def add_user_to_database(self, db_name: str, username: str, role: str, admin_user: str) -> bool:
        """Add a user to a database"""
        try:
            db_path = os.path.join(self.databases_dir, db_name)
            users_file = os.path.join(db_path, "users.json")
            
            if not os.path.exists(users_file):
                logger.error(f"Database '{db_name}' not found")
                return False
            
            # Load current users
            with open(users_file, "r") as f:
                users_data = json.load(f)
            
            # Add new user
            users_data["users"][username] = {
                "role": role,
                "added_by": admin_user,
                "added_at": time.time(),
                "permissions": self.get_role_permissions(role)
            }
            
            # Save updated users
            with open(users_file, "w") as f:
                json.dump(users_data, f, indent=2)
            
            # Add to blockchain
            block_data = {
                "action": "add_user_to_database",
                "database": db_name,
                "username": username,
                "role": role,
                "admin": admin_user,
                "timestamp": time.time()
            }
            
            if self.add_database_block(block_data, users_file):
                logger.info(f"User '{username}' added to database '{db_name}'")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to add user to database: {str(e)}")
            return False
    
    def get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a role"""
        permissions_map = {
            "owner": ["read", "write", "admin", "delete"],
            "admin": ["read", "write", "admin"],
            "user": ["read", "write"],
            "readonly": ["read"]
        }
        return permissions_map.get(role, ["read"])
    
    def store_file_in_database(self, db_name: str, file_path: str, username: str, metadata: Dict = None) -> Optional[str]:
        """Store a file in a database"""
        try:
            # Check user permissions
            if not self.check_user_database_access(db_name, username):
                logger.error(f"User '{username}' does not have access to database '{db_name}'")
                return None
            
            db_path = os.path.join(self.databases_dir, db_name)
            files_dir = os.path.join(db_path, "files")
            os.makedirs(files_dir, exist_ok=True)
            
            # Generate unique filename
            timestamp = int(time.time())
            original_name = os.path.basename(file_path)
            stored_name = f"{timestamp}_{original_name}"
            stored_path = os.path.join(files_dir, stored_name)
            
            # Copy file
            shutil.copy2(file_path, stored_path)
            
            # Create file metadata
            file_metadata = {
                "original_name": original_name,
                "stored_name": stored_name,
                "stored_path": stored_path,
                "uploaded_by": username,
                "uploaded_at": time.time(),
                "size": os.path.getsize(stored_path),
                "hash": self.calculate_file_hash(stored_path),
                "metadata": metadata or {}
            }
            
            # Save file metadata
            metadata_file = os.path.join(files_dir, f"{stored_name}.meta.json")
            with open(metadata_file, "w") as f:
                json.dump(file_metadata, f, indent=2)
            
            # Add to blockchain
            block_data = {
                "action": "store_file",
                "database": db_name,
                "filename": original_name,
                "stored_name": stored_name,
                "uploaded_by": username,
                "file_hash": file_metadata["hash"],
                "timestamp": time.time()
            }
            
            if self.add_database_block(block_data, stored_path):
                logger.info(f"File '{original_name}' stored in database '{db_name}'")
                return stored_path
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to store file in database: {str(e)}")
            return None
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate file hash: {str(e)}")
            return ""
    
    def list_database_files(self, db_name: str, username: str = None) -> List[Dict]:
        """List files in a database"""
        try:
            # Check user permissions
            if username and not self.check_user_database_access(db_name, username):
                logger.error(f"User '{username}' does not have access to database '{db_name}'")
                return []
            
            files = []
            db_path = os.path.join(self.databases_dir, db_name)
            files_dir = os.path.join(db_path, "files")
            
            if not os.path.exists(files_dir):
                return []
            
            # Get file metadata from blockchain
            for block in self.chain:
                if (block.data.get("action") == "store_file" and 
                    block.data.get("database") == db_name):
                    
                    stored_name = block.data.get("stored_name")
                    metadata_file = os.path.join(files_dir, f"{stored_name}.meta.json")
                    
                    if os.path.exists(metadata_file):
                        try:
                            with open(metadata_file, "r") as f:
                                file_metadata = json.load(f)
                            files.append(file_metadata)
                        except Exception as e:
                            logger.error(f"Failed to read file metadata: {str(e)}")
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to list database files: {str(e)}")
            return []
    
    def get_database_stats(self, db_name: str) -> Dict:
        """Get statistics for a database"""
        try:
            stats = {
                "name": db_name,
                "total_files": 0,
                "total_size": 0,
                "users": 0,
                "operations": 0,
                "created_at": None,
                "last_activity": None
            }
            
            # Count operations from blockchain
            for block in self.chain:
                if block.data.get("database") == db_name or block.data.get("name") == db_name:
                    stats["operations"] += 1
                    
                    if block.data.get("action") == "create_database":
                        stats["created_at"] = block.timestamp
                    
                    if not stats["last_activity"] or block.timestamp > stats["last_activity"]:
                        stats["last_activity"] = block.timestamp
            
            # Count files and size
            db_path = os.path.join(self.databases_dir, db_name)
            files_dir = os.path.join(db_path, "files")
            
            if os.path.exists(files_dir):
                for filename in os.listdir(files_dir):
                    if not filename.endswith(".meta.json"):
                        file_path = os.path.join(files_dir, filename)
                        if os.path.isfile(file_path):
                            stats["total_files"] += 1
                            stats["total_size"] += os.path.getsize(file_path)
            
            # Count users
            users_file = os.path.join(db_path, "users.json")
            if os.path.exists(users_file):
                try:
                    with open(users_file, "r") as f:
                        users_data = json.load(f)
                    stats["users"] = len(users_data.get("users", {}))
                except Exception:
                    pass
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database stats: {str(e)}")
            return {}
    
    def verify_database_integrity(self, db_name: str) -> Dict:
        """Verify the integrity of a database"""
        try:
            integrity_report = {
                "database": db_name,
                "valid": True,
                "issues": [],
                "checked_files": 0,
                "corrupted_files": 0,
                "missing_files": 0
            }
            
            # Check if database exists
            db_path = os.path.join(self.databases_dir, db_name)
            if not os.path.exists(db_path):
                integrity_report["valid"] = False
                integrity_report["issues"].append("Database directory does not exist")
                return integrity_report
            
            # Verify files against blockchain records
            files_dir = os.path.join(db_path, "files")
            
            for block in self.chain:
                if (block.data.get("action") == "store_file" and 
                    block.data.get("database") == db_name):
                    
                    stored_name = block.data.get("stored_name")
                    expected_hash = block.data.get("file_hash")
                    file_path = os.path.join(files_dir, stored_name)
                    
                    integrity_report["checked_files"] += 1
                    
                    if not os.path.exists(file_path):
                        integrity_report["valid"] = False
                        integrity_report["missing_files"] += 1
                        integrity_report["issues"].append(f"Missing file: {stored_name}")
                        continue
                    
                    # Verify file hash
                    actual_hash = self.calculate_file_hash(file_path)
                    if actual_hash != expected_hash:
                        integrity_report["valid"] = False
                        integrity_report["corrupted_files"] += 1
                        integrity_report["issues"].append(f"Corrupted file: {stored_name}")
            
            return integrity_report
            
        except Exception as e:
            logger.error(f"Failed to verify database integrity: {str(e)}")
            return {"database": db_name, "valid": False, "error": str(e)}
    
    def export_database(self, db_name: str, export_path: str, username: str) -> bool:
        """Export a database to a backup file"""
        try:
            # Check user permissions
            if not self.check_user_database_access(db_name, username):
                logger.error(f"User '{username}' does not have access to database '{db_name}'")
                return False
            
            db_path = os.path.join(self.databases_dir, db_name)
            if not os.path.exists(db_path):
                logger.error(f"Database '{db_name}' not found")
                return False
            
            # Create export data
            export_data = {
                "database_name": db_name,
                "exported_by": username,
                "exported_at": time.time(),
                "version": "1.0",
                "blockchain_operations": [],
                "files": []
            }
            
            # Export blockchain operations
            for block in self.chain:
                if (block.data.get("database") == db_name or 
                    block.data.get("name") == db_name):
                    export_data["blockchain_operations"].append(block.to_dict())
            
            # Export file metadata
            files = self.list_database_files(db_name, username)
            export_data["files"] = files
            
            # Save export file
            with open(export_path, "w") as f:
                json.dump(export_data, f, indent=2)
            
            # Add export operation to blockchain
            block_data = {
                "action": "export_database",
                "database": db_name,
                "exported_by": username,
                "export_path": export_path,
                "timestamp": time.time()
            }
            
            self.add_database_block(block_data, export_path)
            logger.info(f"Database '{db_name}' exported to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export database: {str(e)}")
            return False

# Utility functions for database management
def create_test_database(db_manager: IntegratedDatabaseManager) -> bool:
    """Create a test database for demonstration"""
    try:
        schema = {
            "tables": {
                "users": {
                    "fields": {
                        "id": "int",
                        "name": "string",
                        "email": "string",
                        "created_at": "timestamp"
                    }
                },
                "documents": {
                    "fields": {
                        "id": "int",
                        "title": "string",
                        "content": "text",
                        "owner_id": "int",
                        "created_at": "timestamp"
                    }
                }
            }
        }
        
        result = db_manager.create_database("test_database", schema, "admin")
        return result is not None
        
    except Exception as e:
        logger.error(f"Failed to create test database: {str(e)}")
        return False

def demonstrate_database_operations(db_manager: IntegratedDatabaseManager):
    """Demonstrate various database operations"""
    print("🗄️ Database Management System Demo")
    print("=" * 50)
    
    # Create test database
    print("1. Creating test database...")
    if create_test_database(db_manager):
        print("✅ Test database created successfully")
    else:
        print("❌ Failed to create test database")
        return
    
    # List databases
    print("\n2. Listing databases...")
    databases = db_manager.list_databases()
    for db in databases:
        print(f"   📁 {db['name']} (Owner: {db['owner']})")
    
    # Add user to database
    print("\n3. Adding user to database...")
    if db_manager.add_user_to_database("test_database", "test_user", "user", "admin"):
        print("✅ User added successfully")
    else:
        print("❌ Failed to add user")
    
    # Get database stats
    print("\n4. Getting database statistics...")
    stats = db_manager.get_database_stats("test_database")
    print(f"   📊 Files: {stats.get('total_files', 0)}")
    print(f"   👥 Users: {stats.get('users', 0)}")
    print(f"   🔄 Operations: {stats.get('operations', 0)}")
    
    # Verify integrity
    print("\n5. Verifying database integrity...")
    integrity = db_manager.verify_database_integrity("test_database")
    print(f"   ✅ Valid: {integrity.get('valid', False)}")
    print(f"   📁 Checked files: {integrity.get('checked_files', 0)}")
    
    print("\n🎉 Database operations demo completed!")

if __name__ == "__main__":
    # Demo the database management system
    try:
        from blockchain_bridge import BlockchainBridge
    except ImportError:
        # Create a mock bridge for testing
        class MockBridge:
            def create_transaction(self, from_addr, to_addr, amount):
                return {"success": True, "mock": True}
        
        BlockchainBridge = MockBridge
    
    print("Starting Database Management System...")
    
    # Initialize bridge (may not connect to actual C++ node in demo)
    bridge = BlockchainBridge()
    
    # Initialize database manager
    db_manager = IntegratedDatabaseManager(bridge)
    
    # Run demonstration
    demonstrate_database_operations(db_manager)