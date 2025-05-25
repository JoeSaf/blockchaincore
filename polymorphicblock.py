# polymorphicblock.py - Python wrapper for C++ blockchain core
"""
Compatibility wrapper for the C++ blockchain core.
This maintains the original Python API while using high-performance C++ backend.
"""

import os
import sys
import json
import time
import getpass
from typing import Dict, List, Tuple, Optional, Any, Union

# Import the C++ core module
try:
    import blockchain_core as _core
except ImportError as e:
    print(f"Error: Could not import C++ blockchain core: {e}")
    print("Please ensure the blockchain_core module is compiled and installed.")
    sys.exit(1)

# Global variables for compatibility
BLOCKCHAIN_DB = "blockchain_db.json"

class Block:
    """Python wrapper for C++ Block class"""
    
    def __init__(self, index: int, timestamp: float, data: Dict[str, Any], previous_hash: str):
        self._cpp_block = _core.Block(index, timestamp, data, previous_hash)
    
    @classmethod
    def from_cpp_block(cls, cpp_block):
        """Create Python Block from C++ Block"""
        instance = cls.__new__(cls)
        instance._cpp_block = cpp_block
        return instance
    
    def calculate_hash(self) -> str:
        """Calculate block hash"""
        return self._cpp_block.calculate_hash()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary (compatibility method)"""
        return self._cpp_block.to_json()
    
    @property
    def index(self) -> int:
        return self._cpp_block.get_index()
    
    @property
    def timestamp(self) -> float:
        return self._cpp_block.get_timestamp()
    
    @property
    def data(self) -> Dict[str, Any]:
        return self._cpp_block.get_data()
    
    @property
    def hash(self) -> str:
        return self._cpp_block.get_hash()
    
    @property
    def previous_hash(self) -> str:
        return self._cpp_block.get_previous_hash()


class User:
    """Python wrapper for C++ User class"""
    
    def __init__(self, username: str, role: str, private_key: Optional[str] = None):
        if private_key:
            # This is a legacy case - we'll need to handle it differently
            # For now, create a new user and replace keys if needed
            self._cpp_user = _core.User(username, role)
        else:
            self._cpp_user = _core.User(username, role)
    
    @classmethod
    def from_cpp_user(cls, cpp_user):
        """Create Python User from C++ User"""
        instance = cls.__new__(cls)
        instance._cpp_user = cpp_user
        return instance
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        return self._cpp_user.get_public_key_pem()
    
    def get_private_key_pem(self, password: str = "") -> str:
        """Get private key in PEM format"""
        return self._cpp_user.get_private_key_pem(password)
    
    def sign_message(self, message: str) -> str:
        """Sign a message"""
        return self._cpp_user.sign_message(message)
    
    def initialize_user_folder(self) -> str:
        """Initialize user folder"""
        self._cpp_user.initialize_user_folder()
        return os.path.join("userData", self.username)
    
    def store_user_item(self, item_name: str, item_data: Any) -> str:
        """Store item in user folder"""
        return self._cpp_user.store_user_item(item_name, item_data)
    
    @property
    def username(self) -> str:
        return self._cpp_user.get_username()
    
    @property
    def role(self) -> str:
        return self._cpp_user.get_role()


class Blockchain:
    """Python wrapper for C++ Blockchain class"""
    
    def __init__(self):
        self._cpp_blockchain = _core.Blockchain(BLOCKCHAIN_DB)
    
    def create_genesis_block(self) -> Block:
        """Create genesis block"""
        cpp_block = self._cpp_blockchain.create_genesis_block()
        return Block.from_cpp_block(cpp_block)
    
    def get_latest_block(self) -> Block:
        """Get the latest block"""
        cpp_block = self._cpp_blockchain.get_latest_block()
        return Block.from_cpp_block(cpp_block)
    
    def add_block(self, new_block: Block) -> None:
        """Add a new block to the blockchain"""
        # Create a new C++ block with the same data
        cpp_block = _core.Block(
            new_block.index,
            new_block.timestamp,
            new_block.data,
            new_block.previous_hash
        )
        self._cpp_blockchain.add_block(cpp_block)
    
    def is_chain_valid(self) -> bool:
        """Validate blockchain integrity"""
        return self._cpp_blockchain.is_chain_valid()
    
    def to_dict(self) -> List[Dict[str, Any]]:
        """Convert blockchain to list of dictionaries"""
        return self._cpp_blockchain.to_json()
    
    def save_chain(self) -> None:
        """Save blockchain to file"""
        self._cpp_blockchain.save_chain()
    
    def load_chain(self) -> None:
        """Load blockchain from file"""
        self._cpp_blockchain.load_chain()
    
    def rehash_chain(self) -> None:
        """Rehash the entire blockchain"""
        self._cpp_blockchain.rehash_chain()
    
    @property
    def chain(self) -> List[Block]:
        """Get the blockchain as a list of Block objects"""
        chain_data = self._cpp_blockchain.to_json()
        blocks = []
        for block_data in chain_data:
            block = Block.__new__(Block)
            block._cpp_block = _core.Block.from_json(block_data)
            blocks.append(block)
        return blocks
    
    def _trigger_fallback_response(self, breach_reason: str) -> None:
        """Trigger security fallback response"""
        self._cpp_blockchain.trigger_fallback_response(breach_reason)


class AuthSystem:
    """Python wrapper for C++ AuthSystem class"""
    
    def __init__(self):
        self._cpp_auth = _core.AuthSystem()
        self._blockchain = Blockchain()
        self._blockchain._cpp_blockchain = self._cpp_auth.get_blockchain()
        self.users = {}  # Compatibility dict
        self.db_manager = None  # Will be set by blockchain_databases
        self.load_users_from_blockchain()
    
    def load_users_from_blockchain(self) -> None:
        """Load users from blockchain into compatibility dict"""
        self._cpp_auth.load_users_from_blockchain()
        self.users.clear()
        
        # Extract user data for compatibility
        chain_data = self._cpp_auth.get_blockchain().to_json()
        for block_data in chain_data:
            if (block_data.get("data", {}).get("action") == "register"):
                data = block_data["data"]
                username = data.get("username", "")
                if username:
                    self.users[username] = {
                        "role": data.get("role", "user"),
                        "public_key": data.get("public_key", ""),
                        "private_key": data.get("private_key", "")
                    }
    
    def register_user(self, username: str, role: str, password: str) -> bool:
        """Register a new user"""
        success = self._cpp_auth.register_user(username, role, password)
        if success:
            self.load_users_from_blockchain()  # Refresh compatibility dict
        return success
    
    def authenticate(self, username: str, password: str) -> Tuple[Optional[str], Optional[str]]:
        """Authenticate a user"""
        result = self._cpp_auth.authenticate(username, password)
        return result if result[0] else (None, None)
    
    def list_users(self) -> None:
        """List all users (prints to console for compatibility)"""
        users = self._cpp_auth.list_users()
        if users:
            print("\nRegistered Users:")
            for user_info in users:
                print(f"  {user_info}")
        else:
            print("No users registered yet.")
    
    def verify_blockchain(self) -> None:
        """Verify blockchain integrity (prints result for compatibility)"""
        self._cpp_auth.verify_blockchain()
    
    def get_previous_user(self, current_user: str) -> Optional[str]:
        """Get previous user in chain (compatibility method)"""
        # This is a simplified version - the C++ core handles this internally
        chain_data = self._cpp_auth.get_blockchain().to_json()
        users_found = []
        
        for block_data in chain_data:
            if (block_data.get("data", {}).get("action") == "register"):
                username = block_data["data"].get("username", "")
                if username and username != current_user:
                    users_found.append(username)
        
        return users_found[-1] if users_found else None
    
    @property
    def blockchain(self) -> Blockchain:
        """Get blockchain instance"""
        return self._blockchain


# High-level functions for compatibility with existing code
def authenticate() -> Tuple[Optional[str], Optional[str], Optional[AuthSystem]]:
    """User authentication interface (compatibility function)"""
    auth_system = AuthSystem()
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    result = auth_system.authenticate(username, password)
    if result[0]:
        return result[0], result[1], auth_system
    return None, None, None


def main_menu(username: str, user_role: str, auth_system: AuthSystem, adjuster=None) -> None:
    """Main menu after successful login (compatibility function)"""
    
    while True:
        print("\nBlockchain Authentication System")
        print("1. List Users")
        print("2. Add User (Admin Only)")
        print("3. Verify Blockchain Integrity")
        print("4. View Blockchain Records")
        print("5. Database Operations")
        print("6. User Item Management")
        print("7. Refresh Blockchain State")
        print("8. Logout")
        choice = input("Enter option: ")

        if choice == "1":
            auth_system.list_users()
            
        elif choice == "2" and user_role == "admin":
            new_user = input("Enter new username: ")
            new_role = input("Enter role (user/admin): ")
            new_pass = getpass.getpass("Enter new password: ")
            success = auth_system.register_user(new_user, new_role, new_pass)
            if success:
                print(f"User '{new_user}' registered successfully.")
            else:
                print("Failed to register user.")
            
        elif choice == "3":
            auth_system.verify_blockchain()
            
        elif choice == "4":
            print("\nBlockchain records:")
            chain_data = auth_system.blockchain.to_dict()
            for block in chain_data:
                block_data = block.get("data", {})
                action = block_data.get("action", "Unknown")
                username_in_block = block_data.get("username", "N/A")
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block["timestamp"]))
                print(f"Block #{block['index']}: {action} - {username_in_block} ({timestamp})")
                
        elif choice == "5":
            # Import here to avoid circular imports
            try:
                from polymorphicblock import database_menu
                database_menu(username, user_role, auth_system)
            except ImportError:
                print("Database operations not available. Please ensure all modules are installed.")
            
        elif choice == "6":
            # Import here to avoid circular imports
            try:
                from polymorphicblock import user_item_menu
                user_item_menu(username, auth_system)
            except ImportError:
                print("User item management not available. Please ensure all modules are installed.")
        
        elif choice == "7":
            # Refresh blockchain state
            auth_system.load_users_from_blockchain()
            auth_system.verify_blockchain()
            print("Blockchain state refreshed successfully.")
            
        elif choice == "8":
            print("Logging out...")
            break
            
        else:
            print("Invalid option or insufficient privileges!")


def database_menu(username: str, user_role: str, auth_system: AuthSystem) -> None:
    """Database operations menu (compatibility function)"""
    print("Database operations moved to blockchain_databases module.")
    print("Please use the database management through the web interface or CLI.")


def user_item_menu(username: str, auth_system: AuthSystem) -> None:
    """User item management menu (compatibility function)"""
    
    def format_size(size_bytes: int) -> str:
        """Convert size in bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    while True:
        print("\nUser Item Management")
        print("1. List My Items")
        print("2. Store New Item")
        print("3. Return to Main Menu")
        choice = input("Enter option: ")
        
        if choice == "1":
            user_folder = os.path.join("userData", username)
            
            if os.path.exists(user_folder):
                items = [f for f in os.listdir(user_folder) if f != 'user_info.json']
                
                if items:
                    print(f"\nItems for user '{username}':")
                    for idx, item in enumerate(items, 1):
                        item_path = os.path.join(user_folder, item)
                        try:
                            stat = os.stat(item_path)
                            size = format_size(stat.st_size)
                            modified = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
                            print(f"{idx}. {item} (Size: {size}, Modified: {modified})")
                        except Exception as e:
                            print(f"{idx}. {item} (Error reading file info: {str(e)})")
                    
                    view_item = input("\nView an item? (y/n): ").lower()
                    if view_item == 'y':
                        try:
                            item_idx = int(input("Select item number: ")) - 1
                            if 0 <= item_idx < len(items):
                                item_path = os.path.join(user_folder, items[item_idx])
                                if item_path.endswith(('.txt', '.json', '.py')):
                                    with open(item_path, "r") as f:
                                        content = f.read()
                                        print(f"\nContent of '{items[item_idx]}':")
                                        print(content)
                                else:
                                    print(f"\nFile '{items[item_idx]}' is not a text file and cannot be displayed.")
                                    print(f"File path: {item_path}")
                            else:
                                print("Invalid selection.")
                        except ValueError:
                            print("Invalid input. Please enter a number.")
                        except Exception as e:
                            print(f"Error reading item: {str(e)}")
                else:
                    print(f"No items found for user '{username}'.")
            else:
                print(f"User folder for '{username}' not found.")
                
        elif choice == "2":
            item_name = input("Enter item name: ")
            
            print("Item storage options:")
            print("1. Text data")
            print("2. JSON data")
            print("3. File upload (requires GUI)")
            
            storage_choice = input("Choose option: ")
            
            if storage_choice == "1":
                text_data = input("Enter text data: ")
                try:
                    # Create a User object to store the item
                    user_obj = User(username, auth_system.users[username]["role"])
                    user_obj.store_user_item(item_name, {"type": "text", "content": text_data})
                    print(f"Text item '{item_name}' stored successfully.")
                except Exception as e:
                    print(f"Error storing item: {str(e)}")
                    
            elif storage_choice == "2":
                json_input = input("Enter JSON data: ")
                try:
                    json_data = json.loads(json_input)
                    user_obj = User(username, auth_system.users[username]["role"])
                    user_obj.store_user_item(item_name, json_data)
                    print(f"JSON item '{item_name}' stored successfully.")
                except json.JSONDecodeError:
                    print("Invalid JSON format.")
                except Exception as e:
                    print(f"Error storing item: {str(e)}")
                    
            elif storage_choice == "3":
                print("File upload requires the GUI interface.")
                print("Please use the web interface for file uploads.")
            else:
                print("Invalid option.")
                
        elif choice == "3":
            break
            
        else:
            print("Invalid option!")


def initialize_system() -> AuthSystem:
    """Initialize system with admin if blockchain is empty"""
    core = _core.BlockchainCore.get_instance()
    core.setup_directories()
    
    auth_system = AuthSystem()
    
    if core.get_chain_length() <= 1:  # Only genesis block exists
        print("Initializing system with admin user...")
        admin_password = getpass.getpass("Create admin password: ")
        success = auth_system.register_user("admin", "admin", admin_password)
        if success:
            print("Admin user created. Please login.")
        else:
            print("Failed to create admin user.")
    
    return auth_system


def simulate_tampering() -> None:
    """Simulate tampering with the blockchain (for demonstration purposes)"""
    print("\n[TEST] Simulating blockchain tampering...")
    try:
        auth_system = AuthSystem()
        blockchain = auth_system.blockchain
        
        if blockchain._cpp_blockchain.get_chain_length() > 1:
            # This would trigger the security response in the C++ core
            print("[TEST] Triggering security response...")
            blockchain._cpp_blockchain.trigger_fallback_response("Simulated tampering detected")
            
            # Verify the chain to see the response
            is_valid = blockchain.is_chain_valid()
            print(f"[TEST] Blockchain integrity after tampering: {'Valid' if is_valid else 'Compromised'}")
        else:
            print("[TEST] Need at least 2 blocks to demonstrate tampering.")
    except Exception as e:
        print(f"[TEST] Error during tampering simulation: {str(e)}")


# Block Adjuster integration (simplified)
class BlockAdjuster:
    """Simplified BlockAdjuster that uses C++ core functionality"""
    
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
    
    def start_timer(self, interval: int = 300) -> None:
        """Start the block adjuster timer"""
        print(f"[Adjuster] Starting block adjuster with {interval} second interval")
        self.blockchain._cpp_blockchain.start_block_adjuster(interval)
    
    def stop_timer(self) -> None:
        """Stop the block adjuster timer"""
        print("[Adjuster] Stopping block adjuster")
        self.blockchain._cpp_blockchain.stop_block_adjuster()
    
    def safely_reorder_blocks(self, start_index: int = 1, count: int = 9) -> bool:
        """Safely reorder blocks"""
        try:
            self.blockchain._cpp_blockchain.safely_reorder_blocks(start_index, count)
            return True
        except Exception as e:
            print(f"[Adjuster] Error during reordering: {str(e)}")
            return False


# Utility functions
def format_size(size_bytes: int) -> str:
    """Convert size in bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


# Export compatibility objects
def get_blockchain_core():
    """Get the singleton blockchain core instance"""
    return _core.BlockchainCore.get_instance()


# Module-level initialization
def _setup_module():
    """Setup the module on import"""
    try:
        core = get_blockchain_core()
        core.setup_directories()
        print("C++ Blockchain Core initialized successfully.")
    except Exception as e:
        print(f"Warning: Failed to initialize C++ core: {e}")


# Initialize on import
_setup_module()


# For backwards compatibility, expose the main classes at module level
__all__ = [
    'Block', 'User', 'Blockchain', 'AuthSystem', 'BlockAdjuster',
    'authenticate', 'main_menu', 'database_menu', 'user_item_menu',
    'initialize_system', 'simulate_tampering', 'format_size',
    'get_blockchain_core', 'BLOCKCHAIN_DB'
]


if __name__ == "__main__":
    # Run the system if called directly
    auth_system = initialize_system()
    
    # Create adjuster
    adjuster = BlockAdjuster(auth_system.blockchain)
    
    # Authenticate user
    username, user_role, auth_system = authenticate()
    
    # If authentication successful, show main menu
    if username:
        main_menu(username, user_role, auth_system, adjuster)
