import os
import json
import sys
import time
import getpass
from polymorphicblock import AuthSystem, authenticate, initialize_system, main_menu
import blockchain_databases
# Removed CoreRefresher import
# Keeping but commenting out the other imports in case you need them later
from polymorphic_adjuster import BlockAdjuster
from storage import BlockchainStorage

# Global objects that can be imported by other modules
auth_system = None
blockchain = None
adjuster = None
# Removed refresher

def setup_directories():
    """Set up all necessary directories for the blockchain system"""
    # Create main directories
    directories = ["userData", "databases", "security_logs"]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
            
    return True

def check_database_files():
    """Check if necessary database files exist"""
    database_files = ["blockchain_db.json", "blockStorage.json"]
    missing_files = []
    
    for file in database_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    return missing_files

def initialize_blockchain_system():
    """Initialize the entire blockchain system"""
    global auth_system, blockchain
    
    print("\n===== Blockchain System Setup =====")
    
    # Setup all directories
    setup_directories()
    
    # Check for missing database files
    missing_files = check_database_files()
    if missing_files:
        print(f"The following database files are missing: {', '.join(missing_files)}")
        print("These will be created during system initialization.")
    
    # Initialize the blockchain system and get auth_system
    auth_system = initialize_system()
    blockchain = auth_system.blockchain
    adjuster = BlockAdjuster(blockchain)
    
    # Initialize database folders
    blockchain_databases.initialize_database_folders()
    
    print("\nBlockchain system initialized successfully.")
    print("Please login to continue.")
    
    return auth_system, blockchain

def run_system():
    """Run the blockchain system"""
    global auth_system, blockchain, adjuster
    
    # Initialize the system if needed
    if not os.path.exists("blockchain_db.json"):
        auth_system, blockchain = initialize_blockchain_system()
    else:
        # Load existing system
        auth_system = AuthSystem()
        blockchain = auth_system.blockchain
        adjuster = BlockAdjuster(blockchain)
        adjuster.start_timer()    
    # Authenticate user
    username, user_role, auth_system_new = authenticate()
    
    # If authentication successful, show main menu
    if username:
        # Update global auth_system with the one from authentication
        auth_system = auth_system_new
        
        # Show main menu - pass auth_system to main_menu
        main_menu(username, user_role, auth_system, adjuster)

if __name__ == "__main__":
    run_system()