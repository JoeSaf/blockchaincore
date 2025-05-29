#!/usr/bin/env python3
"""
Polymorphic Security & Authentication System
Advanced security system with fallback mechanisms, polymorphic adjustments,
and blockchain-based user management integrated with the C++ blockchain node.
"""

import json
import os
import time
import hashlib
import getpass
import base64
import random
from typing import Dict, List, Optional, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class SecurityBlock:
    """Represents a security operation block"""
    
    def __init__(self, index: int, timestamp: float, data: Dict, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate hash for the security block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert block to dictionary"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class PolymorphicUser:
    """Enhanced user class with cryptographic capabilities"""
    
    def __init__(self, username: str, role: str, private_key=None):
        self.username = username
        self.role = role
        self.created_at = time.time()
        self.last_login = None
        self.login_attempts = 0
        self.is_locked = False
        
        # Generate or load cryptographic keys
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        
        self.public_key = self.private_key.public_key()
        self.initialize_user_environment()
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_private_key_pem(self, password: str = None) -> str:
        """Get private key in PEM format"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ).decode('utf-8')
    
    def sign_message(self, message: str) -> str:
        """Sign a message with the user's private key"""
        message_bytes = message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message: str, signature: str, public_key_pem: str) -> bool:
        """Verify a message signature"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            signature_bytes = base64.b64decode(signature)
            message_bytes = message.encode('utf-8')
            
            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.debug(f"Signature verification failed: {str(e)}")
            return False
    
    def initialize_user_environment(self):
        """Initialize user's secure environment"""
        user_dir = os.path.join("secure_users", self.username)
        os.makedirs(user_dir, exist_ok=True)
        
        # Create user profile
        profile = {
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
            "public_key": self.get_public_key_pem(),
            "security_level": self.get_security_level(),
            "permissions": self.get_role_permissions()
        }
        
        profile_file = os.path.join(user_dir, "profile.json")
        with open(profile_file, "w") as f:
            json.dump(profile, f, indent=2)
    
    def get_security_level(self) -> str:
        """Get security level based on role"""
        security_levels = {
            "admin": "maximum",
            "moderator": "high",
            "user": "standard",
            "guest": "minimal"
        }
        return security_levels.get(self.role, "standard")
    
    def get_role_permissions(self) -> List[str]:
        """Get permissions based on role"""
        permissions_map = {
            "admin": ["read", "write", "delete", "admin", "security", "system"],
            "moderator": ["read", "write", "delete", "moderate"],
            "user": ["read", "write"],
            "guest": ["read"]
        }
        return permissions_map.get(self.role, ["read"])

class PolymorphicSecuritySystem:
    """Advanced security system with adaptive responses"""
    
    def __init__(self, blockchain_bridge):
        self.bridge = blockchain_bridge
        self.security_chain = []
        self.users = {}
        self.active_sessions = {}
        self.security_alerts = []
        self.fallback_mode = False
        
        self.storage_root = "security_storage"
        self.chain_file = os.path.join(self.storage_root, "security_chain.json")
        self.fallback_file = os.path.join(self.storage_root, "fallback_security.json")
        
        self.initialize_security_storage()
        self.load_security_chain()
    
    def initialize_security_storage(self):
        """Initialize security storage directories"""
        os.makedirs(self.storage_root, exist_ok=True)
        os.makedirs("secure_users", exist_ok=True)
        logger.info("Security storage initialized")
    
    def load_security_chain(self):
        """Load the security operation chain"""
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, "r") as f:
                    chain_data = json.load(f)
                
                self.security_chain = []
                for block_data in chain_data:
                    block = SecurityBlock(
                        block_data["index"],
                        block_data["timestamp"],
                        block_data["data"],
                        block_data["previous_hash"]
                    )
                    block.hash = block_data["hash"]
                    self.security_chain.append(block)
                
                logger.info(f"Loaded {len(self.security_chain)} security operations")
                
                # Reconstruct users from chain
                self.reconstruct_users_from_chain()
                
            except Exception as e:
                logger.error(f"Failed to load security chain: {str(e)}")
                self.security_chain = [self.create_genesis_block()]
        else:
            self.security_chain = [self.create_genesis_block()]
        
        self.save_security_chain()
    
    def create_genesis_block(self) -> SecurityBlock:
        """Create genesis security block"""
        return SecurityBlock(
            index=0,
            timestamp=time.time(),
            data={"action": "genesis", "message": "Security Genesis Block"},
            previous_hash="0"
        )
    
    def save_security_chain(self):
        """Save the security chain"""
        try:
            with open(self.chain_file, "w") as f:
                json.dump([block.to_dict() for block in self.security_chain], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save security chain: {str(e)}")
    
    def reconstruct_users_from_chain(self):
        """Reconstruct user data from security chain"""
        self.users = {}
        
        for block in self.security_chain:
            if block.data.get("action") == "register_user":
                username = block.data.get("username")
                role = block.data.get("role")
                public_key = block.data.get("public_key")
                private_key_pem = block.data.get("private_key_pem")
                
                if username and role:
                    self.users[username] = {
                        "role": role,
                        "public_key": public_key,
                        "private_key_pem": private_key_pem,
                        "created_at": block.timestamp,
                        "last_login": None,
                        "login_attempts": 0,
                        "is_locked": False
                    }
    
    def add_security_block(self, block_data: Dict) -> bool:
        """Add a new security operation block"""
        try:
            new_block = SecurityBlock(
                index=len(self.security_chain),
                timestamp=time.time(),
                data=block_data,
                previous_hash=self.security_chain[-1].hash if self.security_chain else "0"
            )
            
            self.security_chain.append(new_block)
            self.save_security_chain()
            
            # Also try to record in C++ blockchain
            try:
                cpp_result = self.bridge.create_transaction(
                    from_addr=block_data.get("username", "security_system"),
                    to_addr="security_system",
                    amount=0.001
                )
                if "error" not in cpp_result:
                    logger.info(f"Security operation recorded in C++ blockchain")
            except Exception as e:
                logger.warning(f"Could not record in C++ blockchain: {str(e)}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to add security block: {str(e)}")
            return False
    
    def register_user(self, username: str, role: str, password: str) -> bool:
        """Register a new user with enhanced security"""
        try:
            if username in self.users:
                logger.warning(f"User '{username}' already exists")
                return False
            
            # Create user with cryptographic keys
            user = PolymorphicUser(username, role)
            
            # Store user data
            self.users[username] = {
                "role": role,
                "public_key": user.get_public_key_pem(),
                "private_key_pem": user.get_private_key_pem(password),
                "created_at": user.created_at,
                "last_login": None,
                "login_attempts": 0,
                "is_locked": False
            }
            
            # Add to security blockchain
            block_data = {
                "action": "register_user",
                "username": username,
                "role": role,
                "public_key": user.get_public_key_pem(),
                "private_key_pem": user.get_private_key_pem(password),
                "timestamp": time.time(),
                "security_level": user.get_security_level()
            }
            
            if self.add_security_block(block_data):
                logger.info(f"User '{username}' registered successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to register user: {str(e)}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> Tuple[Optional[str], Optional[str]]:
        """Authenticate user with enhanced security checks"""
        try:
            if username not in self.users:
                logger.warning(f"Authentication failed: User '{username}' not found")
                return None, None
            
            user_data = self.users[username]
            
            # Check if user is locked
            if user_data.get("is_locked", False):
                logger.warning(f"Authentication failed: User '{username}' is locked")
                return None, None
            
            # Try to decrypt private key with password
            try:
                private_key_pem = user_data["private_key_pem"]
                serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=password.encode('utf-8'),
                    backend=default_backend()
                )
                
                # Authentication successful
                user_data["last_login"] = time.time()
                user_data["login_attempts"] = 0
                
                # Create session
                session_id = self.create_session(username)
                
                # Log authentication
                block_data = {
                    "action": "authenticate",
                    "username": username,
                    "session_id": session_id,
                    "timestamp": time.time(),
                    "ip_address": "localhost"  # In real implementation, get actual IP
                }
                self.add_security_block(block_data)
                
                # Verify security chain integrity
                if not self.verify_security_chain():
                    logger.error("Security chain integrity compromised!")
                    self.trigger_security_response("chain_integrity_breach")
                
                logger.info(f"User '{username}' authenticated successfully")
                return username, user_data["role"]
                
            except Exception:
                # Authentication failed
                user_data["login_attempts"] += 1
                
                # Lock user after too many failed attempts
                if user_data["login_attempts"] >= 5:
                    user_data["is_locked"] = True
                    logger.warning(f"User '{username}' locked due to multiple failed attempts")
                    
                    # Log security event
                    block_data = {
                        "action": "user_locked",
                        "username": username,
                        "reason": "multiple_failed_attempts",
                        "timestamp": time.time()
                    }
                    self.add_security_block(block_data)
                
                logger.warning(f"Authentication failed for user '{username}'")
                return None, None
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None, None
    
    def create_session(self, username: str) -> str:
        """Create a secure session for authenticated user"""
        session_id = hashlib.sha256(f"{username}{time.time()}{random.random()}".encode()).hexdigest()
        
        self.active_sessions[session_id] = {
            "username": username,
            "created_at": time.time(),
            "last_activity": time.time(),
            "permissions": self.users[username].get("role", "user")
        }
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """Validate an active session"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Check session timeout (1 hour)
        if time.time() - session["last_activity"] > 3600:
            del self.active_sessions[session_id]
            return None
        
        # Update last activity
        session["last_activity"] = time.time()
        return session["username"]
    
    def verify_security_chain(self) -> bool:
        """Verify integrity of the security chain"""
        try:
            if len(self.security_chain) <= 1:
                return True
            
            for i in range(1, len(self.security_chain)):
                current_block = self.security_chain[i]
                previous_block = self.security_chain[i-1]
                
                # Verify hash
                if current_block.hash != current_block.calculate_hash():
                    logger.error(f"Hash mismatch in security block {i}")
                    return False
                
                # Verify chain linkage
                if current_block.previous_hash != previous_block.hash:
                    logger.error(f"Chain linkage broken at block {i}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Security chain verification failed: {str(e)}")
            return False
    
    def trigger_security_response(self, threat_type: str):
        """Trigger polymorphic security response"""
        logger.warning(f"Security threat detected: {threat_type}")
        
        response_data = {
            "threat_type": threat_type,
            "timestamp": time.time(),
            "response_actions": []
        }
        
        if threat_type == "chain_integrity_breach":
            # Activate fallback mode
            self.fallback_mode = True
            response_data["response_actions"].append("fallback_mode_activated")
            
            # Create fallback security database
            self.create_fallback_security_db()
            response_data["response_actions"].append("fallback_db_created")
            
            # Attempt chain repair
            if self.attempt_chain_repair():
                response_data["response_actions"].append("chain_repair_successful")
                self.fallback_mode = False
            else:
                response_data["response_actions"].append("chain_repair_failed")
        
        # Log security response
        block_data = {
            "action": "security_response",
            "threat_type": threat_type,
            "response_data": response_data,
            "timestamp": time.time()
        }
        self.add_security_block(block_data)
        
        # Add to security alerts
        self.security_alerts.append(response_data)
    
    def create_fallback_security_db(self):
        """Create fallback security database"""
        try:
            fallback_data = {
                "created_at": time.time(),
                "reason": "security_chain_breach",
                "users": {},
                "active_sessions": self.active_sessions.copy()
            }
            
            # Copy user data to fallback
            for username, user_data in self.users.items():
                fallback_data["users"][username] = {
                    "role": user_data["role"],
                    "public_key": user_data["public_key"],
                    "created_at": user_data["created_at"],
                    "migrated_at": time.time()
                }
            
            with open(self.fallback_file, "w") as f:
                json.dump(fallback_data, f, indent=2)
            
            logger.info(f"Fallback security database created with {len(fallback_data['users'])} users")
            
        except Exception as e:
            logger.error(f"Failed to create fallback security database: {str(e)}")
    
    def attempt_chain_repair(self) -> bool:
        """Attempt to repair the security chain"""
        try:
            # Simple repair: recalculate all hashes
            if len(self.security_chain) > 1:
                for i in range(1, len(self.security_chain)):
                    self.security_chain[i].previous_hash = self.security_chain[i-1].hash
                    self.security_chain[i].hash = self.security_chain[i].calculate_hash()
                
                self.save_security_chain()
                logger.info("Security chain repair completed")
                return True
            
            return True
            
        except Exception as e:
            logger.error(f"Chain repair failed: {str(e)}")
            return False
    
    def get_security_stats(self) -> Dict:
        """Get security system statistics"""
        return {
            "total_users": len(self.users),
            "active_sessions": len(self.active_sessions),
            "security_operations": len(self.security_chain),
            "security_alerts": len(self.security_alerts),
            "fallback_mode": self.fallback_mode,
            "chain_integrity": self.verify_security_chain(),
            "locked_users": sum(1 for user in self.users.values() if user.get("is_locked", False))
        }

# Utility functions
def initialize_security_system(blockchain_bridge) -> PolymorphicSecuritySystem:
    """Initialize the security system with default admin user"""
    security_system = PolymorphicSecuritySystem(blockchain_bridge)
    
    # Create admin user if no users exist
    if len(security_system.users) == 0:
        print("🔐 Initializing security system with admin user...")
        admin_password = getpass.getpass("Create admin password: ")
        
        if security_system.register_user("admin", "admin", admin_password):
            print("✅ Admin user created successfully")
        else:
            print("❌ Failed to create admin user")
    
    return security_system

def demonstrate_security_features(security_system: PolymorphicSecuritySystem):
    """Demonstrate security system features"""
    print("\n🔐 Polymorphic Security System Demo")
    print("=" * 50)
    
    # Show security stats
    print("1. Security System Statistics:")
    stats = security_system.get_security_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Test user authentication
    print("\n2. Testing User Authentication:")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    user, role = security_system.authenticate_user(username, password)
    if user:
        print(f"✅ Authentication successful: {user} ({role})")
        
        # Create and validate session
        session_id = security_system.create_session(user)
        print(f"   Session ID: {session_id[:16]}...")
        
        # Validate session
        validated_user = security_system.validate_session(session_id)
        if validated_user:
            print(f"✅ Session validated for: {validated_user}")
        else:
            print("❌ Session validation failed")
    else:
        print("❌ Authentication failed")
    
    # Test security chain integrity
    print("\n3. Verifying Security Chain Integrity:")
    if security_system.verify_security_chain():
        print("✅ Security chain integrity verified")
    else:
        print("❌ Security chain integrity compromised")
    
    # Show recent security operations
    print("\n4. Recent Security Operations:")
    recent_ops = security_system.security_chain[-5:] if len(security_system.security_chain) > 5 else security_system.security_chain
    for block in recent_ops:
        action = block.data.get("action", "unknown")
        username = block.data.get("username", "system")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block.timestamp))
        print(f"   Block #{block.index}: {action} - {username} ({timestamp})")

def security_management_interface(security_system: PolymorphicSecuritySystem):
    """Interactive security management interface"""
    while True:
        print("\n🔐 Security Management Interface")
        print("1. Register New User")
        print("2. List All Users")
        print("3. View Security Statistics")
        print("4. Check Security Chain Integrity")
        print("5. View Security Alerts")
        print("6. Unlock User Account")
        print("7. Create Security Backup")
        print("8. Test Security Response")
        print("9. Return to Main Menu")
        
        choice = input("\nEnter your choice: ")
        
        if choice == "1":
            username = input("Enter username: ")
            role = input("Enter role (admin/moderator/user/guest): ")
            password = getpass.getpass("Enter password: ")
            
            if security_system.register_user(username, role, password):
                print(f"✅ User '{username}' registered successfully")
            else:
                print(f"❌ Failed to register user '{username}'")
        
        elif choice == "2":
            print("\n👥 Registered Users:")
            for username, user_data in security_system.users.items():
                status = "🔒 LOCKED" if user_data.get("is_locked", False) else "🔓 ACTIVE"
                last_login = user_data.get("last_login")
                last_login_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_login)) if last_login else "Never"
                print(f"   {username} ({user_data['role']}) - {status} - Last Login: {last_login_str}")
        
        elif choice == "3":
            print("\n📊 Security Statistics:")
            stats = security_system.get_security_stats()
            for key, value in stats.items():
                print(f"   {key.replace('_', ' ').title()}: {value}")
        
        elif choice == "4":
            print("\n🔍 Checking Security Chain Integrity...")
            if security_system.verify_security_chain():
                print("✅ Security chain integrity verified")
            else:
                print("❌ Security chain integrity compromised")
                print("   Triggering security response...")
                security_system.trigger_security_response("manual_integrity_check")
        
        elif choice == "5":
            print("\n🚨 Security Alerts:")
            if security_system.security_alerts:
                for i, alert in enumerate(security_system.security_alerts, 1):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert["timestamp"]))
                    print(f"   Alert #{i}: {alert['threat_type']} - {timestamp}")
                    print(f"      Actions: {', '.join(alert['response_actions'])}")
            else:
                print("   No security alerts")
        
        elif choice == "6":
            username = input("Enter username to unlock: ")
            if username in security_system.users:
                security_system.users[username]["is_locked"] = False
                security_system.users[username]["login_attempts"] = 0
                
                # Log unlock action
                block_data = {
                    "action": "user_unlocked",
                    "username": username,
                    "unlocked_by": "admin",  # In real implementation, get current user
                    "timestamp": time.time()
                }
                security_system.add_security_block(block_data)
                
                print(f"✅ User '{username}' unlocked successfully")
            else:
                print(f"❌ User '{username}' not found")
        
        elif choice == "7":
            backup_file = f"security_backup_{int(time.time())}.json"
            try:
                backup_data = {
                    "backup_timestamp": time.time(),
                    "users": security_system.users,
                    "security_chain": [block.to_dict() for block in security_system.security_chain],
                    "security_alerts": security_system.security_alerts,
                    "active_sessions": security_system.active_sessions
                }
                
                with open(backup_file, "w") as f:
                    json.dump(backup_data, f, indent=2)
                
                print(f"✅ Security backup created: {backup_file}")
            except Exception as e:
                print(f"❌ Failed to create backup: {str(e)}")
        
        elif choice == "8":
            print("\n🧪 Testing Security Response...")
            threat_type = input("Enter threat type (chain_integrity_breach/unauthorized_access/ddos_attack): ")
            security_system.trigger_security_response(threat_type)
            print("✅ Security response triggered")
        
        elif choice == "9":
            break
        
        else:
            print("❌ Invalid choice")

class SecurityMiddleware:
    """Middleware for integrating security with other systems"""
    
    def __init__(self, security_system: PolymorphicSecuritySystem):
        self.security_system = security_system
    
    def require_authentication(self, session_id: str) -> Optional[Dict]:
        """Middleware to require authentication"""
        username = self.security_system.validate_session(session_id)
        if not username:
            return None
        
        return {
            "username": username,
            "role": self.security_system.users[username]["role"],
            "permissions": self.get_user_permissions(username)
        }
    
    def require_permission(self, session_id: str, required_permission: str) -> bool:
        """Check if user has required permission"""
        user_info = self.require_authentication(session_id)
        if not user_info:
            return False
        
        return required_permission in user_info["permissions"]
    
    def get_user_permissions(self, username: str) -> List[str]:
        """Get user permissions"""
        if username not in self.security_system.users:
            return []
        
        role = self.security_system.users[username]["role"]
        user = PolymorphicUser(username, role)
        return user.get_role_permissions()
    
    def log_security_event(self, event_type: str, username: str, details: Dict = None):
        """Log a security event"""
        block_data = {
            "action": "security_event",
            "event_type": event_type,
            "username": username,
            "details": details or {},
            "timestamp": time.time()
        }
        self.security_system.add_security_block(block_data)

def create_security_decorator(security_middleware: SecurityMiddleware):
    """Create decorator for securing functions"""
    def security_decorator(required_permission: str = None):
        def decorator(func):
            def wrapper(*args, **kwargs):
                session_id = kwargs.get('session_id')
                if not session_id:
                    raise ValueError("Session ID required")
                
                if required_permission:
                    if not security_middleware.require_permission(session_id, required_permission):
                        raise PermissionError(f"Permission '{required_permission}' required")
                else:
                    if not security_middleware.require_authentication(session_id):
                        raise PermissionError("Authentication required")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    return security_decorator

if __name__ == "__main__":
    # Demo the security system
    from blockchain_bridge import BlockchainBridge
    
    print("🔐 Starting Polymorphic Security System...")
    
    # Initialize bridge (may not connect to actual C++ node in demo)
    bridge = BlockchainBridge()
    
    # Initialize security system
    security_system = initialize_security_system(bridge)
    
    # Run demonstration
    demonstrate_security_features(security_system)
    
    # Interactive management interface
    security_management_interface(security_system)
    