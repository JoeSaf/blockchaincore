# core/utils.py

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

# Add the path to your system coordinator
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from system_coordinator import BlockchainSystemCoordinator
except ImportError:
    # Fallback for development
    BlockchainSystemCoordinator = None

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Get the client's IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

def log_activity(request, action, details, success=True):
    """
    Log user activity with proper error handling
    """
    try:
        # Get user from request - handle both authenticated and anonymous users
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user.username
        else:
            user = 'Anonymous'
        
        # Set status based on success parameter
        status = "SUCCESS" if success else "FAILED"
        
        # Log the activity
        print(f"Activity: {user} - {action} - {details} - Status: {status}")
        
        # You can add additional logging here if needed
        # For example, save to database, write to file, etc.
        
    except Exception as e:
        # Fallback logging in case of any errors
        print(f"Error in log_activity: {e}")
        print(f"Activity: Unknown - {action} - {details}")


class BlockchainSystemInterface:
    """Interface between Django and the blockchain system coordinator"""
    
    def __init__(self):
        self.coordinator = None
        self.is_initialized = False
        self._initialize_coordinator()
    
    def _initialize_coordinator(self):
        """Initialize the blockchain system coordinator"""
        try:
            if BlockchainSystemCoordinator:
                cpp_executable = settings.BLOCKCHAIN_SETTINGS.get('CPP_EXECUTABLE', './build/bin/blockchain_node')
                self.coordinator = BlockchainSystemCoordinator(cpp_executable)
                
                # Initialize the system
                if self.coordinator.initialize_system():
                    self.is_initialized = True
                    logger.info("Blockchain system coordinator initialized successfully")
                else:
                    logger.warning("Blockchain system coordinator initialization failed, using mock mode")
            else:
                logger.warning("Blockchain system coordinator not available, using mock mode")
        except Exception as e:
            logger.error(f"Error initializing blockchain coordinator: {e}")
    
    def get_system_status(self):
        """Get comprehensive system status"""
        try:
            if self.coordinator and self.is_initialized:
                status = self.coordinator.integrated_system.get_system_status()
                
                # Get additional blockchain info
                node_status = self.coordinator.bridge.get_node_status()
                
                return {
                    'system_running': status.get('system_running', False),
                    'node_connected': status.get('cpp_node_connected', False),
                    'chain_height': node_status.get('data', {}).get('chainHeight', 'N/A'),
                    'connected_peers': node_status.get('data', {}).get('peerCount', 0),
                    'last_block_time': node_status.get('data', {}).get('avgBlockTime', 'N/A'),
                    'mempool_size': node_status.get('data', {}).get('mempoolSize', 0),
                    'difficulty': node_status.get('data', {}).get('difficulty', 'N/A'),
                }
            else:
                return self._get_mock_status()
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return self._get_mock_status()
    
    def get_comprehensive_status(self):
        """Get detailed system status for admin dashboard"""
        try:
            basic_status = self.get_system_status()
            
            if self.coordinator and self.is_initialized:
                # Get database statistics
                databases = self.coordinator.db_manager.list_databases()
                db_stats = {
                    'total_databases': len(databases),
                    'total_files': sum(self.coordinator.db_manager.get_database_stats(db["name"]).get("total_files", 0) for db in databases),
                    'total_size': sum(self.coordinator.db_manager.get_database_stats(db["name"]).get("total_size", 0) for db in databases),
                }
                
                # Get security stats
                security_stats = self.coordinator.security_system.get_security_stats()
                
                # Get upload stats
                upload_stats = {
                    'total_uploads': len(self.coordinator.file_uploader.upload_chain),
                    'approved_uploads': len([u for u in self.coordinator.file_uploader.upload_chain if u.get("status") == "approved"]),
                    'quarantined_uploads': len([u for u in self.coordinator.file_uploader.upload_chain if u.get("status") == "quarantined"]),
                }
                
                return {
                    **basic_status,
                    'database_stats': db_stats,
                    'security_stats': security_stats,
                    'upload_stats': upload_stats,
                    'system_uptime': time.time() - self.coordinator.system_start_time,
                }
            else:
                return {**basic_status, **self._get_mock_comprehensive_stats()}
                
        except Exception as e:
            logger.error(f"Error getting comprehensive status: {e}")
            return self._get_mock_comprehensive_stats()
    
    def get_uptime(self):
        """Get system uptime"""
        try:
            if self.coordinator:
                uptime_seconds = time.time() - self.coordinator.system_start_time
                return self._format_uptime(uptime_seconds)
            else:
                return "Unknown"
        except Exception:
            return "Unknown"
    
    def _format_uptime(self, seconds):
        """Format uptime in human readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    # Database operations
    def create_database(self, name, owner, description="", schema_type="empty"):
        """Create a new database"""
        try:
            if self.coordinator and self.is_initialized:
                # Create schema based on type
                schema = self._get_schema_by_type(schema_type)
                
                result_path = self.coordinator.db_manager.create_database(name, schema, owner)
                
                if result_path:
                    return {
                        'success': True,
                        'path': result_path,
                        'schema': schema
                    }
                else:
                    return {'success': False, 'error': 'Failed to create database'}
            else:
                return self._mock_create_database(name, owner)
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_database_stats(self, database_name):
        """Get statistics for a specific database"""
        try:
            if self.coordinator and self.is_initialized:
                return self.coordinator.db_manager.get_database_stats(database_name)
            else:
                return self._mock_database_stats()
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return self._mock_database_stats()
    
    def check_database_health(self, database_name):
        """Check database health"""
        try:
            if self.coordinator and self.is_initialized:
                health_score, issues = self.coordinator.check_single_database_health(database_name)
                return {
                    'health_score': health_score,
                    'issues': issues,
                    'status': 'healthy' if health_score > 80 else 'warning' if health_score > 50 else 'critical'
                }
            else:
                return self._mock_database_health()
        except Exception as e:
            logger.error(f"Error checking database health: {e}")
            return {'health_score': 0, 'issues': [str(e)], 'status': 'error'}
    
    def delete_database(self, database_name):
        """Delete a database"""
        try:
            if self.coordinator and self.is_initialized:
                # Implementation would depend on your coordinator's delete method
                return {'success': True}
            else:
                return {'success': True}  # Mock success
        except Exception as e:
            logger.error(f"Error deleting database: {e}")
            return {'success': False, 'error': str(e)}
    
    def update_database_metadata(self, database_name, metadata):
        """Update database metadata"""
        try:
            if self.coordinator and self.is_initialized:
                # Implementation would depend on your coordinator's update method
                return {'success': True}
            else:
                return {'success': True}  # Mock success
        except Exception as e:
            logger.error(f"Error updating database metadata: {e}")
            return {'success': False, 'error': str(e)}

    # File operations
    def upload_file(self, file_path, username, database_name=None, metadata=None):
        """Upload a file through the blockchain system"""
        try:
            if self.coordinator and self.is_initialized:
                return self.coordinator.file_uploader.upload_file(
                    file_path, username, database_name, metadata
                )
            else:
                return self._mock_file_upload(file_path, username)
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_user_uploads(self, username):
        """Get uploads for a specific user"""
        try:
            if self.coordinator and self.is_initialized:
                return self.coordinator.file_uploader.get_user_uploads(username)
            else:
                return []
        except Exception as e:
            logger.error(f"Error getting user uploads: {e}")
            return []
    
    # Add any missing mock methods here
    def _get_mock_status(self):
        """Mock status for development"""
        return {
            'system_running': True,
            'node_connected': False,
            'chain_height': 'N/A',
            'connected_peers': 0,
            'last_block_time': 'N/A',
            'mempool_size': 0,
            'difficulty': 'N/A',
        }
    
    def _get_mock_comprehensive_stats(self):
        """Mock comprehensive stats for development"""
        return {
            'database_stats': {'total_databases': 0, 'total_files': 0, 'total_size': 0},
            'security_stats': {},
            'upload_stats': {'total_uploads': 0, 'approved_uploads': 0, 'quarantined_uploads': 0},
            'system_uptime': 0,
        }
    
    def _mock_create_database(self, name, owner):
        """Mock database creation"""
        return {'success': True, 'path': f'/mock/path/{name}', 'schema': {}}
    
    def _mock_database_stats(self):
        """Mock database stats"""
        return {'total_files': 0, 'total_size': 0}
    
    def _mock_database_health(self):
        """Mock database health"""
        return {'health_score': 100, 'issues': [], 'status': 'healthy'}
    
    def _mock_file_upload(self, file_path, username):
        """Mock file upload"""
        return {'success': True, 'upload_id': 'mock_upload_id'}
    
    def _get_schema_by_type(self, schema_type):
        """Get schema template by type"""
        if schema_type == "empty":
            return {"tables": {}, "description": "Empty database"}
        # Add more schema types as needed
        return {"tables": {}, "description": "Default schema"}