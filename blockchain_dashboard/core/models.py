# core/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json

class UserProfile(models.Model):
    """Extended user profile for blockchain system"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[
        ('admin', 'Administrator'),
        ('user', 'Standard User'),
        ('readonly', 'Read Only'),
    ], default='user')
    
    created_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(auto_now=True)
    is_locked = models.BooleanField(default=False)
    locked_reason = models.TextField(blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    login_attempts = models.IntegerField(default=0)
    
    # Blockchain specific fields
    wallet_address = models.CharField(max_length=100, blank=True)
    total_operations = models.IntegerField(default=0)
    successful_operations = models.IntegerField(default=0)
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"
    
    @property
    def success_rate(self):
        if self.total_operations == 0:
            return 0
        return (self.successful_operations / self.total_operations) * 100

class SystemMetrics(models.Model):
    """System performance and usage metrics"""
    timestamp = models.DateTimeField(default=timezone.now)
    
    # System metrics
    total_operations = models.IntegerField(default=0)
    errors_count = models.IntegerField(default=0)
    average_response_time = models.FloatField(default=0.0)
    active_users = models.IntegerField(default=0)
    
    # Database metrics
    total_databases = models.IntegerField(default=0)
    total_files = models.IntegerField(default=0)
    total_storage_mb = models.FloatField(default=0.0)
    
    # Network metrics
    connected_peers = models.IntegerField(default=0)
    network_health = models.FloatField(default=0.0)
    
    # Security metrics
    security_alerts = models.IntegerField(default=0)
    failed_logins = models.IntegerField(default=0)
    locked_users = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"System Metrics - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

class ActivityLog(models.Model):
    """Log of all system activities"""
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('database_created', 'Database Created'),
        ('database_deleted', 'Database Deleted'),
        ('file_uploaded', 'File Uploaded'),
        ('file_deleted', 'File Deleted'),
        ('mining_started', 'Mining Started'),
        ('transaction_created', 'Transaction Created'),
        ('security_alert', 'Security Alert'),
        ('system_maintenance', 'System Maintenance'),
        ('config_changed', 'Configuration Changed'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Additional context data (JSON)
    context_data = models.JSONField(default=dict, blank=True)
    
    # Success/failure tracking
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
    
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.get_action_display()} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

class DatabaseUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Add other fields as needed
    created_at = models.DateTimeField(auto_now_add=True)
    # Add any other fields your blockchain dashboard needs
    
    def __str__(self):
        return f"DatabaseUser: {self.user.username}"
    
    
class DatabaseInfo(models.Model):
    """Information about blockchain databases"""
    name = models.CharField(max_length=100, unique=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)
    
    # Database metadata
    description = models.TextField(blank=True)
    schema_data = models.JSONField(default=dict, blank=True)
    path = models.CharField(max_length=255)
    
    # Statistics
    total_files = models.IntegerField(default=0)
    total_size_mb = models.FloatField(default=0.0)
    total_users = models.IntegerField(default=0)
    total_operations = models.IntegerField(default=0)
    
    # Status
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} (Owner: {self.owner.username})"

class FileUpload(models.Model):
    """File upload tracking"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('quarantined', 'Quarantined'),
        ('rejected', 'Rejected'),
    ]
    
    upload_id = models.CharField(max_length=64, unique=True)
    original_filename = models.CharField(max_length=255)
    stored_filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)
    database = models.ForeignKey(DatabaseInfo, on_delete=models.CASCADE, null=True, blank=True)
    
    uploaded_at = models.DateTimeField(default=timezone.now)
    file_size = models.BigIntegerField()
    file_type = models.CharField(max_length=50)
    mime_type = models.CharField(max_length=100)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    threats_detected = models.JSONField(default=list, blank=True)
    
    # Security scanning results
    scan_completed = models.BooleanField(default=False)
    scan_results = models.JSONField(default=dict, blank=True)
    
    # Approval workflow
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_files')
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['uploader', 'uploaded_at']),
            models.Index(fields=['status', 'uploaded_at']),
        ]
    
    def __str__(self):
        return f"{self.original_filename} - {self.uploader.username} - {self.status}"
class SystemStatus(models.Model):
    """Real-time system status shared between components"""
    cpp_node_status = models.JSONField(default=dict)
    coordinator_status = models.JSONField(default=dict)
    last_updated = models.DateTimeField(auto_now=True)
    
class LiveMetrics(models.Model):
    """Live system metrics"""
    metric_type = models.CharField(max_length=50)
    metric_value = models.JSONField()
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        indexes = [
            models.Index(fields=['metric_type', '-timestamp'])
        ]
        
        
class SecurityAlert(models.Model):
    """Security alerts and notifications"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    ALERT_TYPES = [
        ('failed_login', 'Failed Login'),
        ('account_locked', 'Account Locked'),
        ('suspicious_file', 'Suspicious File'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('system_breach', 'System Breach'),
        ('malware_detected', 'Malware Detected'),
        ('unusual_activity', 'Unusual Activity'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    
    # Related objects
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    # Alert data
    alert_data = models.JSONField(default=dict, blank=True)
    
    # Status tracking
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['is_resolved', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.get_severity_display()} - {self.title} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"