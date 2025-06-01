# management/commands/setup_blockchain.py

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.conf import settings
import os
import json

class Command(BaseCommand):
    help = 'Setup blockchain dashboard with initial data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-admin',
            action='store_true',
            help='Create admin user',
        )
        parser.add_argument(
            '--admin-username',
            type=str,
            default='admin',
            help='Admin username',
        )
        parser.add_argument(
            '--admin-password',
            type=str,
            default='admin',
            help='Admin password',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Setting up Blockchain Dashboard...'))
        
        # Create required directories
        self.create_directories()
        
        # Create admin user if requested
        if options['create_admin']:
            self.create_admin_user(options['admin_username'], options['admin_password'])
        
        # Initialize blockchain storage
        self.initialize_storage()
        
        # Create sample data
        self.create_sample_data()
        
        self.stdout.write(self.style.SUCCESS('Setup completed successfully!'))

    def create_directories(self):
        """Create required directories for blockchain storage"""
        directories = [
            settings.BLOCKCHAIN_SETTINGS['STORAGE_ROOT'],
            settings.BLOCKCHAIN_SETTINGS['DATABASE_ROOT'],
            settings.BLOCKCHAIN_SETTINGS['UPLOAD_ROOT'],
            settings.BLOCKCHAIN_SETTINGS['BACKUP_ROOT'],
            'logs',
            'exports',
            'static/uploads',
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            self.stdout.write(f'Created directory: {directory}')

    def create_admin_user(self, username, password):
        """Create admin user"""
        from core.models import UserProfile
        
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'Admin user "{username}" already exists'))
            return
        
        admin_user = User.objects.create_superuser(
            username=username,
            email='admin@blockchain.local',
            password=password,
            first_name='System',
            last_name='Administrator'
        )
        
        UserProfile.objects.create(
            user=admin_user,
            role='admin',
            wallet_address=f'admin_wallet_{admin_user.id}'
        )
        
        self.stdout.write(self.style.SUCCESS(f'Created admin user: {username}'))

    def initialize_storage(self):
        """Initialize blockchain storage structure"""
        storage_config = {
            'version': '1.0',
            'created_at': '2025-01-30',
            'storage_root': str(settings.BLOCKCHAIN_SETTINGS['STORAGE_ROOT']),
            'databases': {},
            'system_settings': {
                'auto_backup': True,
                'retention_days': 30,
                'max_database_size': '1GB'
            }
        }
        
        config_file = os.path.join(settings.BLOCKCHAIN_SETTINGS['STORAGE_ROOT'], 'storage_config.json')
        with open(config_file, 'w') as f:
            json.dump(storage_config, f, indent=2)
        
        self.stdout.write('Initialized blockchain storage configuration')

    def create_sample_data(self):
        """Create sample databases and data for demonstration"""
        from core.models import DatabaseInfo, SystemMetrics
        from django.utils import timezone
        import random
        
        # Create sample system metrics
        for i in range(24):  # Last 24 hours
            timestamp = timezone.now() - timezone.timedelta(hours=i)
            SystemMetrics.objects.get_or_create(
                timestamp=timestamp,
                defaults={
                    'total_operations': random.randint(100, 500),
                    'errors_count': random.randint(0, 10),
                    'average_response_time': random.uniform(0.1, 0.5),
                    'active_users': random.randint(1, 5),
                    'total_databases': random.randint(3, 8),
                    'total_files': random.randint(50, 200),
                    'total_storage_mb': random.uniform(100, 1000),
                    'connected_peers': random.randint(2, 6),
                    'network_health': random.uniform(80, 100),
                    'security_alerts': random.randint(0, 3),
                    'failed_logins': random.randint(0, 5),
                    'locked_users': random.randint(0, 1),
                }
            )
        
        self.stdout.write('Created sample system metrics')

# core/middleware.py

from django.utils import timezone
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from .models import UserProfile, ActivityLog

class BlockchainAuthMiddleware:
    """Custom middleware for blockchain system authentication and activity tracking"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Update user activity
        if request.user.is_authenticated:
            self.update_user_activity(request)
            
            # Check if user is locked
            if self.check_user_locked(request):
                return self.handle_locked_user(request)
        
        response = self.get_response(request)
        return response

    def update_user_activity(self, request):
        """Update user's last activity timestamp"""
        try:
            profile, created = UserProfile.objects.get_or_create(user=request.user)
            profile.last_activity = timezone.now()
            profile.save(update_fields=['last_activity'])
        except Exception:
            pass  # Silently fail to avoid breaking the request

    def check_user_locked(self, request):
        """Check if user account is locked"""
        try:
            profile = request.user.userprofile
            return profile.is_locked
        except UserProfile.DoesNotExist:
            return False

    def handle_locked_user(self, request):
        """Handle locked user access"""
        from django.contrib.auth import logout
        
        logout(request)
        messages.error(request, 'Your account has been locked. Please contact an administrator.')
        return redirect('login')

# core/context_processors.py

from django.conf import settings
from .models import SecurityAlert, UserProfile
from .utils import BlockchainSystemInterface

def blockchain_context(request):
    """Add blockchain-specific context to all templates"""
    context = {
        'blockchain_settings': settings.BLOCKCHAIN_SETTINGS,
        'notifications_count': 0,
        'blockchain_status': {
            'node_connected': False,
        }
    }
    
    if request.user.is_authenticated:
        try:
            # Get unresolved security alerts count
            if request.user.userprofile.role == 'admin':
                context['notifications_count'] = SecurityAlert.objects.filter(is_resolved=False).count()
            else:
                context['notifications_count'] = SecurityAlert.objects.filter(
                    user=request.user, 
                    is_resolved=False
                ).count()
            
            # Get blockchain status
            blockchain_system = BlockchainSystemInterface()
            status = blockchain_system.get_system_status()
            context['blockchain_status'] = status
            
        except Exception:
            pass  # Silently fail
    
    return context

# core/api_urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('system-metrics/', views.api_system_metrics, name='api_system_metrics'),
    path('recent-activities/', views.api_recent_activities, name='api_recent_activities'),
    path('resolve-alert/<int:alert_id>/', views.api_resolve_alert, name='api_resolve_alert'),
]

# core/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.user_profile, name='user_profile'),
    path('system-status/', views.system_status, name='system_status'),
    path('system-settings/', views.system_settings, name='system_settings'),
    path('activity-log/', views.activity_log, name='activity_log'),
    path('notifications/', views.notifications, name='notifications'),
    path('search/', views.search, name='search'),
]

# databases/urls.py

from django.urls import path
from . import views

app_name = 'databases'

urlpatterns = [
    path('', views.database_list, name='list'),
    path('create/', views.database_create, name='create'),
    path('<int:database_id>/', views.database_detail, name='detail'),
    path('<int:database_id>/edit/', views.database_edit, name='edit'),
    path('<int:database_id>/delete/', views.database_delete, name='delete'),
    path('<int:database_id>/users/', views.database_users, name='users'),
    path('<int:database_id>/add-user/', views.database_add_user, name='add_user'),
    path('<int:database_id>/analytics/', views.database_analytics, name='analytics'),
    path('<int:database_id>/backup/', views.database_backup, name='backup'),
]

# files/urls.py

from django.urls import path
from . import views

app_name = 'files'

urlpatterns = [
    path('', views.file_list, name='list'),
    path('upload/', views.file_upload, name='upload'),
    path('<int:file_id>/', views.file_detail, name='detail'),
    path('<int:file_id>/download/', views.file_download, name='download'),
    path('<int:file_id>/delete/', views.file_delete, name='delete'),
    path('quarantined/', views.quarantined_files, name='quarantined'),
    path('<int:file_id>/approve/', views.approve_file, name='approve'),
]

# Complete requirements.txt

Django==4.2.7
djangorestframework==3.14.0
django-crispy-forms==2.0
crispy-bootstrap4==2022.1
django-tables2==2.5.3
django-filter==23.3
django-widget-tweaks==1.5.0
celery==5.3.4
redis==5.0.1
channels==4.0.0
channels-redis==4.1.0
psutil==5.9.6
Pillow==10.1.0
python-magic==0.4.27
cryptography==41.0.7
requests==2.31.0
plotly==5.17.0
pandas==2.1.4
numpy==1.25.2

# Docker configuration (docker-compose.yml)

version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: blockchain_dashboard
      POSTGRES_USER: blockchain
      POSTGRES_PASSWORD: blockchain123
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  web:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
    volumes:
      - .:/app
      - blockchain_storage:/app/blockchain_storage
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis
    environment:
      - DEBUG=1
      - DATABASE_URL=postgresql://blockchain:blockchain123@db:5432/blockchain_dashboard

  celery:
    build: .
    command: celery -A blockchain_dashboard worker -l info
    volumes:
      - .:/app
      - blockchain_storage:/app/blockchain_storage
    depends_on:
      - db
      - redis
    environment:
      - DATABASE_URL=postgresql://blockchain:blockchain123@db:5432/blockchain_dashboard

volumes:
  postgres_data:
  blockchain_storage:

# Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create necessary directories
RUN mkdir -p logs blockchain_storage static media

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Additional Model Files

# databases/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from core.models import DatabaseInfo

class DatabaseUser(models.Model):
    """Users with access to specific databases"""
    ROLE_CHOICES = [
        ('readonly', 'Read Only'),
        ('user', 'Standard User'),
        ('admin', 'Administrator'),
        ('owner', 'Owner'),
    ]
    
    database = models.ForeignKey(DatabaseInfo, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    permissions = models.JSONField(default=list)
    
    added_at = models.DateTimeField(default=timezone.now)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='added_database_users')
    
    class Meta:
        unique_together = ['database', 'user']
    
    def __str__(self):
        return f"{self.user.username} - {self.database.name} ({self.role})"

class DatabaseSchema(models.Model):
    """Database schema definitions"""
    database = models.OneToOneField(DatabaseInfo, on_delete=models.CASCADE)
    schema_data = models.JSONField(default=dict)
    version = models.CharField(max_length=20, default='1.0')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Schema for {self.database.name}"

class DatabaseBackup(models.Model):
    """Database backup records"""
    BACKUP_TYPES = [
        ('full', 'Full Backup'),
        ('incremental', 'Incremental'),
        ('schema_only', 'Schema Only'),
    ]
    
    database = models.ForeignKey(DatabaseInfo, on_delete=models.CASCADE)
    backup_type = models.CharField(max_length=20, choices=BACKUP_TYPES)
    file_path = models.CharField(max_length=500)
    file_size = models.BigIntegerField(default=0)
    
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    include_files = models.BooleanField(default=True)
    compression_ratio = models.FloatField(default=0.0)
    
    # Backup metadata
    backup_metadata = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.database.name} - {self.backup_type} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

# files/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from core.models import DatabaseInfo

class FileCategory(models.Model):
    """File categories for organization"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default='#007bff')  # Hex color
    
    def __str__(self):
        return self.name

class FileUploadBatch(models.Model):
    """Batch upload tracking"""
    batch_id = models.CharField(max_length=64, unique=True)
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    total_files = models.IntegerField(default=0)
    successful_uploads = models.IntegerField(default=0)
    failed_uploads = models.IntegerField(default=0)
    
    def __str__(self):
        return f"Batch {self.batch_id} - {self.uploader.username}"

class FileTag(models.Model):
    """Tags for file organization"""
    name = models.CharField(max_length=50, unique=True)
    color = models.CharField(max_length=7, default='#6c757d')
    
    def __str__(self):
        return self.name

# transactions/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Transaction(models.Model):
    """Blockchain transactions"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    transaction_id = models.CharField(max_length=64, unique=True)
    from_address = models.CharField(max_length=100)
    to_address = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=20, decimal_places=8)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    
    # Blockchain specific data
    block_hash = models.CharField(max_length=64, blank=True)
    block_index = models.IntegerField(null=True, blank=True)
    gas_fee = models.DecimalField(max_digits=20, decimal_places=8, default=0)
    
    # User and metadata
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField(blank=True)
    transaction_data = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.transaction_id} - {self.amount} - {self.status}"

class MiningSession(models.Model):
    """Mining session tracking"""
    miner_address = models.CharField(max_length=100)
    miner_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    
    blocks_mined = models.IntegerField(default=0)
    total_rewards = models.DecimalField(max_digits=20, decimal_places=8, default=0)
    
    # Mining configuration
    cpu_threads = models.IntegerField(default=1)
    mining_mode = models.CharField(max_length=20, default='single')
    
    # Performance metrics
    average_hashrate = models.CharField(max_length=50, blank=True)
    total_shares = models.IntegerField(default=0)
    
    def __str__(self):
        return f"Mining Session - {self.miner_address} - {self.started_at.strftime('%Y-%m-%d %H:%M')}"

# security/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class SecurityScan(models.Model):
    """Security scan results"""
    SCAN_TYPES = [
        ('file_scan', 'File Security Scan'),
        ('system_scan', 'System Security Scan'),
        ('database_scan', 'Database Security Scan'),
        ('network_scan', 'Network Security Scan'),
    ]
    
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    # Scan results
    items_scanned = models.IntegerField(default=0)
    threats_found = models.IntegerField(default=0)
    issues_found = models.IntegerField(default=0)
    
    scan_results = models.JSONField(default=dict)
    recommendations = models.JSONField(default=list)
    
    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.started_at.strftime('%Y-%m-%d %H:%M')}"

class AccessLog(models.Model):
    """Detailed access logging"""
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Access details
    resource_type = models.CharField(max_length=50)  # database, file, transaction, etc.
    resource_id = models.CharField(max_length=100, blank=True)
    action = models.CharField(max_length=50)  # read, write, delete, etc.
    
    # Result
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Additional context
    session_id = models.CharField(max_length=100, blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['resource_type', 'timestamp']),
        ]

# Quick Setup Script

# setup.py
"""
Quick setup script for Blockchain Dashboard
Run this after creating the Django project structure
"""

import os
import subprocess
import sys

def run_command(command, description):
    """Run a command and print status"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    print("🚀 Setting up Blockchain Dashboard...")
    
    # Install requirements
    if not run_command("pip install -r requirements.txt", "Installing Python dependencies"):
        return False
    
    # Run migrations
    if not run_command("python manage.py makemigrations", "Creating migrations"):
        return False
    
    if not run_command("python manage.py migrate", "Running migrations"):
        return False
    
    # Collect static files
    if not run_command("python manage.py collectstatic --noinput", "Collecting static files"):
        return False
    
    # Setup blockchain system
    if not run_command("python manage.py setup_blockchain --create-admin", "Setting up blockchain system"):
        return False
    
    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Start the development server: python manage.py runserver")
    print("2. Open your browser to: http://localhost:8000")
    print("3. Login with username: admin, password: admin")
    print("4. Start exploring the blockchain dashboard!")

if __name__ == "__main__":
    main()

# Additional Templates

# templates/databases/list.html
{% extends 'base.html' %}

{% block title %}Databases - Blockchain Dashboard{% endblock %}
{% block page_title %}Database Management{% endblock %}

{% block content %}
<!-- Search and Filter Bar -->
<div class="row mb-4">
    <div class="col-md-8">
        <form method="get" class="d-flex">
            <input type="text" class="form-control me-2" name="search" placeholder="Search databases..." 
                   value="{{ search_query }}">
            <select class="form-select me-2" name="status" style="width: auto;">
                <option value="">All Status</option>
                <option value="active" {% if filters.status == 'active' %}selected{% endif %}>Active</option>
                <option value="inactive" {% if filters.status == 'inactive' %}selected{% endif %}>Inactive</option>
            </select>
            <button class="btn btn-outline-primary" type="submit">
                <i class="fas fa-search"></i>
            </button>
        </form>
    </div>
    <div class="col-md-4 text-end">
        <a href="{% url 'databases:create' %}" class="btn btn-primary">
            <i class="fas fa-plus me-2"></i>Create Database
        </a>
    </div>
</div>

<!-- Summary Statistics -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card metric-card">
            <div class="card-body">
                <h6 class="card-title">Total Databases</h6>
                <h3 class="mb-0">{{ summary_stats.total_databases }}</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card success">
            <div class="card-body">
                <h6 class="card-title">Total Storage</h6>
                <h3 class="mb-0">{{ summary_stats.total_size_mb|floatformat:1 }} MB</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card warning">
            <div class="card-body">
                <h6 class="card-title">Total Files</h6>
                <h3 class="mb-0">{{ summary_stats.total_files }}</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card {% if summary_stats.active_databases == summary_stats.total_databases %}success{% else %}warning{% endif %}">
            <div class="card-body">
                <h6 class="card-title">Active Databases</h6>
                <h3 class="mb-0">{{ summary_stats.active_databases }}</h3>
            </div>
        </div>
    </div>
</div>

<!-- Database Grid -->
<div class="row">
    {% for database in page_obj %}
        <div class="col-md-4 mb-4">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="mb-0">
                        <i class="fas fa-database me-2"></i>
                        {{ database.name }}
                    </h6>
                    <span class="badge {% if database.is_active %}bg-success{% else %}bg-secondary{% endif %}">
                        {% if database.is_active %}Active{% else %}Inactive{% endif %}
                    </span>
                </div>
                <div class="card-body">
                    <p class="card-text text-muted small">{{ database.description|truncatewords:15 }}</p>
                    
                    <div class="row text-center mb-3">
                        <div class="col-4">
                            <strong>{{ database.total_files }}</strong>
                            <br><small class="text-muted">Files</small>
                        </div>
                        <div class="col-4">
                            <strong>{{ database.total_size_mb|floatformat:1 }}</strong>
                            <br><small class="text-muted">MB</small>
                        </div>
                        <div class="col-4">
                            <strong>{{ database.total_users }}</strong>
                            <br><small class="text-muted">Users</small>
                        </div>
                    </div>
                    
                    <small class="text-muted">
                        Owner: {{ database.owner.username }}<br>
                        Created: {{ database.created_at|timesince }} ago<br>
                        Last Activity: {{ database.last_activity|timesince }} ago
                    </small>
                </div>
                <div class="card-footer">
                    <div class="btn-group w-100" role="group">
                        <a href="{% url 'databases:detail' database.id %}" class="btn btn-outline-primary btn-sm">
                            <i class="fas fa-eye"></i> View
                        </a>
                        {% if database.owner == user or user.userprofile.role == 'admin' %}
                            <a href="{% url 'databases:edit' database.id %}" class="btn btn-outline-secondary btn-sm">
                                <i class="fas fa-edit"></i> Edit
                            </a>
                        {% endif %}
                        <a href="{% url 'databases:analytics' database.id %}" class="btn btn-outline-info btn-sm">
                            <i class="fas fa-chart-line"></i> Analytics
                        </a>
                    </div>
                </div>
            </div>
        </div>
    {% empty %}
        <div class="col-12">
            <div class="text-center py-5">
                <i class="fas fa-database fa-4x text-muted mb-3"></i>
                <h4>No databases found</h4>
                <p class="text-muted">{% if search_query %}No databases match your search criteria.{% else %}You don't have access to any databases yet.{% endif %}</p>
                <a href="{% url 'databases:create' %}" class="btn btn-primary">
                    <i class="fas fa-plus me-2"></i>Create Your First Database
                </a>
            </div>
        </div>
    {% endfor %}
</div>

<!-- Pagination -->
{% if page_obj.has_other_pages %}
    <nav aria-label="Database pagination">
        <ul class="pagination justify-content-center">
            {% if page_obj.has_previous %}
                <li class="page-item">
                    <a class="page-link" href="?page={{ page_obj.previous_page_number }}{% if search_query %}&search={{ search_query }}{% endif %}{% if filters.status %}&status={{ filters.status }}{% endif %}">Previous</a>
                </li>
            {% endif %}
            
            {% for num in page_obj.paginator.page_range %}
                {% if page_obj.number == num %}
                    <li class="page-item active">
                        <span class="page-link">{{ num }}</span>
                    </li>
                {% else %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{ num }}{% if search_query %}&search={{ search_query }}{% endif %}{% if filters.status %}&status={{ filters.status }}{% endif %}">{{ num }}</a>
                    </li>
                {% endif %}
            {% endfor %}
            
            {% if page_obj.has_next %}
                <li class="page-item">
                    <a class="page-link" href="?page={{ page_obj.next_page_number }}{% if search_query %}&search={{ search_query }}{% endif %}{% if filters.status %}&status={{ filters.status }}{% endif %}">Next</a>
                </li>
            {% endif %}
        </ul>
    </nav>
{% endif %}
{% endblock %}