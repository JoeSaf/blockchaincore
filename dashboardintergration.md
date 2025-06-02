# Blockchain Dashboard Integration Plan

## 1. Unified Startup Script

### Option A: Process Manager (Recommended)
```python
# startup_manager.py
import subprocess
import time
import signal
import sys
import os
from pathlib import Path

class BlockchainSystemManager:
    def __init__(self):
        self.processes = {}
        self.running = False
    
    def start_cpp_node(self):
        """Start C++ blockchain node"""
        print("🔗 Starting C++ blockchain node...")
        self.processes['cpp_node'] = subprocess.Popen([
            "./build/bin/blockchain_node"
        ])
        time.sleep(3)  # Wait for node to initialize
    
    def start_coordinator(self):
        """Start system coordinator"""
        print("🔧 Starting system coordinator...")
        self.processes['coordinator'] = subprocess.Popen([
            sys.executable, "system_coordinator.py", "--daemon"
        ])
    
    def start_django(self):
        """Start Django dashboard"""
        print("🌐 Starting Django dashboard...")
        self.processes['django'] = subprocess.Popen([
            sys.executable, "manage.py", "runserver", "0.0.0.0:8000"
        ])
    
    def start_all(self):
        """Start all components"""
        try:
            self.start_cpp_node()
            self.start_coordinator() 
            self.start_django()
            self.running = True
            print("🚀 All systems started successfully!")
            return True
        except Exception as e:
            print(f"❌ Startup failed: {e}")
            self.stop_all()
            return False
    
    def stop_all(self):
        """Stop all processes gracefully"""
        print("🛑 Shutting down all systems...")
        for name, process in self.processes.items():
            if process and process.poll() is None:
                process.terminate()
                print(f"   Stopped {name}")
        self.running = False
```

### Option B: Docker Compose (Production)
```yaml
# docker-compose.yml
version: '3.8'
services:
  cpp-node:
    build: ./cpp_node
    ports:
      - "8080:8080"
      - "8333:8333"
    volumes:
      - blockchain_data:/data
    
  coordinator:
    build: .
    command: python system_coordinator.py --daemon
    depends_on:
      - cpp-node
    environment:
      - CPP_NODE_URL=http://cpp-node:8080
    
  dashboard:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
    ports:
      - "8000:8000"
    depends_on:
      - coordinator
    volumes:
      - ./:/app
```

## 2. Data Sharing Strategy

### A. Shared Database Approach
```python
# blockchain_dashboard/core/models.py (Enhanced)
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
```

### B. Message Queue Integration
```python
# blockchain_dashboard/core/message_queue.py
import redis
import json
from django.conf import settings

class MessageQueue:
    def __init__(self):
        self.redis_client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=0
        )
    
    def publish_status_update(self, component, status):
        """Publish status update"""
        message = {
            'component': component,
            'status': status,
            'timestamp': time.time()
        }
        self.redis_client.publish('system_status', json.dumps(message))
    
    def subscribe_to_updates(self, callback):
        """Subscribe to status updates"""
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('system_status')
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                data = json.loads(message['data'])
                callback(data)
```

## 3. Real-time Dashboard Updates

### WebSocket Integration
```python
# blockchain_dashboard/core/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .utils import BlockchainSystemInterface

class SystemStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("system_status", self.channel_name)
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("system_status", self.channel_name)
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        if data['type'] == 'get_status':
            # Get real-time status
            blockchain_interface = BlockchainSystemInterface()
            status = blockchain_interface.get_system_status()
            
            await self.send(text_data=json.dumps({
                'type': 'status_update',
                'data': status
            }))
```

### Enhanced Views with Real-time Data
```python
# blockchain_dashboard/core/views.py (Enhanced)
import asyncio
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .message_queue import MessageQueue

@login_required
def dashboard_api(request):
    """API endpoint for dashboard data"""
    blockchain_interface = BlockchainSystemInterface()
    
    # Get real-time data
    status = blockchain_interface.get_comprehensive_status()
    
    # Add coordinator-specific data
    coordinator_data = get_coordinator_status()
    status['coordinator'] = coordinator_data
    
    return JsonResponse(status)

def get_coordinator_status():
    """Get status from coordinator process"""
    try:
        # Check if coordinator is running
        coordinator_pid = get_coordinator_pid()
        if coordinator_pid:
            return {
                'running': True,
                'pid': coordinator_pid,
                'uptime': get_process_uptime(coordinator_pid)
            }
        return {'running': False}
    except Exception as e:
        return {'running': False, 'error': str(e)}
```

## 4. File Upload Integration

### Enhanced File Upload Views
```python
# blockchain_dashboard/files/views.py (New)
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from core.utils import BlockchainSystemInterface
import json

@login_required
@csrf_exempt
def upload_file_ajax(request):
    """AJAX file upload with progress"""
    if request.method == 'POST':
        files = request.FILES.getlist('files')
        database_id = request.POST.get('database')
        
        blockchain_interface = BlockchainSystemInterface()
        results = []
        
        for file in files:
            # Save temporarily
            temp_path = save_temp_file(file)
            
            # Upload through coordinator
            result = blockchain_interface.upload_file(
                temp_path,
                request.user.username,
                database_id,
                {'web_upload': True}
            )
            
            results.append({
                'filename': file.name,
                'success': result['success'],
                'status': result.get('status', 'failed'),
                'threats': result.get('threats', [])
            })
        
        return JsonResponse({'results': results})
```

### Progressive Upload with WebSocket
```python
# blockchain_dashboard/files/upload_handler.py
class ProgressiveUploadHandler:
    def __init__(self, websocket_group):
        self.websocket_group = websocket_group
    
    async def handle_upload(self, file_data, user, database):
        """Handle upload with progress updates"""
        # Send progress updates
        await self.send_progress(0, "Starting upload...")
        
        # Security scan
        await self.send_progress(25, "Scanning for threats...")
        scan_result = await self.security_scan(file_data)
        
        # Upload to coordinator
        await self.send_progress(50, "Uploading to blockchain...")
        upload_result = await self.coordinator_upload(file_data, user, database)
        
        # Complete
        await self.send_progress(100, "Upload complete!")
        
        return upload_result
    
    async def send_progress(self, percent, message):
        """Send progress update via WebSocket"""
        await self.channel_layer.group_send(
            self.websocket_group,
            {
                'type': 'upload_progress',
                'percent': percent,
                'message': message
            }
        )
```

## 5. Security & Logging Dashboard

### Enhanced Security Views
```python
# blockchain_dashboard/security/views.py (New)
@login_required
@staff_member_required
def security_dashboard(request):
    """Security dashboard with live updates"""
    blockchain_interface = BlockchainSystemInterface()
    
    # Get security data from coordinator
    security_stats = blockchain_interface.get_security_stats()
    
    # Get recent alerts
    recent_alerts = SecurityAlert.objects.filter(
        is_resolved=False
    ).order_by('-timestamp')[:10]
    
    # Get scan results
    scan_results = get_recent_scan_results()
    
    context = {
        'security_stats': security_stats,
        'recent_alerts': recent_alerts,
        'scan_results': scan_results,
        'real_time_enabled': True
    }
    
    return render(request, 'security/dashboard.html', context)

@login_required
def security_logs_api(request):
    """API for security logs with filtering"""
    logs = ActivityLog.objects.filter(
        action__in=['security_alert', 'failed_login', 'user_locked']
    ).order_by('-timestamp')
    
    # Apply filters
    if request.GET.get('severity'):
        logs = logs.filter(context_data__severity=request.GET['severity'])
    
    # Paginate and return
    page = request.GET.get('page', 1)
    paginator = Paginator(logs, 20)
    
    logs_data = []
    for log in paginator.get_page(page):
        logs_data.append({
            'timestamp': log.timestamp.isoformat(),
            'action': log.get_action_display(),
            'user': log.user.username if log.user else 'System',
            'description': log.description,
            'ip_address': log.ip_address
        })
    
    return JsonResponse({
        'logs': logs_data,
        'has_next': paginator.get_page(page).has_next()
    })
```

### Real-time Security Monitoring
```python
# blockchain_dashboard/security/monitoring.py
class SecurityMonitor:
    def __init__(self):
        self.alert_handlers = []
    
    def start_monitoring(self):
        """Start real-time security monitoring"""
        # Monitor coordinator security events
        threading.Thread(
            target=self.monitor_coordinator_security,
            daemon=True
        ).start()
        
        # Monitor Django security events
        threading.Thread(
            target=self.monitor_django_security,
            daemon=True
        ).start()
    
    def monitor_coordinator_security(self):
        """Monitor security events from coordinator"""
        while True:
            try:
                # Get security events from coordinator
                events = get_coordinator_security_events()
                
                for event in events:
                    self.handle_security_event(event)
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Security monitoring error: {e}")
    
    def handle_security_event(self, event):
        """Handle security event"""
        # Create Django security alert
        alert = SecurityAlert.objects.create(
            alert_type=event['type'],
            severity=event['severity'],
            title=event['title'],
            description=event['description'],
            alert_data=event.get('data', {})
        )
        
        # Send real-time notification
        send_realtime_alert(alert)
```

## 6. Enhanced Templates with Real-time Updates

### Dashboard Template with WebSocket
```html
<!-- templates/core/dashboard.html (Enhanced) -->
{% extends 'base.html' %}
{% load static %}

{% block extra_css %}
<link rel="stylesheet" href="{% static 'css/dashboard.css' %}">
{% endblock %}

{% block content %}
<div class="dashboard-container">
    <!-- Real-time Status Cards -->
    <div class="row">
        <div class="col-md-3">
            <div class="status-card" id="cpp-node-status">
                <h5>C++ Node</h5>
                <div class="status-indicator" id="cpp-status">
                    <span class="badge badge-secondary">Connecting...</span>
                </div>
                <div class="status-details">
                    <small id="cpp-details">Checking connection...</small>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="status-card" id="coordinator-status">
                <h5>Coordinator</h5>
                <div class="status-indicator" id="coordinator-status-badge">
                    <span class="badge badge-secondary">Checking...</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="status-card" id="security-status">
                <h5>Security</h5>
                <div class="status-indicator" id="security-status-badge">
                    <span class="badge badge-success">Secure</span>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="status-card" id="upload-status">
                <h5>File System</h5>
                <div class="status-indicator" id="upload-status-badge">
                    <span class="badge badge-info">Active</span>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Progress Indicators -->
    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card">
                <div class="card-header">
                    <h5>System Activity</h5>
                </div>
                <div class="card-body">
                    <div id="activity-feed">
                        <!-- Real-time activity updates -->
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block extra_js %}
<script src="{% static 'js/dashboard-websocket.js' %}"></script>
<script>
// Initialize dashboard WebSocket connection
const dashboard = new DashboardWebSocket('{{ request.user.username }}');
dashboard.connect();
</script>
{% endblock %}
```

### JavaScript for Real-time Updates
```javascript
// static/js/dashboard-websocket.js
class DashboardWebSocket {
    constructor(username) {
        this.username = username;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }
    
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard/`;
        
        this.socket = new WebSocket(wsUrl);
        
        this.socket.onopen = (event) => {
            console.log('Dashboard WebSocket connected');
            this.reconnectAttempts = 0;
            this.requestStatusUpdate();
        };
        
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
        };
        
        this.socket.onclose = (event) => {
            console.log('Dashboard WebSocket disconnected');
            this.handleReconnection();
        };
        
        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleMessage(data) {
        switch(data.type) {
            case 'status_update':
                this.updateSystemStatus(data.data);
                break;
            case 'activity_update':
                this.updateActivityFeed(data.data);
                break;
            case 'security_alert':
                this.handleSecurityAlert(data.data);
                break;
            case 'upload_progress':
                this.updateUploadProgress(data.data);
                break;
        }
    }
    
    updateSystemStatus(status) {
        // Update C++ Node status
        const cppStatus = status.cpp_node_connected ? 'success' : 'danger';
        const cppText = status.cpp_node_connected ? 'Connected' : 'Disconnected';
        
        document.getElementById('cpp-status').innerHTML = 
            `<span class="badge badge-${cppStatus}">${cppText}</span>`;
        
        // Update coordinator status
        const coordStatus = status.system_running ? 'success' : 'warning';
        const coordText = status.system_running ? 'Running' : 'Stopped';
        
        document.getElementById('coordinator-status-badge').innerHTML = 
            `<span class="badge badge-${coordStatus}">${coordText}</span>`;
        
        // Update metrics
        this.updateMetrics(status);
    }
    
    updateActivityFeed(activity) {
        const feed = document.getElementById('activity-feed');
        const timestamp = new Date().toLocaleTimeString();
        
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item';
        activityItem.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="activity-text">${activity.message}</span>
        `;
        
        feed.insertBefore(activityItem, feed.firstChild);
        
        // Limit to 10 items
        while (feed.children.length > 10) {
            feed.removeChild(feed.lastChild);
        }
    }
    
    requestStatusUpdate() {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'get_status'
            }));
        }
    }
}
```

```python

```


```python
# blockchain_dashboard/core/consumers.py
"""
WebSocket consumers for real-time updates
"""
import json
import asyncio
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from .utils import BlockchainSystemInterface
from .models import ActivityLog, SecurityAlert

logger = logging.getLogger(__name__)

class SystemStatusConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time system status updates"""
    
    async def connect(self):
        # Check authentication
        if self.scope["user"] == AnonymousUser():
            await self.close()
            return
        
        # Join system status group
        await self.channel_layer.group_add("system_status", self.channel_name)
        await self.accept()
        
        # Send initial status
        await self.send_status_update()
        
        # Start periodic status updates
        asyncio.create_task(self.periodic_status_updates())
    
    async def disconnect(self, close_code):
        # Leave system status group
        await self.channel_layer.group_discard("system_status", self.channel_name)
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'get_status':
                await self.send_status_update()
            elif message_type == 'get_logs':
                await self.send_recent_logs()
            elif message_type == 'get_alerts':
                await self.send_security_alerts()
            
        except Exception as e:
            logger.error(f"WebSocket receive error: {e}")
            await self.send_error("Invalid message format")
    
    async def send_status_update(self):
        """Send current system status"""
        try:
            # Get status from blockchain interface
            blockchain_interface = BlockchainSystemInterface()
            status = await database_sync_to_async(
                blockchain_interface.get_comprehensive_status
            )()
            
            await self.send(text_data=json.dumps({
                'type': 'status_update',
                'data': status
            }))
            
        except Exception as e:
            logger.error(f"Status update error: {e}")
            await self.send_error("Failed to get system status")
    
    async def send_recent_logs(self):
        """Send recent activity logs"""
        try:
            logs = await database_sync_to_async(self.get_recent_logs)()
            
            await self.send(text_data=json.dumps({
                'type': 'logs_update',
                'data': logs
            }))
            
        except Exception as e:
            logger.error(f"Logs update error: {e}")
            await self.send_error("Failed to get recent logs")
    
    async def send_security_alerts(self):
        """Send recent security alerts"""
        try:
            alerts = await database_sync_to_async(self.get_security_alerts)()
            
            await self.send(text_data=json.dumps({
                'type': 'alerts_update',
                'data': alerts
            }))
            
        except Exception as e:
            logger.error(f"Alerts update error: {e}")
            await self.send_error("Failed to get security alerts")
    
    async def send_error(self, message):
        """Send error message"""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'message': message
        }))
    
    def get_recent_logs(self):
        """Get recent activity logs"""
        logs = ActivityLog.objects.all()[:20]
        return [{
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'action': log.get_action_display(),
            'user': log.user.username if log.user else 'System',
            'description': log.description,
            'success': log.success
        } for log in logs]
    
    def get_security_alerts(self):
        """Get recent security alerts"""
        alerts = SecurityAlert.objects.filter(is_resolved=False)[:10]
        return [{
            'id': alert.id,
            'timestamp': alert.timestamp.isoformat(),
            'type': alert.get_alert_type_display(),
            'severity': alert.get_severity_display(),
            'title': alert.title,
            'description': alert.description
        } for alert in alerts]
    
    async def periodic_status_updates(self):
        """Send periodic status updates"""
        while True:
            try:
                await asyncio.sleep(10)  # Update every 10 seconds
                await self.send_status_update()
            except Exception as e:
                logger.error(f"Periodic update error: {e}")
                break
    
    # Group message handlers
    async def activity_update(self, event):
        """Handle activity update from group"""
        await self.send(text_data=json.dumps({
            'type': 'activity_update',
            'data': event['data']
        }))
    
    async def security_alert(self, event):
        """Handle security alert from group"""
        await self.send(text_data=json.dumps({
            'type': 'security_alert',
            'data': event['data']
        }))


class FileUploadConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for file upload progress"""
    
    async def connect(self):
        if self.scope["user"] == AnonymousUser():
            await self.close()
            return
        
        # Create user-specific group
        self.user_group = f"upload_{self.scope['user'].id}"
        await self.channel_layer.group_add(self.user_group, self.channel_name)
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.user_group, self.channel_name)
    
    async def upload_progress(self, event):
        """Handle upload progress updates"""
        await self.send(text_data=json.dumps({
            'type': 'upload_progress',
            'data': event['data']
        }))
    
    async def upload_complete(self, event):
        """Handle upload completion"""
        await self.send(text_data=json.dumps({
            'type': 'upload_complete',
            'data': event['data']
        }))


# blockchain_dashboard/core/routing.py
"""
WebSocket URL routing
"""
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/status/$', consumers.SystemStatusConsumer.as_asgi()),
    re_path(r'ws/uploads/$', consumers.FileUploadConsumer.as_asgi()),
]




# blockchain_dashboard/core/enhanced_urls.py
"""
Enhanced URL patterns for real-time features
"""
from django.urls import path
from . import enhanced_views

urlpatterns = [
    path('dashboard/', enhanced_views.enhanced_dashboard, name='enhanced_dashboard'),
    path('api/status/', enhanced_views.api_system_status, name='api_system_status'),
    path('api/activities/', enhanced_views.api_recent_activities, name='api_recent_activities'),
    path('api/upload/', enhanced_views.api_upload_file, name='api_upload_file'),
]

```

```

```

## Implementation Priority

1. **Phase 1**: Unified startup script + basic data sharing
2. **Phase 2**: WebSocket integration for real-time updates  
3. **Phase 3**: Enhanced file upload with progress
4. **Phase 4**: Security dashboard integration
5. **Phase 5**: Full analytics and monitoring

Would you like me to implement any specific component first, or would you prefer to see the complete implementation for a particular phase?