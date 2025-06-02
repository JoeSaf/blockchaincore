# blockchain_dashboard/core/enhanced_views.py
"""
Enhanced views with real-time capabilities
"""
import json
import asyncio
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .utils import BlockchainSystemInterface, log_activity
from .models import ActivityLog, SecurityAlert, SystemMetrics


@login_required
def enhanced_dashboard(request):
    """Enhanced dashboard with real-time capabilities"""
    blockchain_interface = BlockchainSystemInterface()
    
    try:
        # Get comprehensive system status
        system_status = blockchain_interface.get_comprehensive_status()
        
        # Get recent activities
        recent_activities = ActivityLog.objects.filter(user=request.user)[:10]
        
        # Get security alerts for admins
        security_alerts = []
        if request.user.userprofile.role == 'admin':
            security_alerts = SecurityAlert.objects.filter(is_resolved=False)[:5]
        
        # Get system metrics
        latest_metrics = SystemMetrics.objects.first()
        
        context = {
            'system_status': system_status,
            'recent_activities': recent_activities,
            'security_alerts': security_alerts,
            'latest_metrics': latest_metrics,
            'real_time_enabled': True,
            'websocket_url': f"ws://{request.get_host()}/ws/status/"
        }
        
        return render(request, 'core/enhanced_dashboard.html', context)
        
    except Exception as e:
        messages.error(request, f'Error loading dashboard: {str(e)}')
        return render(request, 'core/dashboard.html', {'error': str(e)})


@login_required
@csrf_exempt
def api_system_status(request):
    """API endpoint for real-time system status"""
    try:
        blockchain_interface = BlockchainSystemInterface()
        status = blockchain_interface.get_comprehensive_status()
        
        # Add Django-specific metrics
        status['django'] = {
            'active_users': get_active_users_count(),
            'recent_requests': get_recent_requests_count(),
            'database_queries': get_db_query_count(),
            'memory_usage': get_memory_usage()
        }
        
        return JsonResponse({
            'success': True,
            'data': status,
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def api_recent_activities(request):
    """API endpoint for recent activities"""
    try:
        limit = int(request.GET.get('limit', 20))
        
        if request.user.userprofile.role == 'admin':
            activities = ActivityLog.objects.all()[:limit]
        else:
            activities = ActivityLog.objects.filter(user=request.user)[:limit]
        
        activities_data = []
        for activity in activities:
            activities_data.append({
                'id': activity.id,
                'timestamp': activity.timestamp.isoformat(),
                'action': activity.get_action_display(),
                'description': activity.description,
                'user': activity.user.username if activity.user else 'System',
                'success': activity.success,
                'ip_address': activity.ip_address
            })
        
        return JsonResponse({
            'success': True,
            'data': activities_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def api_upload_file(request):
    """Enhanced file upload API with progress tracking"""
    try:
        if 'file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No file provided'
            })
        
        uploaded_file = request.FILES['file']
        database_id = request.POST.get('database')
        description = request.POST.get('description', '')
        
        # Start upload process with progress tracking
        upload_result = process_file_upload_with_progress(
            uploaded_file,
            request.user,
            database_id,
            description
        )
        
        if upload_result['success']:
            # Log successful upload
            log_activity(
                request,
                'file_uploaded',
                f"Uploaded file: {uploaded_file.name}",
                context_data={
                    'filename': uploaded_file.name,
                    'size': uploaded_file.size,
                    'database': database_id
                }
            )
            
            # Broadcast upload completion
            broadcast_upload_completion(request.user.id, upload_result)
        
        return JsonResponse(upload_result)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def process_file_upload_with_progress(uploaded_file, user, database_id, description):
    """Process file upload with progress updates"""
    channel_layer = get_channel_layer()
    user_group = f"upload_{user.id}"
    
    try:
        # Stage 1: Validation (20%)
        async_to_sync(channel_layer.group_send)(user_group, {
            'type': 'upload_progress',
            'data': {
                'filename': uploaded_file.name,
                'progress': 20,
                'stage': 'Validating file...'
            }
        })
        
        # Validate file
        if uploaded_file.size > 100 * 1024 * 1024:  # 100MB limit
            return {
                'success': False,
                'error': 'File too large (max 100MB)'
            }
        
        # Stage 2: Security scan (50%)
        async_to_sync(channel_layer.group_send)(user_group, {
            'type': 'upload_progress',
            'data': {
                'filename': uploaded_file.name,
                'progress': 50,
                'stage': 'Scanning for threats...'
            }
        })
        
        # Mock security scan
        import time
        time.sleep(1)  # Simulate scan time
        
        # Stage 3: Upload to blockchain (80%)
        async_to_sync(channel_layer.group_send)(user_group, {
            'type': 'upload_progress',
            'data': {
                'filename': uploaded_file.name,
                'progress': 80,
                'stage': 'Uploading to blockchain...'
            }
        })
        
        # Save file temporarily and upload via coordinator
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            for chunk in uploaded_file.chunks():
                temp_file.write(chunk)
            temp_path = temp_file.name
        
        try:
            # Upload through blockchain interface
            blockchain_interface = BlockchainSystemInterface()
            result = blockchain_interface.upload_file(
                temp_path,
                user.username,
                database_id,
                {
                    'original_name': uploaded_file.name,
                    'description': description,
                    'web_upload': True
                }
            )
            
            # Stage 4: Complete (100%)
            async_to_sync(channel_layer.group_send)(user_group, {
                'type': 'upload_progress',
                'data': {
                    'filename': uploaded_file.name,
                    'progress': 100,
                    'stage': 'Upload complete!'
                }
            })
            
            return result
            
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
        
    except Exception as e:
        # Send error update
        async_to_sync(channel_layer.group_send)(user_group, {
            'type': 'upload_progress',
            'data': {
                'filename': uploaded_file.name,
                'progress': 0,
                'stage': f'Error: {str(e)}',
                'error': True
            }
        })
        
        return {
            'success': False,
            'error': str(e)
        }


def broadcast_upload_completion(user_id, result):
    """Broadcast upload completion to user"""
    channel_layer = get_channel_layer()
    user_group = f"upload_{user_id}"
    
    async_to_sync(channel_layer.group_send)(user_group, {
        'type': 'upload_complete',
        'data': result
    })


def broadcast_activity_update(activity_data):
    """Broadcast activity update to all connected users"""
    channel_layer = get_channel_layer()
    
    async_to_sync(channel_layer.group_send)("system_status", {
        'type': 'activity_update',
        'data': activity_data
    })


def broadcast_security_alert(alert_data):
    """Broadcast security alert to all admin users"""
    channel_layer = get_channel_layer()
    
    async_to_sync(channel_layer.group_send)("system_status", {
        'type': 'security_alert',
        'data': alert_data
    })


# Helper functions
def get_active_users_count():
    """Get count of active users in last 30 minutes"""
    from django.contrib.auth.models import User
    from django.utils import timezone
    from datetime import timedelta
    
    thirty_min_ago = timezone.now() - timedelta(minutes=30)
    return User.objects.filter(
        userprofile__last_activity__gte=thirty_min_ago
    ).count()


def get_recent_requests_count():
    """Get recent HTTP requests count (mock implementation)"""
    # In a real implementation, this would track actual requests
    import random
    return random.randint(50, 200)


def get_db_query_count():
    """Get database query count (mock implementation)"""
    # In a real implementation, this would use Django debug toolbar or similar
    import random
    return random.randint(100, 500)


def get_memory_usage():
    """Get current memory usage"""
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            'rss': memory_info.rss / 1024 / 1024,  # MB
            'vms': memory_info.vms / 1024 / 1024   # MB
        }
    except:
        return {'rss': 0, 'vms': 0}
