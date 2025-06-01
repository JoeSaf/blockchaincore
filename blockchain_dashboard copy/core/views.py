# core/views.py
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from django.http import JsonResponse, Http404, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count, Sum, Avg
from django.core.paginator import Paginator
from django.conf import settings
import json
import logging
import psutil
from datetime import datetime, timedelta

from .models import UserProfile, SystemMetrics, ActivityLog, DatabaseInfo, FileUpload, SecurityAlert
from .forms import LoginForm, UserProfileForm, SystemSettingsForm
from .utils import BlockchainSystemInterface, get_client_ip, log_activity

logger = logging.getLogger(__name__)

# Initialize blockchain system interface
blockchain_system = BlockchainSystemInterface()

def login_view(request):
    """Custom login view with enhanced security"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Check if user is locked
                try:
                    profile = user.userprofile
                    if profile.is_locked:
                        messages.error(request, 'Your account is locked. Please contact an administrator.')
                        log_activity(request, 'login_attempt_locked', f"Locked user {username} attempted login", success=False)
                        return render(request, 'core/login.html', {'form': form})
                except UserProfile.DoesNotExist:
                    # Create profile if it doesn't exist
                    profile = UserProfile.objects.create(user=user)
                
                # Reset login attempts and login
                profile.login_attempts = 0
                profile.save()
                
                login(request, user)
                log_activity(request, 'login', f"User {username} logged in successfully")
                
                messages.success(request, f'Welcome back, {user.first_name or username}!')
                return redirect('dashboard')
            else:
                # Handle failed login
                try:
                    failed_user = User.objects.get(username=username)
                    profile, created = UserProfile.objects.get_or_create(user=failed_user)
                    profile.login_attempts += 1
                    
                    if profile.login_attempts >= settings.BLOCKCHAIN_SETTINGS['MAX_LOGIN_ATTEMPTS']:
                        profile.is_locked = True
                        profile.locked_at = timezone.now()
                        profile.locked_reason = f"Exceeded maximum login attempts ({profile.login_attempts})"
                        
                        # Create security alert
                        SecurityAlert.objects.create(
                            alert_type='account_locked',
                            severity='medium',
                            title=f'Account Locked: {username}',
                            description=f'Account locked due to {profile.login_attempts} failed login attempts',
                            user=failed_user,
                            ip_address=get_client_ip(request),
                            alert_data={'attempts': profile.login_attempts}
                        )
                        
                        messages.error(request, 'Account locked due to too many failed attempts.')
                    else:
                        remaining = settings.BLOCKCHAIN_SETTINGS['MAX_LOGIN_ATTEMPTS'] - profile.login_attempts
                        messages.error(request, f'Invalid credentials. {remaining} attempts remaining.')
                    
                    profile.save()
                    log_activity(request, 'login_attempt_failed', f"Failed login for {username}", success=False)
                    
                except User.DoesNotExist:
                    messages.error(request, 'Invalid credentials.')
                    log_activity(request, 'login_attempt_failed', f"Failed login for non-existent user {username}")
    else:
        form = LoginForm()
    
    return render(request, 'core/login.html', {'form': form})

@login_required
def logout_view(request):
    """Logout view with activity logging"""
    username = request.user.username
    log_activity(request, 'logout', f"User {username} logged out")
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

@login_required
def dashboard(request):
    """Main dashboard view"""
    # Get system metrics
    latest_metrics = SystemMetrics.objects.first()
    
    # Get user statistics
    user_stats = {
        'total_operations': request.user.userprofile.total_operations,
        'success_rate': request.user.userprofile.success_rate,
        'databases_owned': DatabaseInfo.objects.filter(owner=request.user).count(),
        'files_uploaded': FileUpload.objects.filter(uploader=request.user).count(),
    }
    
    # Get recent activities
    recent_activities = ActivityLog.objects.filter(user=request.user)[:10]
    
    # Get system status from blockchain coordinator
    try:
        system_status = blockchain_system.get_system_status()
        blockchain_status = {
            'chain_height': system_status.get('chain_height', 'N/A'),
            'connected_peers': system_status.get('connected_peers', 0),
            'node_status': 'Connected' if system_status.get('node_connected') else 'Disconnected',
            'last_block_time': system_status.get('last_block_time', 'N/A'),
        }
    except Exception as e:
        logger.error(f"Error getting blockchain status: {e}")
        blockchain_status = {
            'chain_height': 'Error',
            'connected_peers': 0,
            'node_status': 'Error',
            'last_block_time': 'N/A',
        }
    
    # Get recent security alerts (admin only)
    security_alerts = []
    if request.user.userprofile.role == 'admin':
        security_alerts = SecurityAlert.objects.filter(is_resolved=False)[:5]
    
    # Get database statistics
    databases_stats = DatabaseInfo.objects.aggregate(
        total_count=Count('id'),
        total_size=Sum('total_size_mb'),
        total_files=Sum('total_files')
    )
    
    context = {
        'system_metrics': latest_metrics,
        'user_stats': user_stats,
        'recent_activities': recent_activities,
        'blockchain_status': blockchain_status,
        'security_alerts': security_alerts,
        'databases_stats': databases_stats,
        'system_uptime': blockchain_system.get_uptime(),
    }
    
    return render(request, 'core/dashboard.html', context)

@login_required
def system_status(request):
    """Detailed system status page"""
    # Get comprehensive system information
    system_info = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_io': psutil.net_io_counters(),
    }
    
    # Get blockchain system status
    try:
        blockchain_status = blockchain_system.get_comprehensive_status()
    except Exception as e:
        logger.error(f"Error getting blockchain status: {e}")
        blockchain_status = {'error': str(e)}
    
    # Get database health
    database_health = []
    for db in DatabaseInfo.objects.all():
        try:
            health = blockchain_system.check_database_health(db.name)
            database_health.append({
                'name': db.name,
                'health_score': health.get('health_score', 0),
                'issues': health.get('issues', []),
                'status': 'healthy' if health.get('health_score', 0) > 80 else 'warning'
            })
        except Exception as e:
            database_health.append({
                'name': db.name,
                'health_score': 0,
                'issues': [str(e)],
                'status': 'error'
            })
    
    # Get recent metrics for charts
    recent_metrics = SystemMetrics.objects.all()[:24]  # Last 24 entries
    
    context = {
        'system_info': system_info,
        'blockchain_status': blockchain_status,
        'database_health': database_health,
        'recent_metrics': recent_metrics,
    }
    
    return render(request, 'core/system_status.html', context)

@login_required
@require_http_methods(["GET", "POST"])
def user_profile(request):
    """User profile management"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            log_activity(request, 'profile_updated', 'User updated their profile')
            return redirect('user_profile')
    else:
        form = UserProfileForm(instance=profile)
    
    # Get user's activity statistics
    activity_stats = {
        'total_logins': ActivityLog.objects.filter(user=request.user, action='login').count(),
        'databases_created': ActivityLog.objects.filter(user=request.user, action='database_created').count(),
        'files_uploaded': ActivityLog.objects.filter(user=request.user, action='file_uploaded').count(),
        'last_login': ActivityLog.objects.filter(user=request.user, action='login').first(),
    }
    
    context = {
        'form': form,
        'profile': profile,
        'activity_stats': activity_stats,
    }
    
    return render(request, 'core/user_profile.html', context)

@staff_member_required
def system_settings(request):
    """System settings management (admin only)"""
    if request.method == 'POST':
        form = SystemSettingsForm(request.POST)
        if form.is_valid():
            # Update system settings
            try:
                blockchain_system.update_settings(form.cleaned_data)
                messages.success(request, 'System settings updated successfully!')
                log_activity(request, 'config_changed', 'System settings updated')
            except Exception as e:
                messages.error(request, f'Error updating settings: {str(e)}')
                logger.error(f"Error updating system settings: {e}")
    else:
        # Load current settings
        current_settings = blockchain_system.get_current_settings()
        form = SystemSettingsForm(initial=current_settings)
    
    context = {
        'form': form,
        'current_settings': blockchain_system.get_current_settings(),
    }
    
    return render(request, 'core/system_settings.html', context)

@login_required
def activity_log(request):
    """Activity log viewer"""
    # Filter activities based on user role
    if request.user.userprofile.role == 'admin':
        activities = ActivityLog.objects.all()
    else:
        activities = ActivityLog.objects.filter(user=request.user)
    
    # Apply filters
    action_filter = request.GET.get('action')
    date_filter = request.GET.get('date')
    user_filter = request.GET.get('user')
    
    if action_filter:
        activities = activities.filter(action=action_filter)
    
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            activities = activities.filter(timestamp__date=filter_date)
        except ValueError:
            pass
    
    if user_filter and request.user.userprofile.role == 'admin':
        activities = activities.filter(user__username__icontains=user_filter)
    
    # Pagination
    paginator = Paginator(activities, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get filter options
    action_choices = ActivityLog.ACTION_CHOICES
    
    context = {
        'page_obj': page_obj,
        'action_choices': action_choices,
        'filters': {
            'action': action_filter,
            'date': date_filter,
            'user': user_filter,
        }
    }
    
    return render(request, 'core/activity_log.html', context)

@login_required
def notifications(request):
    """User notifications"""
    # Get security alerts for the user
    if request.user.userprofile.role == 'admin':
        alerts = SecurityAlert.objects.filter(is_resolved=False)
    else:
        alerts = SecurityAlert.objects.filter(user=request.user, is_resolved=False)
    
    # Get system notifications
    system_notifications = []
    
    # Check for system maintenance notifications
    try:
        maintenance_status = blockchain_system.get_maintenance_status()
        if maintenance_status.get('maintenance_scheduled'):
            system_notifications.append({
                'type': 'warning',
                'title': 'Scheduled Maintenance',
                'message': f"System maintenance scheduled for {maintenance_status.get('scheduled_time')}",
                'timestamp': timezone.now(),
            })
    except Exception:
        pass
    
    # Check for storage warnings
    try:
        storage_stats = blockchain_system.get_storage_stats()
        if storage_stats.get('usage_percent', 0) > 80:
            system_notifications.append({
                'type': 'warning',
                'title': 'Storage Warning',
                'message': f"Storage usage is at {storage_stats.get('usage_percent')}%. Consider cleanup.",
                'timestamp': timezone.now(),
            })
    except Exception:
        pass
    
    context = {
        'security_alerts': alerts,
        'system_notifications': system_notifications,
    }
    
    return render(request, 'core/notifications.html', context)

# API Views for AJAX requests

@login_required
@csrf_exempt
def api_system_metrics(request):
    """API endpoint for real-time system metrics"""
    try:
        metrics = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'active_users': UserProfile.objects.filter(
                last_activity__gte=timezone.now() - timedelta(minutes=30)
            ).count(),
            'timestamp': timezone.now().isoformat(),
        }
        
        # Add blockchain metrics
        try:
            blockchain_metrics = blockchain_system.get_live_metrics()
            metrics.update(blockchain_metrics)
        except Exception as e:
            logger.error(f"Error getting blockchain metrics: {e}")
            metrics['blockchain_error'] = str(e)
        
        return JsonResponse(metrics)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@csrf_exempt
def api_recent_activities(request):
    """API endpoint for recent activities"""
    try:
        limit = int(request.GET.get('limit', 10))
        
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
                'ip_address': activity.ip_address,
            })
        
        return JsonResponse({'activities': activities_data})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@staff_member_required
@csrf_exempt
def api_resolve_alert(request, alert_id):
    """API endpoint to resolve security alerts"""
    try:
        alert = get_object_or_404(SecurityAlert, id=alert_id)
        
        if request.method == 'POST':
            data = json.loads(request.body)
            alert.is_resolved = True
            alert.resolved_by = request.user
            alert.resolved_at = timezone.now()
            alert.resolution_notes = data.get('notes', '')
            alert.save()
            
            log_activity(request, 'security_alert', f'Resolved security alert: {alert.title}')
            
            return JsonResponse({'success': True, 'message': 'Alert resolved successfully'})
        
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def search(request):
    """Global search functionality"""
    query = request.GET.get('q', '').strip()
    
    if not query:
        return render(request, 'core/search.html', {'query': query, 'results': {}})
    
    results = {}
    
    try:
        # Search databases
        if request.user.userprofile.role == 'admin':
            db_results = DatabaseInfo.objects.filter(
                models.Q(name__icontains=query) | 
                models.Q(description__icontains=query)
            )[:5]
        else:
            db_results = DatabaseInfo.objects.filter(
                owner=request.user
            ).filter(
                models.Q(name__icontains=query) | 
                models.Q(description__icontains=query)
            )[:5]
        
        results['databases'] = db_results
        
        # Search files
        file_results = FileUpload.objects.filter(
            uploader=request.user,
            original_filename__icontains=query
        )[:5]
        results['files'] = file_results
        
        # Search activities
        activity_results = ActivityLog.objects.filter(
            user=request.user,
            description__icontains=query
        )[:5]
        results['activities'] = activity_results
        
        # Search users (admin only)
        if request.user.userprofile.role == 'admin':
            from django.contrib.auth.models import User
            user_results = User.objects.filter(
                models.Q(username__icontains=query) |
                models.Q(first_name__icontains=query) |
                models.Q(last_name__icontains=query) |
                models.Q(email__icontains=query)
            )[:5]
            results['users'] = user_results
        
        log_activity(request, 'search', f'Searched for: {query}')
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        messages.error(request, 'An error occurred during search.')
    
    context = {
        'query': query,
        'results': results,
    }
    
    return render(request, 'core/search.html', context)

# Error handlers
def custom_404(request, exception):
    """Custom 404 error page"""
    return render(request, 'core/404.html', status=404)

def custom_500(request):
    """Custom 500 error page"""
    return render(request, 'core/500.html', status=500)