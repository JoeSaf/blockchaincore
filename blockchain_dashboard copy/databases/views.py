# databases/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from django.http import JsonResponse, Http404, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.utils import timezone
from django.db.models import Q, Sum, Count
from django.conf import settings
import json
import os
import logging

from core.models import DatabaseInfo, ActivityLog, UserProfile
from core.utils import BlockchainSystemInterface, log_activity
from .forms import DatabaseCreateForm, DatabaseEditForm, DatabaseUserForm, DatabaseSchemaForm
from .models import DatabaseUser, DatabaseSchema, DatabaseBackup

logger = logging.getLogger(__name__)
blockchain_system = BlockchainSystemInterface()

@login_required
def database_list(request):
    """List all databases accessible to the user"""
    # Filter databases based on user role
    if request.user.userprofile.role == 'admin':
        databases = DatabaseInfo.objects.all()
    else:
        # Get databases owned by user or where user has access
        owned_databases = DatabaseInfo.objects.filter(owner=request.user)
        accessible_databases = DatabaseInfo.objects.filter(
            databaseuser__user=request.user
        ).distinct()
        databases = (owned_databases | accessible_databases).distinct()
    
    # Search and filtering
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    owner_filter = request.GET.get('owner', '')
    
    if search_query:
        databases = databases.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    if status_filter:
        if status_filter == 'active':
            databases = databases.filter(is_active=True)
        elif status_filter == 'inactive':
            databases = databases.filter(is_active=False)
    
    if owner_filter and request.user.userprofile.role == 'admin':
        databases = databases.filter(owner__username__icontains=owner_filter)
    
    # Sorting
    sort_by = request.GET.get('sort', '-created_at')
    databases = databases.order_by(sort_by)
    
    # Pagination
    paginator = Paginator(databases, 12)  # 12 databases per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Calculate summary statistics
    summary_stats = {
        'total_databases': databases.count(),
        'total_size_mb': databases.aggregate(Sum('total_size_mb'))['total_size_mb__sum'] or 0,
        'total_files': databases.aggregate(Sum('total_files'))['total_files__sum'] or 0,
        'active_databases': databases.filter(is_active=True).count(),
    }
    
    context = {
        'page_obj': page_obj,
        'summary_stats': summary_stats,
        'search_query': search_query,
        'filters': {
            'status': status_filter,
            'owner': owner_filter,
            'sort': sort_by,
        }
    }
    
    return render(request, 'databases/list.html', context)

@login_required
def database_detail(request, database_id):
    """Detailed view of a specific database"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'read'):
        messages.error(request, 'You do not have permission to access this database.')
        return redirect('databases:list')
    
    # Get database statistics from blockchain system
    try:
        stats = blockchain_system.get_database_stats(database.name)
        health = blockchain_system.check_database_health(database.name)
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        stats = {}
        health = {'health_score': 0, 'issues': ['Unable to connect to blockchain system']}
    
    # Get database users
    database_users = DatabaseUser.objects.filter(database=database)
    
    # Get recent files
    recent_files = database.fileupload_set.all()[:10]
    
    # Get database schema
    try:
        schema = DatabaseSchema.objects.get(database=database)
    except DatabaseSchema.DoesNotExist:
        schema = None
    
    # Get recent activities related to this database
    recent_activities = ActivityLog.objects.filter(
        context_data__database_name=database.name
    )[:10]
    
    # Get backup information
    recent_backups = DatabaseBackup.objects.filter(database=database)[:5]
    
    context = {
        'database': database,
        'stats': stats,
        'health': health,
        'database_users': database_users,
        'recent_files': recent_files,
        'schema': schema,
        'recent_activities': recent_activities,
        'recent_backups': recent_backups,
        'user_permissions': _get_user_permissions(request.user, database),
    }
    
    return render(request, 'databases/detail.html', context)

@login_required
@require_http_methods(["GET", "POST"])
def database_create(request):
    """Create a new database"""
    if request.method == 'POST':
        form = DatabaseCreateForm(request.POST)
        if form.is_valid():
            try:
                # Create database through blockchain system
                database_name = form.cleaned_data['name']
                description = form.cleaned_data['description']
                schema_type = form.cleaned_data['schema_type']
                
                # Create database in blockchain system
                result = blockchain_system.create_database(
                    name=database_name,
                    owner=request.user.username,
                    description=description,
                    schema_type=schema_type
                )
                
                if result['success']:
                    # Create database record in Django
                    database = DatabaseInfo.objects.create(
                        name=database_name,
                        owner=request.user,
                        description=description,
                        path=result['path'],
                        schema_data=result.get('schema', {})
                    )
                    
                    # Create database user record for owner
                    DatabaseUser.objects.create(
                        database=database,
                        user=request.user,
                        role='owner',
                        permissions=['read', 'write', 'admin', 'delete', 'manage_users']
                    )
                    
                    log_activity(
                        request, 
                        'database_created', 
                        f'Created database: {database_name}',
                        context_data={'database_name': database_name}
                    )
                    
                    messages.success(request, f'Database "{database_name}" created successfully!')
                    return redirect('databases:detail', database_id=database.id)
                else:
                    messages.error(request, f'Failed to create database: {result.get("error", "Unknown error")}')
            
            except Exception as e:
                logger.error(f"Database creation error: {e}")
                messages.error(request, f'An error occurred while creating the database: {str(e)}')
    else:
        form = DatabaseCreateForm()
    
    context = {
        'form': form,
        'schema_templates': blockchain_system.get_schema_templates(),
    }
    
    return render(request, 'databases/create.html', context)

@login_required
@require_http_methods(["GET", "POST"])
def database_edit(request, database_id):
    """Edit database settings"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'admin'):
        messages.error(request, 'You do not have permission to edit this database.')
        return redirect('databases:detail', database_id=database.id)
    
    if request.method == 'POST':
        form = DatabaseEditForm(request.POST, instance=database)
        if form.is_valid():
            try:
                form.save()
                
                # Update database in blockchain system
                blockchain_system.update_database_metadata(
                    database.name,
                    {
                        'description': database.description,
                        'is_active': database.is_active,
                    }
                )
                
                log_activity(
                    request,
                    'database_updated',
                    f'Updated database: {database.name}',
                    context_data={'database_name': database.name}
                )
                
                messages.success(request, 'Database updated successfully!')
                return redirect('databases:detail', database_id=database.id)
            
            except Exception as e:
                logger.error(f"Database update error: {e}")
                messages.error(request, f'Error updating database: {str(e)}')
    else:
        form = DatabaseEditForm(instance=database)
    
    context = {
        'form': form,
        'database': database,
    }
    
    return render(request, 'databases/edit.html', context)

@login_required
@require_http_methods(["POST"])
def database_delete(request, database_id):
    """Delete a database"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Only owner or admin can delete
    if not (database.owner == request.user or request.user.userprofile.role == 'admin'):
        messages.error(request, 'You do not have permission to delete this database.')
        return redirect('databases:detail', database_id=database.id)
    
    try:
        database_name = database.name
        
        # Delete from blockchain system first
        result = blockchain_system.delete_database(database_name)
        
        if result['success']:
            # Delete from Django
            database.delete()
            
            log_activity(
                request,
                'database_deleted',
                f'Deleted database: {database_name}',
                context_data={'database_name': database_name}
            )
            
            messages.success(request, f'Database "{database_name}" deleted successfully!')
            return redirect('databases:list')
        else:
            messages.error(request, f'Failed to delete database: {result.get("error", "Unknown error")}')
    
    except Exception as e:
        logger.error(f"Database deletion error: {e}")
        messages.error(request, f'Error deleting database: {str(e)}')
    
    return redirect('databases:detail', database_id=database.id)

@login_required
def database_users(request, database_id):
    """Manage database users"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'manage_users'):
        messages.error(request, 'You do not have permission to manage users for this database.')
        return redirect('databases:detail', database_id=database.id)
    
    database_users = DatabaseUser.objects.filter(database=database)
    
    context = {
        'database': database,
        'database_users': database_users,
    }
    
    return render(request, 'databases/users.html', context)

@login_required
@require_http_methods(["GET", "POST"])
def database_add_user(request, database_id):
    """Add a user to database"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'manage_users'):
        messages.error(request, 'You do not have permission to add users to this database.')
        return redirect('databases:detail', database_id=database.id)
    
    if request.method == 'POST':
        form = DatabaseUserForm(request.POST)
        form.fields['user'].queryset = form.fields['user'].queryset.exclude(
            id__in=DatabaseUser.objects.filter(database=database).values_list('user_id', flat=True)
        )
        
        if form.is_valid():
            try:
                database_user = form.save(commit=False)
                database_user.database = database
                database_user.added_by = request.user
                database_user.save()
                
                # Update blockchain system
                blockchain_system.add_database_user(
                    database.name,
                    database_user.user.username,
                    database_user.role,
                    database_user.permissions
                )
                
                log_activity(
                    request,
                    'database_user_added',
                    f'Added user {database_user.user.username} to database {database.name}',
                    context_data={
                        'database_name': database.name,
                        'username': database_user.user.username,
                        'role': database_user.role
                    }
                )
                
                messages.success(request, f'User {database_user.user.username} added to database successfully!')
                return redirect('databases:users', database_id=database.id)
            
            except Exception as e:
                logger.error(f"Error adding database user: {e}")
                messages.error(request, f'Error adding user: {str(e)}')
    else:
        form = DatabaseUserForm()
        form.fields['user'].queryset = form.fields['user'].queryset.exclude(
            id__in=DatabaseUser.objects.filter(database=database).values_list('user_id', flat=True)
        )
    
    context = {
        'form': form,
        'database': database,
    }
    
    return render(request, 'databases/add_user.html', context)

@login_required
def database_analytics(request, database_id):
    """Database analytics and statistics"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'read'):
        messages.error(request, 'You do not have permission to view analytics for this database.')
        return redirect('databases:detail', database_id=database.id)
    
    try:
        # Get comprehensive analytics from blockchain system
        analytics = blockchain_system.get_database_analytics(database.name)
        
        # Get file upload trends
        upload_trends = database.fileupload_set.extra(
            select={'date': 'date(uploaded_at)'}
        ).values('date').annotate(
            count=Count('id'),
            total_size=Sum('file_size')
        ).order_by('date')
        
        # Get user activity
        user_activity = DatabaseUser.objects.filter(database=database).annotate(
            uploads_count=Count('user__fileupload')
        )
        
        context = {
            'database': database,
            'analytics': analytics,
            'upload_trends': list(upload_trends),
            'user_activity': user_activity,
        }
    
    except Exception as e:
        logger.error(f"Error getting database analytics: {e}")
        context = {
            'database': database,
            'analytics': {},
            'upload_trends': [],
            'user_activity': [],
            'error': str(e),
        }
    
    return render(request, 'databases/analytics.html', context)

@login_required
@require_http_methods(["POST"])
def database_backup(request, database_id):
    """Create database backup"""
    database = get_object_or_404(DatabaseInfo, id=database_id)
    
    # Check permissions
    if not _check_database_access(request.user, database, 'admin'):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        backup_type = request.POST.get('backup_type', 'full')
        include_files = request.POST.get('include_files', 'true') == 'true'
        
        # Create backup through blockchain system
        result = blockchain_system.create_database_backup(
            database.name,
            backup_type=backup_type,
            include_files=include_files,
            created_by=request.user.username
        )
        
        if result['success']:
            # Record backup in Django
            backup = DatabaseBackup.objects.create(
                database=database,
                backup_type=backup_type,
                file_path=result['backup_path'],
                file_size=result.get('file_size', 0),
                created_by=request.user,
                include_files=include_files
            )
            
            log_activity(
                request,
                'database_backup',
                f'Created {backup_type} backup for database {database.name}',
                context_data={
                    'database_name': database.name,
                    'backup_type': backup_type,
                    'backup_id': backup.id
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Backup created successfully',
                'backup_id': backup.id,
                'backup_path': result['backup_path']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Unknown error')
            })
    
    except Exception as e:
        logger.error(f"Database backup error: {e}")
        return JsonResponse({'error': str(e)}, status=500)

# Utility functions

def _check_database_access(user, database, permission):
    """Check if user has specific permission for database"""
    if user.userprofile.role == 'admin':
        return True
    
    if database.owner == user:
        return True
    
    try:
        db_user = DatabaseUser.objects.get(database=database, user=user)
        return permission in db_user.permissions
    except DatabaseUser.DoesNotExist:
        return False

def _get_user_permissions(user, database):
    """Get user's permissions for a database"""
    if user.userprofile.role == 'admin':
        return ['read', 'write', 'admin', 'delete', 'manage_users', 'manage_security']
    
    if database.owner == user:
        return ['read', 'write', 'admin', 'delete', 'manage_users', 'manage_security']
    
    try:
        db_user = DatabaseUser.objects.get(database=database, user=user)
        return db_user.permissions
    except DatabaseUser.DoesNotExist:
        return []