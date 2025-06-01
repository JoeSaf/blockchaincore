from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserProfile(models.Model):
    """Extended user profile for blockchain system"""
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('user', 'Standard User'),
        ('readonly', 'Read Only User'),
        ('miner', 'Miner'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    wallet_address = models.CharField(max_length=100, blank=True)
    last_activity = models.DateTimeField(default=timezone.now)
    is_locked = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"

class DatabaseInfo(models.Model):
    """Information about blockchain databases"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name