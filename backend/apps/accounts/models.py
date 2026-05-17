"""
AI Log Monitoring & Security Detection Platform
Accounts App - Models
"""

import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Extended User model with role-based access control"""
    
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
    ]
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='viewer',
        help_text='User role for access control'
    )
    api_key = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        help_text='API key for log ingestion'
    )
    last_activity = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Last user activity timestamp'
    )
    phone = models.CharField(
        max_length=20,
        blank=True,
        help_text='Phone number for notifications'
    )
    email_notifications = models.BooleanField(
        default=True,
        help_text='Enable email notifications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'accounts_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = self.generate_api_key()
        super().save(*args, **kwargs)
    
    @staticmethod
    def generate_api_key():
        """Generate a unique API key"""
        return uuid.uuid4().hex
    
    @property
    def is_admin(self):
        return self.role == 'admin' or self.is_superuser

    
    @property
    def is_analyst(self):
        return self.role in ['admin', 'analyst']
    
    @property
    def can_analyze(self):
        return self.role in ['admin', 'analyst']
    
    @property
    def can_manage_alerts(self):
        return self.role in ['admin', 'analyst']


class UserSession(models.Model):
    """Track user login sessions"""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'accounts_user_session'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"

