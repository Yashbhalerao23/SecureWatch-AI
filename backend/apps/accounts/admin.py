"""
AI Log Monitoring & Security Detection Platform
Accounts App - Admin Configuration
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model"""
    
    list_display = ['username', 'email', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active', 'is_staff']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('role', 'api_key', 'phone', 'email_notifications', 'last_activity')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('role', 'email', 'phone')
        }),
    )


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin configuration for UserSession model"""
    
    list_display = ['user', 'ip_address', 'created_at', 'expires_at', 'is_active']
    list_filter = ['is_active', 'created_at']
    search_fields = ['user__username', 'ip_address']
    raw_id_fields = ['user']
    readonly_fields = ['created_at']

