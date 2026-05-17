
"""
AI Log Monitoring & Security Detection Platform
Alerts App - Admin Configuration
"""

from django.contrib import admin
from .models import Alert, AlertNotification, AlertRule


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """Admin configuration for Alert model"""
    
    list_display = ['id', 'title', 'severity', 'threat_type', 'status', 'ip_address', 'created_at']
    list_filter = ['severity', 'status', 'threat_type', 'created_at']
    search_fields = ['title', 'description', 'ip_address']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('title', 'description', 'severity', 'threat_type')
        }),
        ('Related Objects', {
            'fields': ('source_log', 'ip_address')
        }),
        ('Status', {
            'fields': ('status', 'created_by', 'assigned_to', 'acknowledged_by', 'acknowledged_at', 'resolved_by', 'resolved_at')
        }),
        ('Resolution', {
            'fields': ('resolution_notes',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AlertNotification)
class AlertNotificationAdmin(admin.ModelAdmin):
    """Admin configuration for AlertNotification model"""
    
    list_display = ['alert', 'notification_type', 'recipient', 'status', 'sent_at']
    list_filter = ['notification_type', 'status', 'sent_at']
    search_fields = ['alert__title', 'recipient']
    readonly_fields = ['sent_at']


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    """Admin configuration for AlertRule model"""
    
    list_display = ['name', 'threat_type', 'severity', 'is_active', 'created_at']
    list_filter = ['is_active', 'threat_type', 'severity']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']


