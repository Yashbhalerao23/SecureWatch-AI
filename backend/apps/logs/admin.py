
"""
AI Log Monitoring & Security Detection Platform
Logs App - Admin Configuration
"""

from django.contrib import admin
from .models import Log, LogBatch, Service


@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    """Admin configuration for Log model"""
    
    list_display = ['id', 'timestamp', 'level', 'service', 'ip_address', 'analyzed', 'ai_threat_detected']
    list_filter = ['level', 'analyzed', 'ai_threat_detected', 'service', 'created_at']
    search_fields = ['message', 'ip_address', 'service']
    readonly_fields = ['created_at', 'updated_at', 'analyzed', 'ai_threat_detected', 'ai_threat_type', 'ai_severity', 'ai_analysis']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('timestamp', 'level', 'message', 'ip_address', 'service')
        }),
        ('Request Details', {
            'fields': ('user_id', 'request_method', 'request_path', 'user_agent', 'status_code', 'response_time'),
            'classes': ('collapse',)
        }),
        ('AI Analysis', {
            'fields': ('analyzed', 'ai_threat_detected', 'ai_threat_type', 'ai_severity', 'ai_analysis'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(LogBatch)
class LogBatchAdmin(admin.ModelAdmin):
    """Admin configuration for LogBatch model"""
    
    list_display = ['batch_id', 'source', 'total_count', 'success_count', 'failed_count', 'status', 'created_at']
    list_filter = ['status', 'source', 'created_at']
    search_fields = ['batch_id', 'source']
    readonly_fields = ['created_at', 'completed_at']


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    """Admin configuration for Service model"""
    
    list_display = ['name', 'description', 'is_active', 'log_count', 'last_log_at']
    list_filter = ['is_active']
    search_fields = ['name', 'description']
    readonly_fields = ['log_count', 'last_log_at', 'created_at', 'updated_at']


