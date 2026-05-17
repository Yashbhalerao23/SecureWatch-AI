
"""
AI Log Monitoring & Security Detection Platform
Logs App - Serializers
"""

from rest_framework import serializers
from django.utils import timezone
from django.conf import settings
import ipaddress
from .models import Log, LogBatch, Service


class LogSerializer(serializers.ModelSerializer):
    """Serializer for Log model"""
    
    class Meta:
        model = Log
        fields = [
            # Basic fields
            'id', 'timestamp', 'level', 'message', 'ip_address', 'service',
            # Windows Sysmon fields
            'event_id', 'event_type', 'channel', 'provider_name', 'computer', 'user_name',
            'process_name', 'process_path', 'process_id', 'process_command_line', 'process_hash',
            'parent_process_name', 'parent_process_path', 'parent_process_id', 'parent_command_line',
            'destination_ip', 'destination_port', 'source_ip', 'source_port', 'protocol',
            'registry_key', 'registry_value',
            'file_name', 'file_path',
            'dns_query', 'dns_result',
            'raw_event_data',
            # Additional metadata
            'user_id', 'request_method', 'request_path', 'user_agent',
            'status_code', 'response_time',
            # AI Analysis fields
            'analyzed', 'ai_threat_detected', 'ai_threat_type', 'ai_severity', 'ai_analysis',
            'created_at'
        ]
        read_only_fields = [
            'id', 'analyzed', 'ai_threat_detected', 'ai_threat_type',
            'ai_severity', 'ai_analysis', 'created_at'
        ]


class SysmonLogSerializer(serializers.ModelSerializer):
    """Serializer for Windows Sysmon Event Logs"""
    
    class Meta:
        model = Log
        fields = [
            'timestamp', 'level', 'message', 'ip_address', 'service',
            # Windows Sysmon fields
            'event_id', 'event_type', 'channel', 'provider_name', 'computer', 'user_name',
            'process_name', 'process_path', 'process_id', 'process_command_line', 'process_hash',
            'parent_process_name', 'parent_process_path', 'parent_process_id', 'parent_command_line',
            'destination_ip', 'destination_port', 'source_ip', 'source_port', 'protocol',
            'registry_key', 'registry_value',
            'file_name', 'file_path',
            'dns_query', 'dns_result',
            'raw_event_data',
        ]
    
    def validate_event_id(self, value):
        if value is not None and (value < 1 or value > 255):
            raise serializers.ValidationError('Event ID must be between 1 and 255')
        return value
    
    def validate_timestamp(self, value):
        # Allow timestamps up to 1 hour in the future
        if value > timezone.now() + timezone.timedelta(hours=1):
            raise serializers.ValidationError(
                'Timestamp cannot be more than 1 hour in the future'
            )
        return value
    
    def validate_level(self, value):
        valid_levels = [choice[0] for choice in Log.LEVEL_CHOICES]
        if value.upper() not in valid_levels:
            raise serializers.ValidationError(
                f'Invalid log level. Must be one of: {", ".join(valid_levels)}'
            )
        return value.upper()
    
    def validate_ip_address(self, value):
        if value:  # Only validate if provided
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise serializers.ValidationError('Invalid IP address')
        return value
    
    def validate_destination_ip(self, value):
        if value:  # Only validate if provided
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise serializers.ValidationError('Invalid destination IP address')
        return value
    
    def validate_source_ip(self, value):
        if value:  # Only validate if provided
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise serializers.ValidationError('Invalid source IP address')
        return value


class LogCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating logs via API"""
    
    class Meta:
        model = Log
        fields = [
            'timestamp', 'level', 'message', 'ip_address', 'service',
            'user_id', 'request_method', 'request_path', 'user_agent',
            'status_code', 'response_time'
        ]
    
    def validate_timestamp(self, value):
        # Allow timestamps up to 1 hour in the future
        if value > timezone.now() + timezone.timedelta(hours=1):
            raise serializers.ValidationError(
                'Timestamp cannot be more than 1 hour in the future'
            )
        return value
    
    def validate_level(self, value):
        valid_levels = [choice[0] for choice in Log.LEVEL_CHOICES]
        if value.upper() not in valid_levels:
            raise serializers.ValidationError(
                f'Invalid log level. Must be one of: {", ".join(valid_levels)}'
            )
        return value.upper()
    
    def validate_ip_address(self, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError('Invalid IP address')
        return value
    
    def validate_message(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError('Message cannot be empty')
        if len(value) > 5000:
            raise serializers.ValidationError('Message cannot exceed 5000 characters')
        return value.strip()
    
    def validate_service(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError('Service name cannot be empty')
        if len(value) > 100:
            raise serializers.ValidationError('Service name cannot exceed 100 characters')
        return value.strip()


class LogBatchSerializer(serializers.ModelSerializer):
    """Serializer for LogBatch model"""
    
    class Meta:
        model = LogBatch
        fields = [
            'id', 'batch_id', 'source', 'total_count', 'success_count',
            'failed_count', 'status', 'errors', 'created_at', 'completed_at'
        ]
        read_only_fields = fields


class ServiceSerializer(serializers.ModelSerializer):
    """Serializer for Service model"""
    
    class Meta:
        model = Service
        fields = [
            'id', 'name', 'description', 'is_active', 'log_count',
            'last_log_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'log_count', 'last_log_at', 'created_at', 'updated_at']


class LogStatsSerializer(serializers.Serializer):
    """Serializer for log statistics"""
    
    total_logs = serializers.IntegerField()
    today_logs = serializers.IntegerField()
    error_logs = serializers.IntegerField()
    critical_logs = serializers.IntegerField()
    analyzed_logs = serializers.IntegerField()
    threat_logs = serializers.IntegerField()


class LogLevelCountSerializer(serializers.Serializer):
    """Serializer for log level counts"""
    
    level = serializers.CharField()
    count = serializers.IntegerField()


class ServiceLogCountSerializer(serializers.Serializer):
    """Serializer for service log counts"""
    
    service = serializers.CharField()
    count = serializers.IntegerField()
    error_count = serializers.IntegerField()


class IPLogCountSerializer(serializers.Serializer):
    """Serializer for IP log counts"""
    
    ip_address = serializers.CharField()
    count = serializers.IntegerField()
    threat_count = serializers.IntegerField()
    last_seen = serializers.DateTimeField()


