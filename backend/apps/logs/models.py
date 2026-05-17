"""
AI Log Monitoring & Security Detection Platform
Logs App - Models
"""

from django.db import models
from django.utils import timezone


class Log(models.Model):
    """Model for storing server logs"""
    
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Windows Event Log specific fields
    EVENT_TYPE_CHOICES = [
        ('SYSMON_PROCESS', 'Sysmon - Process Create'),
        ('SYSMON_FILE', 'Sysmon - File Create'),
        ('SYSMON_NETWORK', 'Sysmon - Network Connection'),
        ('SYSMON_REGISTRY', 'Sysmon - Registry Change'),
        ('SYSMON_WMI', 'Sysmon - WMI Event'),
        ('SYSMON_IMAGE', 'Sysmon - Image Load'),
        ('SYSMON_CREATE_REMOTE_THREAD', 'Sysmon - Create Remote Thread'),
        ('SYSMON_RAW_ACCESS_READ', 'Sysmon - Raw Access Read'),
        ('SYSMON_PROCESS_ACCESS', 'Sysmon - Process Access'),
        ('SYSMON_FILE_DELETE', 'Sysmon - File Delete'),
        ('SYSMON_CERTIFICATE', 'Sysmon - Certificate'),
        ('SYSMON_PIPE_EVENT', 'Sysmon - Pipe Event'),
        ('SYSMON_WMI_FILTER', 'Sysmon - WMI Filter'),
        ('SYSMON_DNS_QUERY', 'Sysmon - DNS Query'),
        ('SYSMON_FILE_DELETE_LOG', 'Sysmon - File Delete Log'),
        ('SYSMON_PROCESS_TAMPERING', 'Sysmon - Process Tampering'),
        ('SYSMON_ERROR', 'Windows Error'),
        ('SYSMON_SECURITY', 'Windows Security'),
        ('SYSMON_APPLICATION', 'Windows Application'),
        ('OTHER', 'Other'),
    ]
    
    timestamp = models.DateTimeField(
        help_text='Log timestamp'
    )
    level = models.CharField(
        max_length=20,
        choices=LEVEL_CHOICES,
        db_index=True,
        help_text='Log level'
    )
    message = models.TextField(
        help_text='Log message content'
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        help_text='Source IP address'
    )
    service = models.CharField(
        max_length=100,
        db_index=True,
        help_text='Service name that generated the log'
    )
    
    # === Windows Sysmon / Event Log Fields ===
    event_id = models.IntegerField(
        null=True,
        blank=True,
        db_index=True,
        help_text='Windows Event ID (e.g., 1 for Sysmon Process Create)'
    )
    event_type = models.CharField(
        max_length=50,
        choices=EVENT_TYPE_CHOICES,
        blank=True,
        help_text='Event type/category'
    )
    channel = models.CharField(
        max_length=200,
        blank=True,
        help_text='Windows Event Channel (e.g., Microsoft-Windows-Sysmon/Operational)'
    )
    provider_name = models.CharField(
        max_length=200,
        blank=True,
        help_text='Event Provider Name'
    )
    computer = models.CharField(
        max_length=200,
        blank=True,
        help_text='Source computer name'
    )
    user_name = models.CharField(
        max_length=200,
        blank=True,
        help_text='User who generated the event'
    )
    
    # Process information (for Sysmon Event ID 1, 10, etc.)
    process_name = models.CharField(
        max_length=500,
        blank=True,
        help_text='Process name that was created/accessed'
    )
    process_path = models.CharField(
        max_length=1000,
        blank=True,
        help_text='Full path to the process executable'
    )
    process_id = models.IntegerField(
        null=True,
        blank=True,
        help_text='Process ID (PID)'
    )
    process_command_line = models.TextField(
        blank=True,
        help_text='Full command line of the process'
    )
    process_hash = models.CharField(
        max_length=100,
        blank=True,
        help_text='Process file hash (MD5/SHA256)'
    )
    
    # Parent process information
    parent_process_name = models.CharField(
        max_length=500,
        blank=True,
        help_text='Parent process name'
    )
    parent_process_path = models.CharField(
        max_length=1000,
        blank=True,
        help_text='Full path to parent process'
    )
    parent_process_id = models.IntegerField(
        null=True,
        blank=True,
        help_text='Parent Process ID (PPID)'
    )
    parent_command_line = models.TextField(
        blank=True,
        help_text='Parent process command line'
    )
    
    # Network information (for Sysmon Event ID 3)
    destination_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Destination IP address'
    )
    destination_port = models.IntegerField(
        null=True,
        blank=True,
        help_text='Destination port'
    )
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Source IP address'
    )
    source_port = models.IntegerField(
        null=True,
        blank=True,
        help_text='Source port'
    )
    protocol = models.CharField(
        max_length=20,
        blank=True,
        help_text='Network protocol (TCP/UDP)'
    )
    
    # Registry information (for Sysmon Event ID 12, 13, 14)
    registry_key = models.TextField(
        blank=True,
        help_text='Registry key path'
    )
    registry_value = models.TextField(
        blank=True,
        help_text='Registry value data'
    )
    
    # File information (for Sysmon Event ID 11, 23)
    file_name = models.CharField(
        max_length=1000,
        blank=True,
        help_text='File name that was created/deleted'
    )
    file_path = models.TextField(
        blank=True,
        help_text='Full file path'
    )
    
    # DNS information (for Sysmon Event ID 22)
    dns_query = models.CharField(
        max_length=500,
        blank=True,
        help_text='DNS query string'
    )
    dns_result = models.TextField(
        blank=True,
        help_text='DNS query result'
    )
    
    # Raw event data
    raw_event_data = models.JSONField(
        blank=True,
        null=True,
        help_text='Raw Windows Event Log data'
    )
    # === End Windows Sysmon Fields ===
    
    # Additional metadata
    user_id = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text='User ID if available'
    )
    request_method = models.CharField(
        max_length=10,
        blank=True,
        help_text='HTTP request method'
    )
    request_path = models.CharField(
        max_length=500,
        blank=True,
        help_text='Request path'
    )
    user_agent = models.CharField(
        max_length=500,
        blank=True,
        help_text='Client user agent'
    )
    status_code = models.IntegerField(
        blank=True,
        null=True,
        help_text='HTTP response status code'
    )
    response_time = models.FloatField(
        blank=True,
        null=True,
        help_text='Response time in milliseconds'
    )
    
    # AI Analysis fields
    analyzed = models.BooleanField(
        default=False,
        db_index=True,
        help_text='Whether log has been analyzed by AI'
    )
    ai_threat_detected = models.BooleanField(
        default=False,
        help_text='AI detected threat'
    )
    ai_threat_type = models.CharField(
        max_length=100,
        blank=True,
        help_text='Type of threat detected by AI'
    )
    ai_severity = models.CharField(
        max_length=20,
        blank=True,
        help_text='Threat severity level'
    )
    ai_analysis = models.JSONField(
        blank=True,
        null=True,
        help_text='Full AI analysis result'
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'logs_log'
        verbose_name = 'Log'
        verbose_name_plural = 'Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'level']),
            models.Index(fields=['-timestamp', 'service']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]
    
    def __str__(self):
        return f"[{self.timestamp}] {self.level}: {self.message[:50]}..."
    
    @property
    def is_error(self):
        return self.level in ['ERROR', 'CRITICAL']
    
    @property
    def is_threat(self):
        return self.ai_threat_detected


class LogBatch(models.Model):
    """Model for batch log ingestion"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    batch_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text='Unique batch identifier'
    )
    source = models.CharField(
        max_length=100,
        help_text='Source of the batch'
    )
    total_count = models.IntegerField(
        default=0,
        help_text='Total logs in batch'
    )
    success_count = models.IntegerField(
        default=0,
        help_text='Successfully processed logs'
    )
    failed_count = models.IntegerField(
        default=0,
        help_text='Failed log count'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    errors = models.JSONField(
        blank=True,
        null=True,
        help_text='Error details'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'logs_batch'
        verbose_name = 'Log Batch'
        verbose_name_plural = 'Log Batches'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Batch {self.batch_id} - {self.status}"


class Service(models.Model):
    """Model for tracking services"""
    
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text='Service name'
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        help_text='Service description'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether service is active'
    )
    log_count = models.IntegerField(
        default=0,
        help_text='Total logs from this service'
    )
    last_log_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Last log timestamp'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'logs_service'
        verbose_name = 'Service'
        verbose_name_plural = 'Services'
        ordering = ['name']
    
    def __str__(self):
        return self.name

