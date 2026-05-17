"""
AI Log Monitoring & Security Detection Platform
Alerts App - Models
"""

from django.db import models
from django.conf import settings


class Alert(models.Model):
    """Model for security alerts"""
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('acknowledged', 'Acknowledged'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    THREAT_TYPES = [
        ('brute_force', 'Brute Force Attack'),
        ('suspicious_ip', 'Suspicious IP'),
        ('repeated_errors', 'Repeated Errors'),
        ('unusual_access', 'Unusual Access Pattern'),
        ('sql_injection', 'SQL Injection Attempt'),
        ('xss_attempt', 'XSS Attempt'),
        ('ddos', 'DDoS Attack'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('data_breach', 'Data Breach'),
        ('malware', 'Malware Detected'),
        # Vulnerability types
        ('vulnerability', 'Security Vulnerability'),
        ('command_injection', 'Command Injection'),
        ('path_traversal', 'Path Traversal'),
        ('weak_crypto', 'Weak Cryptography'),
        ('sensitive_data_exposure', 'Sensitive Data Exposure'),
        ('security_misconfig', 'Security Misconfiguration'),
        ('open_redirect', 'Open Redirect'),
        ('other', 'Other'),
    ]
    
    title = models.CharField(
        max_length=255,
        help_text='Alert title'
    )
    description = models.TextField(
        help_text='Detailed alert description'
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        db_index=True,
        help_text='Alert severity level'
    )
    threat_type = models.CharField(
        max_length=50,
        choices=THREAT_TYPES,
        help_text='Type of threat detected'
    )
    
    # Vulnerability-specific fields
    cwe_id = models.CharField(
        max_length=20,
        blank=True,
        help_text='CWE (Common Weakness Enumeration) ID'
    )
    vulnerability_type = models.CharField(
        max_length=50,
        blank=True,
        help_text='Specific vulnerability type'
    )
    recommendation = models.TextField(
        blank=True,
        help_text='Security recommendation for this vulnerability'
    )
    
    # Related objects
    source_log = models.ForeignKey(
        'logs.Log',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='alerts',
        help_text='Source log that triggered the alert'
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Related IP address'
    )
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        db_index=True,
        help_text='Alert status'
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_alerts'
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_alerts'
    )
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_alerts'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_alert'
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at', 'status']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['threat_type']),
            models.Index(fields=['cwe_id']),
        ]
    
    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"
    
    @property
    def is_critical(self):
        return self.severity == 'critical'
    
    @property
    def is_active(self):
        return self.status in ['new', 'acknowledged', 'investigating']
    
    @property
    def is_vulnerability(self):
        """Check if this alert is about a vulnerability"""
        vulnerability_types = ['vulnerability', 'sql_injection', 'xss_attempt', 
                           'command_injection', 'path_traversal', 'weak_crypto',
                           'sensitive_data_exposure', 'security_misconfig', 'open_redirect']
        return self.threat_type in vulnerability_types
    
    def acknowledge(self, user):
        """Mark alert as acknowledged"""
        self.status = 'acknowledged'
        self.acknowledged_by = user
        from django.utils import timezone
        self.acknowledged_at = timezone.now()
        self.save()
    
    def resolve(self, user, notes=''):
        """Mark alert as resolved"""
        self.status = 'resolved'
        self.resolved_by = user
        self.resolution_notes = notes
        from django.utils import timezone
        self.resolved_at = timezone.now()
        self.save()
    
    def mark_false_positive(self, user, notes=''):
        """Mark alert as false positive"""
        self.status = 'false_positive'
        self.resolved_by = user
        self.resolution_notes = notes
        from django.utils import timezone
        self.resolved_at = timezone.now()
        self.save()


class AlertNotification(models.Model):
    """Model for tracking alert notifications"""
    
    NOTIFICATION_TYPES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('webhook', 'Webhook'),
    ]
    
    alert = models.ForeignKey(
        Alert,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    recipient = models.CharField(max_length=255)
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'alerts_notification'
        verbose_name = 'Alert Notification'
        verbose_name_plural = 'Alert Notifications'
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"{self.alert.title} - {self.notification_type}"


class AlertRule(models.Model):
    """Model for custom alert rules"""
    
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Conditions
    threat_type = models.CharField(max_length=50, choices=Alert.THREAT_TYPES)
    severity = models.CharField(max_length=20, choices=Alert.SEVERITY_CHOICES)
    min_occurrences = models.IntegerField(default=1)
    time_window_minutes = models.IntegerField(default=5)
    
    # Actions
    notify_email = models.BooleanField(default=True)
    notify_sms = models.BooleanField(default=False)
    auto_block_ip = models.BooleanField(default=False)
    auto_create_ticket = models.BooleanField(default=False)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_rule'
        verbose_name = 'Alert Rule'
        verbose_name_plural = 'Alert Rules'
    
    def __str__(self):
        return self.name


class BlockedIP(models.Model):
    """Model for blocked IP addresses"""
    
    BLOCK_REASON_CHOICES = [
        ('brute_force', 'Brute Force Attack'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('manual', 'Manually Blocked'),
        ('ddos', 'DDoS Attack'),
        ('sql_injection', 'SQL Injection Attempt'),
        ('xss_attempt', 'XSS Attempt'),
        ('vulnerability', 'Vulnerability Exploit'),
        ('other', 'Other'),
    ]
    
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text='IP address to block'
    )
    reason = models.CharField(
        max_length=50,
        choices=BLOCK_REASON_CHOICES,
        help_text='Reason for blocking'
    )
    description = models.TextField(
        blank=True,
        help_text='Additional details about the block'
    )
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='blocked_ips'
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the block expires (null = permanent)'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether the block is currently active'
    )
    blocked_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_blockedip'
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        ordering = ['-blocked_at']
        indexes = [
            models.Index(fields=['ip_address', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} ({self.get_reason_display()})"
    
    @property
    def is_expired(self):
        """Check if the block has expired"""
        if self.expires_at:
            from django.utils import timezone
            return timezone.now() > self.expires_at
        return False
    
    def unblock(self):
        """Unblock this IP address"""
        self.is_active = False
        self.save()
