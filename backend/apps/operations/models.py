"""
Operations App Models for audit trail and endpoint inventory.
"""

from django.db import models
from django.conf import settings


class AuditEvent(models.Model):
    """Audit trail entries for security actions."""

    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('alert_acknowledged', 'Alert Acknowledged'),
        ('alert_resolved', 'Alert Resolved'),
        ('role_change', 'Role Change'),
        ('configuration', 'Configuration Change'),
        ('log_ingest', 'Log Ingest'),
        ('alert_created', 'Alert Created'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events'
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    level = models.CharField(max_length=20, default='info')
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(blank=True, null=True)

    class Meta:
        db_table = 'operations_auditevent'
        verbose_name = 'Audit Event'
        verbose_name_plural = 'Audit Events'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_action_display()} - {self.user or 'system'} ({self.level})"


class Endpoint(models.Model):
    """Represents a monitored endpoint in the environment."""

    hostname = models.CharField(max_length=200, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    service = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, default='online')
    last_seen = models.DateTimeField(null=True, blank=True)
    event_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'operations_endpoint'
        verbose_name = 'Endpoint'
        verbose_name_plural = 'Endpoints'
        ordering = ['hostname']

    def __str__(self):
        return self.hostname
