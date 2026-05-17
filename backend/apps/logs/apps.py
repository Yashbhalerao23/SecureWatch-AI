"""
AI Log Monitoring & Security Detection Platform
Logs App Configuration
"""

from django.apps import AppConfig


class LogsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.logs'
    verbose_name = 'System Logs'

    def ready(self):
        try:
            import apps.logs.signals  # noqa
        except ImportError:
            pass

