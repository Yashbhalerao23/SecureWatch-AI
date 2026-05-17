"""
AI Log Monitoring & Security Detection Platform
AI Engine App Configuration
"""

from django.apps import AppConfig


class AiEngineConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.ai_engine'
    verbose_name = 'AI Engine'

