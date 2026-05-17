"""
AI Log Monitoring & Security Detection Platform
Context Processors
"""

import os
from django.conf import settings


def ai_settings(request):
    """Add AI settings to all template contexts"""
    return {
        'AI_PROVIDER': getattr(settings, 'AI_PROVIDER', 'ollama'),
        'AI_MODEL': getattr(settings, 'AI_MODEL', 'llama2'),
        'AI_ANALYSIS_ENABLED': getattr(settings, 'AI_ANALYSIS_ENABLED', True),
    }

