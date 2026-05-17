"""
AI Log Monitoring & Security Detection Platform
ASGI Configuration
"""

import os

from django.core.asgi import get_asgi_application

# Set the default settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Initialize Django ASGI application
application = get_asgi_application()

