"""
AI Log Monitoring & Security Detection Platform
Celery Configuration
"""

import os
import sys

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Add project to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from celery import Celery
    
    app = Celery('ai_log_monitoring')
    
    # Load config from Django settings
    app.config_from_object('django.conf:settings', namespace='CELERY')
    
    # Auto-discover tasks in all registered Django apps
    app.autodiscover_tasks()
    
    
    @app.task(bind=True, ignore_result=True)
    def debug_task(self):
        print(f'Request: {self.request!r}')
        
except ImportError:
    # Celery not installed - create a dummy app
    class DummyCelery:
        def task(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator
        
        def autodiscover_tasks(self, *args, **kwargs):
            pass
    
    app = DummyCelery()

