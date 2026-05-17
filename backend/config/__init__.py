# AI Log Monitoring & Security Detection Platform
# Configuration Package

try:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
except ImportError:
    # Celery not installed - tasks will run synchronously
    __all__ = ()

