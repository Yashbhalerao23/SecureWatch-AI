"""
AI Log Monitoring & Security Detection Platform
URL Configuration
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.db import connection

# Health Check Endpoint
def health_check(request):
    try:
        connection.ensure_connection()
        return JsonResponse({
            'status': 'healthy',
            'database': 'connected',
            'version': '1.0.0',
            'components': {
                'dashboard': 'operational',
                'logs': 'operational',
                'alerts': 'operational',
                'ai_engine': 'operational'
            }
        })
    except Exception as e:
        return JsonResponse({
            'status': 'unhealthy',
            'error': str(e)
        }, status=503)

urlpatterns = [
    # Health Check
    path('health/', health_check, name='health'),
    
    # Django Admin
    path('admin/', admin.site.urls),
    
    # API Endpoints (Primary for React)
    path('api/v1/', include('apps.accounts.api_urls')),
    path('api/v1/logs/', include('apps.logs.api_urls')),
    path('api/v1/alerts/', include('apps.alerts.api_urls')),
    path('api/v1/ai/', include('apps.ai_engine.api_urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns
    urlpatterns += staticfiles_urlpatterns()
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
