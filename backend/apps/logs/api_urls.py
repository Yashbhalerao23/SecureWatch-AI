"""
AI Log Monitoring & Security Detection Platform
Logs App - API URLs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api_views import (
    LogViewSet, ServiceViewSet, 
    SysmonLogIngestAPIView
)

router = DefaultRouter()
router.register(r'', LogViewSet, basename='log')
router.register(r'services', ServiceViewSet, basename='service')

urlpatterns = [
    path('sysmon/', SysmonLogIngestAPIView.as_view(), name='sysmon-ingest'),
    path('', include(router.urls)),
]
