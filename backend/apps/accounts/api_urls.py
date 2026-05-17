"""
AI Log Monitoring & Security Detection Platform
Accounts App - API URLs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import UserViewSet, LoginView, LogoutView, SessionIntelligenceView, DashboardMetricsAPIView
from .security_api import BlockIPView, UnblockIPView, BlockedIPListView

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/login/', LoginView.as_view(), name='api_login'),
    path('auth/logout/', LogoutView.as_view(), name='api_logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/session-intelligence/', SessionIntelligenceView.as_view(), name='session_intelligence'),
    path('dashboard/metrics/', DashboardMetricsAPIView.as_view(), name='dashboard_metrics'),
    path('security/block-ip/', BlockIPView.as_view(), name='block_ip'),
    path('security/unblock-ip/', UnblockIPView.as_view(), name='unblock_ip'),
    path('security/blocked-ips/', BlockedIPListView.as_view(), name='blocked_ips'),
]
