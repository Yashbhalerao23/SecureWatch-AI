from django.urls import path
from .views import web_scanner_view, WebScanAPIView

app_name = 'web_scanner'

urlpatterns = [
    path('', web_scanner_view, name='scan'),
    path('api/scan/', WebScanAPIView.as_view(), name='api_scan'),
]
