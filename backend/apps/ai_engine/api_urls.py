"""
AI Log Monitoring & Security Detection Platform
AI Engine - API URLs
"""

from django.urls import path
from .views import (
    AnalyzeLogAPIView, 
    BatchAnalyzeAPIView, 
    AIConfigAPIView,
    DetectVulnerabilitiesAPIView,
    BatchVulnerabilityDetectAPIView,
    SecurityChatAPIView,
    VulnerabilityStatsAPIView,
    ThreatIntelligenceAPIView,
    ThreatSummaryAPIView,
)

urlpatterns = [
    path('analyze/', AnalyzeLogAPIView.as_view(), name='ai-analyze'),
    path('batch/', BatchAnalyzeAPIView.as_view(), name='ai-batch'),
    path('threat-summary/', ThreatSummaryAPIView.as_view(), name='ai-threat-summary'),
    path('vulnerabilities/', DetectVulnerabilitiesAPIView.as_view(), name='ai-vulnerabilities'),
    path('vulnerabilities/batch/', BatchVulnerabilityDetectAPIView.as_view(), name='ai-vulnerabilities-batch'),
    path('vulnerabilities/stats/', VulnerabilityStatsAPIView.as_view(), name='ai-vulnerabilities-stats'),
    path('threat-intel/', ThreatIntelligenceAPIView.as_view(), name='ai-threat-intel'),
    path('chat/', SecurityChatAPIView.as_view(), name='ai-chat'),
    path('config/', AIConfigAPIView.as_view(), name='ai-config'),
]
