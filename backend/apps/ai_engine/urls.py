"""
AI Log Monitoring & Security Detection Platform
AI Engine - HTML URLs
"""

from django.urls import path
from . import views

app_name = 'ai_engine'

urlpatterns = [
    path('', views.ai_analysis_view, name='ai_analysis'),
    path('analyze/', views.ai_analysis_result, name='ai_analysis_result'),
    path('chat/', views.ai_chat_view, name='ai_chat'),
    path('chat/process/', views.ai_chat_process, name='ai_chat_process'),
]
