from django.urls import path
from . import views

app_name = 'operations'

urlpatterns = [
    path('audit-trail/', views.audit_trail_view, name='audit_trail'),
]
