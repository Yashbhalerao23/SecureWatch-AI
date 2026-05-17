from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.reports_view, name='reports'),
    path('pdf/', views.generate_pdf, name='generate_pdf'),
    path('excel/', views.generate_excel, name='generate_excel'),
    path('print/', views.print_view, name='print_view'),
]
