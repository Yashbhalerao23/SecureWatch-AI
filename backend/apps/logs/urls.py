from django.urls import path
from . import views

app_name = 'logs'

urlpatterns = [
    path('', views.log_list, name='list'),
    path('<int:pk>/', views.log_detail, name='detail'),
]
