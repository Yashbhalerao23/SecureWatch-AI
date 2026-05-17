"""
Custom Authentication Backend for API Key
"""
from django.contrib.auth.backends import BaseBackend
from apps.accounts.models import User


class APIKeyAuthentication(BaseBackend):
    """
    Authenticate using API key for log ingestion
    """
    def authenticate(self, request, api_key=None):
        if not api_key:
            return None
        
        try:
            user = User.objects.get(api_key=api_key, is_active=True)
            return user
        except User.DoesNotExist:
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
