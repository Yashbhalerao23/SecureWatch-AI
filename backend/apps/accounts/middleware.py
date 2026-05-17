"""
Security Middleware
"""
from django.utils import timezone
from django.http import JsonResponse
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Middleware for security features:
    - Track user activity
    - Rate limiting
    - Suspicious activity detection
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Track authenticated user activity
        if request.user.is_authenticated:
            request.user.last_activity = timezone.now()
            request.user.save(update_fields=['last_activity'])
        
        # Rate limiting for API endpoints
        if request.path.startswith('/api/'):
            if not self.check_rate_limit(request):
                return JsonResponse({
                    'error': 'Rate limit exceeded. Please try again later.'
                }, status=429)
        
        response = self.get_response(request)
        return response
    
    def check_rate_limit(self, request):
        """
        Simple rate limiting: 100 requests per minute per IP
        """
        ip = self.get_client_ip(request)
        cache_key = f'rate_limit_{ip}'
        
        requests = cache.get(cache_key, 0)
        if requests >= 100:
            return False
        
        cache.set(cache_key, requests + 1, 60)  # 60 seconds
        return True
    
    @staticmethod
    def get_client_ip(request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class APIKeyMiddleware:
    """
    Middleware to authenticate API requests using API key
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check for API key in Authorization header
        if request.path.startswith('/api/v1/logs/'):
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            
            if auth_header.startswith('Bearer '):
                api_key = auth_header.split(' ')[1]
                
                from apps.accounts.models import User
                try:
                    user = User.objects.get(api_key=api_key, is_active=True)
                    request.user = user
                except User.DoesNotExist:
                    pass
        
        response = self.get_response(request)
        return response
