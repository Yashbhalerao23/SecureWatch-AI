"""
AI Log Monitoring & Security Detection Platform
IP Blocking Middleware
"""

from django.utils import timezone
from django.http import JsonResponse
from .models import BlockedIP


class IPBlockingMiddleware:
    """
    Middleware to block requests from blacklisted IP addresses.
    Must be placed after SessionMiddleware in MIDDLEWARE setting.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Get client IP address
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(client_ip):
            return JsonResponse({
                'error': 'Access Denied',
                'message': 'Your IP address has been blocked due to suspicious activity.',
                'blocked_ip': client_ip
            }, status=403)
        
        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP in the list
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_ip_blocked(self, ip_address):
        """Check if an IP address is blocked"""
        if not ip_address:
            return False
        
        # Check for active blocked IPs
        blocked_ips = BlockedIP.objects.filter(
            ip_address=ip_address,
            is_active=True
        )
        
        for blocked_ip in blocked_ips:
            # Check if block has expired
            if blocked_ip.expires_at and blocked_ip.is_expired:
                blocked_ip.is_active = False
                blocked_ip.save()
                continue
            
            if blocked_ip.is_active:
                return True
        
        return False


class RequestLoggingMiddleware:
    """
    Middleware to log all requests for security monitoring.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Log request details
        client_ip = self.get_client_ip(request)
        
        # Store IP in request for later use
        request.client_ip = client_ip
        
        response = self.get_response(request)
        
        return response
    
    def get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
