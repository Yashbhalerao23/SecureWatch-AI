"""
AI Log Monitoring & Security Detection Platform
Accounts App - Services
"""

import uuid
from django.utils import timezone
from .models import User, UserSession


class UserService:
    """Service for user-related operations"""
    
    @staticmethod
    def create_user(username, email, password, **kwargs):
        """Create a new user with API key"""
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            **kwargs
        )
        return user
    
    @staticmethod
    def generate_api_key(user):
        """Generate new API key for user"""
        user.api_key = User.generate_api_key()
        user.save(update_fields=['api_key'])
        return user.api_key
    
    @staticmethod
    def get_user_stats(user):
        """Get user activity statistics"""
        return {
            'total_sessions': user.sessions.count(),
            'active_sessions': user.sessions.filter(is_active=True).count(),
            'created_alerts': user.created_alerts.count(),
            'assigned_alerts': user.assigned_alerts.count(),
        }


class SessionService:
    """Service for session management"""
    
    @staticmethod
    def create_session(user, request):
        """Create a new user session"""
        session_key = uuid.uuid4().hex
        
        # Get IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR', '0.0.0.0')
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Calculate expiration (24 hours)
        from datetime import timedelta
        expires_at = timezone.now() + timedelta(hours=24)
        
        session = UserSession.objects.create(
            user=user,
            session_key=session_key,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )
        
        return session
    
    @staticmethod
    def validate_session(session_key):
        """Validate if session is active and not expired"""
        try:
            session = UserSession.objects.get(
                session_key=session_key,
                is_active=True
            )
            if session.expires_at > timezone.now():
                return session
            else:
                # Session expired, deactivate it
                session.is_active = False
                session.save()
                return None
        except UserSession.DoesNotExist:
            return None
    
    @staticmethod
    def terminate_session(session_key):
        """Terminate a user session"""
        try:
            session = UserSession.objects.get(session_key=session_key)
            session.is_active = False
            session.save()
            return True
        except UserSession.DoesNotExist:
            return False
    
    @staticmethod
    def cleanup_expired_sessions():
        """Remove expired sessions"""
        expired = UserSession.objects.filter(
            expires_at__lt=timezone.now(),
            is_active=True
        )
        count = expired.update(is_active=False)
        return count

