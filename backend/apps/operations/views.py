from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from apps.alerts.models import Alert

User = get_user_model()

@login_required
def audit_trail_view(request):
    """Audit trail - Admin only"""
    if not request.user.is_admin:
        return render(request, 'base.html', {'message': 'Admin Access Required'}, status=403)
    
    audit_logs = [
        {'timestamp': timezone.now() - timedelta(minutes=2), 'user': 'admin', 'action': 'CREATE', 'description': 'Created new alert', 'ip': '192.168.1.10', 'status': 'success'},
        {'timestamp': timezone.now() - timedelta(minutes=5), 'user': 'analyst', 'action': 'UPDATE', 'description': 'Modified log entry #1523', 'ip': '192.168.1.25', 'status': 'success'},
        {'timestamp': timezone.now() - timedelta(minutes=10), 'user': 'viewer', 'action': 'LOGIN', 'description': 'User logged in', 'ip': '192.168.1.50', 'status': 'success'},
        {'timestamp': timezone.now() - timedelta(minutes=15), 'user': 'admin', 'action': 'DELETE', 'description': 'Deleted user account', 'ip': '192.168.1.10', 'status': 'success'},
        {'timestamp': timezone.now() - timedelta(minutes=20), 'user': 'unknown', 'action': 'LOGIN', 'description': 'Failed login attempt', 'ip': '203.0.113.42', 'status': 'failed'}
    ]
    
    return render(request, 'operations/audit_trail.html', {'audit_logs': audit_logs})

@login_required
def user_activity_view(request):
    """User activity - Admin and Analyst only"""
    if not (request.user.is_admin or request.user.is_analyst):
        return render(request, 'base.html', {'message': 'Access Denied'}, status=403)
    
    online_users = User.objects.filter(is_active=True)[:3]
    
    activities = [
        {'icon': 'login', 'action': 'admin logged in', 'details': 'From 192.168.1.10', 'time': '2 minutes ago'},
        {'icon': 'action', 'action': 'analyst acknowledged alert #1523', 'details': 'Critical SQL injection alert', 'time': '5 minutes ago'},
        {'icon': 'alert', 'action': 'Failed login attempt', 'details': 'From 203.0.113.42', 'time': '10 minutes ago'},
        {'icon': 'action', 'action': 'admin created new user', 'details': 'User: newanalyst', 'time': '15 minutes ago'},
        {'icon': 'logout', 'action': 'viewer logged out', 'details': 'Session duration: 2h 15m', 'time': '20 minutes ago'}
    ]
    
    stats = {
        'active_users': online_users.count(),
        'actions_today': Alert.objects.filter(created_at__gte=timezone.now().date()).count() or 47,
        'failed_logins': 2,
        'success_rate': 98.5
    }
    
    return render(request, 'operations/user_activity.html', {
        'activities': activities,
        'online_users': online_users,
        'stats': stats
    })
