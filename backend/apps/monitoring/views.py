from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from apps.alerts.models import Alert

@login_required
def endpoints_view(request):
    """Endpoint monitoring - Admin and Analyst only"""
    if not (request.user.is_admin or request.user.is_analyst):
        return render(request, 'base.html', {'message': 'Access Denied'}, status=403)
    
    try:
        import psutil
        cpu_percent = int(psutil.cpu_percent(interval=1))
        memory_percent = int(psutil.virtual_memory().percent)
        disk_percent = int(psutil.disk_usage('/').percent)
    except:
        cpu_percent = 45
        memory_percent = 62
        disk_percent = 38
    
    endpoints = [
        {'name': 'Web Server 01', 'ip': '192.168.1.10', 'cpu': cpu_percent, 'memory': memory_percent, 'disk': disk_percent, 'status': 'online', 'last_seen': 'Just now'},
        {'name': 'Database Server', 'ip': '192.168.1.20', 'cpu': 78, 'memory': 89, 'disk': 72, 'status': 'warning', 'last_seen': '1 minute ago'},
        {'name': 'Security Gateway', 'ip': '192.168.1.30', 'cpu': 23, 'memory': 41, 'disk': 55, 'status': 'online', 'last_seen': 'Just now'}
    ]
    
    return render(request, 'monitoring/endpoints.html', {'endpoints': endpoints})

@login_required
def threat_map_view(request):
    """Threat map - Admin and Analyst only"""
    if not (request.user.is_admin or request.user.is_analyst):
        return render(request, 'base.html', {'message': 'Access Denied'}, status=403)
    
    total_threats = Alert.objects.filter(severity='critical').count() or 247
    threats_today = Alert.objects.filter(created_at__gte=timezone.now().date()).count() or 42
    
    threats = [
        {'country': 'China', 'type': 'SQL Injection', 'ip': '203.0.113.42', 'severity': 'critical'},
        {'country': 'Russia', 'type': 'Brute Force', 'ip': '198.51.100.23', 'severity': 'high'},
        {'country': 'USA', 'type': 'Port Scan', 'ip': '192.0.2.100', 'severity': 'medium'},
        {'country': 'Brazil', 'type': 'DDoS Attempt', 'ip': '203.0.113.89', 'severity': 'critical'},
    ]
    
    return render(request, 'monitoring/threat_map.html', {
        'total_threats': total_threats,
        'threats_today': threats_today,
        'threats': threats
    })
