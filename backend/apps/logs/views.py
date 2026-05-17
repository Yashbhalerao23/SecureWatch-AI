from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from .models import Log


@login_required
def log_list(request):
    """List logs with pagination and filters - SIEM style"""
    logs = Log.objects.select_related().only(
        'id', 'timestamp', 'level', 'service', 'message', 'ip_address',
        'event_id', 'process_name', 'computer', 'ai_threat_detected', 'analyzed'
    )
    
    # Filter by level
    level = request.GET.get('level')
    if level:
        logs = logs.filter(level=level)
    
    # Filter by service
    service = request.GET.get('service')
    if service:
        logs = logs.filter(service__icontains=service)
    
    # Filter threats only
    if request.GET.get('threat') == 'threats':
        logs = logs.filter(ai_threat_detected=True)
    
    # Search
    search = request.GET.get('search')
    if search:
        logs = logs.filter(
            Q(message__icontains=search) |
            Q(ip_address__icontains=search) |
            Q(service__icontains=search) |
            Q(process_name__icontains=search) |
            Q(computer__icontains=search)
        )
    
    logs = logs.order_by('-timestamp')
    
    paginator = Paginator(logs, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'logs/list.html', {
        'logs': page_obj
    })


@login_required
def log_detail(request, pk):
    """Log detail view - SIEM style"""
    log = Log.objects.select_related().get(pk=pk)
    return render(request, 'logs/detail.html', {'log': log})
