from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import Alert


@login_required
def alert_list(request):
    """List alerts with pagination and filtering - optimized"""
    alerts = Alert.objects.select_related('assigned_to').only(
        'id', 'title', 'severity', 'status', 'created_at', 'assigned_to__username'
    ).all()
    
    # Filter by severity
    severity = request.GET.get('severity')
    if severity:
        alerts = alerts.filter(severity=severity)
    
    # Filter by status
    status = request.GET.get('status')
    if status:
        alerts = alerts.filter(status=status)
    
    # Order by created_at descending
    alerts = alerts.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(alerts, 25)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'alerts/list.html', {
        'alerts': page_obj
    })


@login_required
def alert_detail(request, pk):
    """Alert detail view"""
    from django.shortcuts import get_object_or_404
    alert = get_object_or_404(Alert, pk=pk)
    return render(request, 'alerts/detail.html', {
        'alert': alert
    })
