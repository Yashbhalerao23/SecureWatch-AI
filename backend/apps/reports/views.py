from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from .report_service import ReportGenerator

@login_required
def reports_view(request):
    """Reports dashboard"""
    return render(request, 'reports/reports.html')

@login_required
def generate_pdf(request):
    """Generate PDF report"""
    days = int(request.GET.get('days', 7))
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    generator = ReportGenerator()
    buffer = generator.generate_pdf_report(start_date, end_date)
    
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="security_report_{timezone.now().strftime("%Y%m%d")}.pdf"'
    return response

@login_required
def generate_excel(request):
    """Generate Excel report"""
    days = int(request.GET.get('days', 7))
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    generator = ReportGenerator()
    buffer = generator.generate_excel_report(start_date, end_date)
    
    response = HttpResponse(buffer, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename="security_report_{timezone.now().strftime("%Y%m%d")}.xlsx"'
    return response

@login_required
def print_view(request):
    """Print-friendly report view"""
    days = int(request.GET.get('days', 7))
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    from apps.logs.models import Log
    from apps.alerts.models import Alert
    from django.db.models import Count
    
    logs = Log.objects.filter(timestamp__range=[start_date, end_date])
    alerts = Alert.objects.filter(created_at__range=[start_date, end_date])
    
    stats = {
        'total_logs': logs.count(),
        'critical_logs': logs.filter(level='CRITICAL').count(),
        'error_logs': logs.filter(level='ERROR').count(),
        'threats_detected': logs.filter(ai_threat_detected=True).count(),
        'total_alerts': alerts.count(),
        'critical_alerts': alerts.filter(severity='critical').count(),
        'resolved_alerts': alerts.filter(status='resolved').count(),
    }
    
    threat_logs = logs.filter(ai_threat_detected=True).values('ai_threat_type').annotate(count=Count('id')).order_by('-count')[:10]
    critical_alerts = alerts.filter(severity='critical').order_by('-created_at')[:20]
    
    context = {
        'start_date': start_date,
        'end_date': end_date,
        'stats': stats,
        'threat_logs': threat_logs,
        'critical_alerts': critical_alerts,
    }
    
    return render(request, 'reports/print.html', context)
