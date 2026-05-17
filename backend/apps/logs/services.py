"""
AI Log Monitoring & Security Detection Platform
Logs App - Services
"""

from django.db.models import Count, Q, Max
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta
from .models import Log, LogBatch, Service


class LogService:
    """Service for log-related operations"""
    
    @staticmethod
    def create_log(**kwargs):
        """Create a new log entry"""
        log = Log.objects.create(**kwargs)
        
        # Update service stats
        service_name = log.service
        service, _ = Service.objects.get_or_create(name=service_name)
        service.log_count += 1
        service.last_log_at = log.timestamp
        service.save()
        
        return log
    
    @staticmethod
    def create_logs_batch(logs_data):
        """Create multiple logs in batch"""
        logs = [Log(**data) for data in logs_data]
        created_logs = Log.objects.bulk_create(logs)
        
        # Update service stats
        services = {}
        for log in created_logs:
            services[log.service] = services.get(log.service, 0) + 1
        
        for service_name, count in services.items():
            service, _ = Service.objects.get_or_create(name=service_name)
            service.log_count = (service.log_count or 0) + count
            service.last_log_at = timezone.now()
            service.save()
        
        return created_logs
    
    @staticmethod
    def get_statistics(days=7):
        """Get log statistics for specified days"""
        start_date = timezone.now() - timedelta(days=days)
        
        stats = {
            'total': Log.objects.count(),
            'period': Log.objects.filter(timestamp__gte=start_date).count(),
            'errors': Log.objects.filter(level='ERROR').count(),
            'critical': Log.objects.filter(level='CRITICAL').count(),
            'analyzed': Log.objects.filter(analyzed=True).count(),
            'threats': Log.objects.filter(ai_threat_detected=True).count(),
        }
        
        return stats
    
    @staticmethod
    def get_level_distribution():
        """Get distribution of logs by level"""
        return Log.objects.values('level').annotate(
            count=Count('id')
        ).order_by('-count')
    
    @staticmethod
    def get_service_distribution(limit=10):
        """Get distribution of logs by service"""
        return Log.objects.values('service').annotate(
            count=Count('id'),
            error_count=Count('id', filter=Q(level='ERROR'))
        ).order_by('-count')[:limit]
    
    @staticmethod
    def get_timeline(days=7):
        """Get logs timeline for charts"""
        start_date = timezone.now() - timedelta(days=days)
        
        return Log.objects.filter(
            timestamp__gte=start_date
        ).annotate(
            date=TruncDate('timestamp')
        ).values('date', 'level').annotate(
            count=Count('id')
        ).order_by('date', 'level')
    
    @staticmethod
    def get_suspicious_ips(limit=10):
        """Get IPs with most detected threats"""
        return Log.objects.filter(
            ai_threat_detected=True
        ).values('ip_address').annotate(
            count=Count('id'),
            last_seen=Max('timestamp')
        ).order_by('-count')[:limit]
    
    @staticmethod
    def search_logs(query, filters=None):
        """Search logs with filters"""
        queryset = Log.objects.all()
        
        # Text search
        if query:
            queryset = queryset.filter(
                Q(message__icontains=query) |
                Q(service__icontains=query) |
                Q(ip_address__icontains=query)
            )
        
        # Apply filters
        if filters:
            if filters.get('level'):
                queryset = queryset.filter(level=filters['level'])
            if filters.get('service'):
                queryset = queryset.filter(service=filters['service'])
            if filters.get('ip_address'):
                queryset = queryset.filter(ip_address=filters['ip_address'])
            if filters.get('analyzed'):
                queryset = queryset.filter(analyzed=filters['analyzed'])
            if filters.get('threat_detected'):
                queryset = queryset.filter(ai_threat_detected=filters['threat_detected'])
        
        return queryset.order_by('-timestamp')


class LogBatchService:
    """Service for batch log operations"""
    
    @staticmethod
    def create_batch(batch_id, source, total_count):
        """Create a new log batch"""
        return LogBatch.objects.create(
            batch_id=batch_id,
            source=source,
            total_count=total_count,
            status='pending'
        )
    
    @staticmethod
    def update_batch_status(batch_id, status, success_count=0, failed_count=0, errors=None):
        """Update batch status"""
        try:
            batch = LogBatch.objects.get(batch_id=batch_id)
            batch.status = status
            batch.success_count = success_count
            batch.failed_count = failed_count
            if errors:
                batch.errors = errors
            if status == 'completed':
                batch.completed_at = timezone.now()
            batch.save()
            return batch
        except LogBatch.DoesNotExist:
            return None


class ServiceService:
    """Service for service management"""
    
    @staticmethod
    def get_or_create_service(name, description=''):
        """Get or create a service"""
        service, created = Service.objects.get_or_create(
            name=name,
            defaults={'description': description}
        )
        return service
    
    @staticmethod
    def get_all_services():
        """Get all services ordered by name"""
        return Service.objects.all().order_by('name')
    
    @staticmethod
    def get_active_services():
        """Get all active services"""
        return Service.objects.filter(is_active=True).order_by('name')
    
    @staticmethod
    def toggle_service_status(service_id, is_active):
        """Toggle service active status"""
        try:
            service = Service.objects.get(id=service_id)
            service.is_active = is_active
            service.save()
            return service
        except Service.DoesNotExist:
            return None

