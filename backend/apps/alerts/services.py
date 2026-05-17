"""
AI Log Monitoring & Security Detection Platform
Alerts App - Services
"""

from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import Alert, AlertNotification, AlertRule, BlockedIP


class AlertService:
    """Service for alert-related operations"""
    
    @staticmethod
    def create_alert(title, description, severity, threat_type, **kwargs):
        """Create a new alert"""
        alert = Alert.objects.create(
            title=title,
            description=description,
            severity=severity,
            threat_type=threat_type,
            **kwargs
        )
        return alert
    
    @staticmethod
    def acknowledge_alert(alert_id, user):
        """Acknowledge an alert"""
        try:
            alert = Alert.objects.get(id=alert_id)
            if alert.status not in ['new', 'acknowledged']:
                return None, 'Alert cannot be acknowledged in current status'
            
            alert.acknowledge(user)
            return alert, None
        except Alert.DoesNotExist:
            return None, 'Alert not found'
    
    @staticmethod
    def resolve_alert(alert_id, user, notes=''):
        """Resolve an alert"""
        try:
            alert = Alert.objects.get(id=alert_id)
            if alert.status == 'resolved':
                return None, 'Alert is already resolved'
            
            alert.resolve(user, notes)
            return alert, None
        except Alert.DoesNotExist:
            return None, 'Alert not found'
    
    @staticmethod
    def mark_false_positive(alert_id, user, notes=''):
        """Mark alert as false positive"""
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.mark_false_positive(user, notes)
            return alert, None
        except Alert.DoesNotExist:
            return None, 'Alert not found'
    
    @staticmethod
    def get_statistics():
        """Get alert statistics"""
        queryset = Alert.objects.all()
        
        return {
            'total': queryset.count(),
            'new': queryset.filter(status='new').count(),
            'acknowledged': queryset.filter(status='acknowledged').count(),
            'investigating': queryset.filter(status='investigating').count(),
            'resolved': queryset.filter(status='resolved').count(),
            'critical': queryset.filter(severity='critical').count(),
            'high': queryset.filter(severity='high').count(),
            'medium': queryset.filter(severity='medium').count(),
            'low': queryset.filter(severity='low').count(),
        }
    
    @staticmethod
    def get_by_threat_type():
        """Get alerts grouped by threat type"""
        return Alert.objects.values('threat_type').annotate(
            count=Count('id')
        ).order_by('-count')
    
    @staticmethod
    def get_critical_unhandled():
        """Get critical unhandled alerts"""
        return Alert.objects.filter(
            severity='critical',
            status__in=['new', 'acknowledged']
        )
    
    @staticmethod
    def get_recent_alerts(limit=10):
        """Get recent alerts"""
        return Alert.objects.all()[:limit]
    
    @staticmethod
    def get_user_alerts(user):
        """Get alerts for a specific user"""
        if user.is_analyst:
            return Alert.objects.all()
        return Alert.objects.filter(
            Q(created_by=user) | Q(assigned_to=user)
        )


class AlertRuleService:
    """Service for alert rule operations"""
    
    @staticmethod
    def create_rule(name, threat_type, severity, **kwargs):
        """Create a new alert rule"""
        rule = AlertRule.objects.create(
            name=name,
            threat_type=threat_type,
            severity=severity,
            **kwargs
        )
        return rule
    
    @staticmethod
    def get_active_rules():
        """Get all active alert rules"""
        return AlertRule.objects.filter(is_active=True)
    
    @staticmethod
    def toggle_rule_status(rule_id, is_active):
        """Toggle rule active status"""
        try:
            rule = AlertRule.objects.get(id=rule_id)
            rule.is_active = is_active
            rule.save()
            return rule
        except AlertRule.DoesNotExist:
            return None
    
    @staticmethod
    def evaluate_rules(log):
        """Evaluate if log matches any alert rules"""
        rules = AlertRule.objects.filter(
            is_active=True,
            threat_type=log.ai_threat_type,
            severity__lte=log.ai_severity
        )
        
        matched_rules = []
        for rule in rules:
            # Check time window and occurrences
            time_window = timezone.now() - timedelta(minutes=rule.time_window_minutes)
            recent_count = Alert.objects.filter(
                threat_type=rule.threat_type,
                created_at__gte=time_window
            ).count()
            
            if recent_count >= rule.min_occurrences:
                matched_rules.append(rule)
        
        return matched_rules


class BlockedIPService:
    """Service for IP blocking operations"""
    
    @staticmethod
    def block_ip(ip_address, reason, blocked_by=None, description='', expires_at=None):
        """Block an IP address"""
        blocked_ip, created = BlockedIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'description': description,
                'blocked_by': blocked_by,
                'expires_at': expires_at,
                'is_active': True
            }
        )
        return blocked_ip
    
    @staticmethod
    def unblock_ip(ip_address):
        """Unblock an IP address"""
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            blocked_ip.unblock()
            return True
        except BlockedIP.DoesNotExist:
            return False
    
    @staticmethod
    def is_blocked(ip_address):
        """Check if an IP is blocked"""
        try:
            blocked_ip = BlockedIP.objects.get(
                ip_address=ip_address,
                is_active=True
            )
            if blocked_ip.is_expired:
                blocked_ip.is_active = False
                blocked_ip.save()
                return False
            return True
        except BlockedIP.DoesNotExist:
            return False
    
    @staticmethod
    def get_active_blocks():
        """Get all active blocked IPs"""
        return BlockedIP.objects.filter(is_active=True)
    
    @staticmethod
    def cleanup_expired_blocks():
        """Remove expired blocks"""
        expired = BlockedIP.objects.filter(
            expires_at__lt=timezone.now(),
            is_active=True
        )
        count = expired.update(is_active=False)
        return count


class AlertNotificationService:
    """Service for alert notifications"""
    
    @staticmethod
    def create_notification(alert, notification_type, recipient):
        """Create a notification record"""
        notification = AlertNotification.objects.create(
            alert=alert,
            notification_type=notification_type,
            recipient=recipient,
            status='pending'
        )
        return notification
    
    @staticmethod
    def mark_sent(notification_id):
        """Mark notification as sent"""
        try:
            notification = AlertNotification.objects.get(id=notification_id)
            notification.status = 'sent'
            notification.save()
            return True
        except AlertNotification.DoesNotExist:
            return False
    
    @staticmethod
    def mark_failed(notification_id, error_message):
        """Mark notification as failed"""
        try:
            notification = AlertNotification.objects.get(id=notification_id)
            notification.status = 'failed'
            notification.error_message = error_message
            notification.save()
            return True
        except AlertNotification.DoesNotExist:
            return False

