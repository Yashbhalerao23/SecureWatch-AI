"""
AI Log Monitoring & Security Detection Platform
AI Engine - Celery Tasks
"""

import logging
from celery import shared_task
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def analyze_log(self, log_id: int):
    """Analyze a single log entry for security threats"""
    
    try:
        from apps.logs.models import Log
        from apps.ai_engine.ai_service import get_ai_service
        from apps.ai_engine.threat_detector import get_threat_detector
        
        log = Log.objects.get(id=log_id)
        
        if log.analyzed:
            logger.info(f"Log {log_id} already analyzed")
            return {'status': 'skipped', 'reason': 'already_analyzed'}
        
        ai_service = get_ai_service()
        threat_detector = get_threat_detector()
        
        log_data = {
            'timestamp': log.timestamp.isoformat(),
            'level': log.level,
            'message': log.message,
            'ip_address': log.ip_address,
            'service': log.service,
        }
        
        # Pattern-based threat detection
        pattern_threat = threat_detector.detect_threat(log_data)
        
        # AI-based threat detection
        ai_result = ai_service.analyze_log(log_data)
        
        # Combine results
        if ai_result.get('threat_detected'):
            threat_type = ai_result.get('threat_type')
            severity = ai_result.get('severity')
            description = ai_result.get('description', '')
            recommendation = ai_result.get('recommendation', '')
            confidence = ai_result.get('confidence', 0.0)
        elif pattern_threat:
            threat_type = pattern_threat['type']
            severity = pattern_threat['severity']
            description = pattern_threat['description']
            recommendation = 'Investigate this log entry'
            confidence = 0.7
        else:
            threat_type = None
            severity = None
            description = 'No threats detected'
            recommendation = ''
            confidence = 0.0
        
        # Update log with analysis results
        log.analyzed = True
        log.ai_threat_detected = threat_type is not None
        log.ai_threat_type = threat_type
        log.ai_severity = severity
        log.ai_analysis = {
            'threat_type': threat_type,
            'severity': severity,
            'confidence': confidence,
            'description': description,
            'recommendation': recommendation,
            'analyzed_at': timezone.now().isoformat(),
        }
        log.save()
        
        # Create alert if threat detected
        if threat_type:
            create_alert_from_log(log, threat_type, severity, description)
        
        logger.info(f"Log {log_id} analyzed: threat_detected={log.ai_threat_detected}")
        
        return {
            'status': 'success',
            'log_id': log_id,
            'threat_detected': log.ai_threat_detected,
            'threat_type': threat_type,
            'severity': severity,
        }
    
    except Log.DoesNotExist:
        logger.error(f"Log {log_id} not found")
        return {'status': 'error', 'message': 'Log not found'}
    
    except Exception as e:
        logger.error(f"Error analyzing log {log_id}: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task
def analyze_logs_batch(log_ids: list):
    """Analyze multiple logs in batch"""
    
    results = []
    
    for log_id in log_ids:
        result = analyze_log.delay(log_id)
        results.append({
            'log_id': log_id,
            'task_id': result.id,
        })
    
    return {
        'status': 'queued',
        'total': len(log_ids),
        'tasks': results,
    }


@shared_task
def analyze_recent_logs(hours: int = 24):
    """Analyze recent logs for threats"""
    
    from apps.logs.models import Log
    
    since = timezone.now() - timedelta(hours=hours)
    
    logs = Log.objects.filter(
        timestamp__gte=since,
        analyzed=False,
        level__in=['ERROR', 'CRITICAL']
    )[:100]
    
    analyzed_count = 0
    
    for log in logs:
        analyze_log.delay(log.id)
        analyzed_count += 1
    
    logger.info(f"Queued {analyzed_count} logs for analysis")
    
    return {
        'status': 'completed',
        'logs_queued': analyzed_count,
    }


def create_alert_from_log(log, threat_type: str, severity: str, description: str):
    """Create an alert from a detected threat"""
    
    from apps.alerts.models import Alert
    
    # Check if we already have a recent alert for this
    since = timezone.now() - timedelta(minutes=5)
    
    recent_alert = Alert.objects.filter(
        source_log=log,
        created_at__gte=since,
    ).first()
    
    if recent_alert:
        logger.info(f"Recent alert already exists for log {log.id}")
        return recent_alert
    
    threat_type_map = {
        'brute_force': 'brute_force',
        'sql_injection': 'sql_injection',
        'xss_attempt': 'xss_attempt',
        'ddos': 'ddos',
        'unauthorized_access': 'unauthorized_access',
        'suspicious_ip': 'suspicious_ip',
        'repeated_errors': 'repeated_errors',
    }
    
    alert_threat_type = threat_type_map.get(threat_type, 'other')
    
    alert = Alert.objects.create(
        title=f"Security Threat Detected: {threat_type.replace('_', ' ').title()}",
        description=description,
        severity=severity,
        threat_type=alert_threat_type,
        source_log=log,
        ip_address=log.ip_address,
        status='new',
    )
    
    logger.info(f"Created alert {alert.id} for log {log.id}")
    
    send_alert_notifications.delay(alert.id)
    
    return alert


@shared_task
def send_alert_notifications(alert_id: int):
    """Send notifications for new alerts"""
    
    from apps.alerts.models import Alert, AlertNotification
    from apps.accounts.models import User
    
    try:
        alert = Alert.objects.get(id=alert_id)
    except Alert.DoesNotExist:
        return {'status': 'error', 'message': 'Alert not found'}
    
    users = User.objects.filter(
        is_active=True,
        email_notifications=True,
        role__in=['admin', 'analyst']
    )
    
    for user in users:
        if user.email:
            notification = AlertNotification.objects.create(
                alert=alert,
                notification_type='email',
                recipient=user.email,
                status='pending',
            )
            
            try:
                # Email sending would be implemented here
                notification.status = 'sent'
                notification.save()
                logger.info(f"Sent email notification for alert {alert_id} to {user.email}")
            except Exception as e:
                notification.status = 'failed'
                notification.error_message = str(e)
                notification.save()
                logger.error(f"Failed to send email for alert {alert_id}: {e}")
    
    return {'status': 'completed', 'alert_id': alert_id}


@shared_task
def cleanup_old_logs(days: int = 90):
    """Clean up old logs (retention policy)"""
    
    from apps.logs.models import Log
    
    cutoff = timezone.now() - timedelta(days=days)
    count = Log.objects.filter(created_at__lt=cutoff).count()
    Log.objects.filter(created_at__lt=cutoff).delete()
    
    logger.info(f"Cleaned up {count} logs older than {days} days")
    
    return {
        'status': 'completed',
        'deleted_count': count,
    }

