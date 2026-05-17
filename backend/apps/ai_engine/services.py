"""
AI Log Monitoring & Security Detection Platform
AI Engine - Services
"""

from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


class AIServiceEnhanced:
    """Enhanced AI Service with vulnerability detection and auto-alerting"""
    
    def __init__(self):
        from .ai_service import get_ai_service
        # Get fresh instance each time
        self.ai_service = get_ai_service()
    
    def analyze_log_with_alert(self, log_data, create_alert=True):
        """Analyze log and optionally create alert"""
        
        # Get threat analysis
        threat_result = self.ai_service.analyze_log(log_data)
        
        # Get vulnerability detection
        vuln_result = self.ai_service.detect_vulnerabilities(log_data)
        
        # Combine results
        result = {
            'threat_analysis': threat_result,
            'vulnerability_analysis': vuln_result,
            'has_issues': threat_result.get('threat_detected') or vuln_result.get('vulnerabilities_detected')
        }
        
        # Create alert if issues found and requested
        if create_alert and result['has_issues']:
            self._create_alert_from_analysis(log_data, threat_result, vuln_result)
        
        return result
    
    def _create_alert_from_analysis(self, log_data, threat_result, vuln_result):
        """Create alert from analysis results"""
        
        from apps.alerts.models import Alert
        
        # Determine severity
        severity = 'low'
        if vuln_result.get('vulnerabilities'):
            severities = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            for vuln in vuln_result['vulnerabilities']:
                vuln_severity = severities.get(vuln.get('severity', 'low'), 1)
                if vuln_severity > severities.get(severity, 0):
                    severity = vuln['severity']
        
        if threat_result.get('threat_detected'):
            threat_severity = threat_result.get('severity', 'low')
            severities = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            if severities.get(threat_severity, 0) > severities.get(severity, 0):
                severity = threat_severity
        
        # Build title and description
        title = "Security Alert: "
        if vuln_result.get('vulnerabilities_detected'):
            vuln = vuln_result['vulnerabilities'][0]
            title += f"{vuln['description']}"
        elif threat_result.get('threat_detected'):
            title += f"{threat_result.get('threat_type', 'Unknown threat').replace('_', ' ').title()}"
        
        description = f"Analysis of log entry detected security issues.\n\n"
        if vuln_result.get('vulnerabilities'):
            description += "Vulnerabilities Found:\n"
            for vuln in vuln_result['vulnerabilities']:
                description += f"- {vuln['description']} (CWE: {vuln.get('cwe', 'N/A')})\n"
                description += f"  Recommendation: {vuln.get('recommendation', 'N/A')}\n\n"
        
        if threat_result.get('threat_detected'):
            description += f"Threat: {threat_result.get('description', 'N/A')}\n"
            description += f"Recommendation: {threat_result.get('recommendation', 'N/A')}"
        
        # Determine threat type
        threat_type = 'other'
        if vuln_result.get('vulnerabilities'):
            vuln = vuln_result['vulnerabilities'][0]
            threat_type = vuln.get('type', 'vulnerability')
        elif threat_result.get('threat_detected'):
            threat_type = threat_result.get('threat_type', 'other')
        
        # Get CWE if available
        cwe_id = ''
        if vuln_result.get('vulnerabilities'):
            cwe_id = vuln_result['vulnerabilities'][0].get('cwe', '')
        
        recommendation = ''
        if vuln_result.get('vulnerabilities'):
            recommendation = vuln_result['vulnerabilities'][0].get('recommendation', '')
        
        try:
            alert = Alert.objects.create(
                title=title[:255],
                description=description,
                severity=severity,
                threat_type=threat_type,
                cwe_id=cwe_id,
                vulnerability_type=threat_type if vuln_result.get('vulnerabilities_detected') else '',
                recommendation=recommendation,
                ip_address=log_data.get('ip_address'),
                source_log_id=log_data.get('id')
            )
            logger.info(f"Auto-created alert: {alert.id} for vulnerability/threat")
            return alert
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None
    
    def get_vulnerability_statistics(self, days=30):
        """Get vulnerability statistics"""
        
        from apps.alerts.models import Alert
        
        start_date = timezone.now() - timedelta(days=days)
        
        # Get vulnerability alerts
        vulnerability_alerts = Alert.objects.filter(
            created_at__gte=start_date,
            threat_type__in=[
                'vulnerability', 'sql_injection', 'xss_attempt', 
                'command_injection', 'path_traversal', 'weak_crypto',
                'sensitive_data_exposure', 'security_misconfig', 'open_redirect'
            ]
        )
        
        # Stats by severity
        severity_stats = vulnerability_alerts.values('severity').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Stats by type
        type_stats = vulnerability_alerts.values('threat_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Stats by CWE
        cwe_stats = vulnerability_alerts.exclude(
            cwe_id=''
        ).values('cwe_id').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Recent critical vulnerabilities
        critical_vulns = vulnerability_alerts.filter(
            severity='critical'
        ).order_by('-created_at')[:5]
        
        return {
            'total_vulnerabilities': vulnerability_alerts.count(),
            'by_severity': {item['severity']: item['count'] for item in severity_stats},
            'by_type': {item['threat_type']: item['count'] for item in type_stats},
            'top_cwe': [{'cwe': item['cwe_id'], 'count': item['count']} for item in cwe_stats],
            'critical_vulnerabilities': list(critical_vulns.values('id', 'title', 'severity', 'cwe_id', 'created_at')),
            'period_days': days
        }
    
    def get_threat_intelligence_summary(self):
        """Get threat intelligence summary"""
        
        from apps.alerts.models import Alert
        from apps.logs.models import Log
        
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        return {
            'last_24h': {
                'new_alerts': Alert.objects.filter(created_at__gte=last_24h).count(),
                'critical_alerts': Alert.objects.filter(created_at__gte=last_24h, severity='critical').count(),
                'total_logs': Log.objects.filter(timestamp__gte=last_24h).count(),
            },
            'last_7d': {
                'new_alerts': Alert.objects.filter(created_at__gte=last_7d).count(),
                'critical_alerts': Alert.objects.filter(created_at__gte=last_7d, severity='critical').count(),
                'total_logs': Log.objects.filter(timestamp__gte=last_7d).count(),
            },
            'by_threat_type': list(Alert.objects.values('threat_type').annotate(
                count=Count('id')
            ).order_by('-count')[:10]),
            'top_attack_ips': list(Alert.objects.filter(
                ip_address__isnull=False
            ).values('ip_address').annotate(
                count=Count('id')
            ).order_by('-count')[:5])
        }


# Singleton instance
ai_service_enhanced = AIServiceEnhanced()


def get_ai_service_enhanced() -> AIServiceEnhanced:
    """Get the enhanced AI service instance"""
    return ai_service_enhanced
