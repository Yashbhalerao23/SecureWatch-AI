"""
AI Log Monitoring & Security Detection Platform
AI Engine - Views
"""

from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Count
import logging

from .ai_service import get_ai_service
from .services import get_ai_service_enhanced
from apps.logs.models import Log
from apps.alerts.models import Alert

logger = logging.getLogger(__name__)


class AnalyzeLogAPIView(generics.GenericAPIView):
    """API endpoint for manual log analysis"""
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Analyze provided log text"""
        
        log_text = request.data.get('log_text', '')
        
        if not log_text:
            return Response(
                {'error': 'log_text is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        ai_service = get_ai_service()
        
        try:
            result = ai_service.analyze_manual(log_text)
            return Response(result)
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return Response(
                {'error': 'Analysis failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ThreatSummaryAPIView(generics.GenericAPIView):
    """API endpoint for the AI Threat Analysis dashboard summary"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # 1. Get stats
        total_logs = Log.objects.count()
        analyzed_logs = Log.objects.filter(analyzed=True).count()
        threat_logs = Log.objects.filter(ai_threat_detected=True).count()

        # 2. Get top findings (formatted as AnalysisItem)
        recent_threats = Log.objects.filter(ai_threat_detected=True).order_by('-timestamp')[:5]
        findings = []
        for i, log in enumerate(recent_threats):
            findings.append({
                'id': i + 1,
                'title': log.ai_threat_type.replace('_', ' ').title() if log.ai_threat_type else "Potential Security Threat",
                'score': int((log.ai_analysis.get('confidence', 0.8) if isinstance(log.ai_analysis, dict) else 0.8) * 100),
                'category': 'SECURITY DETECTION',
                'summary': log.ai_analysis.get('description', 'Suspicious activity detected.') if isinstance(log.ai_analysis, dict) else log.message[:200],
                'recommendation': log.ai_analysis.get('recommendation', 'Investigate immediately.') if isinstance(log.ai_analysis, dict) else 'Check raw logs.',
                'related_log_ids': [log.id]
            })

        # 3. Create a dynamic summary string
        summary = f"Gemini AI has analyzed {analyzed_logs} out of {total_logs} total logs. "
        if threat_logs > 0:
            summary += f"It has detected {threat_logs} suspicious security events that require your attention. "
            summary += "The primary threats involve " + ", ".join(list(set([l.ai_threat_type for l in recent_threats if l.ai_threat_type]))) + "."
        else:
            summary += "No critical security threats have been detected in the current log stream."

        return Response({
            'summary': summary,
            'findings': findings
        })


class DetectVulnerabilitiesAPIView(generics.GenericAPIView):
    """API endpoint for vulnerability detection in logs"""
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Detect vulnerabilities in provided log data"""
        
        log_data = request.data
        
        if not log_data:
            return Response(
                {'error': 'log_data is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if we should create an alert
        create_alert = request.data.get('create_alert', False)
        
        ai_service = get_ai_service()
        
        try:
            result = ai_service.detect_vulnerabilities(log_data)
            
            # Optionally create alert
            if create_alert and result.get('vulnerabilities_detected'):
                enhanced = get_ai_service_enhanced()
                alert = enhanced._create_alert_from_analysis(
                    log_data, 
                    {'threat_detected': False, 'threat_type': '', 'severity': '', 'description': '', 'recommendation': ''},
                    result
                )
                if alert:
                    result['alert_created'] = True
                    result['alert_id'] = alert.id
            
            return Response(result)
        except Exception as e:
            logger.error(f"Vulnerability detection failed: {e}")
            return Response(
                {'error': 'Detection failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerabilityStatsAPIView(generics.GenericAPIView):
    """API endpoint for vulnerability statistics"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get vulnerability statistics"""
        
        days = int(request.query_params.get('days', 30))
        
        try:
            enhanced = get_ai_service_enhanced()
            stats = enhanced.get_vulnerability_statistics(days)
            return Response(stats)
        except Exception as e:
            logger.error(f"Failed to get vulnerability stats: {e}")
            return Response(
                {'error': 'Failed to get statistics', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ThreatIntelligenceAPIView(generics.GenericAPIView):
    """API endpoint for threat intelligence summary"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get threat intelligence summary"""
        
        try:
            enhanced = get_ai_service_enhanced()
            intel = enhanced.get_threat_intelligence_summary()
            return Response(intel)
        except Exception as e:
            logger.error(f"Failed to get threat intelligence: {e}")
            return Response(
                {'error': 'Failed to get intelligence', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecurityChatAPIView(generics.GenericAPIView):
    """API endpoint for security assistant chatbot"""
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Chat with security assistant"""
        
        user_message = request.data.get('message', '')
        
        if not user_message:
            return Response(
                {'error': 'message is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get optional context from request
        context = request.data.get('context', None)
        
        ai_service = get_ai_service()
        
        try:
            result = ai_service.chat_with_security_assistant(user_message, context)
            
            # Return 429 if rate limited
            if result.get('mode') == 'rate_limit':
                return Response(result, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            return Response(result)
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return Response(
                {'error': 'Chat failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BatchAnalyzeAPIView(generics.GenericAPIView):
    """API endpoint for batch log analysis"""
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Analyze multiple log entries"""
        
        logs = request.data.get('logs', [])
        
        if not logs:
            return Response(
                {'error': 'logs array is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(logs) > 100:
            return Response(
                {'error': 'Maximum 100 logs can be analyzed at once'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        ai_service = get_ai_service()
        
        try:
            results = ai_service.analyze_logs_batch(logs)
            return Response({
                'total': len(logs),
                'results': results
            })
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            return Response(
                {'error': 'Analysis failed', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BatchVulnerabilityDetectAPIView(generics.GenericAPIView):
    """API endpoint for batch vulnerability detection"""
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Detect vulnerabilities in multiple log entries"""
        
        logs = request.data.get('logs', [])
        
        if not logs:
            return Response(
                {'error': 'logs array is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(logs) > 50:
            return Response(
                {'error': 'Maximum 50 logs can be analyzed at once'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if we should create alerts
        create_alerts = request.data.get('create_alerts', False)
        
        ai_service = get_ai_service()
        
        results = []
        total_vulnerabilities = 0
        alerts_created = 0
        
        for log in logs:
            result = ai_service.detect_vulnerabilities(log)
            if result.get('vulnerabilities_detected'):
                total_vulnerabilities += len(result.get('vulnerabilities', []))
                
                # Create alert if requested
                if create_alerts:
                    enhanced = get_ai_service_enhanced()
                    alert = enhanced._create_alert_from_analysis(
                        log,
                        {'threat_detected': False, 'threat_type': '', 'severity': '', 'description': '', 'recommendation': ''},
                        result
                    )
                    if alert:
                        alerts_created += 1
                        result['alert_created'] = True
                        result['alert_id'] = alert.id
            
            results.append(result)
        
        response = {
            'total': len(logs),
            'logs_with_vulnerabilities': sum(1 for r in results if r.get('vulnerabilities_detected')),
            'total_vulnerabilities': total_vulnerabilities,
            'results': results
        }
        
        if create_alerts:
            response['alerts_created'] = alerts_created
        
        return Response(response)


class AIConfigAPIView(generics.RetrieveAPIView):
    """API endpoint for AI configuration status"""
    
    permission_classes = [IsAuthenticated]
    
    def retrieve(self, request):
        """Get AI configuration status"""
        
        ai_service = get_ai_service()
        
        config = {
            'enabled': ai_service.enabled,
            'provider': ai_service.provider,
            'model': ai_service.model,
            'configured': bool(ai_service.api_key),
            'has_ai': ai_service.has_ai,
            'analysis_mode': 'AI' if ai_service.has_ai else 'Pattern-Based',
        }
        
        # Add rate limit info for Gemini
        if ai_service.provider == 'gemini' and ai_service.has_ai:
            config['rate_limits'] = {
                'requests_per_minute': 15,
                'tokens_per_minute': 1000000,
                'requests_per_day': 1500,
                'remaining_requests': ai_service.rate_limiter.get_remaining_requests()
            }
        
        return Response(config)


# HTML Template Views

@login_required
def ai_analysis_view(request):
    """AI Analysis page"""
    
    ai_service = get_ai_service()
    
    return render(request, 'ai_engine/analysis.html', {
        'ai_enabled': ai_service.enabled,
        'ai_provider': ai_service.provider,
        'ai_model': ai_service.model,
        'ai_configured': bool(ai_service.api_key),
        'analysis_mode': 'AI' if ai_service.has_ai else 'Pattern-Based',
    })


@login_required
def ai_analysis_result(request):
    """Process AI analysis request"""
    
    if request.method == 'POST':
        log_text = request.POST.get('log_text', '')
        
        if not log_text:
            return render(request, 'ai_engine/analysis.html', {
                'error': 'Please provide log text to analyze'
            })
        
        ai_service = get_ai_service()
        
        # Get both analysis and vulnerability detection
        analysis_result = ai_service.analyze_manual(log_text)
        vuln_result = ai_service.detect_vulnerabilities({'message': log_text})
        
        return render(request, 'ai_engine/analysis.html', {
            'result': analysis_result,
            'vulnerability_result': vuln_result,
            'log_text': log_text,
            'ai_enabled': ai_service.enabled,
            'ai_provider': ai_service.provider,
            'ai_model': ai_service.model,
            'ai_configured': bool(ai_service.api_key),
            'analysis_mode': 'AI' if ai_service.has_ai else 'Pattern-Based',
        })
    
    return render(request, 'ai_engine/analysis.html')


@login_required
def ai_chat_view(request):
    """AI Security Assistant Chat page"""
    
    ai_service = get_ai_service()
    
    # Get context for the chat
    from apps.logs.models import Log
    from apps.alerts.models import Alert
    from django.utils import timezone
    from django.db.models import Count
    
    context = {
        'total_logs': Log.objects.count(),
        'active_alerts': Alert.objects.filter(status__in=['new', 'acknowledged']).count(),
        'critical_alerts': Alert.objects.filter(severity='critical', status='new').count(),
    }
    
    # Get recent threat types
    recent_threats = list(Alert.objects.values('threat_type').annotate(
        count=Count('id')
    ).order_by('-count')[:5])
    context['recent_threats'] = [t['threat_type'] for t in recent_threats if t['threat_type']]
    
    return render(request, 'ai_engine/chat.html', {
        'ai_enabled': ai_service.enabled,
        'ai_provider': ai_service.provider,
        'ai_model': ai_service.model,
        'ai_configured': bool(ai_service.api_key),
        'has_ai': ai_service.has_ai,
        'analysis_mode': 'AI' if ai_service.has_ai else 'FAQ',
        'context': context,
    })


@login_required
def ai_chat_process(request):
    """Process AI chat request"""
    
    if request.method == 'POST':
        user_message = request.POST.get('message', '')
        
        if not user_message:
            return render(request, 'ai_analyzer/chat.html', {
                'error': 'Please enter a message'
            })
        
        # Get context
        from apps.logs.models import Log
        from apps.alerts.models import Alert
        from django.db.models import Count
        
        context = {
            'total_logs': Log.objects.count(),
            'active_alerts': Alert.objects.filter(status__in=['new', 'acknowledged']).count(),
            'critical_alerts': Alert.objects.filter(severity='critical', status='new').count(),
        }
        
        recent_threats = list(Alert.objects.values('threat_type').annotate(
            count=Count('id')
        ).order_by('-count')[:5])
        context['recent_threats'] = [t['threat_type'] for t in recent_threats if t['threat_type']]
        
        ai_service = get_ai_service()
        
        try:
            result = ai_service.chat_with_security_assistant(user_message, context)
            
            return render(request, 'ai_engine/chat.html', {
                'user_message': user_message,
                'ai_response': result.get('response'),
                'response_mode': result.get('mode', 'faq'),
                'ai_enabled': ai_service.enabled,
                'ai_provider': ai_service.provider,
                'ai_model': ai_service.model,
                'ai_configured': bool(ai_service.api_key),
                'has_ai': ai_service.has_ai,
                'analysis_mode': 'AI' if ai_service.has_ai else 'FAQ',
                'context': context,
                'remaining_requests': result.get('remaining_requests'),
            })
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return render(request, 'ai_engine/chat.html', {
                'error': f'Chat failed: {str(e)}'
            })
    
    return render(request, 'ai_engine/chat.html')
