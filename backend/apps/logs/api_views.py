from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
import logging
from .models import Log, Service
from .serializers import LogSerializer, SysmonLogSerializer, ServiceSerializer
from .parsers import parse_sysmon_log, get_sysmon_parser
from apps.alerts.models import Alert
from apps.ai_engine.ai_service import get_ai_service

logger = logging.getLogger(__name__)

class LogViewSet(viewsets.ModelViewSet):
    queryset = Log.objects.all()
    serializer_class = LogSerializer


class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer


class SysmonLogIngestAPIView(APIView):
    """
    API endpoint for ingesting Windows Sysmon event logs from Winlogbeat.
    Every log is analyzed by Gemini AI to detect security threats.
    """
    
    def post(self, request):
        """Ingest Sysmon events"""
        data = request.data
        
        # Check if it's a batch of events
        if isinstance(data, list):
            return self._process_batch(request, data)

        # Process single event
        return self._process_single(request, data)

    def _process_single(self, request, data: dict) -> Response:
        """Process a single Sysmon event and analyze with Gemini AI"""
        # Parse the event data into a standard format
        parsed_data = self._parse_event_data(data)
        
        if not parsed_data:
            return Response(
                {'error': 'Failed to parse event data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate and save to DB
        serializer = SysmonLogSerializer(data=parsed_data)
        
        if serializer.is_valid():
            log = serializer.save()

            # --- AI ANALYST START ---
            # Call Gemini AI to analyze this log entry
            ai_analysis = self._run_ai_analysis(log, parsed_data)
            # --- AI ANALYST END ---

            # Return response with AI findings
            response_data = SysmonLogSerializer(log).data
            response_data['ai_analysis_result'] = ai_analysis
            
            return Response(
                response_data,
                status=status.HTTP_201_CREATED
            )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    def _run_ai_analysis(self, log, parsed_data: dict) -> dict:
        """Sends log data to Gemini and updates the log record with results"""
        try:
            ai_service = get_ai_service()
            print(f"[AI ANALYST] Analyzing event ID {log.event_id} from {log.computer} using Gemini...")

            # Get AI opinion
            analysis = ai_service.analyze_log(parsed_data)

            if analysis:
                # Save AI findings to the log record
                log.ai_threat_detected = analysis.get('threat_detected', False)
                log.ai_threat_type = analysis.get('threat_type', 'none')
                log.ai_severity = analysis.get('severity', 'low')
                log.ai_analysis = analysis
                log.analyzed = True
                log.save()

                # If AI detects a threat, create a security alert
                if log.ai_threat_detected:
                    print(f"[AI ALERT] Gemini detected a {log.ai_severity} threat: {log.ai_threat_type}")
                    self._create_alert_from_ai(log, analysis)
                
                return analysis

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            print(f"[AI ERROR] Gemini analysis failed: {str(e)}")

        return {'status': 'failed', 'reason': 'AI service error or disabled'}

    def _create_alert_from_ai(self, log, analysis):
        """Creates an alert record in the DB when AI detects a threat"""
        try:
            Alert.objects.create(
                log=log,
                title=f"AI Alert: {analysis.get('threat_type', 'Security').replace('_', ' ').title()}",
                description=analysis.get('description', 'AI flagged this Sysmon event as suspicious.'),
                severity=analysis.get('severity', 'medium'),
                threat_type=analysis.get('threat_type', 'unknown'),
                source_ip=log.ip_address or log.source_ip,
                affected_service=log.service or 'Windows-Sysmon',
                recommendation=analysis.get('recommendation', 'Follow standard IR procedures.'),
                confidence_score=analysis.get('confidence', 0.8),
                raw_data={'ai_analysis': analysis}
            )
        except Exception as e:
            logger.error(f"Failed to create AI alert: {e}")

    def _process_batch(self, request, events: list) -> Response:
        """Process multiple events and run AI on each"""
        results = {'total': len(events), 'success': 0, 'failed': 0, 'logs': []}
        for event in events:
            parsed = self._parse_event_data(event)
            if parsed:
                serializer = SysmonLogSerializer(data=parsed)
                if serializer.is_valid():
                    log = serializer.save()
                    self._run_ai_analysis(log, parsed)
                    results['success'] += 1
                    results['logs'].append(log.id)
                else:
                    results['failed'] += 1
            else:
                results['failed'] += 1
        return Response(results, status=status.HTTP_200_OK)

    def _parse_event_data(self, data: dict) -> dict:
        """Parses Winlogbeat/Sysmon JSON into standard format"""
        parser = get_sysmon_parser()
        # Direct winlogbeat handling
        if 'winlog' in data:
            return parser.parse_json_event(data)
        # Fallback to field normalization
        return self._normalize_event_data(data)

    def _normalize_event_data(self, data: dict) -> dict:
        """Ensures common field names are used"""
        field_mappings = {
            'EventID': 'event_id', 'Channel': 'channel', 'Computer': 'computer',
            'User': 'user_name', 'Image': 'process_path', 'CommandLine': 'process_command_line',
            'DestinationIp': 'destination_ip', 'SourceIp': 'source_ip'
        }
        normalized = {field_mappings.get(k, k): v for k, v in data.items()}
        if 'level' not in normalized: normalized['level'] = 'INFO'
        return normalized

    def get(self, request):
        return Response({'status': 'online', 'feature': 'AI Ingestion with Gemini'})
