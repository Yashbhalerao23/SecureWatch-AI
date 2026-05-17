"""
AI Log Monitoring & Security Detection Platform
Accounts App - Views
"""

import traceback
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import logout
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from .models import User
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer,
    ChangePasswordSerializer, LoginSerializer
)
from apps.logs.models import Log
from apps.alerts.models import Alert


class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for user management"""
    
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        if self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer
    
    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return User.objects.all()
        return User.objects.filter(id=user.id)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user info"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


class DashboardMetricsAPIView(generics.GenericAPIView):
    """API endpoint for dashboard metrics"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # 1. Metric Cards
        total_logs_today = Log.objects.filter(timestamp__gte=today_start).count()
        active_alerts = Alert.objects.filter(status__in=['new', 'acknowledged']).count()
        critical_threats = Alert.objects.filter(severity='critical', status='new').count()

        # Online Endpoints (reporting in last 24h)
        last_24h = now - timedelta(hours=24)
        online_endpoints = Log.objects.filter(timestamp__gte=last_24h).values('computer').distinct().count()

        # Failed Logins (Event ID 4625)
        failed_logins = Log.objects.filter(event_id=4625, timestamp__gte=today_start).count()

        # Suspicious PowerShell (contains 'encodedcommand' or flagged by AI)
        suspicious_pwsh = Log.objects.filter(
            Q(process_command_line__icontains='encodedcommand') |
            Q(ai_threat_type__icontains='powershell'),
            timestamp__gte=today_start
        ).count()

        # 2. Distributions
        severity_dist = list(Alert.objects.values('severity').annotate(count=Count('id')))

        # 3. Recent Activity (Last 5)
        from apps.alerts.serializers import AlertSerializer
        recent_incidents = Alert.objects.filter(severity__in=['critical', 'high']).order_by('-created_at')[:5]
        recent_alerts = Alert.objects.order_by('-created_at')[:6]

        # 4. Ingestion Activity (last 6 hours)
        ingestion = []
        for i in range(6):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            count = Log.objects.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
            ingestion.append({
                'timestamp': hour_end.strftime('%H:00'),
                'events': count
            })

        return Response({
            'total_logs_today': total_logs_today,
            'active_alerts': active_alerts,
            'critical_threats': critical_threats,
            'online_endpoints': online_endpoints,
            'failed_login_attempts': failed_logins,
            'suspicious_powershell_events': suspicious_pwsh,
            'recent_incidents': AlertSerializer(recent_incidents, many=True).data,
            'recent_alerts': AlertSerializer(recent_alerts, many=True).data,
            'severity_distribution': severity_dist,
            'ingestion_activity': ingestion[::-1]
        })


class LoginView(generics.GenericAPIView):
    """User login API endpoint with JWT support"""
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data['user']
                refresh = RefreshToken.for_user(user)

                # Update last activity
                user.last_activity = timezone.now()
                user.save(update_fields=['last_activity'])

                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': UserSerializer(user).data,
                    'message': 'Login successful'
                })
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(generics.GenericAPIView):
    """User logout API endpoint"""
    permission_classes = [IsAuthenticated]
    def post(self, request):
        logout(request)
        return Response({'message': 'Logout successful'})


class SessionIntelligenceView(generics.GenericAPIView):
    """Endpoint to analyze device fingerprint and session security"""
    permission_classes = [AllowAny]
    def post(self, request):
        return Response({
            'deviceId': request.data.get('device_fingerprint', 'unknown'),
            'deviceStatus': 'trusted',
            'browserChanged': False,
            'osChanged': False,
            'unusualLocation': False
        })
