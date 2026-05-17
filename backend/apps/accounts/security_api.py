from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from apps.alerts.models import BlockedIP
from django.utils import timezone


class BlockIPView(APIView):
    """Block suspicious IP addresses"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        ip_address = request.data.get('ip_address')
        reason = request.data.get('reason', 'Suspicious activity detected')
        
        if not ip_address:
            return Response({'error': 'IP address required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if already blocked
        if BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
            return Response({'message': 'IP already blocked'}, status=status.HTTP_200_OK)
        
        # Block the IP
        blocked = BlockedIP.objects.create(
            ip_address=ip_address,
            reason=reason,
            blocked_by=request.user,
            blocked_at=timezone.now(),
            is_active=True
        )
        
        return Response({
            'message': f'IP {ip_address} blocked successfully',
            'blocked_ip': {
                'ip_address': blocked.ip_address,
                'reason': blocked.reason,
                'blocked_at': blocked.blocked_at
            }
        }, status=status.HTTP_201_CREATED)


class UnblockIPView(APIView):
    """Unblock IP addresses"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        ip_address = request.data.get('ip_address')
        
        if not ip_address:
            return Response({'error': 'IP address required'}, status=status.HTTP_400_BAD_REQUEST)
        
        blocked = BlockedIP.objects.filter(ip_address=ip_address, is_active=True).first()
        
        if not blocked:
            return Response({'error': 'IP not found in blocklist'}, status=status.HTTP_404_NOT_FOUND)
        
        blocked.is_active = False
        blocked.save()
        
        return Response({'message': f'IP {ip_address} unblocked'}, status=status.HTTP_200_OK)


class BlockedIPListView(APIView):
    """List all blocked IPs"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        blocked_ips = BlockedIP.objects.filter(is_active=True).order_by('-blocked_at')
        
        data = [{
            'ip_address': ip.ip_address,
            'reason': ip.reason,
            'blocked_at': ip.blocked_at,
            'blocked_by': ip.blocked_by.username if ip.blocked_by else 'System'
        } for ip in blocked_ips]
        
        return Response({'blocked_ips': data}, status=status.HTTP_200_OK)
