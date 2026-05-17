"""
AI Log Monitoring & Security Detection Platform
Alerts App - Serializers
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Alert, AlertNotification, AlertRule, BlockedIP

User = get_user_model()


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert model"""
    
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    assigned_to_username = serializers.CharField(source='assigned_to.username', read_only=True)
    acknowledged_by_username = serializers.CharField(source='acknowledged_by.username', read_only=True)
    resolved_by_username = serializers.CharField(source='resolved_by.username', read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']
    
    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class AlertCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating alerts"""
    
    class Meta:
        model = Alert
        fields = [
            'title', 'description', 'severity', 'threat_type',
            'ip_address', 'source_log', 'assigned_to'
        ]
    
    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class AlertUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating alerts"""
    
    class Meta:
        model = Alert
        fields = [
            'title', 'description', 'severity', 'threat_type',
            'status', 'assigned_to', 'resolution_notes'
        ]


class AlertStatsSerializer(serializers.Serializer):
    """Serializer for alert statistics"""
    
    total = serializers.IntegerField()
    new = serializers.IntegerField()
    acknowledged = serializers.IntegerField()
    investigating = serializers.IntegerField()
    resolved = serializers.IntegerField()
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()


class AlertListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for alert list views"""
    
    class Meta:
        model = Alert
        fields = [
            'id', 'title', 'description', 'severity', 'threat_type',
            'ip_address', 'status', 'created_at'
        ]


class AlertNotificationSerializer(serializers.ModelSerializer):
    """Serializer for AlertNotification model"""
    
    class Meta:
        model = AlertNotification
        fields = '__all__'


class AlertRuleSerializer(serializers.ModelSerializer):
    """Serializer for AlertRule model"""
    
    class Meta:
        model = AlertRule
        fields = '__all__'


class BlockedIPSerializer(serializers.ModelSerializer):
    """Serializer for BlockedIP model"""
    
    blocked_by_username = serializers.CharField(source='blocked_by.username', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = BlockedIP
        fields = '__all__'
        read_only_fields = ['blocked_at', 'updated_at']
    
    def create(self, validated_data):
        validated_data['blocked_by'] = self.context['request'].user
        return super().create(validated_data)


class BlockIPSerializer(serializers.Serializer):
    """Serializer for blocking an IP address"""
    
    ip_address = serializers.IPAddressField()
    reason = serializers.ChoiceField(choices=BlockedIP.BLOCK_REASON_CHOICES)
    description = serializers.CharField(required=False, allow_blank=True)
    expires_hours = serializers.IntegerField(required=False, default=None, min_value=1)
    
    def validate_ip_address(self, value):
        # Check if already blocked
        if BlockedIP.objects.filter(ip_address=value, is_active=True).exists():
            raise serializers.ValidationError("This IP address is already blocked")
        return value
    
    def create(self, validated_data):
        user = self.context['request'].user
        expires_hours = validated_data.pop('expires_hours', None)
        
        if expires_hours:
            from django.utils import timezone
            from datetime import timedelta
            validated_data['expires_at'] = timezone.now() + timedelta(hours=expires_hours)
        
        validated_data['blocked_by'] = user
        validated_data['is_active'] = True
        
        return BlockedIP.objects.create(**validated_data)


class UnblockIPSerializer(serializers.Serializer):
    """Serializer for unblocking an IP address"""
    
    ip_address = serializers.IPAddressField()
    
    def validate_ip_address(self, value):
        blocked_ip = BlockedIP.objects.filter(ip_address=value, is_active=True).first()
        if not blocked_ip:
            raise serializers.ValidationError("This IP address is not currently blocked")
        return value
