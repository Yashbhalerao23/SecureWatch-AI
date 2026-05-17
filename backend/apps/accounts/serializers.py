"""
AI Log Monitoring & Security Detection Platform
Accounts App - Serializers
"""

import logging
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, UserSession

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    full_name = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'role', 'phone', 'email_notifications', 'is_active', 'status',
            'created_at', 'updated_at', 'last_activity'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_activity']

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username

    def get_status(self, obj):
        return 'active' if obj.is_active else 'disabled'


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating users with React compatibility"""
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        help_text='User password'
    )
    full_name = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'full_name', 'role', 'phone'
        ]

    def create(self, validated_data):
        full_name = validated_data.pop('full_name', '')
        first_name = ""
        last_name = ""

        if full_name:
            parts = full_name.split(' ', 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            first_name=first_name,
            last_name=last_name,
            role=validated_data.get('role', 'viewer'),
            phone=validated_data.get('phone', '')
        )
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating users"""
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone',
            'email_notifications', 'role', 'is_active'
        ]


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change"""
    
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match'
            })
        return attrs


class LoginSerializer(serializers.Serializer):
    """Serializer for user login with enhanced diagnostics"""
    
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    login_intelligence = serializers.JSONField(required=False)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )

            if not user:
                raise serializers.ValidationError('Invalid username or password')

            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')

            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include "username" and "password"')

        return attrs


class SessionSerializer(serializers.ModelSerializer):
    """Serializer for user sessions"""
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'ip_address', 'user_agent', 'created_at',
            'expires_at', 'is_active'
        ]
        read_only_fields = fields
