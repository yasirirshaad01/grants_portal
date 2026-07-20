from django.conf import settings
from rest_framework import serializers

from .models import GrantRequest


class JumpConnectSerializer(serializers.Serializer):
    host = serializers.CharField()
    username = serializers.CharField()
    first_factor = serializers.CharField(trim_whitespace=False)
    second_factor = serializers.CharField(trim_whitespace=False)

    def validate_host(self, value):
        if value not in settings.JUMP_SERVERS:
            raise serializers.ValidationError("Unknown jump server.")
        return value


class DirectConnectSerializer(serializers.Serializer):
    host = serializers.CharField()
    username = serializers.CharField()
    password = serializers.CharField(trim_whitespace=False)

    def validate_host(self, value):
        if value not in settings.TRUSTED_SUPERUSER_HOSTS:
            raise serializers.ValidationError("Unknown trusted host.")
        return value


class HopSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    host = serializers.CharField()
    username = serializers.CharField()
    password = serializers.CharField(required=False, allow_blank=True, trim_whitespace=False)
    mode = serializers.ChoiceField(choices=["password", "trusted"], default="trusted")


class SessionResponseSerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    status = serializers.CharField()
    current_host = serializers.CharField()


class GrantRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = GrantRequest
        fields = ["rights_type", "granter_name", "jira_ticket"]
