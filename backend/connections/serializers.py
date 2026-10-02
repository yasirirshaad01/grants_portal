from django.conf import settings
from rest_framework import serializers


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


class GrantRequestSerializer(serializers.Serializer):
    rights_type = serializers.ChoiceField(choices=["informix", "mysql", "greenplum", "postgres"])
    granter_name = serializers.CharField(max_length=150)
    jira_ticket = serializers.CharField(max_length=64)
