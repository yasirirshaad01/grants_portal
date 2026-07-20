import uuid

from django.conf import settings
from django.db import models


class SSHSession(models.Model):
    """
    Metadata about a live backend SSH hop-chain. Never stores passwords,
    OTPs, or any credential - only what's needed for display and audit.
    """

    JUMP = "jump"
    DIRECT = "direct"
    CONNECTION_TYPES = [
        (JUMP, "Jump Server"),
        (DIRECT, "Direct Trusted Server"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    portal_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    connection_type = models.CharField(max_length=10, choices=CONNECTION_TYPES)
    jump_host = models.GenericIPAddressField(null=True, blank=True)
    current_host = models.GenericIPAddressField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    # The sourcing command for the loaded Informix instance, e.g. ". /mcp_qasi".
    # Every subsequent dbaccess call is prefixed with this, since each SSH
    # exec_command() is a fresh shell and doesn't inherit a prior `source`.
    env_script = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.portal_user} -> {self.current_host or self.jump_host} ({self.id})"


class AuditLog(models.Model):
    """Append-only record of every meaningful action for compliance review."""

    session = models.ForeignKey(SSHSession, on_delete=models.SET_NULL, null=True, blank=True)
    portal_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)
    detail = models.TextField(blank=True)
    executed_sql = models.TextField(blank=True)
    result_summary = models.TextField(blank=True)
    status = models.CharField(max_length=20, default="success")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.timestamp}] {self.portal_user} {self.action} ({self.status})"


class GrantRequest(models.Model):
    INFORMIX = "informix"
    MYSQL = "mysql"
    GREENPLUM = "greenplum"
    POSTGRES = "postgres"
    RIGHTS_CHOICES = [
        (INFORMIX, "Informix"),
        (MYSQL, "MySQL"),
        (GREENPLUM, "Greenplum"),
        (POSTGRES, "Postgres"),
    ]

    portal_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    rights_type = models.CharField(max_length=20, choices=RIGHTS_CHOICES)
    granter_name = models.CharField(max_length=150)
    jira_ticket = models.CharField(max_length=64)
    requested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self):
        return f"{self.rights_type} request by {self.granter_name} ({self.jira_ticket})"
