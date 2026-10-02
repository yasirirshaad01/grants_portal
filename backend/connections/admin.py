from django.contrib import admin

from .models import SSHSession, AuditLog


@admin.register(SSHSession)
class SSHSessionAdmin(admin.ModelAdmin):
    list_display = ("id", "portal_user", "connection_type", "jump_host", "current_host", "is_active", "created_at")
    list_filter = ("connection_type", "is_active")
    search_fields = ("portal_user__username", "jump_host", "current_host")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "portal_user", "action", "status")
    list_filter = ("action", "status")
    search_fields = ("portal_user__username", "detail", "executed_sql")
    readonly_fields = [f.name for f in AuditLog._meta.fields]
