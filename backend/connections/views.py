"""
Step 1 of the workflow: authenticate the portal user (handled by
/api/auth/login/, see gpsite/urls.py) then let them open an SSH session
either to a jump server (keyboard-interactive, First Factor / Second
Factor) or directly to a known trusted host (username/password).

Later steps (load environment, list databases, list roles, grant,
verify) hang off the same `session_id` and are natural follow-on
endpoints once this page is working - see the "Next steps" note in the
project README.
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serializers import JumpConnectSerializer, DirectConnectSerializer, HopSerializer, GrantRequestSerializer
from .ssh_manager import SSHManager, SSHConnectionError
from .models import SSHSession, AuditLog
from . import dbops

# Maps SSHSession.id (str) -> live SSHManager. This is process-local.
# Fine for a single `runserver` / single-worker deployment; for anything
# multi-worker, back this with Redis and make sure a given session's
# requests always land on the worker that owns the Paramiko connection.
ACTIVE_SESSIONS = {}

# Maps SSHSession.id (str) -> list of previous current_host values, in hop
# order, so HopBackView can undo a mistaken hop without a full reconnect.
# Same process-local caveat as ACTIVE_SESSIONS.
HOST_HISTORY = {}

SSH_PORT = 22


def _get_owned_session(request, session_id):
    """
    Fetch the SSHSession row (making sure it belongs to the requesting
    portal user and hasn't been disconnected) and the live SSHManager
    for it, if one is still resident in this process.

    Returns (session, manager). `session` is None if the id is unknown,
    inactive, or belongs to someone else. `manager` is None if the
    session row exists but this process has no live SSH connection for
    it (e.g. after a backend restart) - callers should ask the user to
    reconnect in that case.
    """
    if not session_id:
        return None, None
    try:
        session = SSHSession.objects.get(id=session_id, portal_user=request.user, is_active=True)
    except (SSHSession.DoesNotExist, ValueError, ValidationError):
        return None, None
    manager = ACTIVE_SESSIONS.get(str(session_id))
    return session, manager


def _get_saved_user_password(username):
    return dbops.get_or_create_informix_user_password(username)


def _ensure_user_rights_detail(user_id, env_scr, db_name):
    dbops.ensure_informix_user_rights_detail(user_id, env_scr, db_name)


def _existing_informix_users(session, manager, db_name, usernames):
    if not usernames:
        return set()
    sql = dbops.build_user_lookup_sql(usernames)
    cmd = dbops.build_session_dbaccess_command(session.env_script, db_name, sql)
    result = manager.run(cmd)
    rows = dbops.parse_user_lookup_usernames(result["stdout"])
    return {row for row in rows if row}


def _discover_existing_grants(session, manager, db_name, usernames):
    if not usernames:
        return {}, {}
    discovered_privileges = {username: [] for username in usernames}
    discovered_roles = {username: [] for username in usernames}

    for username in usernames:
        lookup_sql = f"select username, usertype, priority, defrole from sysusers where username = '{dbops._escape(username)}';"
        lookup_cmd = dbops.build_session_dbaccess_command(session.env_script, db_name, lookup_sql)
        lookup_result = manager.run(lookup_cmd)
        default_roles = dbops.parse_user_lookup_default_roles(lookup_result["stdout"])
        if username in default_roles:
            discovered_roles[username] = default_roles[username]

    return discovered_privileges, discovered_roles


class JumpServerConnectView(APIView):
    def post(self, request):
        serializer = JumpConnectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        manager = SSHManager()
        try:
            manager.connect_jump_keyboard_interactive(
                host=data["host"],
                username=data["username"],
                first_factor=data["first_factor"],
                second_factor=data["second_factor"],
                port=SSH_PORT,
            )
        except SSHConnectionError as exc:
            AuditLog.objects.create(
                portal_user=request.user,
                action="jump_connect_failed",
                detail=f"host={data['host']} user={data['username']}",
                status="failed",
                result_summary=str(exc),
            )
            return Response({"detail": "Access denied"}, status=status.HTTP_401_UNAUTHORIZED)

        session = SSHSession.objects.create(
            portal_user=request.user,
            connection_type=SSHSession.JUMP,
            jump_host=data["host"],
            current_host=data["host"],
            source_ip=request.META.get("REMOTE_ADDR"),
        )
        ACTIVE_SESSIONS[str(session.id)] = manager

        AuditLog.objects.create(
            session=session,
            portal_user=request.user,
            action="jump_connect_success",
            detail=f"host={data['host']} user={data['username']}",
        )

        return Response({
            "session_id": str(session.id),
            "status": "connected",
            "current_host": data["host"],
        })


class DirectServerConnectView(APIView):
    def post(self, request):
        serializer = DirectConnectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        manager = SSHManager()
        try:
            manager.connect_password(
                host=data["host"],
                username=data["username"],
                password=data["password"],
                port=SSH_PORT,
            )
        except SSHConnectionError as exc:
            AuditLog.objects.create(
                portal_user=request.user,
                action="direct_connect_failed",
                detail=f"host={data['host']} user={data['username']}",
                status="failed",
                result_summary=str(exc),
            )
            return Response({"detail": "Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)

        session = SSHSession.objects.create(
            portal_user=request.user,
            connection_type=SSHSession.DIRECT,
            current_host=data["host"],
            source_ip=request.META.get("REMOTE_ADDR"),
        )
        ACTIVE_SESSIONS[str(session.id)] = manager

        AuditLog.objects.create(
            session=session,
            portal_user=request.user,
            action="direct_connect_success",
            detail=f"host={data['host']} user={data['username']}",
        )

        return Response({
            "session_id": str(session.id),
            "status": "connected",
            "current_host": data["host"],
        })


class HopView(APIView):
    def post(self, request):
        serializer = HopSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        session_id = data.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager:
            return Response({"detail": "SSH session expired, please reconnect"}, status=status.HTTP_409_CONFLICT)

        try:
            if data.get("mode") == "password":
                pwd = data.get("password") or ""
                manager.hop_password(host=data.get("host"), username=data.get("username") or "", password=pwd, port=SSH_PORT)
            else:
                manager.hop_trusted(host=data.get("host"), username=data.get("username") or "", port=SSH_PORT)
        except SSHConnectionError as exc:
            AuditLog.objects.create(
                session=session, portal_user=request.user, action="hop_failed",
                detail=f"host={data.get('host')} mode={data.get('mode')}", status="failed",
                result_summary=str(exc),
            )
            return Response({"detail": "Could not hop to target host", "stderr": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        HOST_HISTORY.setdefault(str(session.id), []).append(session.current_host)
        session.current_host = data.get("host")
        session.save(update_fields=["current_host"])

        AuditLog.objects.create(
            session=session, portal_user=request.user, action="hop_success",
            detail=f"host={data.get('host')} mode={data.get('mode')}",
        )

        return Response({
            "status": "hopped",
            "current_host": data.get("host"),
            "can_go_back": manager.can_go_back(),
        })


class HopBackView(APIView):
    """Undo the most recent hop - closes the current (mistaken) host's SSH
    connection and reactivates whichever host was active before it, without
    a full disconnect/reconnect through the jump server."""
    def post(self, request):
        session_id = request.data.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager:
            return Response({"detail": "SSH session expired, please reconnect"}, status=status.HTTP_409_CONFLICT)

        history = HOST_HISTORY.get(str(session.id)) or []
        if not history:
            return Response({"detail": "No previous host to go back to"}, status=status.HTTP_409_CONFLICT)

        try:
            manager.go_back()
        except SSHConnectionError as exc:
            return Response({"detail": "Could not go back", "stderr": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        previous_host = history.pop()
        session.current_host = previous_host
        session.save(update_fields=["current_host"])

        AuditLog.objects.create(
            session=session, portal_user=request.user, action="hop_back_success",
            detail=f"host={previous_host}",
        )

        return Response({
            "status": "hopped_back",
            "current_host": previous_host,
            "can_go_back": bool(history),
        })


class DisconnectView(APIView):
    def post(self, request):
        session_id = request.data.get("session_id")
        manager = ACTIVE_SESSIONS.pop(session_id, None)
        if manager:
            manager.close()
        HOST_HISTORY.pop(session_id, None)
        SSHSession.objects.filter(id=session_id, portal_user=request.user).update(is_active=False)
        return Response({"status": "disconnected"})


class GrantRequestCreateView(APIView):
    def post(self, request):
        serializer = GrantRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        saved = dbops.save_grant_request(
            rights_type=data["rights_type"],
            granter_name=data["granter_name"],
            jira_ticket=data["jira_ticket"],
            portal_user=request.user.username,
        )
        return Response({
            "status": "saved",
            "id": saved["id"],
            "requested_at": saved["requested_at"],
        })


# ----------------------------------------------------------------------
# Step 6: connect to the Informix instance - either directly (known
# instances from mcp_instances, no SSH sourcing needed) or by sourcing an
# environment script by hand (". /mcp_qasi", for instances not in that
# table, which still have to be reached from the right host)
# ----------------------------------------------------------------------
class EnvironmentLoadView(APIView):
    def post(self, request):
        session_id = request.data.get("session_id")
        env_script = (request.data.get("env_script") or "").strip()
        if not env_script:
            return Response({"detail": "env_script is required"}, status=status.HTTP_400_BAD_REQUEST)

        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager:
            return Response({"detail": "SSH session expired, please reconnect"}, status=status.HTTP_409_CONFLICT)

        instance_name = dbops.extract_instance_name(env_script)
        host_str = None
        if instance_name and session.current_host == settings.INFORMIX_MCP_INSTANCES_HOST:
            # mcp_instances only applies on the host where db_monitoring/
            # mcp00 actually live - its bootstrap script won't exist to
            # source on any other host, so don't even try the direct-
            # connect shortcut there; fall straight through to legacy
            # sourcing, which is the only thing that can work.
            host_str = dbops.fetch_instance_host(instance_name)

        if host_str:
            # Known instance: connect straight to it over the network - no
            # dependency on which physical host we're SSH'd into right now.
            # `dbaccess` still needs *some* environment sourced first just to
            # be on PATH at all, hence build_direct_probe_command rather than
            # a bare dbaccess call.
            result = manager.run(dbops.build_direct_probe_command(host_str))

            if result["exit_code"] != 0:
                AuditLog.objects.create(
                    session=session, portal_user=request.user, action="env_load_failed",
                    detail=env_script, status="failed", result_summary=(result["stdout"] + result["stderr"])[:2000],
                )
                return Response({
                    "detail": f"Could not connect to {instance_name} ({host_str})",
                    "stderr": result["stderr"],
                    "raw_stdout": result["stdout"],
                }, status=status.HTTP_400_BAD_REQUEST)

            session.env_script = f"@{host_str}"
            session.save(update_fields=["env_script"])

            AuditLog.objects.create(
                session=session, portal_user=request.user, action="env_load_success",
                detail=env_script, result_summary=f"direct connect via {host_str}",
            )

            return Response({
                "status": "loaded",
                "instance": {"status": "connected", "mode": "direct", "host_str": host_str},
                "raw_stdout": result["stdout"],
            })

        # Fallback: not a known instance - source it by hand, exactly as before.
        result = manager.run(dbops.build_env_prefixed_command(env_script, "onstat -"))
        instance = dbops.parse_onstat_summary(result["stdout"])

        if result["exit_code"] != 0 and instance["status"] == "unknown":
            AuditLog.objects.create(
                session=session, portal_user=request.user, action="env_load_failed",
                detail=env_script, status="failed", result_summary=(result["stdout"] + result["stderr"])[:2000],
            )
            return Response({
                "detail": "Environment failed to load",
                "stderr": result["stderr"],
                "raw_stdout": result["stdout"],
            }, status=status.HTTP_400_BAD_REQUEST)

        session.env_script = env_script
        session.save(update_fields=["env_script"])

        AuditLog.objects.create(
            session=session, portal_user=request.user,
            action="env_load_success" if result["exit_code"] == 0 else "env_load_success_with_warnings",
            detail=env_script,
            result_summary=(result["stdout"] + result["stderr"])[:2000],
        )

        response_payload = {
            "status": "loaded",
            "instance": instance,
            "raw_stdout": result["stdout"],
        }
        if result["stderr"]:
            response_payload["stderr"] = result["stderr"]
        return Response(response_payload)


class EnvironmentListView(APIView):
    """List Informix instances available on the currently connected host.

    - On settings.INFORMIX_MCP_INSTANCES_HOST (where db_monitoring/mcp00
      live): every known instance from db_monitoring.mcp_instances, across
      every server - not just this one - with port/IP/databases. One ODBC
      query, no SSH needed. mcp_instances has one row per database within
      an instance, so rows are grouped by env_scr into one entry per
      instance, carrying the full list of its databases alongside.
    - On any other host: mcp_instances doesn't apply there (its bootstrap
      script and sqlhosts setup are local to the host above), so this falls
      back to the original approach - `ls -1d /mcp*` on the connected host
      to find locally symlinked env scripts, then sources each one and
      reads back its IDSNETSERVICE port. One SSH round trip per instance,
      but it's the only way to discover instances that were never
      registered in mcp_instances at all.

    Returns JSON: { envs: [{name, port, ip, host, databases, description,
    active, is_monitored}] }
    """
    def get(self, request):
        session_id = request.query_params.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)

        if session.current_host == settings.INFORMIX_MCP_INSTANCES_HOST:
            instances = [row for row in dbops.fetch_mcp_instances() if row.get("env_scr")]
            envs_by_name = {}
            order = []
            for row in instances:
                name = row["env_scr"]
                if name not in envs_by_name:
                    order.append(name)
                    envs_by_name[name] = {
                        "name": name,
                        "port": row.get("portno") or None,
                        "ip": row.get("ip") or None,
                        "host": row.get("host_str") or None,
                        "description": row.get("db_desc") or None,
                        "active": row.get("active") or None,
                        "is_monitored": row.get("is_monitored") or None,
                        "databases": [],
                    }
                dbname = row.get("dbname")
                if dbname and dbname not in envs_by_name[name]["databases"]:
                    envs_by_name[name]["databases"].append(dbname)

            envs = [envs_by_name[name] for name in order]
            return Response({"envs": envs})

        # Fallback: not the mcp_instances host - discover instances the
        # original way, from what's actually symlinked on this host.
        if not manager:
            return Response({"detail": "SSH session expired, please reconnect"}, status=status.HTTP_409_CONFLICT)

        list_cmd = "ls -1d /mcp* 2>/dev/null || true"
        ls_result = manager.run(list_cmd)
        entries = [l.strip() for l in ls_result["stdout"].splitlines() if l.strip()]

        envs = []
        for entry in entries:
            name = entry.rsplit("/", 1)[-1]
            res = manager.run(dbops.build_legacy_instance_probe_command(name))
            probe = dbops.parse_legacy_instance_probe_output(res.get("stdout") or "")
            envs.append({
                "name": name,
                "port": probe["port"],
                "ip": session.current_host,
                "databases": probe["databases"],
            })

        return Response({"envs": envs})


# ----------------------------------------------------------------------
# Step 7: list databases on the loaded instance
# ----------------------------------------------------------------------
class DatabaseListView(APIView):
    def get(self, request):
        session_id = request.query_params.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager or not session.env_script:
            return Response({"detail": "Load an environment first"}, status=status.HTTP_409_CONFLICT)

        sql = dbops.build_list_databases_sql()
        cmd = dbops.build_session_dbaccess_command(session.env_script, "sysmaster", sql)
        result = manager.run(cmd)

        return Response({
            "databases": dbops.parse_database_list(result["stdout"], include_system=(request.query_params.get("include_system") == "true")),
            "raw_stdout": result["stdout"],
            "raw_stderr": result["stderr"],
        })


# ----------------------------------------------------------------------
# Step 9: list roles that exist in a chosen database
# ----------------------------------------------------------------------
class RoleListView(APIView):
    def get(self, request, db_name):
        session_id = request.query_params.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager or not session.env_script:
            return Response({"detail": "Load an environment first"}, status=status.HTTP_409_CONFLICT)

        sql = dbops.build_list_roles_sql()
        cmd = dbops.build_session_dbaccess_command(session.env_script, db_name, sql)
        result = manager.run(cmd)

        return Response({
            "roles": dbops.parse_role_list(result["stdout"]),
            "raw_stdout": result["stdout"],
            "raw_stderr": result["stderr"],
        })


# ----------------------------------------------------------------------
# Step 10: look up the target user and show current rights
# ----------------------------------------------------------------------
class UserLookupView(APIView):
    def get(self, request, db_name, username):
        session_id = request.query_params.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager or not session.env_script:
            return Response({"detail": "Load an environment first"}, status=status.HTTP_409_CONFLICT)

        usernames = [u.strip() for u in username.split(",") if u.strip()]
        if not usernames:
            return Response({"detail": "username is required"}, status=status.HTTP_400_BAD_REQUEST)

        sql = dbops.build_user_lookup_sql(usernames)
        cmd = dbops.build_session_dbaccess_command(session.env_script, db_name, sql)
        result = manager.run(cmd)
        rows = dbops.parse_pipe_separated(result["stdout"])
        found_usernames = {row.split()[0] for row in rows if row}

        return Response({
            "results": [
                {
                    "username": u,
                    "found": u in found_usernames,
                    "raw_stdout": result["stdout"],
                }
                for u in usernames
            ],
            "rows": rows,
            "raw_stdout": result["stdout"],
        })


# ----------------------------------------------------------------------
# Step 11-12: build the GRANT statements for review, without running them
# ----------------------------------------------------------------------
class GrantPreviewView(APIView):
    def post(self, request):
        usernames = request.data.get("usernames") or request.data.get("username")
        grants = request.data.get("grants", [])
        roles = request.data.get("roles", [])
        db_names = request.data.get("db_names") or []
        db_name = (request.data.get("db_name") or "").strip()
        session_id = request.data.get("session_id")

        if isinstance(db_names, str):
            db_names = [d.strip() for d in db_names.split(",") if d.strip()]
        if db_name:
            db_names = [db_name] if not db_names else db_names
        if isinstance(usernames, str):
            usernames = [u.strip() for u in usernames.split(",") if u.strip()]
        if not usernames:
            return Response({"detail": "username is required"}, status=status.HTTP_400_BAD_REQUEST)

        statements = dbops.build_grant_statements(usernames, grants, roles)
        if not statements:
            return Response({"detail": "No grants or roles selected"}, status=status.HTTP_400_BAD_REQUEST)

        created_user_statements = []
        cleanup_user_statements = []
        user_actions = []
        if session_id and db_names:
            session, manager = _get_owned_session(request, session_id)
            if session and manager and session.env_script:
                existing_users = _existing_informix_users(session, manager, db_names[0], usernames)
                recreate_usernames = [u for u in usernames if u in existing_users]
                cleanup_user_statements = dbops.build_revoke_and_drop_user_statements(recreate_usernames, grants, roles)
                created_user_statements = [
                    dbops.build_create_user_statement(username, _get_saved_user_password(username))
                    for username in usernames
                ]

                for username in usernames:
                    if username in recreate_usernames:
                        user_actions.append({"username": username, "status": "recreated"})
                    else:
                        user_actions.append({"username": username, "status": "created"})

        combined = cleanup_user_statements + created_user_statements + statements if (cleanup_user_statements or created_user_statements) else statements
        response = {"statements": combined}
        if created_user_statements:
            response["created_user_statements"] = created_user_statements
        if cleanup_user_statements:
            response["cleanup_user_statements"] = cleanup_user_statements
        if user_actions:
            response["user_actions"] = user_actions
        return Response(response)


# ----------------------------------------------------------------------
# Step 13: actually execute the previously previewed statements
# ----------------------------------------------------------------------
class GrantExecuteView(APIView):
    def post(self, request):
        session_id = request.data.get("session_id")
        db_names = request.data.get("db_names") or []
        db_name = (request.data.get("db_name") or "").strip()
        usernames = request.data.get("usernames") or request.data.get("username")
        grants = request.data.get("grants", [])
        roles = request.data.get("roles", [])

        if isinstance(db_names, str):
            db_names = [d.strip() for d in db_names.split(",") if d.strip()]
        if db_name:
            db_names = [db_name] if not db_names else db_names
        if isinstance(usernames, str):
            usernames = [u.strip() for u in usernames.split(",") if u.strip()]

        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager or not session.env_script:
            return Response({"detail": "Load an environment first"}, status=status.HTTP_409_CONFLICT)
        if not db_names or not usernames:
            return Response({"detail": "db_names and usernames are required"}, status=status.HTTP_400_BAD_REQUEST)

        statements = dbops.build_grant_statements(usernames, grants, roles)
        if not statements:
            return Response({"detail": "No grants or roles selected"}, status=status.HTTP_400_BAD_REQUEST)

        connects = [s for s in statements if s.strip().lower().startswith("grant connect")]
        others = [s for s in statements if not s.strip().lower().startswith("grant connect")]
        ordered = connects + others
        sql_block = "\n".join(ordered)

        results = []
        overall_ok = True
        aggregated_user_actions = {}
        # Informix user accounts (CREATE USER ... WITH PASSWORD) are
        # instance-wide, not per-database - once created against the first
        # selected database, every other database on that same instance
        # already has it. Without tracking this, the second database's
        # CREATE USER fails with "already exists" even though its grants
        # still go through fine.
        created_this_call = set()
        for db in db_names:
            existing_users = _existing_informix_users(session, manager, db, usernames)

            # Ensure we have passwords and whether they existed in eng_user_rights
            passwords = {}
            password_existed = {}
            for username in usernames:
                password_existed[username] = dbops.informix_user_password_exists(username)
                passwords[username] = _get_saved_user_password(username)

            recreate_usernames = [u for u in usernames if u in existing_users and u not in created_this_call]
            existing_privileges, existing_roles = ({}, {})
            if recreate_usernames:
                existing_privileges, existing_roles = _discover_existing_grants(session, manager, db, recreate_usernames)
            new_usernames = [u for u in usernames if u not in created_this_call]
            create_user_statements = [
                dbops.build_create_user_statement(username, passwords[username])
                for username in new_usernames
            ]
            cleanup_statements = dbops.build_revoke_and_drop_user_statements(
                recreate_usernames,
                grants,
                roles,
                existing_privileges=existing_privileges,
                existing_roles=existing_roles,
            )
            ordered = cleanup_statements + create_user_statements + connects + others
            sql_block = "\n".join(ordered)

            result = manager.run(dbops.build_session_dbaccess_command(session.env_script, db, sql_block))
            # dbaccess returns one exit code for the whole batch - a benign
            # error (e.g. "already exists") on one statement shouldn't mask
            # that the real grants in the same batch succeeded.
            ok = result["exit_code"] == 0 or dbops.dbaccess_output_has_only_benign_errors(result["stdout"])
            overall_ok = overall_ok and ok

            # Prepare user action records for this instance
            user_actions = []
            for username in usernames:
                if username in recreate_usernames:
                    status_flag = "recreated"
                elif username in created_this_call:
                    status_flag = "granted"
                else:
                    status_flag = "created"
                user_actions.append({"username": username, "status": status_flag})
                # keep only the first, most informative status per username
                # across databases in this call, instead of counting the
                # same user as "created" once per database
                aggregated_user_actions.setdefault(username, {"username": username, "status": status_flag})

            created_this_call.update(usernames)

            # If we created/granted users, append them to the one running
            # credentials log on the remote host and email them - but only
            # if this exact password hasn't already been emailed to them
            # before (mailx on the remote host is no longer available, and
            # was also the source of users getting the same unchanged
            # password emailed repeatedly). There's no more per-user
            # /tmp/{username}_creds.txt file - everything goes into the one
            # tracked log now, see dbops.PASSWORD_LOG_FILE.
            email_results = []
            if ok:
                for username in usernames:
                    pwd = passwords[username]

                    try:
                        mail_outcome = dbops.maybe_send_credentials_email(username, pwd)
                        email_sent = mail_outcome["sent"]
                        email_note = mail_outcome["reason"]
                    except Exception as exc:
                        email_sent = False
                        email_note = f"email send failed: {exc}"

                    log_cmd = dbops.build_password_log_command(username, pwd)
                    log_result = manager.run(dbops.build_silent_env_prefixed_command(session.env_script, log_cmd))
                    password_logged = log_result.get("exit_code") == 0

                    email_results.append({
                        "username": username,
                        "file_path": dbops.PASSWORD_LOG_FILE,
                        "email_sent": email_sent,
                        "email_note": email_note,
                        "password_logged": password_logged,
                        "password_log_stderr": log_result.get("stderr"),
                    })

            results.append({
                "db_name": db,
                "exit_code": result["exit_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "ok": ok,
                "created_users": create_user_statements,
                "cleanup_statements": cleanup_statements,
                "recreated_users": recreate_usernames,
                "sql": sql_block,
                "user_actions": user_actions,
                "email_results": email_results,
            })

            for username in usernames:
                _ensure_user_rights_detail(username, session.env_script, db)

        AuditLog.objects.create(
            session=session, portal_user=request.user, action="grant_execute",
            detail=f"db_names={db_names} users={usernames} grants={grants} roles={roles}",
            executed_sql=sql_block,
            result_summary=("\n".join([r["stdout"] + r["stderr"] for r in results]))[:4000],
            status="success" if overall_ok else "failed",
        )

        detail = None
        if not overall_ok:
            failed = next((r for r in results if not r["ok"]), None)
            if failed:
                detail = failed.get("stderr") or failed.get("stdout") or "Execution failed"

        payload = {
            "status": "executed" if overall_ok else "error",
            "executed_sql": sql_block,
            "results": results,
            "debug": results,
            "user_actions": list(aggregated_user_actions.values()),
            "detail": detail,
        }
        return Response(payload, status=status.HTTP_200_OK if overall_ok else status.HTTP_400_BAD_REQUEST)


# ----------------------------------------------------------------------
# Step 14: re-query sysusers to confirm the grant actually stuck
# ----------------------------------------------------------------------
class GrantVerifyView(APIView):
    def get(self, request, db_name=None, username=None):
        session_id = request.query_params.get("session_id")
        db_names = request.query_params.get("db_names")
        usernames = request.query_params.get("usernames")

        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager or not session.env_script:
            return Response({"detail": "Load an environment first"}, status=status.HTTP_409_CONFLICT)

        if db_name and username:
            db_names = db_names or db_name
            usernames = usernames or username
        if isinstance(db_names, str):
            db_names = [d.strip() for d in db_names.split(",") if d.strip()]
        if isinstance(usernames, str):
            usernames = [u.strip() for u in usernames.split(",") if u.strip()]

        if not db_names or not usernames:
            return Response({"detail": "db_names and usernames are required"}, status=status.HTTP_400_BAD_REQUEST)

        results = []
        combined_stdout = []
        for db in db_names:
            sql = dbops.build_user_lookup_sql(usernames)
            cmd = dbops.build_session_dbaccess_command(session.env_script, db, sql)
            result = manager.run(cmd)
            rows = dbops.parse_pipe_separated(result["stdout"])
            combined_stdout.append(result["stdout"])
            results.append({
                "db_name": db,
                "usernames": usernames,
                "rows": rows,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            })
            AuditLog.objects.create(
                session=session, portal_user=request.user, action="grant_verify",
                detail=f"db={db} users={usernames}", result_summary=result["stdout"][:2000],
            )

        return Response({
            "results": results,
            "raw_stdout": "\n---\n".join(combined_stdout),
        })
