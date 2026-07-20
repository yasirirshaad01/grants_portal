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

from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serializers import JumpConnectSerializer, DirectConnectSerializer, HopSerializer, GrantRequestSerializer
from .ssh_manager import SSHManager, SSHConnectionError
from .models import SSHSession, AuditLog, GrantRequest
from . import dbops
import re

# Maps SSHSession.id (str) -> live SSHManager. This is process-local.
# Fine for a single `runserver` / single-worker deployment; for anything
# multi-worker, back this with Redis and make sure a given session's
# requests always land on the worker that owns the Paramiko connection.
ACTIVE_SESSIONS = {}

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

        session.current_host = data.get("host")
        session.save(update_fields=["current_host"]) 

        AuditLog.objects.create(
            session=session, portal_user=request.user, action="hop_success",
            detail=f"host={data.get('host')} mode={data.get('mode')}",
        )

        return Response({"status": "hopped", "current_host": data.get("host")})


class DisconnectView(APIView):
    def post(self, request):
        session_id = request.data.get("session_id")
        manager = ACTIVE_SESSIONS.pop(session_id, None)
        if manager:
            manager.close()
        SSHSession.objects.filter(id=session_id, portal_user=request.user).update(is_active=False)
        return Response({"status": "disconnected"})


class GrantRequestCreateView(APIView):
    def post(self, request):
        serializer = GrantRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request_obj = serializer.save(portal_user=request.user)
        return Response({
            "status": "saved",
            "id": request_obj.id,
            "requested_at": request_obj.requested_at,
        })


# ----------------------------------------------------------------------
# Step 6: load the Informix environment (". /mcp_qasi")
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
    """List available environment scripts under /mcp* and show the
    associated IDSNETSERVICE port where available.

    Returns JSON: { envs: [{name, port, raw_stdout}], raw_ls }
    """
    def get(self, request):
        session_id = request.query_params.get("session_id")
        session, manager = _get_owned_session(request, session_id)
        if not session:
            return Response({"detail": "Unknown or inactive session"}, status=status.HTTP_404_NOT_FOUND)
        if not manager:
            return Response({"detail": "SSH session expired, please reconnect"}, status=status.HTTP_409_CONFLICT)

        # List /mcp* entries (use -d so we get the symlink names, not their contents)
        list_cmd = "ls -1d /mcp* 2>/dev/null || true"
        ls_result = manager.run(list_cmd)
        entries = [l.strip() for l in ls_result["stdout"].splitlines() if l.strip()]

        envs = []
        for entry in entries:
            # basename, e.g. /mcp_devmi -> mcp_devmi
            name = entry.rsplit("/", 1)[-1]
            # Try sourcing the env and echoing IDSNETSERVICE to extract port
            cmd = dbops.build_silent_env_prefixed_command(f". /{name}", "echo $IDSNETSERVICE")
            res = manager.run(cmd)
            raw = (res.get("stdout") or "").strip()
            port = None
            if raw:
                m = re.search(r"-(\d{2,5})$", raw.strip())
                if m:
                    port = m.group(1)
                else:
                    parts = raw.strip().split("-")
                    if parts and parts[-1].isdigit():
                        port = parts[-1]
            envs.append({"name": name, "port": port, "raw_stdout": raw})

        return Response({"envs": envs, "raw_ls": ls_result["stdout"]})


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
        cmd = dbops.build_silent_env_prefixed_command(session.env_script, f'echo "{sql}" | dbaccess sysmaster -')
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
        cmd = dbops.build_silent_env_prefixed_command(session.env_script, f'echo "{sql}" | dbaccess {db_name} -')
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
        cmd = dbops.build_silent_env_prefixed_command(session.env_script, f'echo "{sql}" | dbaccess {db_name} -')
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

        if isinstance(usernames, str):
            usernames = [u.strip() for u in usernames.split(",") if u.strip()]
        if not usernames:
            return Response({"detail": "username is required"}, status=status.HTTP_400_BAD_REQUEST)

        statements = dbops.build_grant_statements(usernames, grants, roles)
        if not statements:
            return Response({"detail": "No grants or roles selected"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"statements": statements})


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
        for db in db_names:
            cmd = dbops.build_silent_env_prefixed_command(session.env_script, f'echo "{sql_block}" | dbaccess {db} -')
            result = manager.run(cmd)
            ok = result["exit_code"] == 0 and "error" not in result["stdout"].lower() and "error" not in result["stderr"].lower()
            overall_ok = overall_ok and ok
            results.append({
                "db_name": db,
                "exit_code": result["exit_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "ok": ok,
            })

        AuditLog.objects.create(
            session=session, portal_user=request.user, action="grant_execute",
            detail=f"db_names={db_names} users={usernames} grants={grants} roles={roles}",
            executed_sql=sql_block,
            result_summary=("\n".join([r["stdout"] + r["stderr"] for r in results]))[:4000],
            status="success" if overall_ok else "failed",
        )

        payload = {
            "status": "executed" if overall_ok else "error",
            "executed_sql": sql_block,
            "results": results,
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
            cmd = dbops.build_silent_env_prefixed_command(session.env_script, f'echo "{sql}" | dbaccess {db} -')
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
