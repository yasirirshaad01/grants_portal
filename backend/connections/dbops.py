"""
Small, deliberately simple helpers for talking to Informix through
non-interactive dbaccess calls, and for parsing what comes back.

IMPORTANT: dbaccess's plain-text output format varies by IDS version,
terminal width, and query shape. The parsing here is a reasonable
starting point (strip headers/row-count footers, keep everything else)
but you should compare `raw_stdout` (returned by every endpoint below)
against the parsed result on your actual server and adjust
`parse_pipe_separated` / `parse_onstat_summary` to match what you
actually see. Don't trust the parsed fields blindly for anything that
gates a grant - eyeball the raw output too until you're confident.
"""

import contextlib
import datetime
import os
import re
import secrets
import string
import subprocess
import tempfile
from django.conf import settings
from django.core.mail import send_mail


def build_env_prefixed_command(env_script, command):
    """Chain the environment source and the real command in one shell,
    since each SSH exec_command() call is a brand-new, non-login shell.
    Use this only where you WANT the source script's own printed output
    (e.g. the initial environment-load step, to show the instance banner)."""
    return f"{env_script} && {command}"


def build_silent_env_prefixed_command(env_script, command):
    """Same as build_env_prefixed_command, but throws away whatever the
    sourcing step itself prints to stdout/stderr. Environment scripts
    like `. /mcp_qasi` commonly print an instance/replication banner as
    a side effect of being sourced - harmless the first time, but if you
    don't suppress it here it gets prepended to every single query's
    output afterward (databases, roles, user lookups, ...) and corrupts
    the parsing. Only the actual command's own output survives.

    Uses `;` rather than `&&` between the source and the real command:
    some environment scripts exit non-zero as a side effect (e.g. an
    internal status check on a read-only/secondary instance) even
    though sourcing itself worked fine. With `&&`, that would silently
    skip the real command entirely - empty output, no error text,
    looks exactly like "0 rows" with nothing to explain it. `;` always
    runs the real command, so a genuine failure to source (missing
    dbaccess on PATH, etc.) surfaces as a visible error from that
    command instead of vanishing."""
    return f"{env_script} > /dev/null 2>&1; {command}"


def build_list_databases_sql():
    return "select name from sysdatabases order by name;"


# Markers used to split build_legacy_instance_probe_command's single blob of
# stdout back into its port-echo section and its sysdatabases section.
_LEGACY_PROBE_PORT_MARKER = "___GP_PORT___"
_LEGACY_PROBE_DB_MARKER = "___GP_DBS___"


def build_legacy_instance_probe_command(name):
    """For one /mcp* entry discovered via `ls` on a host that isn't
    settings.INFORMIX_MCP_INSTANCES_HOST (see EnvironmentListView's
    fallback path): source it once and, in that same shell, both echo back
    its IDSNETSERVICE port AND list its databases via sysdatabases - the
    exact same query the "Get databases" step already uses - so the
    per-instance table can show databases there too, in a single SSH round
    trip instead of two."""
    sql = build_list_databases_sql()
    return (
        f". /{name} > /dev/null 2>&1; "
        f"echo '{_LEGACY_PROBE_PORT_MARKER}'; echo $IDSNETSERVICE; "
        f"echo '{_LEGACY_PROBE_DB_MARKER}'; "
        f"cat <<'EOF' | dbaccess sysmaster -\n{sql}\nEOF"
    )


def parse_legacy_instance_probe_output(output):
    """Splits build_legacy_instance_probe_command's combined stdout back
    into {"port": ..., "databases": [...]}."""
    port_section, db_section = "", ""
    if _LEGACY_PROBE_PORT_MARKER in output and _LEGACY_PROBE_DB_MARKER in output:
        _, rest = output.split(_LEGACY_PROBE_PORT_MARKER, 1)
        port_section, db_section = rest.split(_LEGACY_PROBE_DB_MARKER, 1)

    port = None
    raw_port = port_section.strip()
    if raw_port:
        m = re.search(r"-(\d{2,5})$", raw_port)
        if m:
            port = m.group(1)
        else:
            parts = raw_port.split("-")
            if parts and parts[-1].isdigit():
                port = parts[-1]

    return {"port": port, "databases": parse_database_list(db_section, include_system=False)}


def build_list_roles_sql():
    return "select distinct rolename from sysroleauth order by rolename;"


def build_user_lookup_sql(username):
    if isinstance(username, (list, tuple)):
        names = [f"'{_escape(u)}'" for u in username if u]
        if not names:
            return "select username, usertype, priority, defrole from sysusers where 1=0;"
        return f"select username, usertype, priority, defrole from sysusers where username in ({', '.join(names)}) order by username;"

    safe = _escape(username)
    return f"select username, usertype, priority, defrole from sysusers where username = '{safe}';"


def build_create_user_statement(username, password):
    safe_user = _escape(username)
    safe_password = password.replace('"', '\\"')
    return (
        f'CREATE USER {safe_user} WITH PASSWORD "{safe_password}" PROPERTIES USER ifx_guest '
        f'HOME "/home/{safe_user}";'
    )


def build_dbaccess_sql_command(db_name, sql):
    return f"cat <<'EOF' | dbaccess {db_name} -\n{sql}\nEOF"


# A direct-connect target is stored in SSHSession.env_script as "@host_str"
# (e.g. "@inst_template_net_41") instead of a ". /mcp_xxx" sourcing command.
_DIRECT_TARGET_PREFIX = "@"

_INSTANCE_NAME_RE = re.compile(r"^\.\s*/+([A-Za-z0-9_]+)\s*$")


def extract_instance_name(env_script):
    """Pulls the bare instance name out of a '. /name' sourcing command,
    e.g. '. /mcp00' -> 'mcp00'. Returns None for anything that doesn't look
    like that shape, so a freeform manual script (e.g. '. /inst_uat_env;
    export FOO=bar') falls straight through to the legacy sourced path
    instead of being mistaken for a known instance name."""
    match = _INSTANCE_NAME_RE.match((env_script or "").strip())
    return match.group(1) if match else None


def fetch_instance_host(env_scr):
    """dbservername (host_str) for one instance in mcp_instances, or None if
    it isn't a known instance. Known instances don't need SSH environment
    sourcing at all - dbaccess can connect to `database@host_str` directly
    over the network from wherever we're SSH'd in, since mcp_instances
    already tells us which Informix server owns it."""
    env_scr = (env_scr or "").strip()
    if not env_scr:
        return None
    safe = _escape(env_scr)
    rows = _db_monitoring_fetchall(
        f"select first 1 host_str from mcp_instances where env_scr = '{safe}' order by host_str"
    )
    if not rows or not rows[0][0]:
        return None
    return rows[0][0].strip() if isinstance(rows[0][0], str) else rows[0][0]


def build_session_dbaccess_command(env_script, db_name, sql):
    """The one place every view builds its dbaccess call from whatever is
    stored in SSHSession.env_script:

      - a direct-connect target ("@host_str", set by EnvironmentLoadView
        when the requested instance was found in mcp_instances) -> connect
        straight to `db_name@host_str`, independent of which host we're
        SSH'd into. `dbaccess` still isn't a system-wide binary though, so
        settings.INFORMIX_DIRECT_CONNECT_BOOTSTRAP is sourced silently
        first just to get it (and the Informix client libraries) onto
        PATH - that script does NOT need to match the target instance.
      - a legacy sourcing command (". /mcp_xxx", for instances that aren't
        in mcp_instances and have to be sourced by hand on the right host)
        -> source it silently, exactly as before.
    """
    if (env_script or "").startswith(_DIRECT_TARGET_PREFIX):
        host_str = env_script[len(_DIRECT_TARGET_PREFIX):]
        direct_cmd = build_dbaccess_sql_command(f"{db_name}@{host_str}", sql)
        return build_silent_env_prefixed_command(settings.INFORMIX_DIRECT_CONNECT_BOOTSTRAP, direct_cmd)
    return build_silent_env_prefixed_command(env_script, build_dbaccess_sql_command(db_name, sql))


def build_direct_probe_command(host_str):
    """Trivial connectivity check used by EnvironmentLoadView to confirm a
    known instance (resolved from mcp_instances) is actually reachable
    before committing the session to it - same bootstrap-then-direct-
    connect shape as build_session_dbaccess_command, against sysmaster
    since every instance has one."""
    probe_cmd = build_dbaccess_sql_command(f"sysmaster@{host_str}", "select count(*) from systables;")
    return build_silent_env_prefixed_command(settings.INFORMIX_DIRECT_CONNECT_BOOTSTRAP, probe_cmd)


PASSWORD_LOG_DIR = "/tmp/all_user_passwords"
PASSWORD_LOG_FILE = f"{PASSWORD_LOG_DIR}/all_user_password"


def build_password_log_command(username, password):
    """Shell command that appends one line (user_id|password|created_date)
    to a single running log on whichever host this is run on - every
    username and password ever issued, in one place.

    Idempotent: checks for an existing "username|password|" entry first
    (fixed-string match via `grep -F`, so a password containing regex
    metacharacters like * or ^ can't be misinterpreted) and only appends if
    it's not already there. Without this, re-running a grant with an
    unchanged password - which happens routinely, since execute already
    runs once per selected database - just piles up duplicate lines.

    Restricts the log to owner-read after every write since it accumulates
    plaintext passwords."""
    entry_prefix = f"{username}|{password}|"
    return (
        f"mkdir -p {PASSWORD_LOG_DIR} && touch {PASSWORD_LOG_FILE} && "
        f"(grep -qF \"{entry_prefix}\" {PASSWORD_LOG_FILE} || "
        f"printf '%s|%s|%s\\n' \"{username}\" \"{password}\" \"$(date +%F)\" >> {PASSWORD_LOG_FILE}) && "
        f"chmod 600 {PASSWORD_LOG_FILE}"
    )


def build_grant_statements(usernames, grants, roles):
    """
    usernames: a single username string or a list of strings
    grants: list of strings from {"connect", "resource", "dba"}
    roles:  list of role names to set as default role, e.g. ["app_role"]
    Returns a list of individual SQL statements, each ending in ';'.
    """
    if isinstance(usernames, str):
        usernames = [usernames]
    statements = []

    for username in usernames:
        safe_user = _escape(username)
        if "connect" in grants:
            statements.append(f"grant connect to {safe_user};")
        if "resource" in grants:
            statements.append(f"grant resource to {safe_user};")
        if "dba" in grants:
            statements.append(f"grant dba to {safe_user};")

        for role in roles:
            safe_role = _escape(role)
            statements.append(f"grant default role {safe_role} to {safe_user};")

    return statements


def build_revoke_and_drop_user_statements(usernames, grants, roles, existing_privileges=None, existing_roles=None):
    """Build cleanup SQL for users that already exist before recreating them.

    Try the base privilege revokes first, then revoke any default roles that the
    user already has, and finally drop the user. The role revoke uses the
    `revoke role ... from ...` form because the `default role` form is rejected
    by the Informix instances in this environment.
    """
    if isinstance(usernames, str):
        usernames = [usernames]
    statements = []
    existing_privileges = existing_privileges or {}
    existing_roles = existing_roles or {}

    for username in usernames:
        safe_user = _escape(username)
        if "connect" in (grants or []):
            statements.append(f"revoke connect from {safe_user};")
        if "resource" in (grants or []):
            statements.append(f"revoke resource from {safe_user};")
        if "dba" in (grants or []):
            statements.append(f"revoke dba from {safe_user};")

        for role in list(existing_roles.get(username, [])) + list(roles or []):
            if not role:
                continue
            safe_role = _escape(role)
            statements.append(f"revoke {safe_role} from {safe_user};")

        statements.append(f"drop user {safe_user};")
        statements.append(f"-- ignore missing user errors")

    return statements


# dbaccess runs a whole batch of statements per call and only reports one
# exit code for all of them - a single statement erroring (e.g. "user
# already exists" when creating one that's already there from an earlier
# database in the same multi-db grant run) makes the whole batch look
# "failed" even though every other statement, including the actual grants,
# went through fine. Only codes confirmed benign are listed here - an
# unrecognized error code still surfaces as a real failure.
_BENIGN_DBACCESS_ERROR_CODES = {
    "26701",  # "User (x) was not created because it already exists."
}
_DBACCESS_ERROR_LINE_RE = re.compile(r"(?m)^(\d+):\s")


def dbaccess_output_has_only_benign_errors(stdout):
    """True only if every SQL-level error line in dbaccess's stdout is a
    known-benign code. False if there's a real error, or no error lines were
    found at all (so an unexplained nonzero exit still surfaces as failed
    rather than being silently waved through)."""
    error_codes = _DBACCESS_ERROR_LINE_RE.findall(stdout or "")
    if not error_codes:
        return False
    return all(code in _BENIGN_DBACCESS_ERROR_CODES for code in error_codes)


def generate_strong_password(length=15):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


def get_informix_odbc_connection():
    """Raw pyodbc connection to db_monitoring - not used by the app itself
    (see the _db_monitoring_* primitives below, which also support the
    "dbaccess" backend), kept around as a quick debugging/ad-hoc-query
    helper on a machine that has the Informix ODBC driver installed."""
    import pyodbc
    return contextlib.closing(pyodbc.connect(settings.INFORMIX_ODBC_CONNECTION))


# ----------------------------------------------------------------------
# db_monitoring access: two backends, selected by settings.
# INFORMIX_DRIVER_BACKEND.
#
#   "pyodbc" (default) - a real DB-API connection via the Informix ODBC
#     driver. What this app has used from the start; needs unixODBC + the
#     driver installed (true on the Windows dev machine).
#
#   "dbaccess" - no driver install at all. Shells out *locally* to the same
#     `dbaccess` CLI the grant workflow already uses over SSH elsewhere in
#     this file - just run directly as a subprocess since, on the server
#     this backend is for, the app runs on the same box as db_monitoring
#     itself. SELECTs go through UNLOAD to a temp file (pipe-delimited)
#     rather than parsing dbaccess's normal interactive display output,
#     which isn't reliably machine-parseable for multi-column results. The
#     temp file is read directly off local disk (no SSH needed) and removed
#     immediately after.
#
# Every function below builds fully-escaped literal SQL (via _escape())
# instead of using bind parameters, since dbaccess has no such concept -
# this keeps both backends running the exact same SQL text rather than
# needing two different query-building code paths.
#
# Also note: every value that comes back through the "dbaccess" backend is
# a plain string (or None for NULL), regardless of the column's real SQL
# type - that's all free-text UNLOAD output can give us. Nothing in this
# file does arithmetic on a db_monitoring value (ports/ids are only ever
# displayed or compared as text), so this is a deliberate, harmless
# simplification rather than a workaround for anything.
# ----------------------------------------------------------------------

_DBACCESS_FIELD_DELIM = "|"


def _db_monitoring_fetchall(sql):
    """Runs one SELECT against db_monitoring, returns a list of tuples."""
    if settings.INFORMIX_DRIVER_BACKEND == "dbaccess":
        return _dbaccess_local_fetchall(sql)
    import pyodbc
    conn = pyodbc.connect(settings.INFORMIX_ODBC_CONNECTION)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        return [tuple(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def _db_monitoring_execute(sql):
    """Runs one INSERT/UPDATE/DELETE against db_monitoring."""
    if settings.INFORMIX_DRIVER_BACKEND == "dbaccess":
        _dbaccess_local_execute(sql)
        return
    import pyodbc
    conn = pyodbc.connect(settings.INFORMIX_ODBC_CONNECTION)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
    finally:
        conn.close()


def _db_monitoring_execute_returning_serial(sql):
    """Runs one INSERT and returns the SERIAL id it generated."""
    if settings.INFORMIX_DRIVER_BACKEND == "dbaccess":
        return _dbaccess_local_execute_returning_serial(sql)
    import pyodbc
    conn = pyodbc.connect(settings.INFORMIX_ODBC_CONNECTION)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        cursor.execute("select dbinfo('sqlca.sqlerrd2') from systables where tabid = 1")
        request_id = cursor.fetchone()[0]
        conn.commit()
        return request_id
    finally:
        conn.close()


def _dbaccess_local_run(command):
    """Runs one shell command locally (not over SSH - the app and
    db_monitoring are on the same box for this backend)."""
    result = subprocess.run(
        ["sh", "-c", command], capture_output=True, text=True, timeout=30,
    )
    return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}


def _dbaccess_run_sql(sql_block, unload_path=None):
    """Runs a block of SQL (one or more statements) via a local dbaccess
    call against settings.INFORMIX_DATABASE. If unload_path is given, reads
    that file back afterward (expected to have been populated by an UNLOAD
    clause inside sql_block) and returns its rows; otherwise returns None."""
    command = build_dbaccess_sql_command(settings.INFORMIX_DATABASE, sql_block)
    result = _dbaccess_local_run(command)
    if result["exit_code"] != 0 and not dbaccess_output_has_only_benign_errors(result["stdout"]):
        raise RuntimeError(f"dbaccess failed: {(result['stderr'] or result['stdout']).strip()}")

    if unload_path is None:
        return None
    if not os.path.exists(unload_path):
        return []
    with open(unload_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    rows = []
    for line in content.splitlines():
        if not line:
            continue
        fields = line.split(_DBACCESS_FIELD_DELIM)
        rows.append(tuple(field if field != "" else None for field in fields))
    return rows


@contextlib.contextmanager
def _unload_temp_path():
    """A unique path for UNLOAD to write to, guaranteed not to already
    exist (UNLOAD creates its own file and some Informix versions error on
    a pre-existing one) and cleaned up afterward regardless of outcome."""
    fd, path = tempfile.mkstemp(suffix=".unl", prefix="gp_dbmon_")
    os.close(fd)
    os.remove(path)
    try:
        yield path
    finally:
        if os.path.exists(path):
            os.remove(path)


def _dbaccess_local_fetchall(sql):
    with _unload_temp_path() as path:
        unload_sql = f"UNLOAD TO '{path}' DELIMITER '{_DBACCESS_FIELD_DELIM}'\n{sql}"
        return _dbaccess_run_sql(unload_sql, unload_path=path)


def _dbaccess_local_execute(sql):
    _dbaccess_run_sql(sql)


def _dbaccess_local_execute_returning_serial(sql):
    with _unload_temp_path() as path:
        combined = (
            f"{sql}\n"
            f"UNLOAD TO '{path}' DELIMITER '{_DBACCESS_FIELD_DELIM}'\n"
            "select dbinfo('sqlca.sqlerrd2') from systables where tabid = 1;"
        )
        rows = _dbaccess_run_sql(combined, unload_path=path)
        return rows[0][0] if rows else None


def fetch_mcp_instances():
    """Every known Informix instance (every server, not just the one we're
    currently SSH'd into), straight from db_monitoring.mcp_instances - the
    same ODBC connection already used for eng_user_rights.

    This replaces the old approach of SSH'ing to the current host, running
    `ls -1d /mcp*` to find env scripts, then sourcing each one individually
    just to read back its port (one SSH round trip per instance). The table
    already has the env name, port, host IP, and database for every instance,
    so one query replaces all of that.

    mcp_instances has one row per *database* in an instance (env_scr repeats
    once per dbname) - this returns every row as-is, dbname included, so
    callers that want one row per instance (for selection) can group by
    env_scr themselves while still showing which databases live under it.

    Informix CHAR columns are fixed-width and come back space-padded, so
    every string value is stripped before use.
    """
    columns = ["env_scr", "ip", "portno", "host_str", "dbname", "db_desc", "active", "is_monitored"]
    records = _db_monitoring_fetchall(
        "select env_scr, ip, portno, host_str, dbname, db_desc, active, "
        "is_monitored from mcp_instances order by env_scr, dbname"
    )
    rows = []
    for record in records:
        row = dict(zip(columns, record))
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = value.strip()
        rows.append(row)
    return rows


def get_or_create_informix_user_password(username):
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    safe = _escape(username)
    rows = _db_monitoring_fetchall(f"select user_password from eng_user_rights where user_id = '{safe}'")
    if rows and rows[0][0]:
        return rows[0][0]

    password = generate_strong_password()
    safe_pwd = _escape(password)
    if rows:
        _db_monitoring_execute(f"update eng_user_rights set user_password = '{safe_pwd}' where user_id = '{safe}'")
    else:
        _db_monitoring_execute(f"insert into eng_user_rights (user_id, user_password) values ('{safe}', '{safe_pwd}')")
    return password


def ensure_informix_user_rights_detail(user_id, env_scr, db_name):
    user_id = (user_id or "").strip()
    env_scr = (env_scr or "").strip()[:30]
    db_name = (db_name or "").strip()[:30]
    if not user_id or not db_name:
        raise ValueError("user_id and db_name are required")
    safe_user, safe_env, safe_db = _escape(user_id), _escape(env_scr), _escape(db_name)
    rows = _db_monitoring_fetchall(
        f"select 1 from eng_user_rights_detail where user_id = '{safe_user}' "
        f"and env_scr = '{safe_env}' and db_name = '{safe_db}'"
    )
    if not rows:
        _db_monitoring_execute(
            f"insert into eng_user_rights_detail (user_id, env_scr, db_name) "
            f"values ('{safe_user}', '{safe_env}', '{safe_db}')"
        )


def save_grant_request(rights_type, granter_name, jira_ticket, portal_user):
    """Persist an audit/grant request (granter + JIRA ticket) directly into
    db_monitoring on the real Informix server, instead of the portal's local
    SQLite database - so it lives alongside eng_user_rights where DBAs
    already look, not in a file only this app instance can see.

    Expects this table to already exist on the Informix side:

        CREATE TABLE eng_grant_request (
            id SERIAL PRIMARY KEY,
            rights_type VARCHAR(20),
            granter_name VARCHAR(150),
            jira_ticket VARCHAR(64),
            portal_user VARCHAR(150),
            requested_at DATETIME YEAR TO SECOND
        );
    """
    requested_at = datetime.datetime.now()
    safe_rights, safe_granter = _escape(rights_type), _escape(granter_name)
    safe_jira, safe_user = _escape(jira_ticket), _escape(portal_user)
    ts = requested_at.strftime("%Y-%m-%d %H:%M:%S")
    request_id = _db_monitoring_execute_returning_serial(
        "insert into eng_grant_request "
        "(rights_type, granter_name, jira_ticket, portal_user, requested_at) "
        f"values ('{safe_rights}', '{safe_granter}', '{safe_jira}', '{safe_user}', '{ts}')"
    )
    return {"id": request_id, "requested_at": requested_at}


def informix_user_password_exists(username):
    username = (username or "").strip()
    if not username:
        return False
    safe = _escape(username)
    return bool(_db_monitoring_fetchall(f"select 1 from eng_user_rights where user_id = '{safe}'"))


def fetch_last_sent_password(username):
    """The password we last emailed this user, per db_monitoring.
    eng_user_password_mail_log - or None if we've never emailed them.
    Used to avoid re-sending the same password on every grant run."""
    username = (username or "").strip()
    if not username:
        return None
    safe = _escape(username)
    rows = _db_monitoring_fetchall(
        f"select last_password_sent from eng_user_password_mail_log where user_id = '{safe}'"
    )
    return rows[0][0] if rows and rows[0][0] else None


def record_password_mail_sent(username, password):
    """Upserts the one row per user in eng_user_password_mail_log, bumping
    send_count so there's a durable record of how many times - and when -
    each user has actually been emailed."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_user, safe_pwd = _escape(username), _escape(password)
    rows = _db_monitoring_fetchall(
        f"select 1 from eng_user_password_mail_log where user_id = '{safe_user}'"
    )
    if rows:
        _db_monitoring_execute(
            f"update eng_user_password_mail_log set last_password_sent = '{safe_pwd}', "
            f"last_sent_at = '{now}', send_count = send_count + 1 where user_id = '{safe_user}'"
        )
    else:
        _db_monitoring_execute(
            "insert into eng_user_password_mail_log "
            "(user_id, last_password_sent, last_sent_at, send_count) "
            f"values ('{safe_user}', '{safe_pwd}', '{now}', 1)"
        )


def send_user_credentials_email(username, password):
    """Sends the user's Informix credentials by email straight from this
    backend over SMTP (see settings.EMAIL_HOST) - replaces the old `mailx`
    call on the remote Informix host, which is no longer available there."""
    send_mail(
        subject="user_and_password_details",
        message=f"user_id: {username}\npassword: {password}\n",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[f"{username}@i2cinc.com"],
        fail_silently=False,
    )


def maybe_send_credentials_email(username, password):
    """Sends the credentials email only if this exact password hasn't
    already been sent to this user before (per eng_user_password_mail_log) -
    this is what actually stops a user getting the same unchanged password
    emailed to them over and over, whether that's from multiple databases
    in one grant run or from re-running a grant in a later session. Returns
    {"sent": bool, "reason": str}; raises if the send itself fails so the
    caller can report a real email delivery problem instead of a silent
    "not sent".

    Until settings.EMAIL_HOST is actually configured, this is a deliberate
    no-op that doesn't touch eng_user_password_mail_log at all - Django's
    console-backend fallback "succeeds" without delivering anything, and if
    that got recorded as sent, every user granted while email is unconfigured
    would be silently skipped forever once real SMTP is finally turned on.
    """
    if not settings.EMAIL_HOST:
        return {"sent": False, "reason": "email not configured yet"}
    if fetch_last_sent_password(username) == password:
        return {"sent": False, "reason": "password unchanged since last email - skipped"}
    send_user_credentials_email(username, password)
    record_password_mail_sent(username, password)
    return {"sent": True, "reason": "sent"}


def parse_onstat_summary(output):
    """Pulls the instance status line out of `onstat -` output, e.g.:
    'IBM Informix Dynamic Server ... -- On-Line (Prim) -- Up 1 days 10:21:11 -- ...'"""
    line = next((l for l in output.splitlines() if "Informix Dynamic Server" in l), None)
    if not line:
        return {"status": "unknown", "raw": output.strip()[:500]}

    match = re.search(r"--\s*([A-Za-z-]+(?:\s*\([^)]*\))?)\s*--\s*Up\s*([^-]+)--", line)
    return {
        "version_line": line.strip(),
        "status": match.group(1).strip() if match else "unknown",
        "uptime": match.group(2).strip() if match else None,
    }


# A single Informix identifier: dbaccess prints one of these per line for
# `select name from sysdatabases` / `select rolename from sysroles`. Any
# line with spaces, punctuation, or symbols in it is banner noise, a
# header, or a separator - not an actual name - and gets dropped.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$#]{0,127}$")

# Built-in Informix system databases - hidden by default since they're
# almost never what someone's granting access to from this tool.
_SYSTEM_DATABASES = {
    "sysmaster", "sysutils", "sysuser", "sysadmin", "syscdr",
    "sysha", "sysdbopen", "sysauth", "sysmasterdb", "sysha0",
    "syscdcv1",
}


def parse_identifier_list(output, exclude_names=None, exclude_prefixes=None, header_name=None):
    """Generic 'one identifier per line' parser used for both database
    and role listings. Filters out anything that isn't a clean single
    token (which rules out the sourced-environment banner, dbaccess
    headers/footers, and blank lines) plus any explicitly excluded
    names/prefixes, and de-duplicates while preserving order.

    Some dbaccess sessions reprint the column header on every single
    row (e.g. "name  cards" instead of just "cards") because they
    can't determine a real terminal size when there's no pty behind the
    SSH session and mis-detect a 1-line "page" after every row. If
    `header_name` is given, lines of the form "<header>  <value>" are
    unwrapped to just the value before the identifier check runs."""
    exclude_names = {n.lower() for n in (exclude_names or [])}
    exclude_prefixes = tuple(p.lower() for p in (exclude_prefixes or []))
    header_pattern = (
        re.compile(rf"^{re.escape(header_name)}\s+([A-Za-z_][A-Za-z0-9_$#]{{0,127}})$", re.IGNORECASE)
        if header_name else None
    )

    results = []
    seen = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered_line = line.lower()
        if lowered_line.startswith(("select", "define", "(1 row", "row(s)")) or "row(s) retrieved" in lowered_line:
            # dbaccess query echo / row-count footer (e.g. "2 row(s)
            # retrieved.") - without this, the fallback token extraction
            # below would happily pull "row", "s", "retrieved" out of it
            # and report them as real database/role names.
            continue

        if header_pattern:
            match = header_pattern.match(line)
            if match:
                line = match.group(1)
            else:
                # Some dbaccess sessions print the header and value separated by
                # whitespace but with slightly different spacing/columns
                # (e.g. "name  cards" or "name cards  "). Try a loose
                # split-based fallback so we still extract the value.
                found = []
                for m in re.finditer(
                    rf"\b{re.escape(header_name)}\b\s+([A-Za-z_][A-Za-z0-9_$#]{{0,127}})",
                    line,
                    re.IGNORECASE,
                ):
                    found.append(m.group(1))

                if found:
                    for value in found:
                        lowered_value = value.lower()
                        if lowered_value in exclude_names or lowered_value.startswith(exclude_prefixes):
                            continue
                        if lowered_value not in seen:
                            seen.add(lowered_value)
                            results.append(value)
                    continue
                low = line.lower()
                if low.startswith(header_name.lower() + " "):
                    parts = line.split()
                    if len(parts) >= 2:
                        line = parts[1]

        # If the whole line isn't a single clean identifier, try a
        # conservative fallback: find any identifier-like tokens in the
        # line and treat them as candidates. This handles outputs like
        # "name  cards" or rows where the column header is repeated.
        if not _IDENTIFIER_RE.match(line):
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_$#]{0,127}", line)
            if not tokens:
                continue
            for token in tokens:
                lowered_tok = token.lower()
                if lowered_tok in exclude_names or lowered_tok.startswith(exclude_prefixes):
                    continue
                if lowered_tok not in seen:
                    seen.add(lowered_tok)
                    results.append(token)
            continue

        lowered = line.lower()
        if lowered in exclude_names or lowered.startswith(exclude_prefixes):
            continue
        if lowered not in seen:
            seen.add(lowered)
            results.append(line)
    return results


def parse_database_list(output, include_system=False):
    return parse_identifier_list(
        output,
        exclude_names={"name"} | (set() if include_system else _SYSTEM_DATABASES),
        exclude_prefixes=() if include_system else ("sys",),
        header_name="name",
    )


def parse_role_list(output):
    return parse_identifier_list(output, exclude_names={"rolename"}, header_name="rolename")


def parse_pipe_separated(output):
    """Looser fallback for multi-column output (e.g. the sysusers lookup
    row, which has spaces between columns so parse_identifier_list
    doesn't apply). Strips common dbaccess noise and blank lines."""
    rows = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("select", "define", "(1 row", "row(s)")) or "row(s) retrieved" in lowered:
            continue
        rows.append(line)
    return rows


def parse_user_lookup_usernames(output):
    """Parse sysusers lookup output and return the actual usernames found.

    dbaccess can produce either tabular rows like "alice C 5" or vertical
    column/value pairs like "username  alice". This helper extracts the
    real username values and ignores the query header and other field names.
    """
    usernames = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("select", "define", "(1 row", "row(s)")) or "row(s) retrieved" in lowered:
            continue

        tokens = re.split(r"\s+", line)
        if not tokens:
            continue

        first = tokens[0].lower()
        if first == "username":
            if len(tokens) > 1 and tokens[1].lower() == "usertype":
                continue
            if len(tokens) > 1:
                usernames.append(tokens[1])
            continue

        if first in {"usertype", "priority", "defrole"}:
            continue

        usernames.append(tokens[0])

    return usernames


def parse_user_lookup_default_roles(output):
    """Parse sysusers lookup output and return a mapping of username -> default role(s)."""
    user_roles = {}
    current_user = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("select", "define", "(1 row", "row(s)")) or "row(s) retrieved" in lowered:
            continue

        tokens = re.split(r"\s+", line)
        if not tokens:
            continue

        first = tokens[0].lower()
        if first == "username":
            if len(tokens) > 1 and tokens[1].lower() == "usertype":
                continue
            if len(tokens) > 1:
                current_user = tokens[1]
                user_roles.setdefault(current_user, [])
            else:
                current_user = None
            continue

        if first == "defrole":
            role_name = " ".join(tokens[1:]).strip() if len(tokens) > 1 else ""
            if current_user and role_name:
                user_roles[current_user] = [role_name]
            continue

        if first in {"usertype", "priority"}:
            continue

    return user_roles


def parse_user_grant_details(output):
    """Parse user grant output into a simple {privileges: [...], roles: [...]} structure.

    The expected input is a plain-text dbaccess output that contains either one
    or more lines like `grant connect`, `grant resource`, `grant dba`, or
    `default role foo`. The parser is purposely permissive and only extracts
    the known privilege/role names.
    """
    privileges = []
    roles = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("select", "define", "(1 row", "row(s)")) or "row(s) retrieved" in lowered:
            continue
        if lowered.startswith("grant connect"):
            privileges.append("connect")
        elif lowered.startswith("grant resource"):
            privileges.append("resource")
        elif lowered.startswith("grant dba"):
            privileges.append("dba")
        elif lowered.startswith("default role"):
            role_name = line.split("default role", 1)[1].strip().split()[0]
            roles.append(role_name)

    return {"privileges": privileges, "roles": roles}


def _escape(value):
    return value.replace("'", "''")
