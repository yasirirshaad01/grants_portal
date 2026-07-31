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

import re
import secrets
import string
import pyodbc
from django.conf import settings


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
    conn_str = settings.INFORMIX_ODBC_CONNECTION
    return pyodbc.connect(conn_str)


def get_or_create_informix_user_password(username):
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    with get_informix_odbc_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "select user_password from eng_user_rights where user_id = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

        password = generate_strong_password()
        if row:
            cursor.execute(
                "update eng_user_rights set user_password = ? where user_id = ?",
                (password, username),
            )
        else:
            cursor.execute(
                "insert into eng_user_rights (user_id, user_password) values (?, ?)",
                (username, password),
            )
        conn.commit()
        return password


def ensure_informix_user_rights_detail(user_id, env_scr, db_name):
    user_id = (user_id or "").strip()
    env_scr = (env_scr or "").strip()[:30]
    db_name = (db_name or "").strip()[:30]
    if not user_id or not db_name:
        raise ValueError("user_id and db_name are required")
    with get_informix_odbc_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "select 1 from eng_user_rights_detail where user_id = ? and env_scr = ? and db_name = ?",
            (user_id, env_scr, db_name),
        )
        if not cursor.fetchone():
            cursor.execute(
                "insert into eng_user_rights_detail (user_id, env_scr, db_name) values (?, ?, ?)",
                (user_id, env_scr, db_name),
            )
            conn.commit()


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


def _escape(value):
    return value.replace("'", "''")
