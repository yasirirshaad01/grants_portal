"""
Django settings for the Grant Portal project.

This is a minimal, development-oriented settings file. Before running
this anywhere near production:
  - Set GP_DEBUG=0
  - Set a real GP_SECRET_KEY
  - Set GP_ALLOWED_HOSTS and GP_CORS_ORIGINS to the real deployed
    hostname(s) - the dev defaults only work for localhost
  - Set GP_INFORMIX_PASSWORD (or override GP_INFORMIX_ODBC_CONNECTION
    entirely) - there is no working default password anymore
  - Put the app behind HTTPS and set GP_FORCE_HTTPS=1 (see below)
  - Run the backend as exactly ONE worker process, with no auto-reload.
    ACTIVE_SESSIONS and HOST_HISTORY (connections/views.py) are plain
    in-process Python dicts holding live Paramiko connections - they are
    not shared across worker processes, so more than one worker (or a
    restart mid-session) silently breaks everyone's active SSH session.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("GP_SECRET_KEY", "dev-only-secret-change-me")

DEBUG = os.environ.get("GP_DEBUG", "1") == "1"

ALLOWED_HOSTS = os.environ.get("GP_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

# Opt-in, not tied to DEBUG: flipping this on before HTTPS is actually
# terminated in front of the app (reverse proxy or Django itself) breaks
# login outright, since browsers won't send secure cookies over plain HTTP.
# Set GP_FORCE_HTTPS=1 once HTTPS is actually in place in front of this app.
if os.environ.get("GP_FORCE_HTTPS", "0") == "1":
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "connections",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "gpsite.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "gpsite.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

# During local dev, allow the frontend (served separately, e.g. via
# `python -m http.server`) to call the API.
CORS_ALLOWED_ORIGINS = os.environ.get(
    "GP_CORS_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080"
).split(",")
CORS_ALLOW_CREDENTIALS = True

# Jump servers and known trusted destination hosts. In a real deployment
# pull this from the database (a ServerProfile model) instead of a
# hardcoded list, so it can be managed without a redeploy.
JUMP_SERVERS = ["10.11.82.50", "10.11.82.51"]
TRUSTED_SUPERUSER_HOSTS = ["10.11.56.185"]

# `dbaccess` isn't a system-wide binary - it's only on PATH after some
# Informix environment script has been sourced. For instances resolved
# directly from mcp_instances (connections/dbops.py build_session_dbaccess_
# command), we don't source that specific instance's own script (the whole
# point is reaching instances on other hosts without hopping there), so this
# one script is sourced first just to get `dbaccess` itself available before
# connecting to the real target via `dbaccess db@host_str`.
INFORMIX_DIRECT_CONNECT_BOOTSTRAP = os.environ.get("GP_INFORMIX_BOOTSTRAP_ENV", ". /mcp00")

# Optional: a private key file this backend can use for "trusted hop"
# connections (mode="trusted" in POST /api/connect/hop/), i.e. hopping
# to a same-VLAN host without a password. This only works if the
# matching public key is already in that user's ~/.ssh/authorized_keys
# on the destination host - there is no such thing as a real "no
# credential needed" SSH login. Leave blank to disable trusted hops
# (password hops still work regardless).
TRUSTED_HOP_PRIVATE_KEY_PATH = (
    os.environ.get("TRUSTED_HOP_PRIVATE_KEY_PATH")
    or os.environ.get("GP_TRUSTED_HOP_KEY", "")
)
TRUSTED_HOP_PRIVATE_KEY_PASSPHRASE = (
    os.environ.get("GP_TRUSTED_HOP_KEY_PASSPHRASE")
    or os.environ.get("TRUSTED_HOP_PRIVATE_KEY_PASSPHRASE")
    or None
)

# The Informix password used to be hardcoded here as a literal default -
# that's a real credential sitting in plaintext in a file that gets
# committed to git (and an older one is already permanently in this repo's
# history from before). It now comes from its own env var with no fallback,
# so an unconfigured deployment fails to authenticate loudly instead of
# silently working with a leaked password. Set GP_INFORMIX_PASSWORD (just
# the password) for the usual case, or override GP_INFORMIX_ODBC_CONNECTION
# entirely if anything else about the connection needs to change too.
# Named pieces, so both connection backends below can each build their own
# driver-specific connection string from the same source of truth instead
# of one of them having to parse the other's format.
INFORMIX_HOST = os.environ.get("GP_INFORMIX_HOST", "10.11.56.182")
INFORMIX_SERVICE = os.environ.get("GP_INFORMIX_SERVICE", "2043")
INFORMIX_SERVER = os.environ.get("GP_INFORMIX_SERVER", "inst0000_41")
INFORMIX_DATABASE = os.environ.get("GP_INFORMIX_DATABASE", "db_monitoring")
INFORMIX_UID = os.environ.get("GP_INFORMIX_UID", "informix")
INFORMIX_PASSWORD = os.environ.get("GP_INFORMIX_PASSWORD", "")

# Which Python library connections/dbops.py uses to reach Informix:
#   "pyodbc" (default) - needs the Informix ODBC driver + unixODBC. What
#     this app has used from the start, works fine on the Windows dev
#     machine with the driver installed.
#   "ibm_db" - uses IBM's own DB2-CLI-compatible driver (ibm_db / ibm_db_dbi)
#     instead, bundled as a pip package with its own client driver - no
#     unixODBC or system ODBC driver install needed at all. Use this on a
#     Linux Informix host that doesn't have unixODBC set up but already has
#     (or can pip install) ibm_db, as proven by other Python tools already
#     running on these DB servers.
INFORMIX_DRIVER_BACKEND = os.environ.get("GP_INFORMIX_DRIVER_BACKEND", "pyodbc")

INFORMIX_ODBC_CONNECTION = os.environ.get("GP_INFORMIX_ODBC_CONNECTION") or (
    "DRIVER={IBM INFORMIX ODBC DRIVER (64-bit)};"
    f"HOST={INFORMIX_HOST};"
    f"SERVER={INFORMIX_SERVER};"
    f"SERVICE={INFORMIX_SERVICE};"
    "PROTOCOL=onsoctcp;"
    f"DATABASE={INFORMIX_DATABASE};"
    f"UID={INFORMIX_UID};"
    f"PWD={INFORMIX_PASSWORD};"
)

# The one host where db_monitoring.mcp_instances applies - direct-connect
# listing (EnvironmentListView) and the "@host_str" fast path
# (EnvironmentLoadView/build_session_dbaccess_command) only make sense when
# actually SSH'd into this host. Any other host (e.g. a staging server with
# its own local /mcp* symlinks that were never registered in mcp_instances)
# falls back to the original `ls -1d /mcp*` discovery on that host.
INFORMIX_MCP_INSTANCES_HOST = os.environ.get("GP_MCP_INSTANCES_HOST", "10.11.56.182")

# User credential emails used to be sent via `mailx` on whatever Informix
# host the portal was SSH'd into (see connections/views.py GrantExecuteView).
# That's now disabled server-side, so emails are sent directly from this
# Django backend over SMTP instead (connections/dbops.py
# send_user_credentials_email) - decoupled from the SSH session entirely.
# GP_EMAIL_HOST MUST be set to a real relay for sending to actually work;
# left blank, Django's console backend is used instead (prints the email to
# the server log rather than sending it, so nothing silently fails).
EMAIL_HOST = os.environ.get("GP_EMAIL_HOST", "")
EMAIL_BACKEND = (
    "django.core.mail.backends.smtp.EmailBackend"
    if EMAIL_HOST
    else "django.core.mail.backends.console.EmailBackend"
)
EMAIL_PORT = int(os.environ.get("GP_EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.environ.get("GP_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("GP_EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("GP_EMAIL_USE_TLS", "0") == "1"
DEFAULT_FROM_EMAIL = os.environ.get("GP_EMAIL_FROM", "yarfat@i2cinc.com")
