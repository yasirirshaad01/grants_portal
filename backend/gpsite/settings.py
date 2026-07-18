"""
Django settings for the Grant Portal project.

This is a minimal, development-oriented settings file. Before running
this anywhere near production:
  - Set DEBUG = False
  - Set a real SECRET_KEY from an environment variable
  - Restrict ALLOWED_HOSTS and CORS_ALLOWED_ORIGINS
  - Put the app behind HTTPS (nginx/traefik + TLS)
  - Replace the in-process ACTIVE_SESSIONS registry (see connections/views.py)
    with something backed by Redis, and run a single worker per session
    (or route by session affinity), since raw Paramiko sessions cannot be
    shared across separate worker processes.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("GP_SECRET_KEY", "dev-only-secret-change-me")

DEBUG = os.environ.get("GP_DEBUG", "1") == "1"

ALLOWED_HOSTS = os.environ.get("GP_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

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
