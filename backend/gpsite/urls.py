from django.contrib import admin
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path("admin/", admin.site.urls),
    # POST {"username": "...", "password": "..."} -> {"token": "..."}
    # This is the *portal* login (Django user), separate from any
    # jump-server / Informix credentials, which are never stored.
    path("api/auth/login/", obtain_auth_token, name="api-login"),
    path("api/", include("connections.urls")),
]
