from django.urls import path

from .views import (
    JumpServerConnectView,
    DirectServerConnectView,
    HopView,
    HopBackView,
    DisconnectView,
    GrantRequestCreateView,
    EnvironmentLoadView,
    EnvironmentListView,
    DatabaseListView,
    RoleListView,
    UserLookupView,
    GrantPreviewView,
    GrantExecuteView,
    GrantVerifyView,
)

urlpatterns = [
    path("connect/jump/", JumpServerConnectView.as_view(), name="connect-jump"),
    path("connect/direct/", DirectServerConnectView.as_view(), name="connect-direct"),
    path("connect/hop/", HopView.as_view(), name="connect-hop"),
    path("connect/hop-back/", HopBackView.as_view(), name="connect-hop-back"),
    path("disconnect/", DisconnectView.as_view(), name="disconnect"),
    path("audit/request/", GrantRequestCreateView.as_view(), name="grant-request-create"),

    path("environment/load/", EnvironmentLoadView.as_view(), name="environment-load"),
    path("environment/list/", EnvironmentListView.as_view(), name="environment-list"),
    path("databases/", DatabaseListView.as_view(), name="database-list"),
    path("databases/<str:db_name>/roles/", RoleListView.as_view(), name="role-list"),
    path("databases/<str:db_name>/users/<str:username>/", UserLookupView.as_view(), name="user-lookup"),

    path("grants/preview/", GrantPreviewView.as_view(), name="grant-preview"),
    path("grants/execute/", GrantExecuteView.as_view(), name="grant-execute"),
    path("grants/verify/<str:db_name>/<str:username>/", GrantVerifyView.as_view(), name="grant-verify"),
    path("grants/verify/", GrantVerifyView.as_view(), name="grant-verify-multi"),
]
