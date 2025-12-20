import platform
import time
from time import monotonic
from importlib.metadata import version
from typing import Any, cast, Callable

import django
import ldap
import structlog
from  psycopg import pq

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django_auth_ldap.backend import LDAPBackend
from rest_framework import serializers, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import HttpResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from mreg.__about__ import __version__ as mreg_version
from mreg.api.permissions import IsSuperOrNetworkAdminMember
from mreg.models.auth import User
from mreg.models.base import ExpiringToken
from mreg.models.network import NetGroupRegexPermission

logger = structlog.getLogger(__name__)

start_time = int(time.time())


def _observe_ldap_call(operation: str, func: Callable[[], Any]) -> Any:
    """Observe an LDAP operation's duration and count failures.

    Labels by operation and exception class name (for failures).
    """
    t0 = monotonic()
    outcome = "success"
    try:
        return func()
    except Exception as e:  # pragma: no cover - defensive metrics recording
        outcome = "failure"
        try:
            LDAP_CALL_FAILURES.labels(operation, e.__class__.__name__).inc()
        except Exception:
            pass
        raise
    finally:
        duration = monotonic() - t0
        try:
            LDAP_CALL_LATENCY.labels(operation).observe(duration)
        except Exception:  # pragma: no cover - defensive
            pass
        try:
            LDAP_CALL_LATENCY_BY_OUTCOME.labels(operation, outcome).observe(duration)
        except Exception:  # pragma: no cover - defensive
            pass

LDAP_CALL_LATENCY = Histogram(
    "mreg_ldap_call_duration_seconds",
    "LDAP call duration seconds",
    ["operation"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)

LDAP_CALL_LATENCY_BY_OUTCOME = Histogram(
    "mreg_ldap_call_duration_seconds_by_outcome",
    "LDAP call duration seconds split by success or failure",
    ["operation", "outcome"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)

LDAP_CALL_FAILURES = Counter(
    "mreg_ldap_call_failures_total",
    "LDAP call failures by operation and exception type",
    ["operation", "exception"],
)

# Note the order here. This order is preserved in the response.
# Also, we add libpq-data to the end of this list so letting psycopg
# be last makes the context of the libpq version more clear.
LIBRARIES_TO_REPORT = [
    "djangorestframework",
    "django-auth-ldap",
    "django-filter",
    "django-logging-json",
    "django-netfields",
    "gunicorn",
    "sentry-sdk",
    "structlog",
    "rich",
    "psycopg",
]


class ObtainExpiringAuthToken(ObtainAuthToken):
    def post(self, request: Request, *args: Any, **kwargs: Any):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as err:
            if isinstance(request.POST, dict) and "username" in request.POST and "password" in request.POST:
                raise AuthenticationFailed()
            else:
                raise err

        if (  # pragma: no cover
            # Not covered: Defensive check for malformed serializer output.
            # Django REST Framework's AuthTokenSerializer guarantees validated_data
            # is a dict with 'user' key when validation succeeds.
            not isinstance(serializer.validated_data, dict) or "user" not in serializer.validated_data
        ):
            raise AuthenticationFailed()

        user = cast(str, serializer.validated_data["user"])

        token, created = ExpiringToken.objects.get_or_create(user=user)

        if not created and token.is_expired:
            # Force rotation of expired tokens.
            ExpiringToken.objects.filter(user=user).delete()
            token, _ = ExpiringToken.objects.get_or_create(user=user)

        # django.contrib.auth.models.update_last_login expects to be a signal receiver.
        # But, it does not use its first argument, so it is safe to pass it None even if
        # the stubs complain.
        userobject = User.objects.get(username=user)
        update_last_login(None, userobject)  # type: ignore[call-arg]

        return Response({"token": token.key})


class TokenLogout(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request: Request):
        # delete the user on logout to clean up the local user database and
        # group memberships. As the user owns the token, it will also be deleted.
        request.user.delete()
        return Response(status=status.HTTP_200_OK)


class TokenIsValid(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        return Response(status=status.HTTP_200_OK)


###
### User infomation views
####


class UserInfo(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        # Identify the requesting user
        req_user = User.from_request(request)

        # Determine target user (default is the requesting user)
        username = request.query_params.get("username")
        target_user = req_user

        if username and username != req_user.username:
            if not (req_user.is_mreg_superuser_or_admin or req_user.is_mreg_hostgroup_admin):
                raise PermissionDenied("You do not have permission to view other users' details.")
            try:
                target_user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise NotFound(f"User with username '{username}' not found.")

        # Gather target user's information
        target_groups = target_user.groups.all()
        target_permissions = NetGroupRegexPermission.objects.filter(group__in=[group.name for group in target_groups])

        token = ExpiringToken.objects.filter(user=target_user).first()
        token_data = None
        if token:
            token_data = {
                "is_valid": not token.is_expired,
                "created": token.created_at.astimezone(),
                "expire": token.expire_at.astimezone(),
                "last_used": token.last_used.astimezone() if token.last_used else None,
                "lifespan": str(token.lifespan_left),
            }

        data = {
            "username": target_user.username,
            "last_login": target_user.last_login.astimezone() if target_user.last_login else None,
            "token": token_data if token else None,
            "django_status": {
                "superuser": target_user.is_superuser,
                "staff": target_user.is_staff,
                "active": target_user.is_active,
            },
            "mreg_status": {
                "superuser": target_user.is_mreg_superuser,
                "admin": target_user.is_mreg_admin,
                "group_admin": target_user.is_mreg_hostgroup_admin,
                "network_admin": target_user.is_mreg_network_admin,
                "hostpolicy_admin": target_user.is_mreg_hostpolicy_admin,
                "dns_wildcard_admin": target_user.is_mreg_dns_wildcard_admin,
                "underscore_admin": target_user.is_mreg_dns_underscore_admin,
            },
            "groups": [group.name for group in target_groups],
            "permissions": [
                {
                    "group": permission.group,
                    "range": str(permission.range),
                    "regex": permission.regex,
                    "labels": [label.name for label in permission.labels.all()],
                }
                for permission in target_permissions
            ],
        }

        return Response(status=status.HTTP_200_OK, data=data)


###
### Introspection views
###
class MregVersion(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        data = {
            "version": mreg_version,
        }
        return Response(status=status.HTTP_200_OK, data=data)


class MetaVersions(APIView):
    permission_classes = (IsSuperOrNetworkAdminMember,)

    def get(self, request: Request):
        data = {
            "python": platform.python_version(),
            "django": django.get_version(),
        }

        for library in LIBRARIES_TO_REPORT:
            try:
                data[library] = version(library)
            except Exception as e:  # pragma: no cover
                # Not covered: Requires a library to be installed but fail version lookup.
                # importlib.metadata.version is reliable for properly installed packages.
                logger.warning(event="library", reason=f"Failed to get version for {library}: {e}")
                data[library] = "<unknown>"
        
        data["libpq"] = str(pq.version())
        return Response(status=status.HTTP_200_OK, data=data)


class HealthHeartbeat(APIView):
    def get(self, request: Request):
        uptime = int(time.time() - start_time)
        data = {
            "start_time": start_time,
            "uptime": uptime,
        }
        return Response(status=status.HTTP_200_OK, data=data)


class HealthLDAP(APIView):
    def get(self, request: Request) -> Response:
        ok = self.check_ldap_connection()
        st = status.HTTP_200_OK if ok else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(status=st)

    def check_ldap_connection(self) -> bool:
        """Check if we can connect to LDAP.

        :return: Whether the LDAP connection test was successful.
        :rtype: bool
        """
        try:
            self._check_ldap_connection()
            return True
        except ldap.LDAPError as e: # type: ignore[attr-defined]
            logger.exception("LDAP connection error", error=str(e))
        except Exception as e:
            logger.exception("Error during LDAP check", error=str(e))
        return False

    def _check_ldap_connection(self) -> None:
        connection = None  # may be set in the try block

        try:
            ldap_backend = LDAPBackend()
            connection = _observe_ldap_call(
                "initialize", lambda: ldap_backend.ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            )
            _observe_ldap_call(
                "bind", lambda: connection.simple_bind_s(settings.AUTH_LDAP_BIND_DN, settings.AUTH_LDAP_BIND_PASSWORD)
            )
        finally:
            # We may have established a connection, so we should close it
            if connection:
                try:
                    _observe_ldap_call("unbind", connection.unbind_s)
                except Exception:
                    logger.exception("Failed to unbind from LDAP server")


class MetricsView(APIView):
    """Expose Prometheus metrics at a stable API url.

    The middleware avoids instrumenting this endpoint to prevent recursion.
    """

    permission_classes = ()

    def get(self, request: Request):
        return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)
