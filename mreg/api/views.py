import platform
import time
from importlib.metadata import version
from typing import Any, cast

import django
import ldap
import structlog
from django.conf import settings
from django_auth_ldap.backend import LDAPBackend
from django.contrib.auth.models import update_last_login
from psycopg2 import __libpq_version__ as libpq_version
from rest_framework import serializers, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from mreg.__about__ import __version__ as mreg_version
from mreg.api.permissions import IsSuperOrNetworkAdminMember
from mreg.models.auth import User
from mreg.models.base import ExpiringToken
from mreg.models.network import NetGroupRegexPermission

logger = structlog.getLogger(__name__)

start_time = int(time.time())

# Note the order here. This order is preserved in the response.
# Also, we add libpq-data to the end of this list so letting psycopg2-binary
# be last makes the context of the libpq version more clear.
LIBRARIES_TO_REPORT = [
    "djangorestframework",
    "django-auth-ldap",
    "django-filter", 
    "django-logging-json",
    "django-netfields",
    "drf-standardized-errors",
    "gunicorn", 
    "sentry-sdk",
    "structlog",
    "rich",
    "psycopg2-binary",
]


class ObtainExpiringAuthToken(ObtainAuthToken):

    def post(self, request: Request, *args: Any, **kwargs: Any):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as err:
            if (
                isinstance(request.POST, dict)
                and "username" in request.POST
                and "password" in request.POST
            ):
                raise AuthenticationFailed()
            else:
                raise err

        if (
            not isinstance(serializer.validated_data, dict)
            or "user" not in serializer.validated_data
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
        update_last_login(None, userobject) # type: ignore[call-arg]

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
        target_permissions = NetGroupRegexPermission.objects.filter(
            group__in=[group.name for group in target_groups]
        )
        
        token = ExpiringToken.objects.filter(user=target_user).first()
        token_data = None
        if token:
            token_data = {
                "is_valid": not token.is_expired,
                "created": token.created_at.astimezone(),
                "expire": token.expire_at.astimezone(),
                "last_used": token.last_used.astimezone() if token.last_used else None,
                "lifespan": str(token.lifespan_left)
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
            except Exception as e:
                logger.warning(event="library", reason=f"Failed to get version for {library}: {e}")
                data[library] = "<unknown>"
        
        data["libpq"] = str(libpq_version)
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
        except ldap.LDAPError as e:
            logger.exception("LDAP connection error", error=str(e))
        except Exception as e:
            logger.exception("Error during LDAP check", error=str(e))
        return False
    
    def _check_ldap_connection(self) -> None:
        connection = None  # may be set in the try block

        try:
            ldap_backend = LDAPBackend()
            connection = ldap_backend.ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            connection.simple_bind_s(settings.AUTH_LDAP_BIND_DN, settings.AUTH_LDAP_BIND_PASSWORD)
        finally:
            # We may have established a connection, so we should close it
            if connection:
                try:
                    connection.unbind_s()
                except Exception:
                    logger.exception("Failed to unbind from LDAP server")
