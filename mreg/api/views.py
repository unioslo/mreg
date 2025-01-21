import platform
import time
from dataclasses import asdict, dataclass
from importlib.metadata import version
from typing import Any, Optional, cast

import django
import ldap
import structlog
from django.conf import settings
from django_auth_ldap.backend import LDAPBackend
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
        
        data = {
            "username": target_user.username,
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

    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        uptime = int(time.time() - start_time)
        data = {
            "start_time": start_time,
            "uptime": uptime,
        }
        return Response(status=status.HTTP_200_OK, data=data)


@dataclass
class LDAPDetails:
    """Details about the LDAP connection and search test."""

    connect: bool = False
    search: bool = False
    error: Optional[str] = None

    @property
    def healthy(self) -> bool:
        return not self.error and all([self.connect, self.search])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["healthy"] = self.healthy
        return d


class HealthLDAP(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        details = self._check_ldap_connection()
        st = status.HTTP_200_OK if details.healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(status=st, data=details.to_dict())

    def _check_ldap_connection(self) -> LDAPDetails:
        """Perform LDAP connection and search test.

        Attempts to establish an LDAP connection using configured settings
        and perform a basic search operation.

        :return: Details about the LDAP connection health status
        :rtype: LDAPDetails
        """
        details = LDAPDetails()
        connection = None  # may be set in the try block

        try:
            ldap_backend = LDAPBackend()
            connection = ldap_backend.ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            connection.timeout = getattr(settings, "AUTH_LDAP_TIMEOUT", 10)

            # Test connectivity
            connection.simple_bind_s(settings.AUTH_LDAP_BIND_DN, settings.AUTH_LDAP_BIND_PASSWORD)
            details.connect = True

            # Test search
            try:
                user_dn = settings.AUTH_LDAP_USER_DN_TEMPLATE
                if not user_dn:
                    raise Exception("Cannot test LDAP search without a user DN template")

                # Search in the user base DN. Get rid of the user placeholder.
                if "%(user)s," in user_dn:
                    user_dn = user_dn.partition(",")[2]

                results = connection.search_ext_s(
                    user_dn,
                    ldap.SCOPE_BASE,
                    sizelimit=1,
                )

                details.search = bool(results)
                if not details.search:
                    logger.warning("No results found in LDAP search. Is the LDAP server empty?", base=user_dn)

            except ldap.LDAPError as e:
                details.error = f"LDAP search error: {str(e)}"

            except Exception as e:
                details.error = f"Unexpected error during LDAP search: {str(e)}"

            return details

        except ldap.LDAPError as e:
            details.error = f"LDAP connection error: {str(e)}"
            return details

        except Exception as e:
            details.error = f"Unexpected error during LDAP check: {str(e)}"
            return details

        finally:
            # We may have established a connection, so we should close it
            if connection and details.connect:
                try:
                    connection.unbind_s()
                except Exception:
                    logger.exception("Failed to unbind from LDAP server")
