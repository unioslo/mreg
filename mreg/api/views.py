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
from django_auth_ldap.config import LDAPSearch
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
    connection_successful: bool = False
    search_successful: bool = False
    error: Optional[str] = None

    @property
    def healthy(self) -> bool:
        return not self.error and all([self.connection_successful, self.search_successful])

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
    
    def _get_search_config(self) -> Optional[tuple[str, int, str]]:
        """Extract search configuration from django-auth-ldap settings.

        :return: Tuple of (base_dn, scope, filter_string) if configured, None otherwise
        :rtype: Optional[Tuple[str, int, str]]
        """
        user_search = getattr(settings, 'AUTH_LDAP_USER_SEARCH', None)
        if isinstance(user_search, LDAPSearch):
            return user_search.base_dn, user_search.scope, user_search.filterstr
        return None
    
    def _check_ldap_connection(self) -> LDAPDetails:
        """Perform LDAP connection and search test.

        Attempts to establish an LDAP connection using configured settings
        and perform a basic search operation.

        :return: A tuple containing overall health status and check details
        :rtype: LDAPDetails
    
        :raises: No exceptions are raised; all errors are caught and returned in the details dict
        """
        details = LDAPDetails()

        try:
            # Initialize LDAP backend and connection
            ldap_backend = LDAPBackend()
            connection = ldap_backend.ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            
            connection.timeout = getattr(settings, 'AUTH_LDAP_TIMEOUT', 10)
            
            connection.simple_bind_s(
                settings.AUTH_LDAP_BIND_DN,
                settings.AUTH_LDAP_BIND_PASSWORD
            )

            details.connection_successful = True

            search_config = self._get_search_config()
            if search_config:
                base_dn, scope, filterstr = search_config
                # Perform a search with a limit of 1 to verify search functionality
                connection.search_s(
                    base_dn,
                    scope,
                    filterstr.replace('%(user)s', '*'),  # Replace user template with wildcard
                    attrlist=['dn'],
                    sizelimit=1
                )
                details.search_successful = True
            else:
                # If no search is configured, we'll just mark it as successful
                # since it's not required for basic LDAP functionality
                details.search_successful = True
                logger.debug("No LDAP search configuration found, skipping search test")

            return details

        except ldap.LDAPError as e:
            error_msg = f"LDAP connection error: {str(e)}"
            logger.error(error_msg)
            details.error = error_msg
            return details

        except Exception as e:
            error_msg = f"Unexpected error during LDAP check: {str(e)}"
            logger.error(error_msg)
            details.error = error_msg
            return details