import platform
import time
from typing import Any, cast

import django
from rest_framework import __version__ as res_version
from rest_framework import serializers, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from django_auth_ldap import __version__ as ldap_version
from django_filters import __version__ as filters_version
from gunicorn import __version__ as gunicorn_version
from sentry_sdk import VERSION as sentry_sdk_version
from psycopg2 import __libpq_version__ as libpq_version

from mreg.api.permissions import IsSuperOrNetworkAdminMember
from mreg.models.base import ExpiringToken
from mreg.__about__ import __version__ as mreg_version

start_time = int(time.time())


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
            "djangorestframework": res_version,
            "django_auth_ldap": ldap_version,
            "django_filters": filters_version,
            "gunicorn": gunicorn_version,
            "sentry_sdk": sentry_sdk_version,
            "libpq": libpq_version,
        }
        return Response(status=status.HTTP_200_OK, data=data)


class MetaHeartbeat(APIView):

    permission_classes = (IsAuthenticated,)

    def get(self, request: Request):
        uptime = int(time.time() - start_time)
        data = {
            "start_time": start_time,
            "uptime": uptime,
        }
        return Response(status=status.HTTP_200_OK, data=data)
