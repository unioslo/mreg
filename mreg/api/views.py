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

from mreg.api.permissions import IsSuperOrNetworkAdminMember
from mreg.models.base import ExpiringToken

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


class MetaVersions(APIView):

    permission_classes = (IsSuperOrNetworkAdminMember,)

    def get(self, request: Request):
        data = {
            "django_version": django.get_version(),
            "rest_framework_version": res_version,
            "python_version": platform.python_version(),
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
