from django.utils import timezone

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed


class ObtainExpiringAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as err:
            if 'username' in request.POST and 'password' in request.POST:
                raise AuthenticationFailed()
            else:
                raise err

        token, created = Token.objects.get_or_create(user=serializer.validated_data['user'])
        if not created:
            # update the created time of the token to keep it valid
            token.created = timezone.now()
            token.save()

        return Response({'token': token.key})


class TokenLogout(APIView):

    permission_classes = (IsAuthenticated, )

    def post(self, request):
        # delete the user on logout to clean up the local user database and
        # group memberships. As the user owns the token, it will also be deleted.
        request.user.delete()
        return Response(status=status.HTTP_200_OK)
