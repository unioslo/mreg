from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from mreg.models import ExpiringToken

EXPIRE_HOURS = getattr(settings, 'REST_FRAMEWORK_TOKEN_EXPIRE_HOURS', 8)


class ExpiringTokenAuthentication(TokenAuthentication):

    def __init__(self, *args, **kwargs):
        self.model = ExpiringToken
        super().__init__(*args, **kwargs)

    def authenticate_credentials(self, key):
        try:
            token = self.get_model().objects.get(key=key)
        except ObjectDoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted')

        if token.last_used < timezone.now() - timedelta(hours=EXPIRE_HOURS):
            raise exceptions.AuthenticationFailed('Token has expired')

        # Save the token to update the last_used field.
        token.save()

        return token.user, token
