from django.core.exceptions import ObjectDoesNotExist

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from mreg.models import ExpiringToken


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

        if token.is_expired:
            raise exceptions.AuthenticationFailed('Token has expired')

        # Save the token to update the last_used field.
        token.save()

        return token.user, token
