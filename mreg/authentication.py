from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication, get_authorization_header

from mreg.models.base import ExpiringToken


class ExpiringTokenAuthentication(TokenAuthentication):

    def authenticate_header(self, request):
        header = get_authorization_header(request).split()
        if settings.MREG_OIDC_ENABLED and header and header[0].lower() == b"bearer":
            return "Bearer"
        return super().authenticate_header(request)

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


class KeycloakBearerAuthentication(TokenAuthentication):
    """Accept Keycloak user access tokens without minting local API tokens."""

    keyword = "Bearer"

    def authenticate(self, request):
        if not settings.MREG_OIDC_ENABLED:
            return None
        return super().authenticate(request)

    def authenticate_credentials(self, key):
        from mreg.oidc import resolve_ldap_user, validate_access_token

        claims = validate_access_token(key)
        user = resolve_ldap_user(claims)
        return user, {name: claims[name] for name in ("iss", "sub", "azp")}
