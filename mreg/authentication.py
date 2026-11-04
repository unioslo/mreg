from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication, get_authorization_header

from mreg.models.base import ExpiringToken
from mreg.models.auth import LDAPUserState

if TYPE_CHECKING:
    from rest_framework.request import Request

    from mreg.models.auth import User


class ExpiringTokenAuthentication(TokenAuthentication):

    def authenticate_header(self, request: Request) -> str:
        header = get_authorization_header(request).split()
        if settings.MREG_OIDC_ENABLED and header and header[0].lower() == b"bearer":
            return "Bearer"
        return super().authenticate_header(request)

    def __init__(self, *args, refresh_directory=True, **kwargs):
        self.model = ExpiringToken
        self.refresh_directory = refresh_directory
        super().__init__(*args, **kwargs)

    def authenticate_credentials(self, key: str) -> tuple[User, ExpiringToken]:
        try:
            token: ExpiringToken = self.get_model().objects.get(key=key)
        except ObjectDoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted')

        if token.is_expired:
            raise exceptions.AuthenticationFailed('Token has expired')

        user = self.resolve_user(token.user)

        # An overlapping logout may have deleted the token since we read it.
        # Model.save() could reinsert it, so only update an existing credential.
        token.last_used = timezone.now()
        if not self.get_model().objects.filter(pk=token.pk).update(last_used=token.last_used):
            raise exceptions.AuthenticationFailed('Invalid token')

        return user, token

    def resolve_user(self, user):
        if self.refresh_directory and settings.MREG_LDAP_REFRESH_LOCAL_TOKENS:
            state = LDAPUserState.objects.filter(user_id=user.pk).first()
            if state is not None:
                from mreg.directory import refresh_directory_user

                refreshed = refresh_directory_user(state.username)
                if refreshed.pk != user.pk:
                    raise exceptions.AuthenticationFailed("Directory identity changed.")
                return refreshed
        return user


class KeycloakBearerAuthentication(TokenAuthentication):
    """Accept Keycloak user access tokens without minting local API tokens."""

    keyword = "Bearer"

    def authenticate(self, request: Request) -> tuple[User, dict[str, object]] | None:
        if not settings.MREG_OIDC_ENABLED:
            return None
        return super().authenticate(request)

    def authenticate_credentials(self, key: str) -> tuple[User, dict[str, object]]:
        from mreg.oidc import resolve_ldap_user, validate_access_token

        claims = validate_access_token(key)
        user = resolve_ldap_user(claims)
        return user, {name: claims[name] for name in ("iss", "sub", "azp")}
