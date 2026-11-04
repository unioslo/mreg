"""Password authentication that shares directory state with token authentication."""

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from mreg.directory import DirectoryLDAPBackend, directory_username, refresh_directory_user, validate_directory_settings
from mreg.models.auth import LDAPUserState


def validate_local_directory_settings():
    if not settings.MREG_LDAP_REFRESH_LOCAL_TOKENS:
        return
    validate_directory_settings()
    expected = ("mreg.directory_auth.LocalUserBackend", "mreg.directory_auth.LDAPPasswordBackend")
    if tuple(settings.AUTHENTICATION_BACKENDS) != expected:
        raise ImproperlyConfigured(
            f"MREG_LDAP_REFRESH_LOCAL_TOKENS requires AUTHENTICATION_BACKENDS={expected!r}."
        )


class LocalUserBackend(ModelBackend):
    """Local passwords cannot bypass LDAP for explicitly directory-managed users."""

    def user_can_authenticate(self, user):
        return super().user_can_authenticate(user) and not LDAPUserState.objects.filter(user_id=user.pk).exists()


class LDAPPasswordBackend(DirectoryLDAPBackend):
    def __init__(self):
        super().__init__()
        # The inherited backend verifies the password, without persisting a user
        # or checking authorization. The shared refresher handles those afterward.
        self.settings.ALWAYS_UPDATE_USER = False
        self.settings.REQUIRE_GROUP = None
        self.settings.DENY_GROUP = None
        self.settings.MIRROR_GROUPS = False
        self.settings.MIRROR_GROUPS_EXCEPT = None
        self.settings.PERMIT_EMPTY_PASSWORD = False

    def get_or_build_user(self, username, ldap_user):
        # An unsaved identity is sufficient for the password verification phase.
        # built=False and ALWAYS_UPDATE_USER=False prevent population or saving.
        return get_user_model()(username=directory_username(username)), False

    def authenticate_ldap_user(self, ldap_user, password):
        if ldap_user.dn is None:
            raise AuthenticationFailed("Directory account is missing or ambiguous.")
        return super().authenticate_ldap_user(ldap_user, password)

    def authenticate(self, request, username=None, password=None, **kwargs):
        username = kwargs.get(get_user_model().USERNAME_FIELD, username)
        if username is None or not isinstance(password, str) or not password:
            return None
        username = directory_username(username)
        try:
            verified = super().authenticate(request, username=username, password=password)
        except AuthenticationFailed:
            # A definitive DN lookup failure must invalidate earlier eligibility.
            # Wrong passwords return None in django-auth-ldap and never enter here.
            LDAPUserState.objects.filter(username=username).update(
                eligible=False, last_error="denied",
                retry_after=timezone.now() + timedelta(seconds=settings.MREG_LDAP_RETRY_SECONDS),
            )
            raise
        if verified is None:
            return None
        # A successful bind does not prove the cached permissions are current.
        # Force population; grace may cover a later outage, never a failed bind.
        return refresh_directory_user(verified.username, force=True)
