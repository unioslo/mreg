"""Directory authorization shared by credential-specific authentication methods."""

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Never

import ldap
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import transaction
from django.dispatch import receiver
from django.utils import timezone
from django_auth_ldap.backend import LDAPBackend, ldap_error
from django_auth_ldap.config import LDAPGroupQuery, LDAPSearchUnion
from rest_framework.exceptions import APIException, AuthenticationFailed
from structlog import get_logger

from mreg.models.auth import LDAPUserState

if TYPE_CHECKING:
    from datetime import datetime
    from types import ModuleType

    from django_auth_ldap.backend import _LDAPUser
    from ldap.ldapobject import LDAPObject

    from mreg.models.auth import User


logger = get_logger(__name__)


class DirectoryFailure(APIException):
    status_code = 503
    default_detail = "Unable to resolve directory account."
    default_code = "directory_failure"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.wait: int = settings.MREG_LDAP_RETRY_SECONDS


class DirectoryUnavailable(DirectoryFailure):
    default_detail = "Directory temporarily unavailable."
    default_code = "directory_unavailable"


def validate_directory_settings() -> None:
    for suffix in ("REFRESH_SECONDS", "GRACE_SECONDS", "RETRY_SECONDS", "TIMEOUT_SECONDS"):
        name = f"MREG_LDAP_{suffix}"
        value = getattr(settings, name)
        minimum = 1 if suffix == "TIMEOUT_SECONDS" else 0
        if type(value) is not int or value < minimum:
            raise ImproperlyConfigured(f"{name} must be an integer >= {minimum}.")
    if not settings.LDAP_GROUP_ATTR or not settings.LDAP_GROUP_RE:
        raise ImproperlyConfigured("Directory refresh requires LDAP_GROUP_ATTR and LDAP_GROUP_RE.")
    if getattr(settings, "AUTH_LDAP_USER_QUERY_FIELD", None):
        raise ImproperlyConfigured("Directory refresh requires username lookup, not AUTH_LDAP_USER_QUERY_FIELD.")
    if get_user_model().USERNAME_FIELD in getattr(settings, "AUTH_LDAP_USER_ATTR_MAP", {}):
        raise ImproperlyConfigured("Directory refresh cannot rename users through AUTH_LDAP_USER_ATTR_MAP.")
    for name in ("AUTH_LDAP_USER_SEARCH", "AUTH_LDAP_GROUP_SEARCH"):
        if isinstance(getattr(settings, name, None), LDAPSearchUnion):
            raise ImproperlyConfigured(f"Directory refresh does not support LDAPSearchUnion in {name}; use a single LDAPSearch.")
    if settings.DATABASES["default"].get("ATOMIC_REQUESTS", False):
        raise ImproperlyConfigured("Directory refresh requires ATOMIC_REQUESTS=False so failed requests retain denial/retry state.")


class _TimedLDAP:
    """Set python-ldap's result timeout before the backend binds or searches."""

    def __init__(self, module: ModuleType) -> None:
        self.module = module

    def __getattr__(self, name: str) -> Any:
        return getattr(self.module, name)

    def initialize(self, *args: Any, **kwargs: Any) -> LDAPObject:
        connection = self.module.initialize(*args, **kwargs)
        connection.timeout = settings.MREG_LDAP_TIMEOUT_SECONDS
        return connection


class DirectoryLDAPBackend(LDAPBackend):
    """Population with the account restrictions normally checked at LDAP login."""

    def __init__(self) -> None:
        validate_directory_settings()
        # Library caches must not make a successful refresh appear newer than its data.
        self.settings.CACHE_TIMEOUT = 0
        self.settings.ALWAYS_UPDATE_USER = True
        self.settings.CONNECTION_OPTIONS = {
            **self.settings.CONNECTION_OPTIONS,
            ldap.OPT_NETWORK_TIMEOUT: settings.MREG_LDAP_TIMEOUT_SECONDS,
            ldap.OPT_TIMEOUT: settings.MREG_LDAP_TIMEOUT_SECONDS,
        }

    @property
    def ldap(self) -> _TimedLDAP:
        return _TimedLDAP(super().ldap)

    def get_or_build_user(self, username: str, ldap_user: _LDAPUser) -> tuple[User, bool]:
        # populate_user() skips the requirements normally checked during a password bind.
        for requirement, expected in ((self.settings.REQUIRE_GROUP, True), (self.settings.DENY_GROUP, False)):
            if requirement is not None:
                query = LDAPGroupQuery(requirement) if isinstance(requirement, str) else requirement
                if query.resolve(ldap_user) != expected:
                    raise AuthenticationFailed("Directory account is not allowed.")
        user, built = super().get_or_build_user(username, ldap_user)
        if built:
            if self.settings.NO_NEW_USERS:
                return user, built
            user.set_unusable_password()
            user, built = get_user_model().objects.get_or_create(username=user.username, defaults={"password": user.password})
        user = get_user_model().objects.select_for_update().get(pk=user.pk)
        if not user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")
        return user, built


def _raise_directory_error(exception: Exception) -> Never:
    if isinstance(exception, (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.UNAVAILABLE, ldap.BUSY)):
        raise DirectoryUnavailable() from exception
    if isinstance(exception, ldap.NO_SUCH_OBJECT):
        raise AuthenticationFailed("Directory account is missing.") from exception
    raise DirectoryFailure() from exception


@receiver(ldap_error)
def reject_directory_error(sender: object, exception: Exception, **kwargs: object) -> None:
    # The library otherwise swallows errors from some group/attribute lookups.
    if isinstance(sender, type) and issubclass(sender, DirectoryLDAPBackend):
        _raise_directory_error(exception)


def directory_username(username: object) -> str:
    if not isinstance(username, str) or not username or username != username.strip():
        raise AuthenticationFailed("Invalid directory username.")
    username = username.lower()
    try:
        get_user_model()._meta.get_field("username").run_validators(username)
    except ValidationError as exc:
        raise AuthenticationFailed("Invalid directory username.") from exc
    return username


def _local_user(username: str, *, lock: bool = False) -> User | None:
    users = get_user_model().objects
    if lock:
        users = users.select_for_update()
    try:
        user = users.get(username__iexact=username)
    except get_user_model().DoesNotExist:
        return None
    except get_user_model().MultipleObjectsReturned as exc:
        raise AuthenticationFailed("Ambiguous directory identity.") from exc
    if not user.is_active:
        raise AuthenticationFailed("User inactive or deleted.")
    return user


def _grace_user(state: LDAPUserState, user: User | None, now: datetime) -> User:
    maximum_age = settings.MREG_LDAP_REFRESH_SECONDS + settings.MREG_LDAP_GRACE_SECONDS
    if (settings.MREG_LDAP_GRACE_SECONDS > 0 and user is not None and state.user_id == user.pk
            and state.eligible and state.last_success_at is not None
            and now < state.last_success_at + timedelta(seconds=maximum_age)):
        logger.warning("ldap_grace_access", username=state.username, last_success_at=state.last_success_at.isoformat())
        return user
    raise DirectoryUnavailable()


def _cached_user(state: LDAPUserState | None, user: User | None, now: datetime) -> User | None:
    if state is None:
        return None
    if (user is not None and state.user_id == user.pk and state.eligible and state.last_success_at is not None
            and now < state.last_success_at + timedelta(seconds=settings.MREG_LDAP_REFRESH_SECONDS)):
        return user
    if state.retry_after is not None and now < state.retry_after:
        if state.last_error == "unavailable":
            return _grace_user(state, user, now)
        if state.last_error == "denied":
            raise AuthenticationFailed("Directory account is not allowed.")
        raise DirectoryFailure()
    return None


def _populate(username: str) -> User:
    try:
        user = DirectoryLDAPBackend().populate_user(username)
    except ldap.LDAPError as exc:
        _raise_directory_error(exc)
    except get_user_model().MultipleObjectsReturned as exc:
        raise AuthenticationFailed("Ambiguous directory identity.") from exc
    if user is None or not user.is_active:
        raise AuthenticationFailed("Directory account is missing or inactive.")
    return user


def refresh_directory_user(username: object, *, force: bool = False) -> User:
    """Return a current user or bounded outage fallback, after credential verification.

    The username row serializes first provisioning as well as later refreshes.
    Failed population rolls back in a savepoint; failure metadata commits before
    raising so an authoritative denial cannot be undone by a subsequent outage.
    """
    validate_directory_settings()
    username = directory_username(username)
    user = _local_user(username)
    state: LDAPUserState | None = LDAPUserState.objects.filter(username=username).first()
    cached = None if force else _cached_user(state, user, timezone.now())
    if cached is not None:
        return cached

    error: AuthenticationFailed | DirectoryFailure | None = None
    with transaction.atomic():
        LDAPUserState.objects.get_or_create(username=username)
        state = LDAPUserState.objects.select_for_update().get(username=username)
        user = _local_user(username, lock=True)
        now = timezone.now()
        cached = None if force else _cached_user(state, user, now)
        if cached is not None:
            return cached
        try:
            with transaction.atomic():
                populated = _populate(username)
        except (AuthenticationFailed, DirectoryFailure) as exc:
            error = exc
            state.last_error = "unavailable" if isinstance(exc, DirectoryUnavailable) else (
                "denied" if isinstance(exc, AuthenticationFailed) else "error"
            )
            if state.last_error != "unavailable":
                state.eligible = False
            state.retry_after = timezone.now() + timedelta(seconds=settings.MREG_LDAP_RETRY_SECONDS)
            logger.warning("ldap_refresh_failed", username=username, outcome=state.last_error)
        else:
            state.user = populated
            state.last_success_at = now
            state.eligible = True
            state.last_error = ""
            state.retry_after = None
            user = get_user_model().objects.get(pk=populated.pk)
        state.save()

    if isinstance(error, DirectoryUnavailable):
        return _grace_user(state, user, timezone.now())
    if error is not None:
        raise error
    return user
