"""Validate Keycloak access tokens and resolve users through the LDAP directory."""

from functools import lru_cache
from urllib.parse import urlsplit

import jwt
import ldap
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import transaction
from django.dispatch import receiver
from django_auth_ldap.backend import LDAPBackend, ldap_error
from django_auth_ldap.config import LDAPGroupQuery
from rest_framework.exceptions import AuthenticationFailed


def validate_oidc_settings():
    """Fail startup on incomplete trust configuration; never perform network I/O."""
    if not settings.MREG_OIDC_ENABLED:
        return
    for name in ("ISSUER", "AUDIENCE", "JWKS_URL", "USERNAME_CLAIM"):
        value = getattr(settings, f"MREG_OIDC_{name}")
        if not isinstance(value, str) or not value or value != value.strip():
            raise ImproperlyConfigured(f"MREG_OIDC_{name} must be a nonempty string without surrounding whitespace.")
    for name in ("ISSUER", "JWKS_URL"):
        url = urlsplit(getattr(settings, f"MREG_OIDC_{name}"))
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ImproperlyConfigured(f"MREG_OIDC_{name} must be an HTTPS URL without credentials, query, or fragment.")
    for name in ("ALGORITHMS", "ALLOWED_CLIENT_IDS"):
        values = getattr(settings, f"MREG_OIDC_{name}")
        if not isinstance(values, (tuple, list)) or not values or any(
            not isinstance(value, str) or not value or value != value.strip() for value in values
        ):
            raise ImproperlyConfigured(f"MREG_OIDC_{name} must be a nonempty list of nonempty strings without whitespace.")
    algorithms = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
    if not set(settings.MREG_OIDC_ALGORITHMS) <= algorithms:
        raise ImproperlyConfigured("MREG_OIDC_ALGORITHMS must contain only supported asymmetric signing algorithms.")
    for name in ("JWKS_TIMEOUT", "JWKS_CACHE_SECONDS", "JWKS_COOLDOWN_SECONDS", "LEEWAY_SECONDS"):
        value = getattr(settings, f"MREG_OIDC_{name}")
        minimum = 0 if name == "LEEWAY_SECONDS" else 1
        if type(value) is not int or value < minimum:
            raise ImproperlyConfigured(f"MREG_OIDC_{name} must be an integer >= {minimum}.")
    if not settings.LDAP_GROUP_ATTR or not settings.LDAP_GROUP_RE:
        raise ImproperlyConfigured("OIDC requires LDAP_GROUP_ATTR and LDAP_GROUP_RE for directory authorization.")
    if getattr(settings, "AUTH_LDAP_USER_QUERY_FIELD", None):
        raise ImproperlyConfigured("OIDC requires LDAP users to be looked up by username, not AUTH_LDAP_USER_QUERY_FIELD.")


@lru_cache(maxsize=1)
def _jwks_client(url, timeout, lifespan, cooldown):
    # Cache the client across requests, but let its JWKS cache expire. Per-key
    # caching has no time limit and could keep accepting a removed signing key.
    return jwt.PyJWKClient(url, timeout=timeout, lifespan=lifespan, cooldown_duration=cooldown, cache_keys=False)


def validate_access_token(token):
    """Return verified claims. No directory or user lookup may precede this."""
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in settings.MREG_OIDC_ALGORITHMS:
            raise AuthenticationFailed("Invalid access token.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationFailed("Invalid access token.")
        client = _jwks_client(
            settings.MREG_OIDC_JWKS_URL,
            settings.MREG_OIDC_JWKS_TIMEOUT,
            settings.MREG_OIDC_JWKS_CACHE_SECONDS,
            settings.MREG_OIDC_JWKS_COOLDOWN_SECONDS,
        )
        # kid is only a selector within our configured key set. Token-supplied
        # issuer URLs, jku, x5u, and embedded keys never select a trust source.
        key = client.get_signing_key(kid)
        if key.algorithm_name != header["alg"]:
            raise AuthenticationFailed("Invalid access token signing algorithm.")
        claims = jwt.decode(
            token,
            key.key,
            algorithms=settings.MREG_OIDC_ALGORITHMS,
            issuer=settings.MREG_OIDC_ISSUER,
            audience=settings.MREG_OIDC_AUDIENCE,
            leeway=settings.MREG_OIDC_LEEWAY_SECONDS,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "typ", "azp"]},
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        # Do not disclose token contents or upstream connection details.
        raise AuthenticationFailed("Unable to validate access token.") from exc
    if claims["typ"] != "Bearer" or not claims["sub"]:
        raise AuthenticationFailed("Expected a Keycloak user access token.")
    if not isinstance(claims["azp"], str) or claims["azp"] not in settings.MREG_OIDC_ALLOWED_CLIENT_IDS:
        raise AuthenticationFailed("Access token client is not allowed.")
    return claims


class OIDCLDAPBackend(LDAPBackend):
    """Population with the account restrictions normally checked at LDAP login."""

    def get_or_build_user(self, username, ldap_user):
        # populate_user() skips LDAPBackend's password-login requirements.
        for requirement, expected in ((self.settings.REQUIRE_GROUP, True), (self.settings.DENY_GROUP, False)):
            if requirement is not None:
                query = LDAPGroupQuery(requirement) if isinstance(requirement, str) else requirement
                if query.resolve(ldap_user) != expected:
                    raise AuthenticationFailed("Directory account is not allowed.")
        user, built = super().get_or_build_user(username, ldap_user)
        if not built:
            # Serialize with concurrent provisioning and administrative updates.
            user = get_user_model().objects.select_for_update().get(pk=user.pk)
            if not user.is_active:
                raise AuthenticationFailed("User inactive or deleted.")
        return user, built


@receiver(ldap_error, sender=OIDCLDAPBackend)
def reject_ldap_error(sender, **kwargs):
    # django-auth-ldap can otherwise swallow a directory error while populating
    # permissions. A failed lookup must not reuse previously stored privileges.
    raise AuthenticationFailed("Unable to resolve directory account.")


@transaction.atomic
def resolve_ldap_user(claims):
    username = claims.get(settings.MREG_OIDC_USERNAME_CLAIM)
    if not isinstance(username, str) or not username or username != username.strip():
        raise AuthenticationFailed("Access token lacks a valid directory username.")
    user_model = get_user_model()
    try:
        user_model._meta.get_field("username").run_validators(username)
    except ValidationError as exc:
        raise AuthenticationFailed("Invalid directory username.") from exc
    backend = OIDCLDAPBackend()
    # Group checks and is_active mappings must use this request's directory state.
    backend.settings.CACHE_TIMEOUT = 0
    try:
        user = backend.populate_user(username)
    except (ldap.LDAPError, user_model.MultipleObjectsReturned) as exc:
        raise AuthenticationFailed("Unable to resolve directory account.") from exc
    if user is None or not user.is_active:
        raise AuthenticationFailed("Directory account is missing or inactive.")
    # Permission properties on User are cached per instance; use a fresh instance
    # after the population signal has replaced group memberships.
    return user_model.objects.get(pk=user.pk)
