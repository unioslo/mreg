"""Signed-token tests: exercise cryptography, JWKS caching, and the LDAP backend."""

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import io
import json
from threading import Barrier
import time
from typing import Never
from unittest.mock import Mock, patch
from urllib.error import URLError

import jwt
import ldap
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.db import connections
from django.test import SimpleTestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone
from django_auth_ldap.backend import populate_user
from django_auth_ldap.config import GroupOfNamesType, LDAPGroupQuery, LDAPSearch, LDAPSearchUnion, NestedGroupOfNamesType
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory, APITestCase
from rest_framework.views import APIView

from mreg.authentication import ExpiringTokenAuthentication, KeycloakBearerAuthentication
from mreg.models.auth import LDAPUserState, User
from mreg.models.base import ExpiringToken, History
from mreg.models.host import Host, Ipaddress
from mreg.models.network import NetGroupRegexPermission, Network
from mreg.directory import DirectoryLDAPBackend, DirectoryUnavailable
from mreg.oidc import _jwks_client, resolve_ldap_user, validate_access_token, validate_oidc_settings


OIDC_SETTINGS: dict[str, object] = {
    "MREG_OIDC_ENABLED": True,
    "MREG_LDAP_REFRESH_SECONDS": 0,
    "MREG_LDAP_GRACE_SECONDS": 0,
    "MREG_LDAP_RETRY_SECONDS": 0,
    "MREG_OIDC_ISSUER": "https://login.example.org/realms/test",
    "MREG_OIDC_AUDIENCE": "mreg",
    "MREG_OIDC_JWKS_URL": "https://login.example.org/realms/test/protocol/openid-connect/certs",
    "MREG_OIDC_USERNAME_CLAIM": "ldap_username",
    "MREG_OIDC_ALLOWED_CLIENT_IDS": ["webapp"],
    "MREG_OIDC_ALGORITHMS": ["RS256"],
    "MREG_OIDC_JWKS_TIMEOUT": 5,
    "MREG_OIDC_JWKS_CACHE_SECONDS": 300,
    "MREG_OIDC_JWKS_COOLDOWN_SECONDS": 30,
    "MREG_OIDC_LEEWAY_SECONDS": 0,
}


class SignedTokenMixin:
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self) -> None:
        super().setUp()
        _jwks_client.cache_clear()
        self.addCleanup(_jwks_client.cache_clear)
        self.jwks = {"keys": [self.public_jwk(self.signing_key, "key-1")]}
        opener = self.enterContext(patch("jwt.jwks_client.urllib.request.build_opener"))
        self.http = opener.return_value.open
        self.http.side_effect = lambda *args, **kwargs: io.BytesIO(json.dumps(self.jwks).encode())

    @staticmethod
    def public_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, object]:
        return {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())), "kid": kid, "alg": "RS256", "use": "sig"}

    def claims(self, **changes: object) -> dict[str, object]:
        now = int(time.time())
        return {
            "iss": settings.MREG_OIDC_ISSUER, "aud": "mreg", "sub": "f:provider:jsmith",
            "azp": "webapp", "typ": "Bearer", "iat": now, "exp": now + 300,
            "ldap_username": "jsmith", **changes,
        }

    def token(
        self, *, key: rsa.RSAPrivateKey | None = None, headers: dict[str, object] | None = None,
        claims: dict[str, object] | None = None, **changes: object,
    ) -> str:
        return jwt.encode(
            self.claims(**changes) if claims is None else claims,
            key or self.signing_key, algorithm="RS256", headers={"kid": "key-1", **(headers or {})},
        )


@override_settings(**OIDC_SETTINGS)
class AccessTokenTests(SignedTokenMixin, SimpleTestCase):
    def assert_rejected_before_ldap(self, token: str) -> None:
        request = APIRequestFactory().get("/api/token-is-valid/", HTTP_AUTHORIZATION=f"Bearer {token}")
        with patch("mreg.oidc.resolve_ldap_user") as resolve:
            with self.assertRaises(AuthenticationFailed):
                KeycloakBearerAuthentication().authenticate(request)
            resolve.assert_not_called()

    def test_signed_token_and_array_audience(self) -> None:
        for audience in ("mreg", ["account", "mreg"]):
            self.assertEqual(validate_access_token(self.token(aud=audience))["ldap_username"], "jsmith")
        self.assertEqual(self.http.call_count, 1)
        request = self.http.call_args.args[0]
        self.assertEqual(request.full_url, settings.MREG_OIDC_JWKS_URL)
        self.assertEqual(self.http.call_args.kwargs["timeout"], 5)

    def test_forged_and_modified_tokens_never_reach_ldap(self) -> None:
        legitimate = self.token()
        header, _, signature = legitimate.split(".")
        forged = base64.urlsafe_b64encode(json.dumps(self.claims(ldap_username="admin")).encode()).rstrip(b"=").decode()
        for token in (
            f"{header}.{forged}.{signature}",
            self.token(key=self.other_key),
            jwt.encode(self.claims(), key=None, algorithm="none"),
            jwt.encode(self.claims(), "attacker-controlled-secret-of-at-least-32-bytes", algorithm="HS256"),
            "not.a.jwt",
        ):
            with self.subTest(token=token[:20]):
                self.assert_rejected_before_ldap(token)

    def test_invalid_claims_never_reach_ldap(self) -> None:
        now = int(time.time())
        for changes in (
            {"iss": "https://attacker.example/realms/test"}, {"aud": "webapp"},
            {"azp": "unapproved-client"}, {"azp": ["webapp"]},
            {"typ": "ID"}, {"typ": "Refresh"}, {"sub": ""}, {"sub": 123},
            {"exp": now - 1}, {"nbf": now + 100}, {"iat": now + 100}, {"exp": []},
        ):
            with self.subTest(changes=changes):
                self.assert_rejected_before_ldap(self.token(**changes))
        for claim in ("iss", "aud", "exp", "iat", "sub", "typ", "azp"):
            with self.subTest(missing=claim):
                claims = self.claims()
                del claims[claim]
                self.assert_rejected_before_ldap(self.token(claims=claims))

    def test_key_id_required_and_token_urls_are_ignored(self) -> None:
        self.assert_rejected_before_ldap(jwt.encode(self.claims(), self.signing_key, algorithm="RS256"))
        self.assert_rejected_before_ldap(self.token(headers={"kid": ""}))
        self.http.assert_not_called()
        self.assert_rejected_before_ldap(self.token(
            key=self.other_key,
            headers={"jku": "https://attacker.example/keys", "x5u": "https://attacker.example/cert",
                     "jwk": self.public_jwk(self.other_key, "key-1")},
        ))
        self.assertEqual(self.http.call_args.args[0].full_url, settings.MREG_OIDC_JWKS_URL)

    def test_jwk_algorithm_must_match(self) -> None:
        self.jwks["keys"][0]["alg"] = "RS512"
        self.assert_rejected_before_ldap(self.token())

    def test_unknown_key_refresh_is_bounded_and_rotation_works(self) -> None:
        with patch("time.monotonic", return_value=1000):
            validate_access_token(self.token())
            self.jwks["keys"].append(self.public_jwk(self.other_key, "key-2"))
            for kid in ("key-2", "unknown-1", "unknown-2"):
                self.assert_rejected_before_ldap(self.token(key=self.other_key, headers={"kid": kid}))
            self.assertEqual(self.http.call_count, 1)
        with patch("time.monotonic", return_value=1031):
            validate_access_token(self.token(key=self.other_key, headers={"kid": "key-2"}))
            self.assertEqual(self.http.call_count, 2)

    def test_removed_key_stops_working_after_cache_expiry(self) -> None:
        with patch("time.monotonic", return_value=1000):
            validate_access_token(self.token())
        self.jwks = {"keys": [self.public_jwk(self.other_key, "key-2")]}
        with patch("time.monotonic", return_value=1301):
            self.assert_rejected_before_ldap(self.token())
            validate_access_token(self.token(key=self.other_key, headers={"kid": "key-2"}))

    def test_outage_only_allows_keys_within_cache_lifetime(self) -> None:
        with patch("time.monotonic", return_value=1000):
            validate_access_token(self.token())
            self.http.side_effect = URLError("unavailable")
            validate_access_token(self.token())
            self.assertEqual(self.http.call_count, 1)
        with patch("time.monotonic", return_value=1301):
            self.assert_rejected_before_ldap(self.token())

    def test_unavailable_or_malformed_jwks_rejected(self) -> None:
        for effect in (
            URLError("unavailable"), TimeoutError(),
            lambda *a, **kw: io.BytesIO(b"not json"),
            lambda *a, **kw: io.BytesIO(b'{"keys": []}'),
        ):
            with self.subTest(effect=effect):
                _jwks_client.cache_clear()
                self.http.side_effect = effect
                self.assert_rejected_before_ldap(self.token())

    def test_disabled_and_other_schemes_do_not_attempt_authentication(self) -> None:
        auth = KeycloakBearerAuthentication()
        factory = APIRequestFactory()
        for header in ("", "Token local-token", "Basic something"):
            self.assertIsNone(auth.authenticate(factory.get("/", HTTP_AUTHORIZATION=header)))
        with override_settings(MREG_OIDC_ENABLED=False):
            self.assertIsNone(auth.authenticate(factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.token()}")))
        self.http.assert_not_called()

    def test_malformed_bearer_header(self) -> None:
        for header in ("Bearer", "Bearer one two"):
            with self.subTest(header=header), self.assertRaises(AuthenticationFailed):
                KeycloakBearerAuthentication().authenticate(APIRequestFactory().get("/", HTTP_AUTHORIZATION=header))


@override_settings(**OIDC_SETTINGS)
class OIDCConfigurationTests(SimpleTestCase):
    def test_valid_configuration_and_disabled_configuration_require_no_network(self) -> None:
        with patch("jwt.PyJWKClient") as client:
            validate_oidc_settings()
            with override_settings(MREG_OIDC_ENABLED=False, MREG_OIDC_ISSUER=""):
                validate_oidc_settings()
            client.assert_not_called()

    def test_invalid_configuration(self) -> None:
        cases = {
            "MREG_OIDC_ISSUER": ["", None, "http://login.example", "https://user:secret@login.example", " https://login.example"],
            "MREG_OIDC_JWKS_URL": ["file:///tmp/keys", "https://login.example/keys?query=1", "https://login.example/keys#fragment"],
            "MREG_OIDC_AUDIENCE": ["", 12],
            "MREG_OIDC_USERNAME_CLAIM": ["", " username "],
            "MREG_OIDC_ALGORITHMS": [["none"], ["HS256"], [], "RS256"],
            "MREG_OIDC_ALLOWED_CLIENT_IDS": [[], [""], [None], "webapp"],
            "MREG_OIDC_JWKS_TIMEOUT": [0, -1, True],
            "MREG_OIDC_JWKS_CACHE_SECONDS": [0],
            "MREG_OIDC_JWKS_COOLDOWN_SECONDS": [0],
            "MREG_OIDC_LEEWAY_SECONDS": [-1],
            "LDAP_GROUP_ATTR": [None], "LDAP_GROUP_RE": [None],
            "AUTH_LDAP_USER_QUERY_FIELD": ["email"],
            "AUTH_LDAP_USER_ATTR_MAP": [{"username": "uid"}],
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value), override_settings(**{name: value}):
                    with self.assertRaises(ImproperlyConfigured):
                        validate_oidc_settings()

    def test_union_searches_are_rejected_at_startup_and_backend_initialization(self) -> None:
        search = LDAPSearchUnion(
            LDAPSearch("ou=one,dc=example", ldap.SCOPE_SUBTREE),
            LDAPSearch("ou=two,dc=example", ldap.SCOPE_SUBTREE),
        )
        for name in ("AUTH_LDAP_USER_SEARCH", "AUTH_LDAP_GROUP_SEARCH"):
            with self.subTest(setting=name), override_settings(
                **{name: search}, AUTH_LDAP_GROUP_TYPE=NestedGroupOfNamesType(),
                AUTH_LDAP_DENY_GROUP="cn=denied,ou=one,dc=example",
            ), patch("ldap.initialize") as initialize:
                with self.assertRaisesRegex(ImproperlyConfigured, name):
                    validate_oidc_settings()
                with self.assertRaisesRegex(ImproperlyConfigured, name):
                    DirectoryLDAPBackend()
                initialize.assert_not_called()
                # Legacy LDAP configurations are unaffected when OIDC is off.
                with override_settings(MREG_OIDC_ENABLED=False):
                    validate_oidc_settings()


@override_settings(
    **OIDC_SETTINGS,
    AUTH_LDAP_SERVER_URI="ldap://directory.example",
    AUTH_LDAP_USER_DN_TEMPLATE="uid=%(user)s,ou=users,dc=example",
    AUTH_LDAP_BIND_DN="cn=reader,dc=example", AUTH_LDAP_BIND_PASSWORD="reader-password",
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch("ou=groups,dc=example", ldap.SCOPE_SUBTREE),
    AUTH_LDAP_GROUP_TYPE=GroupOfNamesType(),
    LDAP_GROUP_ATTR="memberOf", LDAP_GROUP_RE=r"^cn=(?P<group_name>[^,]+),",
)
class OIDCIntegrationTests(SignedTokenMixin, APITestCase):
    def setUp(self) -> None:
        super().setUp()
        # The error formatter emits got_request_exception even for expected 503 responses.
        self.client.raise_request_exception = False
        self.enterContext(patch.object(APIView, "authentication_classes", (ExpiringTokenAuthentication, KeycloakBearerAuthentication)))
        self.connection = Mock()
        self.initialize = self.enterContext(patch("ldap.initialize", return_value=self.connection))
        self.groups = ["dns-users"]
        self.connection.search_s.side_effect = lambda base, *args: [
            (base, {"uid": [b"jsmith"], "memberOf": [f"cn={group},ou=groups,dc=example".encode() for group in self.groups]})
        ]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token()}")

    def test_new_user_directory_groups_and_no_local_token(self) -> None:
        response = self.client.get("/api/meta/user")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["username"], "jsmith")
        self.assertEqual(response.data["groups"], ["dns-users"])
        self.assertIsNone(response.data["token"])
        self.assertFalse(ExpiringToken.objects.exists())
        self.assertFalse(User.objects.get(username="jsmith").has_usable_password())
        self.connection.simple_bind_s.assert_called_once_with("cn=reader,dc=example", "reader-password")
        self.connection.start_tls_s.assert_called_once()

    def test_existing_user_and_groups_refresh_on_every_request(self) -> None:
        user = User.objects.create_user("jsmith")
        user.groups.add(Group.objects.create(name="stale-admins"))
        response = self.client.get("/api/meta/user")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.get(username="jsmith").pk, user.pk)
        self.groups = []
        response = self.client.get("/api/meta/user")
        self.assertEqual(response.data["groups"], [])
        self.assertEqual(self.connection.search_s.call_count, 2)
        self.assertEqual(self.http.call_count, 1)

    @override_settings(MREG_LDAP_REFRESH_SECONDS=300, MREG_LDAP_GRACE_SECONDS=60, MREG_LDAP_RETRY_SECONDS=30)
    def test_new_tokens_do_not_extend_directory_grace_or_skip_signature_checks(self) -> None:
        now = timezone.now()
        with patch("mreg.directory.timezone.now", return_value=now) as clock:
            self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
            self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token(key=self.other_key)}")
            self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
            self.initialize.assert_called_once()
            self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token(jti='new-token')}")
            self.connection.search_s.side_effect = ldap.SERVER_DOWN()
            clock.return_value = now + timedelta(seconds=300)
            self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
            self.assertEqual(LDAPUserState.objects.get(username="jsmith").last_success_at, now)
            clock.return_value = now + timedelta(seconds=360)
            response = self.client.get("/api/meta/user")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response["Retry-After"], "30")

    def test_configured_username_claims(self) -> None:
        for name in ("username", "preferred_username"):
            with self.subTest(claim=name), override_settings(MREG_OIDC_USERNAME_CLAIM=name):
                self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token(**{name: 'jsmith', 'ldap_username': 'wrong'})}")
                self.assertEqual(self.client.get("/api/meta/user").data["username"], "jsmith")
        self.assertEqual(User.objects.count(), 1)

    def test_missing_invalid_or_fallback_username_rejected(self) -> None:
        for value in (None, "", ["jsmith"], " jsmith", "jsmith\n", "admin,dc=example", "x" * 151):
            with self.subTest(value=value):
                self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token(ldap_username=value, preferred_username='jsmith')}")
                self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        self.initialize.assert_not_called()
        self.assertFalse(User.objects.exists())

    def test_forgery_is_401_with_bearer_challenge_and_no_directory_access(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token(key=self.other_key)}")
        response = self.client.get("/api/token-is-valid/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], "Bearer")
        self.initialize.assert_not_called()
        self.assertFalse(User.objects.exists())

    def test_directory_failure_does_not_fall_back_to_existing_user(self) -> None:
        user = User.objects.create_user("jsmith")
        user.groups.add(Group.objects.create(name="stale-admins"))
        for result, status in (([], 401), (ldap.SERVER_DOWN("unavailable"), 503)):
            with self.subTest(result=result):
                self.connection.search_s.side_effect = result if isinstance(result, Exception) else lambda *a: result
                self.assertEqual(self.client.get("/api/meta/user").status_code, status)
                self.assertEqual(list(user.groups.values_list("name", flat=True)), ["stale-admins"])

    def test_inactive_local_user_cannot_be_reactivated_by_population(self) -> None:
        user = User.objects.create_user("jsmith", is_active=False)
        with override_settings(AUTH_LDAP_USER_FLAGS_BY_GROUP={"is_active": "cn=enabled,ou=groups,dc=example"}):
            self.connection.compare_s.return_value = True
            self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_directory_disabled_user_rolls_back_population(self) -> None:
        with override_settings(AUTH_LDAP_USER_FLAGS_BY_GROUP={"is_active": "cn=enabled,ou=groups,dc=example"}):
            self.connection.compare_s.return_value = False
            self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        self.assertFalse(User.objects.exists())
        self.assertFalse(Group.objects.filter(name="dns-users").exists())

    def test_required_and_denied_groups(self) -> None:
        group = "cn=enabled,ou=groups,dc=example"
        for name, value, membership, expected in (
            ("AUTH_LDAP_REQUIRE_GROUP", group, False, 401),
            ("AUTH_LDAP_REQUIRE_GROUP", LDAPGroupQuery(group), True, 200),
            ("AUTH_LDAP_DENY_GROUP", group, True, 401),
            ("AUTH_LDAP_DENY_GROUP", group, False, 200),
        ):
            with self.subTest(setting=name, membership=membership), override_settings(**{name: value}):
                self.connection.compare_s.return_value = membership
                self.assertEqual(self.client.get("/api/token-is-valid/").status_code, expected)

    @override_settings(AUTH_LDAP_DENY_GROUP="cn=denied,ou=groups,dc=example")
    def test_group_lookup_failure_is_not_treated_as_absence(self) -> None:
        self.connection.compare_s.side_effect = ldap.SERVER_DOWN("unavailable")
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 503)
        self.assertFalse(User.objects.exists())

    @override_settings(
        AUTH_LDAP_DENY_GROUP="cn=denied,ou=groups,dc=example",
        AUTH_LDAP_GROUP_TYPE=NestedGroupOfNamesType(),
    )
    def test_nested_group_search_failure_rejects_authentication(self) -> None:
        user = User.objects.create_user("jsmith")
        user.groups.add(Group.objects.create(name="existing-membership"))

        def search(base: str, *args: object) -> list[tuple[str, dict[str, list[bytes]]]]:
            if base == "ou=groups,dc=example":
                raise ldap.SERVER_DOWN("group search failed")
            return [(base, {"uid": [b"jsmith"], "memberOf": []})]

        self.connection.search_s.side_effect = search
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 503)
        self.assertEqual(list(user.groups.values_list("name", flat=True)), ["existing-membership"])

    @override_settings(AUTH_LDAP_NO_NEW_USERS=True)
    def test_no_new_users_restriction(self) -> None:
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 401)
        self.assertFalse(User.objects.exists())
        user = User.objects.create_user("jsmith")
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 200)
        self.assertEqual(User.objects.get(username="jsmith").pk, user.pk)

    def test_ambiguous_local_identity_is_rejected(self) -> None:
        User.objects.create_user("jsmith")
        User.objects.create_user("JSmith")
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 401)

    def test_failure_after_group_signal_rolls_back(self) -> None:
        def fail(sender: object, **kwargs: object) -> Never:
            raise ldap.SERVER_DOWN("failed during population")
        populate_user.connect(fail, sender=DirectoryLDAPBackend)
        self.addCleanup(populate_user.disconnect, fail, sender=DirectoryLDAPBackend)
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 503)
        self.assertFalse(User.objects.exists())
        self.assertFalse(Group.objects.filter(name="dns-users").exists())

    def test_network_admin_permissions_use_ldap_groups(self) -> None:
        Network.objects.create(network="192.0.2.0/24")
        NetGroupRegexPermission.objects.create(group="dns-users", range="192.0.2.0/24", regex=r".*")
        response = self.client.patch("/api/v1/networks/192.0.2.0/24", {"description": "updated"}, format="json")
        # Ordinary DNS permission must not grant network administration.
        self.assertEqual(response.status_code, 403, response.data)
        self.groups = [settings.NETWORK_ADMIN_GROUP]
        response = self.client.patch("/api/v1/networks/192.0.2.0/24", {"description": "updated"}, format="json")
        self.assertEqual(response.status_code, 204, response.data)
        self.groups = []
        self.assertEqual(self.client.patch("/api/v1/networks/192.0.2.0/24", {"description": "denied"}, format="json").status_code, 403)

    def test_host_object_permissions_and_audit_use_ldap_user(self) -> None:
        Network.objects.create(network="192.0.2.0/24")
        NetGroupRegexPermission.objects.create(group="dns-users", range="192.0.2.0/24", regex=r"^allowed\.example\.org$")
        allowed = Host.objects.create(name="allowed.example.org")
        denied = Host.objects.create(name="denied.example.org")
        Ipaddress.objects.create(host=allowed, ipaddress="192.0.2.10")
        Ipaddress.objects.create(host=denied, ipaddress="192.0.2.11")
        response = self.client.patch(f"/api/v1/hosts/{allowed.name}", {"comment": "updated"}, format="json")
        self.assertEqual(response.status_code, 204, response.data)
        self.assertTrue(History.objects.filter(user="jsmith", action="update", name=allowed.name).exists())
        response = self.client.patch(f"/api/v1/hosts/{denied.name}", {"comment": "denied"}, format="json")
        self.assertEqual(response.status_code, 403)
        self.groups = []
        response = self.client.patch(f"/api/v1/hosts/{allowed.name}", {"comment": "denied"}, format="json")
        self.assertEqual(response.status_code, 403)

    @override_settings(
        AUTH_LDAP_USER_DN_TEMPLATE=None,
        AUTH_LDAP_USER_SEARCH=LDAPSearch("ou=users,dc=example", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"),
    )
    def test_ambiguous_directory_search_is_rejected(self) -> None:
        self.connection.search_s.side_effect = None
        self.connection.search_s.return_value = [
            ("uid=jsmith,ou=one,dc=example", {"uid": [b"jsmith"]}),
            ("uid=jsmith,ou=two,dc=example", {"uid": [b"jsmith"]}),
        ]
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 401)
        self.assertFalse(User.objects.exists())

    def test_hostpolicy_permissions_refresh(self) -> None:
        self.groups = [settings.HOSTPOLICYADMIN_GROUP]
        response = self.client.post("/api/v1/hostpolicy/atoms/", {"name": "allowed", "description": "test"}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(History.objects.filter(user="jsmith", action="create").exists())
        self.groups = []
        response = self.client.post("/api/v1/hostpolicy/atoms/", {"name": "denied", "description": "test"}, format="json")
        self.assertEqual(response.status_code, 403)

    def test_local_tokens_coexist_and_logout_keeps_user(self) -> None:
        user = User.objects.create_user("jsmith", password="local-test-password")
        token = ExpiringToken.objects.create(user=user)
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 200)
        response = self.client.post("/api/token-logout/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], "Token")
        self.assertTrue(ExpiringToken.objects.filter(pk=token.pk).exists())
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(self.client.post("/api/token-logout/").status_code, 200)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertFalse(ExpiringToken.objects.exists())
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 401)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token()}")
        self.assertEqual(self.client.get("/api/token-is-valid/").status_code, 200)

    def test_raw_ldap_exception_rejected(self) -> None:
        with patch.object(DirectoryLDAPBackend, "populate_user", side_effect=ldap.SERVER_DOWN()):
            with self.assertRaises(DirectoryUnavailable):
                resolve_ldap_user(self.claims())


@override_settings(
    **OIDC_SETTINGS,
    AUTH_LDAP_SERVER_URI="ldap://directory.example",
    AUTH_LDAP_USER_DN_TEMPLATE="uid=%(user)s,ou=users,dc=example",
    LDAP_GROUP_ATTR="memberOf", LDAP_GROUP_RE=r"^cn=(?P<group_name>[^,]+),",
)
@skipUnlessDBFeature("has_select_for_update")
class OIDCProvisioningConcurrencyTests(TransactionTestCase):
    def provision_concurrently(self) -> list[tuple[int, bool, list[str]] | AuthenticationFailed]:
        requests_ready = Barrier(2, timeout=20)

        def directory_connection(*args: object, **kwargs: object) -> Mock:
            connection = Mock()
            connection.search_s.side_effect = lambda base, *a: [
                (base, {"uid": [b"jsmith"], "memberOf": [b"cn=dns-users,ou=groups,dc=example"]}),
            ]
            return connection

        def provision(username: str) -> tuple[int, bool, list[str]] | AuthenticationFailed:
            try:
                requests_ready.wait()
                user = resolve_ldap_user({"ldap_username": username})
                return user.pk, user.has_usable_password(), user.group_list
            except AuthenticationFailed as exc:
                return exc
            finally:
                # Django maintains a separate database connection per thread.
                connections.close_all()

        with patch("ldap.initialize", side_effect=directory_connection), ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(provision, name) for name in ("jsmith", "JSmith")]
            return [future.result(timeout=40) for future in futures]

    def test_concurrent_first_requests_provision_one_user(self) -> None:
        results = self.provision_concurrently()
        user = User.objects.get(username="jsmith")
        self.assertEqual(results, [(user.pk, False, ["dns-users"])] * 2)
        self.assertEqual(User.objects.count(), 1)
        self.assertFalse(ExpiringToken.objects.exists())

    @override_settings(AUTH_LDAP_NO_NEW_USERS=True)
    def test_concurrent_requests_respect_no_new_users(self) -> None:
        results = self.provision_concurrently()
        self.assertTrue(all(isinstance(result, AuthenticationFailed) for result in results))
        self.assertFalse(User.objects.exists())
        self.assertFalse(Group.objects.filter(name="dns-users").exists())
