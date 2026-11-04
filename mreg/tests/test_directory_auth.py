"""Shared refresh behavior for password logins and existing local API tokens."""

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

import ldap
from django.contrib.auth import authenticate
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command, CommandError
from django.test import override_settings
from django_auth_ldap.config import LDAPSearch
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APITestCase
from rest_framework.views import APIView

from mreg.authentication import ExpiringTokenAuthentication, KeycloakBearerAuthentication
from mreg.directory import DirectoryUnavailable, refresh_directory_user
from mreg.directory_auth import validate_local_directory_settings
from mreg.models.auth import LDAPUserState, User
from mreg.models.base import ExpiringToken
from mreg.tests.test_directory import DIRECTORY_SETTINGS, DirectoryFixture
from mreg.tests.test_oidc import OIDC_SETTINGS, SignedTokenMixin


BACKENDS = ("mreg.directory_auth.LocalUserBackend", "mreg.directory_auth.LDAPPasswordBackend")


@override_settings(**{
    **OIDC_SETTINGS, **DIRECTORY_SETTINGS,
    "MREG_LDAP_REFRESH_LOCAL_TOKENS": True, "AUTHENTICATION_BACKENDS": BACKENDS,
})
class DirectoryAuthenticationTests(SignedTokenMixin, DirectoryFixture, APITestCase):
    def setUp(self):
        super().setUp()
        self.client.raise_request_exception = False
        self.enterContext(patch.object(APIView, "authentication_classes", (ExpiringTokenAuthentication, KeycloakBearerAuthentication)))
        self.connection.simple_bind_s.side_effect = self.bind

    def bind(self, dn, password):
        if dn.startswith("uid=") and password != "correct-password":
            raise ldap.INVALID_CREDENTIALS()

    def login(self):
        self.client.credentials()
        response = self.client.post("/api/token-auth/", {"username": "jsmith", "password": "correct-password"})
        self.assertEqual(response.status_code, 200, response.data)
        token = ExpiringToken.objects.get(key=response.data["token"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return token

    def test_password_login_records_complete_refresh_and_token_reuses_it(self):
        token = self.login()
        user = User.objects.get(pk=token.user_id)
        self.assertFalse(user.has_usable_password())
        self.assertEqual((user.first_name, user.group_list), ("Original", ["dns-users"]))
        self.assertEqual(self.state().last_success_at, self.now)
        calls = self.initialize.call_count
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        self.assertEqual(self.initialize.call_count, calls)

    def test_password_login_forces_refresh_even_with_fresh_information(self):
        original_token = self.login()
        self.advance(1)
        self.groups = ["new-group"]
        self.first_name = "Updated"
        token = self.login()
        self.assertEqual(token.key, original_token.key)
        self.assertEqual(token.user.first_name, "Updated")
        self.assertEqual(token.user.group_list, ["new-group"])
        self.assertEqual(self.state().last_success_at, self.now)

    def test_local_token_refreshes_groups_when_due(self):
        self.login()
        self.groups = []
        self.advance(299)
        self.assertEqual(self.client.get("/api/meta/user").data["groups"], ["dns-users"])
        self.advance(1)
        self.assertEqual(self.client.get("/api/meta/user").data["groups"], [])
        self.assertEqual(self.state().last_success_at, self.now)

    def test_oidc_and_local_token_requests_share_the_same_clock(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token()}")
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        token = ExpiringToken.objects.create(user=User.objects.get(username="jsmith"))
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        self.initialize.assert_called_once()
        self.advance(300)
        self.groups = ["from-token-refresh"]
        self.assertEqual(self.client.get("/api/meta/user").data["groups"], ["from-token-refresh"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token()}")
        self.assertEqual(self.client.get("/api/meta/user").data["groups"], ["from-token-refresh"])
        self.assertEqual(self.initialize.call_count, 2)

    def test_local_token_grace_expires_without_extending_token_usage_on_failure(self):
        token = self.login()
        initial_refresh = self.state().last_success_at
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        token.refresh_from_db()
        last_used = token.last_used
        self.advance(3600)
        response = self.client.get("/api/meta/user")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "30")
        token.refresh_from_db()
        self.assertEqual(token.last_used, last_used)
        self.assertEqual(self.state().last_success_at, initial_refresh)

    def test_expired_or_revoked_token_cannot_use_directory_grace(self):
        token = self.login()
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        self.initialize.reset_mock()
        ExpiringToken.objects.filter(pk=token.pk).update(last_used=self.now - timedelta(hours=9))
        self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        token.delete()
        self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        self.initialize.assert_not_called()

    def test_logout_during_refresh_cannot_resurrect_token(self):
        token = self.login()
        key = token.key
        self.advance(300)

        def logout_during_search(base, *args):
            ExpiringToken.objects.filter(pk=key).delete()
            return self.search(base, *args)

        self.connection.search_s.side_effect = logout_during_search
        self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        self.assertFalse(ExpiringToken.objects.filter(pk=key).exists())

    def test_logout_does_not_require_directory_eligibility_or_availability(self):
        self.login()
        self.advance(4000)
        LDAPUserState.objects.update(eligible=False, last_error="denied")
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        self.initialize.reset_mock()
        self.assertEqual(self.client.post("/api/token-logout/").status_code, 200)
        self.assertFalse(ExpiringToken.objects.exists())
        self.assertTrue(User.objects.filter(username="jsmith").exists())
        self.initialize.assert_not_called()

    def test_known_denial_applies_to_local_tokens_and_later_outages(self):
        self.login()
        self.advance(300)
        self.connection.search_s.side_effect = lambda *a: []
        self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
        self.assertFalse(self.state().eligible)
        self.advance(30)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        self.assertEqual(self.client.get("/api/meta/user").status_code, 503)

    def test_local_account_works_without_ldap(self):
        User.objects.create_user("local-admin", password="local-password")
        self.connection.simple_bind_s.side_effect = ldap.SERVER_DOWN()
        response = self.client.post("/api/token-auth/", {"username": "local-admin", "password": "local-password"})
        self.assertEqual(response.status_code, 200, response.data)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {response.data['token']}")
        self.advance(4000)
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        self.initialize.assert_not_called()
        self.assertFalse(LDAPUserState.objects.exists())

    def test_directory_account_cannot_fall_back_to_a_local_password(self):
        token = self.login()
        user = token.user
        user.set_password("local-password")
        user.save()
        self.assertIsNone(authenticate(username="jsmith", password="local-password"))
        self.connection.simple_bind_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaises(DirectoryUnavailable):
            authenticate(username="jsmith", password="local-password")

    def test_wrong_password_does_not_refresh_or_invalidate_directory_state(self):
        self.login()
        refreshed_at = self.state().last_success_at
        self.advance(300)
        self.assertIsNone(authenticate(username="jsmith", password="wrong-password"))
        self.assertEqual(self.state().last_success_at, refreshed_at)
        self.assertTrue(self.state().eligible)

    def test_password_login_requires_a_live_successful_bind_even_during_grace(self):
        self.login()
        refreshed_at = self.state().last_success_at
        self.connection.simple_bind_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaises(DirectoryUnavailable):
            authenticate(username="jsmith", password="correct-password")
        self.assertEqual(self.state().last_success_at, refreshed_at)

    def test_grace_can_cover_population_failure_after_successful_password_bind(self):
        self.login()
        refreshed_at = self.state().last_success_at
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        user = authenticate(username="jsmith", password="correct-password")
        self.assertEqual(user.group_list, ["dns-users"])
        self.assertEqual(self.state().last_success_at, refreshed_at)

    def test_bad_password_does_not_provision_an_account(self):
        self.assertIsNone(authenticate(username="jsmith", password="wrong-password"))
        self.assertFalse(User.objects.exists())
        self.assertFalse(LDAPUserState.objects.exists())

    def test_empty_password_is_never_accepted(self):
        with override_settings(AUTH_LDAP_PERMIT_EMPTY_PASSWORD=True):
            self.assertIsNone(authenticate(username="jsmith", password=""))
        self.initialize.assert_not_called()

    @override_settings(AUTH_LDAP_NO_NEW_USERS=True)
    def test_password_login_respects_no_new_users(self):
        with self.assertRaises(AuthenticationFailed):
            authenticate(username="jsmith", password="correct-password")
        self.assertFalse(User.objects.exists())

    def test_password_login_for_missing_search_dn_invalidates_old_eligibility(self):
        self.login()
        with override_settings(
            AUTH_LDAP_USER_DN_TEMPLATE=None,
            AUTH_LDAP_USER_SEARCH=LDAPSearch("ou=users,dc=example", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"),
        ):
            self.connection.search_s.side_effect = lambda *a: []
            with self.assertRaises(AuthenticationFailed):
                authenticate(username="jsmith", password="correct-password")
        self.assertFalse(self.state().eligible)

    @override_settings(MREG_LDAP_REFRESH_LOCAL_TOKENS=False)
    def test_disabled_switch_preserves_existing_local_token_behavior(self):
        user = refresh_directory_user("jsmith")
        token = ExpiringToken.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.advance(4000)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        self.assertEqual(self.client.get("/api/meta/user").status_code, 200)
        self.initialize.assert_called_once()

    @override_settings(MREG_OIDC_ENABLED=False)
    def test_local_token_refresh_does_not_require_oidc(self):
        self.login()
        self.advance(300)
        self.groups = []
        self.assertEqual(self.client.get("/api/meta/user").data["groups"], [])

    def test_enrollment_command_verifies_only_named_existing_users(self):
        User.objects.create_user("jsmith")
        local = User.objects.create_user("local-admin", password="local-password")
        output = StringIO()
        call_command("refresh_ldap_users", "jsmith", stdout=output)
        self.assertIn("Refreshed directory user jsmith", output.getvalue())
        self.assertTrue(self.state().eligible)
        self.assertFalse(LDAPUserState.objects.filter(user=local).exists())
        with self.assertRaises(CommandError):
            call_command("refresh_ldap_users", "unknown-user", stdout=StringIO())
        self.assertEqual(User.objects.count(), 2)

    def test_enrollment_command_does_not_report_grace_as_a_fresh_refresh(self):
        self.login()
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaisesRegex(CommandError, "grace is not enrollment"):
            call_command("refresh_ldap_users", "jsmith", stdout=StringIO())

    def test_local_backend_settings_are_validated(self):
        validate_local_directory_settings()
        with override_settings(AUTHENTICATION_BACKENDS=("django.contrib.auth.backends.ModelBackend",)):
            with self.assertRaises(ImproperlyConfigured):
                validate_local_directory_settings()
            with override_settings(MREG_LDAP_REFRESH_LOCAL_TOKENS=False):
                validate_local_directory_settings()

    def test_local_token_cannot_switch_to_a_different_directory_user(self):
        self.login()
        other = User.objects.create_user("other-user")
        with patch("mreg.directory.refresh_directory_user", return_value=other):
            self.assertEqual(self.client.get("/api/meta/user").status_code, 401)
