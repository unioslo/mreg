"""Directory freshness, outage grace, and shared database coordination."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import Barrier
from unittest.mock import Mock, patch

import ldap
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connections
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django_auth_ldap.backend import populate_user
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch
from rest_framework.exceptions import AuthenticationFailed

from mreg.directory import DirectoryFailure, DirectoryLDAPBackend, DirectoryUnavailable, refresh_directory_user, validate_directory_settings
from mreg.models.auth import LDAPUserState, User


DIRECTORY_SETTINGS = {
    "MREG_LDAP_REFRESH_SECONDS": 300,
    "MREG_LDAP_GRACE_SECONDS": 3600,
    "MREG_LDAP_RETRY_SECONDS": 30,
    "MREG_LDAP_TIMEOUT_SECONDS": 5,
    "AUTH_LDAP_SERVER_URI": "ldap://directory.example",
    "AUTH_LDAP_USER_DN_TEMPLATE": "uid=%(user)s,ou=users,dc=example",
    "AUTH_LDAP_USER_ATTR_MAP": {"first_name": "givenName", "email": "mail"},
    "AUTH_LDAP_GROUP_SEARCH": LDAPSearch("ou=groups,dc=example", ldap.SCOPE_SUBTREE),
    "AUTH_LDAP_GROUP_TYPE": GroupOfNamesType(),
    "LDAP_GROUP_ATTR": "memberOf",
    "LDAP_GROUP_RE": r"^cn=(?P<group_name>[^,]+),",
}


class DirectoryFixture:
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 1, 1, tzinfo=dt_timezone.utc)
        self.clock = self.enterContext(patch("mreg.directory.timezone.now", return_value=self.now))
        self.groups = ["dns-users"]
        self.first_name = "Original"
        self.email = "original@example.org"
        self.connection = Mock()
        self.connection.search_s.side_effect = self.search
        self.initialize = self.enterContext(patch("ldap.initialize", return_value=self.connection))

    def search(self, base, *args):
        return [(base, {
            "uid": [b"jsmith"], "givenName": [self.first_name.encode()], "mail": [self.email.encode()],
            "memberOf": [f"cn={name},ou=groups,dc=example".encode() for name in self.groups],
        })]

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.clock.return_value = self.now

    def state(self):
        return LDAPUserState.objects.get(username="jsmith")


@override_settings(**DIRECTORY_SETTINGS)
class DirectoryRefreshTests(DirectoryFixture, TestCase):
    def test_fresh_user_and_attributes_refresh_only_when_due(self):
        first = refresh_directory_user("JSmith")
        self.groups = ["new-group"]
        self.first_name, self.email = "Changed", "changed@example.org"
        self.advance(299)
        cached = refresh_directory_user("jsmith")
        self.assertEqual((cached.pk, cached.first_name, cached.group_list), (first.pk, "Original", ["dns-users"]))
        self.initialize.assert_called_once()
        self.advance(1)
        updated = refresh_directory_user("jsmith")
        self.assertEqual((updated.pk, updated.first_name, updated.email), (first.pk, "Changed", "changed@example.org"))
        self.assertEqual(updated.group_list, ["new-group"])
        self.assertEqual(self.initialize.call_count, 2)
        self.assertEqual(self.state().last_success_at, self.now)

    def test_anonymous_bind_and_network_and_operation_timeouts(self):
        refresh_directory_user("jsmith")
        self.connection.simple_bind_s.assert_called_once_with("", "")
        self.assertEqual(self.connection.timeout, 5)
        self.connection.set_option.assert_any_call(ldap.OPT_NETWORK_TIMEOUT, 5)
        self.connection.set_option.assert_any_call(ldap.OPT_TIMEOUT, 5)

    def test_transient_failures_retain_information_and_retry_after_cooldown(self):
        original = refresh_directory_user("jsmith")
        refreshed_at = self.state().last_success_at
        self.advance(300)
        for error in (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.UNAVAILABLE, ldap.BUSY):
            with self.subTest(error=error):
                self.connection.search_s.side_effect = error()
                user = refresh_directory_user("jsmith")
                self.assertEqual((user.pk, user.first_name, user.group_list), (original.pk, "Original", ["dns-users"]))
                calls = self.initialize.call_count
                self.advance(29)
                refresh_directory_user("jsmith")
                self.assertEqual(self.initialize.call_count, calls)
                self.assertEqual(self.state().last_success_at, refreshed_at)
                self.advance(1)
        self.assertEqual(self.state().last_error, "unavailable")

    def test_grace_deadline_is_absolute_and_survives_new_backend_instances(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        refresh_directory_user("jsmith")
        self.advance(3599)
        refresh_directory_user("jsmith")
        calls = self.initialize.call_count
        self.advance(1)
        with self.assertRaises(DirectoryUnavailable):
            refresh_directory_user("jsmith")
        self.assertEqual(self.initialize.call_count, calls)  # Grace expired even during retry backoff.
        self.assertEqual(User.objects.get(username="jsmith").group_list, ["dns-users"])

    def test_first_failure_after_long_inactivity_does_not_start_new_grace(self):
        refresh_directory_user("jsmith")
        self.advance(3900)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaises(DirectoryUnavailable):
            refresh_directory_user("jsmith")

    @override_settings(MREG_LDAP_GRACE_SECONDS=0)
    def test_grace_can_be_disabled(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.connection.search_s.side_effect = ldap.TIMEOUT()
        with self.assertRaises(DirectoryUnavailable):
            refresh_directory_user("jsmith")

    @override_settings(MREG_LDAP_REFRESH_SECONDS=0)
    def test_zero_refresh_interval_reads_on_every_request(self):
        refresh_directory_user("jsmith")
        self.groups = []
        self.assertEqual(refresh_directory_user("jsmith").group_list, [])
        self.assertEqual(self.initialize.call_count, 2)

    def test_existing_user_without_verified_state_cannot_use_grace(self):
        user = User.objects.create_user("jsmith", first_name="Local")
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        for _ in range(2):
            with self.assertRaises(DirectoryUnavailable):
                refresh_directory_user("jsmith")
        self.initialize.assert_called_once()
        self.assertIsNone(self.state().last_success_at)
        self.assertEqual(User.objects.get(pk=user.pk).first_name, "Local")

    def test_failed_first_population_preserves_only_retry_metadata(self):
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaises(DirectoryUnavailable):
            refresh_directory_user("jsmith")
        self.assertFalse(User.objects.exists())
        self.assertIsNone(self.state().user_id)
        self.assertFalse(self.state().eligible)

    def test_denial_cannot_be_undone_by_an_outage_and_recovery_can_reenable(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.connection.search_s.side_effect = lambda *a: []
        with self.assertRaises(AuthenticationFailed):
            refresh_directory_user("jsmith")
        self.assertFalse(self.state().eligible)
        calls = self.initialize.call_count
        with self.assertRaises(AuthenticationFailed):
            refresh_directory_user("jsmith")
        self.assertEqual(self.initialize.call_count, calls)
        self.advance(30)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        with self.assertRaises(DirectoryUnavailable):
            refresh_directory_user("jsmith")
        self.assertFalse(self.state().eligible)
        self.advance(30)
        self.connection.search_s.side_effect = self.search
        self.groups = ["restored"]
        self.assertEqual(refresh_directory_user("jsmith").group_list, ["restored"])
        self.assertTrue(self.state().eligible)

    def test_authoritative_deny_group_cannot_use_grace(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        with override_settings(AUTH_LDAP_DENY_GROUP="cn=denied,ou=groups,dc=example"):
            self.connection.compare_s.return_value = True
            with self.assertRaises(AuthenticationFailed):
                refresh_directory_user("jsmith")
        self.assertFalse(self.state().eligible)

    def test_directory_inactive_flag_invalidates_grace_without_changing_local_active_flag(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        with override_settings(AUTH_LDAP_USER_FLAGS_BY_GROUP={"is_active": "cn=enabled,ou=groups,dc=example"}):
            self.connection.compare_s.return_value = False
            with self.assertRaises(AuthenticationFailed):
                refresh_directory_user("jsmith")
        self.assertTrue(User.objects.get(username="jsmith").is_active)
        self.assertFalse(self.state().eligible)

    def test_nontransient_errors_never_use_grace(self):
        for error in (ldap.INVALID_CREDENTIALS, ldap.INSUFFICIENT_ACCESS, ldap.FILTER_ERROR):
            with self.subTest(error=error):
                self.connection.search_s.side_effect = self.search
                refresh_directory_user("jsmith")
                self.advance(300)
                self.connection.search_s.side_effect = error()
                with self.assertRaises(DirectoryFailure) as raised:
                    refresh_directory_user("jsmith")
                self.assertNotIsInstance(raised.exception, DirectoryUnavailable)
                self.assertFalse(self.state().eligible)
                with self.assertRaises(DirectoryFailure):
                    refresh_directory_user("jsmith")
                self.advance(30)

    def test_missing_directory_object_is_a_denial(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.connection.search_s.side_effect = ldap.NO_SUCH_OBJECT()
        with self.assertRaises(AuthenticationFailed):
            refresh_directory_user("jsmith")
        self.assertFalse(self.state().eligible)

    def test_failed_population_rolls_back_before_grace_is_used(self):
        refresh_directory_user("jsmith")
        refreshed_at = self.state().last_success_at
        self.advance(300)
        self.groups = ["partial-update"]
        self.first_name = "Partial"

        def fail(sender, **kwargs):
            raise ldap.SERVER_DOWN()

        populate_user.connect(fail, sender=DirectoryLDAPBackend)
        self.addCleanup(populate_user.disconnect, fail, sender=DirectoryLDAPBackend)
        user = refresh_directory_user("jsmith")
        self.assertEqual((user.first_name, user.group_list), ("Original", ["dns-users"]))
        self.assertEqual(self.state().last_success_at, refreshed_at)

    def test_local_disabling_is_immediate_even_with_fresh_information(self):
        user = refresh_directory_user("jsmith")
        User.objects.filter(pk=user.pk).update(is_active=False)
        with self.assertRaises(AuthenticationFailed):
            refresh_directory_user("jsmith")
        self.initialize.assert_called_once()

    def test_new_ambiguous_local_identity_cannot_use_fresh_information(self):
        refresh_directory_user("jsmith")
        User.objects.create_user("JSmith")
        with self.assertRaises(AuthenticationFailed):
            refresh_directory_user("jsmith")
        self.initialize.assert_called_once()

    def test_settings_require_nonnegative_intervals_and_positive_timeouts(self):
        for name in ("REFRESH_SECONDS", "GRACE_SECONDS", "RETRY_SECONDS", "TIMEOUT_SECONDS"):
            for value in (-1, True, "30", None):
                with self.subTest(setting=name, value=value), override_settings(**{f"MREG_LDAP_{name}": value}):
                    with self.assertRaises(ImproperlyConfigured):
                        validate_directory_settings()
        with override_settings(MREG_LDAP_TIMEOUT_SECONDS=0), self.assertRaises(ImproperlyConfigured):
            validate_directory_settings()
        with patch.dict(settings.DATABASES["default"], {"ATOMIC_REQUESTS": True}):
            with self.assertRaisesRegex(ImproperlyConfigured, "ATOMIC_REQUESTS"):
                validate_directory_settings()


@override_settings(**DIRECTORY_SETTINGS)
@skipUnlessDBFeature("has_select_for_update")
class DirectoryConcurrencyTests(DirectoryFixture, TransactionTestCase):
    def simultaneous_requests(self):
        ready = Barrier(2, timeout=20)

        def refresh():
            try:
                ready.wait()
                user = refresh_directory_user("jsmith")
                return user.pk, user.group_list
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(refresh) for _ in range(2)]
            return [future.result(timeout=30) for future in futures]

    def test_concurrent_first_requests_share_one_refresh(self):
        results = self.simultaneous_requests()
        self.assertEqual(results[0], results[1])
        self.assertEqual(User.objects.count(), 1)
        self.initialize.assert_called_once()

    def test_concurrent_expired_requests_share_one_refresh(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.groups = ["changed"]
        results = self.simultaneous_requests()
        self.assertEqual([groups for _, groups in results], [["changed"], ["changed"]])
        self.assertEqual(self.initialize.call_count, 2)

    def test_concurrent_outage_requests_share_failure_backoff(self):
        refresh_directory_user("jsmith")
        self.advance(300)
        self.connection.search_s.side_effect = ldap.SERVER_DOWN()
        results = self.simultaneous_requests()
        self.assertEqual([groups for _, groups in results], [["dns-users"], ["dns-users"]])
        self.assertEqual(self.initialize.call_count, 2)
