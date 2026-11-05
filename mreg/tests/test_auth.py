from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone
from rest_framework.exceptions import NotAuthenticated

from mreg.authentication import ExpiringTokenAuthentication
from mreg.models.auth import LDAPUserState, User
from mreg.models.base import ExpiringToken


class UserFromRequestTests(TestCase):
    def test_from_request_unauthenticated_raises(self):
        factory = RequestFactory()
        request = factory.get("/api/v1/hosts/")
        request.user = AnonymousUser()

        with self.assertRaises(NotAuthenticated):
            User.from_request(request)


class TokenAuthenticationQueryTests(TestCase):
    def test_local_accounts_need_only_token_lookup_and_usage_update(self) -> None:
        user = User.objects.create_user("local-user")
        token = ExpiringToken.objects.create(user=user)
        for refresh_enabled in (False, True):
            with self.subTest(refresh_enabled=refresh_enabled), override_settings(MREG_LDAP_REFRESH_LOCAL_TOKENS=refresh_enabled):
                with self.assertNumQueries(2):
                    authenticated, _ = ExpiringTokenAuthentication().authenticate_credentials(token.key)
                self.assertEqual(authenticated.pk, user.pk)
        self.assertFalse(LDAPUserState.objects.exists())

    @override_settings(MREG_LDAP_REFRESH_LOCAL_TOKENS=False)
    def test_directory_accounts_add_only_the_activity_update(self) -> None:
        user = User.objects.create_user("directory-user")
        old = timezone.now() - timedelta(days=1)
        state = LDAPUserState.objects.create(username=user.username, user=user, last_activity_at=old)
        token = ExpiringToken.objects.create(user=user)

        with self.assertNumQueries(3):
            authenticated, _ = ExpiringTokenAuthentication().authenticate_credentials(token.key)
        self.assertEqual(authenticated.pk, user.pk)
        state.refresh_from_db()
        self.assertGreater(state.last_activity_at, old)
