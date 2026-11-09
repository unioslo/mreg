"""Retention applies to inactive directory users, preserving local accounts and history."""

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.core.management import call_command, CommandError
from django.test import TestCase
from django.utils import timezone
from rest_framework.authtoken.models import Token

from mreg.models.auth import LDAPUserState, User
from mreg.models.base import ExpiringToken, History


class PurgeOldUsersTests(TestCase):
    def setUp(self) -> None:
        self.now = timezone.now()
        self.old = self.now - timedelta(days=91)
        self.cutoff = self.now - timedelta(days=90)
        self.enterContext(patch("django.utils.timezone.now", return_value=self.now))

    def directory_user(self, username: str = "old-user", **kwargs: Any) -> User:
        user = User.objects.create_user(username, date_joined=self.old, **kwargs)
        LDAPUserState.objects.create(
            username=username, user=user, last_success_at=self.old,
            last_activity_at=self.old, eligible=True,
        )
        return user

    def run_command(self, **kwargs: Any) -> str:
        output = StringIO()
        call_command("purge_old_users", days=90, stdout=output, **kwargs)
        return output.getvalue()

    def test_preview_is_default_and_does_not_delete(self) -> None:
        user = self.directory_user()
        output = self.run_command()
        self.assertIn("Would delete old-user.", output)
        self.assertIn("Dry run", output)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertTrue(LDAPUserState.objects.filter(user=user).exists())

    def test_execute_cascades_tokens_and_memberships_but_preserves_history_and_groups(self) -> None:
        user = self.directory_user()
        token = ExpiringToken.objects.create(user=user)
        ExpiringToken.objects.filter(pk=token.pk).update(last_used=self.old)
        group = Group.objects.create(name="dns-users")
        user.groups.add(group)
        history = History.objects.create(
            user=user.username, resource="Host", name="example.org", model_id=1,
            model="Host", action="update", data={},
        )

        self.assertIn("Deleted 1 user(s).", self.run_command(execute=True))
        self.assertFalse(User.objects.filter(pk=user.pk).exists())
        self.assertFalse(LDAPUserState.objects.filter(user_id=user.pk).exists())
        self.assertFalse(ExpiringToken.objects.filter(pk=token.pk).exists())
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())
        self.assertTrue(Group.objects.filter(pk=group.pk).exists())
        self.assertEqual(History.objects.get(pk=history.pk).user, "old-user")

    def test_local_disabled_and_unenrolled_users_are_preserved(self) -> None:
        local = User.objects.create_user("local-admin", password="password", date_joined=self.old)
        legacy = User.objects.create_user("unenrolled", date_joined=self.old)
        disabled = self.directory_user("disabled", is_active=False)
        LDAPUserState.objects.create(username="unenrolled", last_activity_at=self.old, last_error="denied")
        self.directory_user("eligible-for-purge")

        self.run_command(execute=True)
        self.assertSetEqual(set(User.objects.values_list("pk", flat=True)), {local.pk, legacy.pk, disabled.pk})
        self.assertTrue(LDAPUserState.objects.filter(username="unenrolled").exists())

    def test_recent_activity_login_creation_or_token_use_prevents_deletion(self) -> None:
        for signal in ("activity", "login", "creation", "token"):
            for timestamp in (self.cutoff, self.now):
                with self.subTest(signal=signal, timestamp=timestamp):
                    user = self.directory_user(f"{signal}-{timestamp.date()}")
                    if signal == "activity":
                        LDAPUserState.objects.filter(user=user).update(last_activity_at=timestamp)
                    elif signal == "login":
                        User.objects.filter(pk=user.pk).update(last_login=timestamp)
                    elif signal == "creation":
                        User.objects.filter(pk=user.pk).update(date_joined=timestamp)
                    else:
                        token = ExpiringToken.objects.create(user=user)
                        ExpiringToken.objects.filter(pk=token.pk).update(last_used=timestamp)
                    self.assertIn("Deleted 0 user(s).", self.run_command(execute=True))
                    self.assertTrue(User.objects.filter(pk=user.pk).exists())

    def test_newly_enrolled_accounts_get_a_full_retention_window(self) -> None:
        user = User.objects.create_user("newly-enrolled", date_joined=self.old)
        LDAPUserState.objects.create(username=user.username, user=user, last_success_at=self.now, eligible=True)
        self.assertIn("Deleted 0 user(s).", self.run_command(execute=True))
        self.assertTrue(User.objects.filter(pk=user.pk).exists())

    def test_activity_is_rechecked_after_candidate_selection(self) -> None:
        user = self.directory_user()
        output = StringIO()
        original_write = output.write

        def become_active(message: str) -> int:
            LDAPUserState.record_activity(user.pk)
            return original_write(message)

        with patch.object(output, "write", side_effect=become_active):
            call_command("purge_old_users", days=90, execute=True, stdout=output)
        self.assertIn("Deleted 0 user(s).", output.getvalue())
        self.assertTrue(User.objects.filter(pk=user.pk).exists())

    def test_retention_days_must_be_explicit_and_positive(self) -> None:
        for days in (0, -1, 10**20):
            with self.subTest(days=days), self.assertRaises(CommandError):
                call_command("purge_old_users", days=days, stdout=StringIO())
        with self.assertRaises(CommandError):
            call_command("purge_old_users", stdout=StringIO())
