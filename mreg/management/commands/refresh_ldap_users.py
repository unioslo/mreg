"""Explicitly verify existing accounts and enroll them in directory refresh."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import APIException

from mreg.directory import directory_username, refresh_directory_user
from mreg.models.auth import LDAPUserState


class Command(BaseCommand):
    help = "Refresh named existing users from LDAP and mark them as directory-managed."

    def add_arguments(self, parser):
        parser.add_argument("usernames", nargs="+", help="Existing LDAP-backed users; exclude local/emergency accounts.")

    def handle(self, *args, **options):
        for name in options["usernames"]:
            try:
                username = directory_username(name)
                get_user_model().objects.get(username__iexact=username)
                user = refresh_directory_user(username, force=True)
                state = LDAPUserState.objects.get(user_id=user.pk)
                if state.last_error:
                    raise CommandError(f"No fresh directory information for {username}; outage grace is not enrollment.")
            except (get_user_model().DoesNotExist, get_user_model().MultipleObjectsReturned, APIException) as exc:
                raise CommandError(f"Unable to refresh {name}: {exc}") from exc
            self.stdout.write(f"Refreshed directory user {user.username}.")
