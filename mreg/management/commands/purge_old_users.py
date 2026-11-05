"""Remove inactive directory-managed accounts without touching local accounts."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from mreg.models.auth import LDAPUserState
from mreg.models.base import ExpiringToken


class Command(BaseCommand):
    help = "Preview inactive LDAP/OIDC users; pass --execute to delete them. Local and disabled accounts are preserved."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, required=True, help="Required number of days without activity (positive integer).")
        parser.add_argument("--execute", action="store_true", help="Delete the listed accounts. The default only previews them.")

    def handle(self, *args, **options):
        days = options["days"]
        if days <= 0:
            raise CommandError("--days must be a positive integer.")
        try:
            cutoff = timezone.now() - timedelta(days=days)
        except OverflowError as exc:
            raise CommandError("--days is too large.") from exc

        candidates = LDAPUserState.objects.filter(last_activity_at__lt=cutoff, user__isnull=False)
        usernames = list(candidates.order_by("username").values_list("username", flat=True))
        count = 0
        action = "Deleted" if options["execute"] else "Would delete"
        self.stdout.write(f"Directory accounts inactive since before {cutoff.isoformat()}:")
        for username in usernames:
            with transaction.atomic():
                # Match the refresher's lock order and recheck activity after acquiring the lock.
                state = candidates.select_for_update().filter(username=username).first()
                if state is None:
                    continue
                user = get_user_model().objects.select_for_update().filter(
                    pk=state.user_id, is_active=True, date_joined__lt=cutoff,
                ).exclude(last_login__gte=cutoff).first()
                if user is None or ExpiringToken.objects.filter(user_id=user.pk, last_used__gte=cutoff).exists():
                    continue
                name = user.username
                if options["execute"]:
                    user.delete()
            count += 1
            self.stdout.write(f"{action} {name}.")
        self.stdout.write(f"{action} {count} user(s).")
        if not options["execute"]:
            self.stdout.write("Preview only; pass --execute to delete these accounts.")
