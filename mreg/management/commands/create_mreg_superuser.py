import getpass
from sys import stdout

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    """Create a local MREG user, by default with superuser privileges."""

    help = "Create a local MREG user, by default with superuser privileges."

    def add_arguments(self, parser):
        """Add arguments to the command."""
        parser.add_argument(
            "--username",
            type=str,
            help="The username for the new user. If not provided, will be read from stdin.",
        )
        parser.add_argument(
            "--password",
            type=str,
            help="The password for the new user. If not provided, will be read from stdin.",
        )
        parser.add_argument(
            "--group",
            type=str,
            help=(
                "Group to add the user to. The default, 'default-super-group'"
                "grants superuser privileges."
            ),
            default="default-super-group",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force the creation, delete any existing user with the given username.",
            default=False,
        )

    def handle(self, *args, **options):
        """Create the user."""
        username = options["username"]
        password = options["password"]
        groupname = options["group"]

        # The username and password will be a quoted str due to argparse type=str.
        # This means that "not username" will work fine if the username is given as 0
        # as argparse will deliver it as "0" and not int(0), which is false.
        if not username:
            username = input("Username: ")

        if not password:
            password = getpass.getpass("Password: ")

        operation = "Created"
        if get_user_model().objects.filter(username=username).exists():
            if options["force"]:
                operation = "Deleted and recreated"
                get_user_model().objects.filter(username=username).delete()
            else:
                raise CommandError(f"User {username} already exists.")

        # We use create_user as it hashes the password for us.
        # Using get_or_create would require us to hash the password ourselves.
        user = get_user_model().objects.create_user(
            username=username, password=password
        )
        # Clearing groups should be superfluous, but we do it in case there are
        # some default groups that are added to the user.
        user.groups.clear()
        group, _ = Group.objects.get_or_create(name=groupname)
        group.user_set.add(user)

        stdout.write(f"{operation} user '{username}' in the group '{group.name}'.\n")
        stdout.flush()
