from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from sys import stdout
from django.conf import settings
from psycopg2 import connect


class Command(BaseCommand):
    help = 'Create the CITEXT extension in the database.'

    def add_arguments(self, parser):
        # optional argument
        parser.add_argument(
            '--database',
            type=str,
            help='Database name',
        )

    def handle(self, *args, **options):
        stdout.write("Attempting to create the CITEXT extension in the database...\n")
        stdout.flush()
        try:
            con = connection
            if options['database']:
                stdout.write(f"Connecting to database {options['database']}\n")
                stdout.flush()
                con = connect(
                        host=settings.DATABASES['default']['HOST'],
                        user=settings.DATABASES['default']['USER'],
                        password=settings.DATABASES['default']['PASSWORD'],
                        database=options['database']
                )
            with con.cursor() as cursor:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS citext")
                stdout.write(cursor.statusmessage+"\n")
                stdout.flush()
                con.commit()
        except Exception as e:
            stdout.write(e.__str__())
            stdout.flush()
            raise CommandError('Failed to create the CITEXT extension in the database.')
