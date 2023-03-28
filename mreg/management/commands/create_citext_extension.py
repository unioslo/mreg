from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from sys import stdout

class Command(BaseCommand):
	help = 'Create the CITEXT extension in the database.'

	def handle(self, *args, **kwargs):
		stdout.write("Attempting to create the CITEXT extension in the database...\n")
		stdout.flush()
		try:
			with connection.cursor() as cursor:
				cursor.execute("CREATE EXTENSION IF NOT EXISTS citext")
				stdout.write(cursor.statusmessage+"\n")
				stdout.flush()
		except Exception as e:
			raise CommandError('Failed to create the CITEXT extension in the database.')
