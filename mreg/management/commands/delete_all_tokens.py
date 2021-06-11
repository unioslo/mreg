from django.core.management.base import BaseCommand, CommandError

class Command(BaseCommand):
    help = 'Delete all tokens from the database.'

    def handle(self, *args, **kwargs):
        try:
            from rest_framework.authtoken.models import Token
            Token.objects.all().delete()
        except:
            raise CommandError('Failed to delete tokens.')
