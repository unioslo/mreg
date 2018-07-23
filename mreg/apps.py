from django.apps import AppConfig


class MregAppConfig(AppConfig):
    name = 'mreg'

    def ready(self):
        import mreg.signals
