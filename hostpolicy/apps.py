from django.apps import AppConfig


class HostpolicyAppConfig(AppConfig):
    name = 'hostpolicy'

    def ready(self):
        import hostpolicy.signals # noqa
