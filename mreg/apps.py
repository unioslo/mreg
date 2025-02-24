from django.apps import AppConfig
from django.conf import settings
from django.db.models.signals import post_migrate


class MregAppConfig(AppConfig):
    name = 'mreg'

    def ready(self):
        import mreg.signals # noqa
        from mreg.models.network_policy import NetworkPolicyAttribute

        def create_protected_attributes(sender, **kwargs):
            protected_attrs = getattr(settings, 'MREG_PROTECTED_POLICY_ATTRIBUTES', [])
            for attr in protected_attrs:
                NetworkPolicyAttribute.objects.get_or_create(
                    name=attr,
                    defaults={'description': 'Automatically created protected attribute.'}
                )

        # Connect the signal; using self ensures it only runs for this app.
        post_migrate.connect(create_protected_attributes, sender=self)