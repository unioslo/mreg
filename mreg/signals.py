from django.db.models.signals import post_save
from django.dispatch import receiver

from mreg.models import *


@receiver(post_save, sender=Hosts)
def save_host_history(sender, instance, created, **kwargs):
    print(instance.name)