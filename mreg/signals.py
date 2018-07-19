from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import datetime

from mreg.models import *
from mreg.api.v1.serializers import *


@receiver(post_save, sender=Hosts)
def save_host_history(sender, instance, created, **kwargs):
    content = HostsSerializer(instance).data
    new_log_entry = ModelChangeLogs(table_name=Hosts,
                                    table_row=content['hostid'],
                                    data=content,
                                    action='saved',
                                    timestamp=datetime.now())
    new_log_entry.save()
    logs = ModelChangeLogs.objects.filter(table_row=content['hostid'])
    print(log.data for log in logs)
