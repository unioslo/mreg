from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from mreg.models import *
from mreg.api.v1.serializers import *


@receiver(post_save, sender=Ipaddress)
def save_host_history_ip(sender, instance, created, **kwargs):

    ip = IpaddressSerializer(instance)
    hostdata = HostsSerializer(Hosts.objects.get(hostid=ip.data['hostid'])).data
    hostdata['ipaddress'] = [arecord['ipaddress'] for arecord in hostdata['ipaddress']]
    print(hostdata)

    # new_log_entry = ModelChangeLogs(table_name=Hosts,
    #                                 table_row=content['hostid'],
    #                                 data=content,
    #                                 action='saved',
    #                                 timestamp=timezone.now())
    # new_log_entry.save()
    # logs = ModelChangeLogs.objects.filter(table_row=content['hostid']).order_by('timestamp').values('data')

