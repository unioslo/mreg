from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from mreg.models import *
from mreg.api.v1.serializers import *


@receiver(post_save, sender=Ipaddress)
def save_host_history_ip(sender, instance, created, **kwargs):
    print(instance)
    hostdata = HostsSerializer(Hosts.objects.get(hostid=instance.hostid_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddress'] = [record['ipaddress'] for record in hostdata['ipaddress']]
    hostdata['txt'] = [record['txt'] for record in hostdata['txt']]
    hostdata['cname'] = [record['cname'] for record in hostdata['cname']]
    print(hostdata)

    # new_log_entry = ModelChangeLogs(table_name=Hosts,
    #                                 table_row=hostdata['hostid'],
    #                                 data=hostdata,
    #                                 action='saved',
    #                                 timestamp=timezone.now())
    # new_log_entry.save()


@receiver(post_save, sender=Txt)
def save_host_history_txt(sender, instance, created, **kwargs):
    hostdata = HostsSerializer(Hosts.objects.get(hostid=instance.hostid_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddress'] = [record['ipaddress'] for record in hostdata['ipaddress']]
    hostdata['txt'] = [record['txt'] for record in hostdata['txt']]
    hostdata['cname'] = [record['cname'] for record in hostdata['cname']]
    print(hostdata)


@receiver(post_save, sender=Cname)
def save_host_history_cname(sender, instance, created, **kwargs):
    hostdata = HostsSerializer(Hosts.objects.get(hostid=instance.hostid_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddress'] = [record['ipaddress'] for record in hostdata['ipaddress']]
    hostdata['txt'] = [record['txt'] for record in hostdata['txt']]
    hostdata['cname'] = [record['cname'] for record in hostdata['cname']]
    print(hostdata)
