from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone

from mreg.models import *
from mreg.api.v1.serializers import *

# To log host history, an approach using post_save signals for related objects was chosen.
# Ex: When you update an Ipaddress, the Hosts model object itself is not saved, so reading the
# post_save signal from the Hosts model you won't get anything useful.
#
# Additionally, the Hosts object is saved before the related objects when creating a new host,
# so ipaddress data isn't available at the time of post_save for the Hosts object.
#
# Currently saves a JSON-snapshot of all data for the host.
# TODO: Deleting a host should probably do something. Export/delete log for that host after some time?


@receiver(post_save, sender=PtrOverride)
@receiver(post_save, sender=Ipaddress)
@receiver(post_save, sender=Txt)
@receiver(post_save, sender=Cname)
@receiver(post_save, sender=Naptr)
def save_host_history_on_save(sender, instance, created, **kwargs):
    """Receives post_save signal for models that have a ForeignKey to Hosts and updates the host history log."""
    hostdata = HostSerializer(Host.objects.get(hostid=instance.hostid_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddress'] = [record['ipaddress'] for record in hostdata['ipaddress']]
    hostdata['txt'] = [record['txt'] for record in hostdata['txt']]
    hostdata['cname'] = [record['cname'] for record in hostdata['cname']]
    hostdata['ptr_override'] = [record['ipaddress'] for record in hostdata['ptr_override']]
    new_log_entry = ModelChangeLog(table_name='host',
                                   table_row=hostdata['hostid'],
                                   data=hostdata,
                                   action='saved',
                                   timestamp=timezone.now())
    new_log_entry.save()


@receiver(post_delete, sender=PtrOverride)
@receiver(post_delete, sender=Ipaddress)
@receiver(post_delete, sender=Txt)
@receiver(post_delete, sender=Cname)
@receiver(post_delete, sender=Naptr)
def save_host_history_on_delete(sender, instance, **kwargs):
    """Receives post_delete signal for models that have a ForeignKey to Hosts and updates the host history log."""
    hostdata = HostSerializer(Host.objects.get(hostid=instance.hostid_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddress'] = [record['ipaddress'] for record in hostdata['ipaddress']]
    hostdata['txt'] = [record['txt'] for record in hostdata['txt']]
    hostdata['cname'] = [record['cname'] for record in hostdata['cname']]
    hostdata['ptr_override'] = [record['ipaddress'] for record in hostdata['ptr_override']]

    new_log_entry = ModelChangeLog(table_name='host',
                                   table_row=hostdata['hostid'],
                                   data=hostdata,
                                   action='deleted',
                                   timestamp=timezone.now())
    new_log_entry.save()
