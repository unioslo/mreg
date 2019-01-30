import ipaddress

from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone

from mreg.models import (Cname, Host, Ipaddress, ModelChangeLog, Naptr,
                         PtrOverride, Srv, Txt, ReverseZone, ForwardZoneMember)
from mreg.api.v1.serializers import HostSerializer


def _del_ptr(ipaddress):
    ptrs = PtrOverride.objects.filter(ipaddress=ipaddress)
    if ptrs:
        assert(ptrs.count() == 1)
        ptrs.delete()

# Update PtrOverride whenever a Ipaddress is created or changed
@receiver(pre_save, sender=Ipaddress)
def updated_ipaddress_fix_ptroverride(sender, instance, raw, using, update_fields, **kwargs):
    if instance.id:
        oldinstance = Ipaddress.objects.get(id=instance.id)
        _del_ptr(oldinstance.ipaddress)
    else:
        # Can only add a PtrOverride if count == 1, otherwise we can not guess which
        # one should get it.
        if Ipaddress.objects.filter(ipaddress=instance.ipaddress).count() == 1:
            host = Ipaddress.objects.get(ipaddress=instance.ipaddress).host
            ptr = PtrOverride.objects.create(host=host, ipaddress=instance.ipaddress)
            ptr.save()

# Remove old PtrOverride, if possible, when an Ipaddress is deleted.
@receiver(post_delete, sender=Ipaddress)
def deleted_ipaddress_fix_ptroverride(sender, instance, using, **kwargs):
    _del_ptr(instance.ipaddress)


def _get_zone_for_ip(ip):
    ip = ipaddress.ip_address(ip)
    if ip.version == 4:
        # endswith = 10.in-addr.arpa for 10.2.3.4
        endswith = ip.reverse_pointer.split('.', 3)[-1]
    elif ip.version == 6:
        # endswith = 1.0.0.2.ip6.arpa for 2001:db8::1
        endswith = ip.reverse_pointer.split('.', 28)[-1]
    for zone in ReverseZone.objects.filter(name__endswith=endswith):
        if ip in zone.network:
            return zone
    return None


def _common_update_zone(signal, sender, instance):
    zones = set()

    if isinstance(instance, ForwardZoneMember):
        zones.add(instance.zone)
        if signal == "pre_save" and instance.id:
            oldzone = sender.objects.get(id=instance.id).zone
            zones.add(oldzone)

    if hasattr(instance, 'host'):
        zones.add(instance.host.zone)
        if signal == "pre_save" and instance.host.id:
            oldzone = Host.objects.get(id=instance.host.id).zone
            zones.add(oldzone)

    if sender in (Ipaddress, PtrOverride):
        zone = _get_zone_for_ip(instance.ipaddress)
        zones.add(zone)

    # Check if host has been renamed, and if so, update other zones
    # where the host is used. Such as reverse zones, Cname targets etc.
    if signal == "pre_save" and sender == Host and instance.id:
        oldname = Host.objects.get(id=instance.id).name
        if instance.name != oldname:
            # XXX: add SRV in after usit-gd/mreg#192
            for model in (Cname,):
                for i in model.objects.filter(host=instance):
                    zones.add(i.zone)
            for model in (Ipaddress, PtrOverride):
                for i in model.objects.filter(host=instance):
                    zones.add(_get_zone_for_ip(i.ipaddress))

    for zone in zones:
        if zone:
            zone.updated = True
            zone.save()


@receiver(pre_save, sender=Cname)
@receiver(pre_save, sender=Ipaddress)
@receiver(pre_save, sender=Host)
@receiver(pre_save, sender=Naptr)
@receiver(pre_save, sender=PtrOverride)
@receiver(pre_save, sender=Srv)
@receiver(pre_save, sender=Txt)
def updated_objects_update_zone_serial(sender, instance, raw, using, update_fields, **kwargs):
    _common_update_zone("pre_save", sender, instance)


# Update zone serial when objects are gone
@receiver(post_delete, sender=Cname)
@receiver(post_delete, sender=Ipaddress)
@receiver(post_delete, sender=Host)
@receiver(post_delete, sender=Naptr)
@receiver(post_delete, sender=PtrOverride)
@receiver(post_delete, sender=Srv)
@receiver(post_delete, sender=Txt)
def deleted_objects_update_zone_serial(sender, instance, using, **kwargs):
    _common_update_zone("post_delete", sender, instance)

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
    hostdata = HostSerializer(Host.objects.get(pk=instance.host_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddresses'] = [record['ipaddress'] for record in hostdata['ipaddresses']]
    hostdata['txts'] = [record['txt'] for record in hostdata['txts']]
    hostdata['cnames'] = [record['name'] for record in hostdata['cnames']]
    hostdata['ptr_overrides'] = [record['ipaddress'] for record in hostdata['ptr_overrides']]
    new_log_entry = ModelChangeLog(table_name='host',
                                   table_row=hostdata['id'],
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
    hostdata = HostSerializer(Host.objects.get(pk=instance.host_id)).data

    # Cleaning up data from related tables
    hostdata['ipaddresses'] = [record['ipaddress'] for record in hostdata['ipaddresses']]
    hostdata['txts'] = [record['txt'] for record in hostdata['txts']]
    hostdata['cnames'] = [record['name'] for record in hostdata['cnames']]
    hostdata['ptr_overrides'] = [record['ipaddress'] for record in hostdata['ptr_overrides']]

    new_log_entry = ModelChangeLog(table_name='host',
                                   table_row=hostdata['id'],
                                   data=hostdata,
                                   action='deleted',
                                   timestamp=timezone.now())
    new_log_entry.save()
