from django.db.models.signals import pre_save, post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.utils import timezone

from django.core.exceptions import ValidationError

from mreg.models import (Cname, Host, HostGroup, Ipaddress, ModelChangeLog, Naptr,
        PtrOverride, Srv, Txt, ZoneMember)
from mreg.api.v1.serializers import HostSerializer


def _del_ptr(ipaddress):
    ptrs = PtrOverride.objects.filter(ipaddress=ipaddress)
    if ptrs:
        assert(len(ptrs) == 1)
        ptrs.first().delete()

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

def _update_zone_for_ip(ip):
    # For now..
    pass


def _common_update_zone(signal, sender, instance):
    zones = set()

    if isinstance(instance, ZoneMember):
        zones.add(instance.zone)
        if signal == "pre_save" and instance.id:
            oldzone = sender.objects.get(id=instance.id).zone
            zones.add(oldzone)

    if hasattr(instance, 'host'):
        zones.add(instance.host.zone)
        if signal == "pre_save" == instance.host.id:
            oldzone = Host.objecs.get(id=instance.host.id).zone
            zones.add(oldzone)

    if sender in (Ipaddress, PtrOverride):
        _update_zone_for_ip(instance.ipaddress)

    for zone in zones:
        if zone:
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


@receiver(m2m_changed, sender=HostGroup.parent.through)
def prevent_hostgroup_parent_recursion(sender, instance, action, model, reverse, pk_set, **kwargs):
    """
    pk_set contains the group(s) being added to a group
    instance is the group getting new group members
    This whole pk_set-function should be rewritten to handle multiple groups
    """
    if action == 'pre_add':
        for host_id in pk_set:
            child_id = host_id

        parent_parents = HostGroup.objects.get(id=instance.id).parent.all()

        for parent in parent_parents.iterator():
            if child_id == parent.id:
                raise ValidationError(
                    _('Recursive memberships are not allowed. The group is a member of %(group)s'),
                    code='invalid',
                    params={'group' : HostGroup.objects.get(id=parent.id).hostgroup_name})
                return
            elif HostGroup.objects.get(id=parent.id).parent.all():
                pk_set = {child_id}
                prevent_hostgroup_parent_recursion(sender, parent, action, model, reverse, pk_set, **kwargs)
    else:
        return

