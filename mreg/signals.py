import functools
import re

from django.conf import settings
from django.contrib.auth.models import Group
from django.db.models.signals import m2m_changed, post_delete, pre_delete , post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django_auth_ldap.backend import populate_user

from mreg.api.v1.serializers import HostSerializer
from mreg.models import (Cname, ForwardZoneMember, Host, HostGroup, Ipaddress,
        ModelChangeLog, Mx, Naptr, NameServer, PtrOverride, ReverseZone, Srv,
        Txt)
from rest_framework.exceptions import PermissionDenied


@receiver(populate_user)
def populate_user_from_ldap(sender, signal, user=None, ldap_user=None, **kwargs):
    """Find all groups from ldap with attr LDAP_GROUP_ATTR and matching
    the regular expression LDAP_GROUP_RE. Will wipe previous group memberships
    before adding new."""
    LDAP_GROUP_ATTR = getattr(settings, 'LDAP_GROUP_ATTR', None)
    LDAP_GROUP_RE = getattr(settings, 'LDAP_GROUP_RE', None)
    if LDAP_GROUP_ATTR is None or LDAP_GROUP_RE is None:
        return
    user.save()
    user.groups.clear()
    ldap_groups = ldap_user.attrs.get(LDAP_GROUP_ATTR, [])
    group_re = re.compile(LDAP_GROUP_RE)
    for group_str in ldap_groups:
        res = group_re.match(group_str)
        if res:
            group_name = res.group('group_name')
            group, created = Group.objects.get_or_create(name=group_name)
            group.user_set.add(user)
            group.save()

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


def _common_update_zone(signal, sender, instance):

    @functools.lru_cache()
    def _get_zone_for_ip(ip):
        return ReverseZone.get_zone_by_ip(ip)

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
@receiver(pre_save, sender=Mx)
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
@receiver(post_delete, sender=Mx)
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
    """
    if action == 'pre_add':
        child_id = pk_set.pop()
        print("dette er child_id/pk_set :" + str(child_id))
        parent_parents = HostGroup.objects.get(id=instance.id).parent.all()
        print(parent_parents)
        print("my instance id is :" + str(instance.id) )
        if parent_parents:
            for parent in parent_parents:
                print("dette er parent.id" + str(parent.id))
                if child_id == parent.id:
                    print("child_id er tydeligvis samme som parent.id")
                    raise PermissionDenied(
                        _('Recursive memberships are not allowed. The group is a member of %(group)s'),
                        params={'group' : HostGroup.objects.get(id=parent.id).hostgroup_name})
                    return
                elif HostGroup.objects.get(id=parent.id).parent.all():
                    print("we elsed the fuck out of there1")
                    pk_set = {child_id}
                    prevent_hostgroup_parent_recursion(sender, parent, action, model, reverse, pk_set, **kwargs)
    else:
        print("we elsed the fuck out of there2")
        return



@receiver(pre_delete, sender=Ipaddress)
@receiver(pre_delete, sender=Host)
def prevent_nameserver_deletion(sender, instance, using, **kwargs):
    """
    Receives pre_delete signal for Host and Ipaddress-models that are about to be deleted.
    It then checks if the object about to be deleted belongs to a nameserver, and then prevents the deletion.
    """
    if isinstance(instance, Host):
        name = instance.name
    elif isinstance(instance, Ipaddress):
        name = instance.host.name
        if instance.host.ipaddresses.count() > 1:
            return

    nameserver = NameServer.objects.filter(name=name).first()

    if nameserver:
        usedcount = 0
        for i in ('forwardzone', 'reversezone', 'forwardzonedelegation',
                  'reversezonedelegation'):
            usedcount += getattr(nameserver, f"{i}_set").count()

        if usedcount >= 1:
            raise PermissionDenied(detail='This host is a nameserver and cannot be deleted until' \
                                    'it has been removed from all zones its setup as a nameserver')
