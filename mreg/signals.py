import functools
import re

from django.conf import settings
from django.contrib.auth.models import Group
from django.db.models.signals import m2m_changed, post_delete, pre_delete , post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django_auth_ldap.backend import populate_user
from django.utils.translation import ugettext as _

from mreg.api.v1.serializers import HostSerializer
from mreg.models import (Cname, ForwardZoneMember, Host, HostGroup, Ipaddress,
        ModelChangeLog, Mx, Naptr, NameServer, PtrOverride, ReverseZone, Srv,
        Txt, Sshfp, Network, NetGroupRegexPermission)
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

def _del_ptr(ipaddress):
    PtrOverride.objects.filter(ipaddress=ipaddress).delete()

# Update PtrOverride whenever a Ipaddress is created or changed
@receiver(pre_save, sender=Ipaddress)
def updated_ipaddress_fix_ptroverride(sender, instance, raw, using, update_fields, **kwargs):
    if instance.id:
        oldinstance = Ipaddress.objects.get(id=instance.id)
        if oldinstance.ipaddress != instance.ipaddress:
            _del_ptr(oldinstance.ipaddress)
    else:
        # Can only add a PtrOverride if count == 1, otherwise we can not guess which
        # one should get it.
        qs = Ipaddress.objects.filter(ipaddress=instance.ipaddress)
        if qs and qs.count() == 1:
            host = qs.first().host
            PtrOverride.objects.create(host=host, ipaddress=instance.ipaddress)

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
            for model in (Cname, Srv,):
                for i in model.objects.filter(host=instance).exclude(zone=instance.zone):
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
@receiver(pre_save, sender=Sshfp)
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
@receiver(post_delete, sender=Sshfp)
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


@receiver(pre_save, sender=Host)
def hostgroups_update_update_at_on_host_rename(sender, instance, raw, using, update_fields, **kwargs):
    """
    Update hostgroup on host rename
    """
    # Ignore newly created hosts
    if not instance.id:
        return

    oldname = Host.objects.get(id=instance.id).name
    if oldname != instance.name:
        for hostgroup in instance.hostgroups.all():
            hostgroup.save()


@receiver(pre_delete, sender=Host)
def hostgroup_update_updated_at_on_host_delete(sender, instance, using, **kwargs):
    """
    No signal is sent for m2m relations on delete, so use a pre_delete on Host
    instead.
    """
    for hostgroup in instance.hostgroups.all():
        hostgroup.save()

@receiver(m2m_changed, sender=HostGroup.hosts.through)
@receiver(m2m_changed, sender=HostGroup.parent.through)
def hostgroup_update_updated_at_on_changes(sender, instance, action, model, reverse, pk_set, **kwargs):
    """
    Update the hostgroups updated_at field whenever its hosts or parent
    m2m relations have successfully been altered.
    """
    if action in ('post_add', 'post_remove', 'post_clear',):
        instance.save()

@receiver(m2m_changed, sender=HostGroup.parent.through)
def prevent_hostgroup_parent_recursion(sender, instance, action, model, reverse, pk_set, **kwargs):
    """
    pk_set contains the group(s) being added to a group
    instance is the group getting new group members
    This prevents groups from being able to become their own parent
    """

    if action != 'pre_add':
        return

    if instance.id in pk_set:
        raise PermissionDenied(detail='A group can not be its own child')

    child_id = list(pk_set)[0]

    for parent in instance.parent.all():
        if child_id == parent.id:
            raise PermissionDenied(detail='Recursive memberships are not allowed.' \
                                          ' This group is a member of %s' % parent.name)
        elif parent.parent.exists():
            pk_set = {child_id}
            prevent_hostgroup_parent_recursion(sender, parent, action, model, reverse, pk_set, **kwargs)



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

    try:
        nameserver = NameServer.objects.get(name=name)
    except NameServer.DoesNotExist:
        return

    zones = list()
    for i in ('forwardzone', 'reversezone', 'forwardzonedelegation',
              'reversezonedelegation'):
        qs = getattr(nameserver, f"{i}_set")
        if qs.exists():
            zones.append([i, list(qs.values_list('name', flat=True))])

    if zones:
        if sender == Ipaddress:
            raise PermissionDenied(f'IP {instance.ipaddress} is the only IP for host {name} '
                                   f'that is used as nameserver in {zones}')
        raise PermissionDenied(detail=f'Host {name} is a nameserver in {zones} and cannot '
                                      'be deleted until it is removed from them.')

@receiver(post_delete, sender=Network)
def cleanup_network_permissions(sender, instance, **kwargs):
    """Remove any permissions equal to or smaller than the newly deleted
       Network's network range."""
    NetGroupRegexPermission.objects.filter(
            range__net_contained_or_equal=instance.network).delete()

@receiver(post_save, sender=Host)
def add_auto_txt_records_on_new_host(sender, instance, created, **kwargs):
    """Create TXT record(s) for a host if the host's zone defines
       records in settings.TXT_AUTO_RECORDS."""
    if created:
        autozones = getattr(settings, 'TXT_AUTO_RECORDS', None)
        if autozones is None:
            return
        if instance.zone is None:
            return
        for data in autozones.get(instance.zone.name, []):
            Txt.objects.create(host=instance, txt=data)
