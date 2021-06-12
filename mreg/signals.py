import functools
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver

from django_auth_ldap.backend import populate_user

from rest_framework.exceptions import PermissionDenied

from .models import (Cname, ForwardZoneMember, Hinfo, History, Host, HostGroup,
                     Ipaddress, Loc, Mx, NameServer, Naptr,
                     NetGroupRegexPermission, Network, PtrOverride,
                     ForwardZone, ReverseZone, Srv, Sshfp, Txt)

from .utils import send_event_to_mq

@receiver(populate_user)
def populate_user_from_ldap(sender, signal, user=None, ldap_user=None, **kwargs):
    """Find all groups from ldap with attr LDAP_GROUP_ATTR and matching
    the regular expression LDAP_GROUP_RE. Will wipe previous group memberships
    before adding new."""
    LDAP_GROUP_ATTR = getattr(settings, 'LDAP_GROUP_ATTR', None)
    LDAP_GROUP_RE = getattr(settings, 'LDAP_GROUP_RE', None)
    if LDAP_GROUP_ATTR is None or LDAP_GROUP_RE is None:
        return
    with transaction.atomic():
        user.save()
        user = get_user_model().objects.filter(id=user.id).select_for_update().first()
        user.groups.clear()
        ldap_groups = ldap_user.attrs.get(LDAP_GROUP_ATTR, [])
        group_re = re.compile(LDAP_GROUP_RE)
        for group_str in ldap_groups:
            res = group_re.match(group_str)
            if res:
                group_name = res.group('group_name')
                group, created = Group.objects.get_or_create(name=group_name)
                user.groups.add(group)


def _signal_history(resource, name, action, model, model_id, data):
    user = 'system-signals'
    history = History(user=user,
                      resource=resource,
                      name=name,
                      model_id=model_id,
                      model=model,
                      action=action,
                      data=data)
    try:
        history.full_clean()
    except ValidationError:
        return
    history.save()


def _signal_host_history(host, action, model, data):
    _signal_history('host', host.name, action, model, host.id, data)


# Update PtrOverride whenever a Ipaddress is created or changed
@receiver(pre_save, sender=Ipaddress)
def updated_ipaddress_fix_ptroverride(sender, instance, raw, using, update_fields, **kwargs):

    def _create_ptr_if_ipaddress_in_use():
        # Can only add a PtrOverride if count == 1, otherwise we can not guess which
        # one should get it.
        qs = Ipaddress.objects.filter(ipaddress=instance.ipaddress)
        if qs and qs.count() == 1:
            host = qs.first().host
            if not PtrOverride.objects.filter(ipaddress=instance.ipaddress).exists():
                data = {'ipaddress': instance.ipaddress}
                PtrOverride.objects.create(host=host, **data)
                _signal_host_history(host, 'create', 'PtrOverride', data)

    if instance.id:
        oldinstance = Ipaddress.objects.get(id=instance.id)
        if oldinstance.ipaddress != instance.ipaddress:
            data = {'ipaddress': oldinstance.ipaddress}
            qs = PtrOverride.objects.filter(host=instance.host, **data)
            if qs.exists():
                qs.delete()
                _signal_host_history(instance.host, 'destroy', 'PtrOverride', data)
            _create_ptr_if_ipaddress_in_use()
    else:
        _create_ptr_if_ipaddress_in_use()


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
@receiver(pre_save, sender=Hinfo)
@receiver(pre_save, sender=Host)
@receiver(pre_save, sender=Mx)
@receiver(pre_save, sender=Loc)
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
@receiver(post_delete, sender=Hinfo)
@receiver(post_delete, sender=Host)
@receiver(post_delete, sender=Mx)
@receiver(post_delete, sender=Loc)
@receiver(post_delete, sender=Naptr)
@receiver(post_delete, sender=PtrOverride)
@receiver(post_delete, sender=Sshfp)
@receiver(post_delete, sender=Srv)
@receiver(post_delete, sender=Txt)
def deleted_objects_update_zone_serial(sender, instance, using, **kwargs):
    _common_update_zone("post_delete", sender, instance)


def _host_update_m2m_relations(instance):
    for hostgroup in instance.hostgroups.all():
        hostgroup.save()
    for role in instance.hostpolicyroles.all():
        role.save()


@receiver(pre_save, sender=Host)
def host_update_m2m_relations_on_rename(sender, instance, raw, using, update_fields, **kwargs):
    """
    Update hostgroup and hostpolicy on host rename
    """
    # Ignore newly created hosts
    if not instance.id:
        return

    oldname = Host.objects.get(id=instance.id).name
    if oldname != instance.name:
        _host_update_m2m_relations(instance)


@receiver(pre_delete, sender=Host)
def host_update_m2m_relations_on_delete(sender, instance, using, **kwargs):
    """
    No signal is sent for m2m relations on delete, so use a pre_delete on Host
    instead.
    """
    _host_update_m2m_relations(instance)


@receiver(m2m_changed, sender=HostGroup.hosts.through)
@receiver(m2m_changed, sender=HostGroup.parent.through)
def hostgroup_update_updated_at_on_changes(sender, instance, action, model,
                                           reverse, pk_set, **kwargs):
    """
    Update the hostgroups updated_at field whenever its hosts or parent
    m2m relations have successfully been altered.
    """
    if action in ('post_add', 'post_remove', 'post_clear',):
        instance.save()


@receiver(m2m_changed, sender=HostGroup.parent.through)
def prevent_hostgroup_parent_recursion(sender, instance, action, model,
                                       reverse, pk_set, **kwargs):
    """
    pk_set contains the group(s) being added to a group
    instance is the group getting new group members
    This prevents groups from being able to become their own parent
    """

    if action != 'pre_add':
        return

    if instance.id in pk_set:
        raise PermissionDenied(detail='A group can not be its own child')

    for parent in instance.parent.all():
        if parent.id in pk_set:
            raise PermissionDenied(detail='Recursive memberships are not allowed.'
                                          ' This group is a member of %s' % parent.name)
        elif parent.parent.exists():
            prevent_hostgroup_parent_recursion(sender, parent, action, model,
                                               reverse, pk_set, **kwargs)


@receiver(pre_delete, sender=Ipaddress)
@receiver(pre_delete, sender=Host)
def prevent_nameserver_deletion(sender, instance, using, **kwargs):
    """
    Receives pre_delete signal for Host and Ipaddress-models that are about to be deleted.
    It then checks if the object about to be deleted belongs to a nameserver,
    and then prevents the deletion.
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
            _signal_host_history(instance, 'create', 'Txt', {'txt': data})

@receiver(post_save, sender=ForwardZone)
def update_hosts_when_zone_is_added(sender, instance, created, **kwargs):
    """When a zone is created, any existing hosts that would be in that zone
       must be updated."""
    if created:
        zonename = "." + instance.name
        for h in Host.objects.filter(name__endswith = zonename):
            # The filter will also match hosts in sub-zones, so we must check for that.
            if "." in h.name[0:-len(zonename)]:
                continue
            h.zone = instance
            h.save()

@receiver(post_delete, sender=Ipaddress)
def send_event_ip_removed_from_host(sender, instance, **kwargs):
    obj = {
        'host': instance.host.name,
        'ipaddress': instance.ipaddress,
        'action': 'remove_ip_from_host',
    }
    send_event_to_mq(obj, "host.ipaddress")

@receiver(post_save, sender=Ipaddress)
def send_event_ip_added_to_host(sender, instance, created, **kwargs):
    obj = {
        'host': instance.host.name,
        'ipaddress': instance.ipaddress,
        'action': 'add_ip_to_host',
    }
    send_event_to_mq(obj, "host.ipaddress")
