from django.db.models.signals import m2m_changed, pre_delete, pre_save, post_save, post_delete
from django.dispatch import receiver

from .models import HostPolicyAtom, HostPolicyRole
from mreg.models import Host
from mreg.utils import send_event_to_mq

@receiver(m2m_changed, sender=HostPolicyRole.atoms.through)
@receiver(m2m_changed, sender=HostPolicyRole.hosts.through)
def role_update_updated_at_on_changes(sender, instance, action, model,
                                      reverse, pk_set, **kwargs):
    """
    Update the hostpolicyrole updated_at field whenever its atoms, hosts or
    parent  m2m relations have successfully been altered.
    """
    if action in ('post_add', 'post_remove', 'post_clear',):
        instance.save()


def _hostpolicyatom_update_m2m_relations(instance):
    for role in instance.roles.all():
        role.save()


@receiver(pre_save, sender=HostPolicyAtom)
def atom_update_m2m_relations_on_rename(sender, instance, raw, using, update_fields, **kwargs):
    """
    Update hostgroup and hostpolicy on host rename
    """
    # Ignore newly created hosts
    if not instance.id:
        return

    oldname = HostPolicyAtom.objects.get(id=instance.id).name
    if oldname != instance.name:
        _hostpolicyatom_update_m2m_relations(instance)


@receiver(pre_delete, sender=HostPolicyAtom)
def atom_update_m2m_relations_on_delete(sender, instance, using, **kwargs):
    """
    No signal is sent for m2m relations on delete, so use a pre_delete on
    HostPolicyAtom instead.
    """
    _hostpolicyatom_update_m2m_relations(instance)

@receiver(m2m_changed, sender=HostPolicyRole.hosts.through)
def send_event_for_host_role_changes(sender, instance, action, model,
             reverse, pk_set, **kwargs):
    if not action in ('post_add','post_remove',):
        return
    for pk in pk_set:
        obj = {
            'host': Host.objects.get(id=pk).name,
            'role': instance.name,
        }
        if action == 'post_add':
            obj['action'] = 'add_role_to_host'
        elif action == 'post_remove':
            obj['action'] = 'remove_role_from_host'
        send_event_to_mq(obj, "host.role")

@receiver(m2m_changed, sender=HostPolicyRole.atoms.through)
def send_event_for_role_atom_changes(sender, instance, action, model,
             reverse, pk_set, **kwargs):
    if not action in ('post_add','post_remove',):
        return
    for pk in pk_set:
        obj = {
            'role': instance.name,
            'atom': HostPolicyAtom.objects.get(id=pk).name,
        }
        if action == 'post_add':
            obj['action'] = 'add_atom_to_role'
        elif action == 'post_remove':
            obj['action'] = 'remove_atom_from_role'
        send_event_to_mq(obj, "role.atom")

@receiver(post_save, sender=HostPolicyRole)
def send_event_when_role_created(sender, instance, created, **kwargs):
    if created:
        obj = {
            'role': instance.name,
            'action': 'role_created',
        }
        send_event_to_mq(obj, "role")

@receiver(post_delete, sender=HostPolicyRole)
def send_event_when_role_removed(sender, instance, **kwargs):
    obj = {
        'role': instance.name,
        'action': 'role_removed',
    }
    send_event_to_mq(obj, "role")

@receiver(post_save, sender=HostPolicyAtom)
def send_event_when_atom_created(sender, instance, created, **kwargs):
    if created:
        obj = {
            'atom': instance.name,
            'action': 'atom_created',
        }
        send_event_to_mq(obj, "atom")

@receiver(post_delete, sender=HostPolicyAtom)
def send_event_when_atom_removed(sender, instance, **kwargs):
    obj = {
        'atom': instance.name,
        'action': 'atom_removed',
    }
    send_event_to_mq(obj, "atom")
