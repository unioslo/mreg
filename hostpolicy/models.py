import datetime

from django.core.exceptions import ValidationError
from django.db import models

from mreg.fields import LowerCaseCharField
from mreg.managers import LowerCaseManager
from mreg.models.base import Label
from mreg.models.host import Host


class HostPolicyComponent(models.Model):

    updated_at = models.DateTimeField(auto_now=True)
    create_date = models.DateField(default=datetime.date.today)
    description = models.CharField(max_length=150)

    class Meta:
        abstract = True

    def __str__(self):
        return f'"{self.name}"'


def _validate_atom_name(name):
    qs = HostPolicyRole.objects.filter(name=name)
    if qs.exists():
        raise ValidationError('Already a Role with that name')


class HostPolicyAtom(HostPolicyComponent):

    name = LowerCaseCharField(max_length=64, unique=True, validators=[_validate_atom_name])

    objects = LowerCaseManager()

    class Meta:
        db_table = 'hostpolicy_atom'
        ordering = ('name',)


def _validate_role_name(name):
    qs = HostPolicyAtom.objects.filter(name=name)
    if qs.exists():
        raise ValidationError('Already an Atom with that name')


class HostPolicyRole(HostPolicyComponent):

    name = LowerCaseCharField(max_length=64, unique=True, validators=[_validate_role_name])
    atoms = models.ManyToManyField(HostPolicyAtom, related_name='roles')
    hosts = models.ManyToManyField(Host, related_name='hostpolicyroles')
    labels = models.ManyToManyField(Label, blank=True, related_name='hostpolicyroles')

    objects = LowerCaseManager()

    class Meta:
        db_table = 'hostpolicy_role'
        ordering = ('name',)
