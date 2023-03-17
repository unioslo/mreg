from django.core.exceptions import ValidationError
from django.test import TestCase

from rest_framework.exceptions import PermissionDenied

from mreg.models import Host
from mreg.mqsender import MQSender
from .models import (HostPolicyAtom, HostPolicyRole)


def clean_and_save(entity):
    entity.full_clean()
    entity.save()


class Internals(TestCase):
    """Test internal data structures."""

    def test_str(self):
        """Test that __str__ returns obj.name."""
        name = "test1"
        atom = HostPolicyAtom(name=name, description='test')
        self.assertEqual(str(atom), '"' + name + '"')


class UniqueNamespace(TestCase):
    """Atoms and Roles must jointly have unique names, so test that."""

    def test_atom_and_role_share_namespace(self):
        atom_one = HostPolicyAtom(name='test1', description='test')
        role_one = HostPolicyRole(name='test1', description='test')
        atom_two = HostPolicyAtom(name='test2', description='test')
        role_two = HostPolicyRole(name='TEST2', description='test')
        clean_and_save(atom_one)
        with self.assertRaises(ValidationError):
            role_one.full_clean()
        clean_and_save(role_two)
        with self.assertRaises(ValidationError):
            atom_two.full_clean()


class ModelHostPolicyRole(TestCase):

    def setUp(self):
        self.role_one = HostPolicyRole(name='role 1', description='desc 1')
        self.role_two = HostPolicyRole(name='role 2', description='desc 2')
        self.role_three = HostPolicyRole(name='role 3', description='desc 3')
        clean_and_save(self.role_one)
        clean_and_save(self.role_two)
        clean_and_save(self.role_three)

    def test_require_description(self):
        with self.assertRaises(ValidationError):
            HostPolicyRole(name='test', description='').full_clean()

    def test_model_updated_at_field_updated_on_changes(self):
        host_one = Host.objects.create(name='host1.example.org')
        updated_at = self.role_one.updated_at
        self.role_one.hosts.add(host_one)
        self.assertLess(updated_at, self.role_one.updated_at)
        atom_one = HostPolicyAtom.objects.create(name='atom1',  description='atom1')
        updated_at = self.role_one.updated_at
        self.role_one.atoms.add(atom_one)
        self.assertLess(updated_at, self.role_one.updated_at)
        updated_at = self.role_one.updated_at
        atom_one.name = 'newname'
        atom_one.save()
        self.role_one.refresh_from_db()
        self.assertLess(updated_at, self.role_one.updated_at)
        updated_at = self.role_one.updated_at
        atom_one.delete()
        self.role_one.refresh_from_db()
        self.assertLess(updated_at, self.role_one.updated_at)
