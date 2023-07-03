from django.test import TestCase
from mreg.models.host import Host, HostGroup
from rest_framework.exceptions import PermissionDenied

from .base import clean_and_save


class ModelHostGroupTestCase(TestCase):
    """This class defines the test suite for the HostGroup model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.group_one = HostGroup(name="group1")
        self.group_two = HostGroup(name="group2")
        self.group_three = HostGroup(name="group3")
        self.group_four = HostGroup(name="group4")
        self.host_one = Host.objects.create(name="host1.example.org")
        clean_and_save(self.group_one)
        clean_and_save(self.group_two)
        clean_and_save(self.group_three)
        clean_and_save(self.group_four)

    def test_model_can_create_hostgroup(self):
        old_count = HostGroup.objects.count()
        group = HostGroup(name="testing")
        clean_and_save(group)
        new_count = HostGroup.objects.count()
        self.assertLess(old_count, new_count)
        str(group)

    def test_model_can_delete_hostgroup(self):
        old_count = HostGroup.objects.count()
        self.group_one.delete()
        new_count = HostGroup.objects.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_add_host_to_hostgroup(self):
        old_count = self.group_one.hosts.count()
        self.group_one.hosts.add(self.host_one)
        new_count = self.group_one.hosts.count()
        self.assertLess(old_count, new_count)

    def test_model_can_remove_host_from_hostgroup(self):
        self.group_one.hosts.add(self.host_one)
        old_count = self.group_one.hosts.count()
        self.group_one.hosts.remove(self.host_one)
        new_count = self.group_one.hosts.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_add_group_to_group(self):
        old_count = self.group_one.groups.count()
        self.group_one.groups.add(self.group_two)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_remove_group_from_group(self):
        self.group_one.groups.add(self.group_two)
        old_count = self.group_one.groups.count()
        self.group_two.parent.remove(self.group_one)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_not_be_own_child(self):
        with self.assertRaises(PermissionDenied):
            self.group_one.groups.add(self.group_one)

    def test_model_can_not_be_own_grandchild(self):
        self.group_one.groups.add(self.group_two)
        with self.assertRaises(PermissionDenied):
            self.group_two.groups.add(self.group_one)

    def test_model_group_parent_can_never_be_child_of_child_groupmember(self):
        self.group_one.groups.add(self.group_two)
        self.group_two.groups.add(self.group_three)
        self.group_three.groups.add(self.group_four)
        with self.assertRaises(PermissionDenied):
            self.group_four.groups.add(self.group_one)

    def test_model_altered_updated_at_group_changes(self):
        group1_updated_at = self.group_one.updated_at
        group2_updated_at = self.group_two.updated_at
        self.group_one.groups.add(self.group_two)
        self.group_one.refresh_from_db()
        self.group_two.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)
        self.assertEqual(group2_updated_at, self.group_two.updated_at)

    def test_model_altered_updated_at_on_hosts_add(self):
        group1_updated_at = self.group_one.updated_at
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)

    def test_model_altered_updated_at_on_host_rename(self):
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        group1_updated_at = self.group_one.updated_at
        self.host_one.name = "newname"
        self.host_one.save()
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)

    def test_model_altered_updated_at_on_host_delete(self):
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        group1_updated_at = self.group_one.updated_at
        self.host_one.delete()
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)
