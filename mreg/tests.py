from django.core.exceptions import ValidationError
from django.test import TestCase

from mreg.models import (ForwardZone, Host, HostGroup, HostGroupMember, Ipaddress, NameServer, Network, ReverseZone)
from rest_framework.exceptions import PermissionDenied


def clean_and_save(entity):
    entity.full_clean()
    entity.save()


class ModelReverseZoneTestCase(TestCase):
    """This class defines the test suite for the ReverseZone model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_v4 = ReverseZone(name='0.10.in-addr.arpa',
                                   primary_ns='ns.example.org',
                                   email='hostmaster@example.org')
        self.zone_v6 = ReverseZone(name='8.b.d.0.1.0.0.2.ip6.arpa',
                                   primary_ns='ns.example.org',
                                   email='hostmaster@example.org')

    def test_model_can_create_a_ipv4_zone(self):
        """Test that the model is able to create a ipv4 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v4)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_create_a_ipv6_zone(self):
        """Test that the model is able to create a ipv6 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v6)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        clean_and_save(self.zone_v4)
        clean_and_save(self.zone_v6)
        self.zone_v4.delete()
        self.zone_v6.delete()

    def test_model_rfc2317_valid_names(self):
        """Test that the model can handle RFC 2317 zone names"""
        zone_1 = ReverseZone(name='0/25.0.0.10.in-addr.arpa',
                             primary_ns='ns.example.org',
                             email='hostmaster@example.org')
        zone_2 = ReverseZone(name='0/32.0.1.10.in-addr.arpa',
                             primary_ns='ns.example.org',
                             email='hostmaster@example.org')
        clean_and_save(zone_1)
        clean_and_save(zone_2)

    def test_model_rfc2317_invalid_names(self):
        """Test that the model rejects too large delegations.
           RFC 2317 requires maximum of /25"""
        zone = ReverseZone(name='0/24.0.0.10.in-addr.arpa',
                           primary_ns='ns.example.org',
                           email='hostmaster@example.org')
        with self.assertRaises(ValidationError) as context:
            clean_and_save(zone)
        self.assertEqual(context.exception.messages,
                         ['Maximum CIDR for RFC 2317 is 25'])


class NameServerDeletionTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='ns.example.org',
                                       email='hostmaster@example.org')
        clean_and_save(self.zone_sample)

        self.zone_1010 = ReverseZone(name='10.10.in-addr.arpa',
                                     primary_ns='ns.example.org',
                                     email='hostmaster@example.org')
        clean_and_save(self.zone_1010)

        self.network_sample = Network(range='10.0.0.0/24',
                                      description='some description')
        clean_and_save(self.network_sample)

        self.ns_hostsample = Host(name='ns.example.org',
                                  contact='mail@example.org')
        clean_and_save(self.ns_hostsample)

        self.ns_hostip = Ipaddress(host=self.ns_hostsample,
                                   ipaddress='10.0.0.111')
        clean_and_save(self.ns_hostip)

        self.ns_sample = NameServer(name='ns.example.org',
                                    ttl=300)
        clean_and_save(self.ns_sample)
        self.zone_sample.nameservers.add(self.ns_sample)
        self.zone_sample.save()

    def test_model_cant_delete_ns_host(self):
        """Test that it won't delete nameserver host-object if in use in a zone"""
        with self.assertRaises(PermissionDenied) as context:
            self.ns_hostsample.delete()

    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        with self.assertRaises(PermissionDenied) as context:
            self.ns_hostip.delete()

    def test_model_can_delete_ns_hostip(self):
        """Test that the model is able to delete an IP from a nameserver, if nameserver has multiple IPs."""
        self.ns_hostip2 = Ipaddress(host=self.ns_hostsample,
                                    ipaddress='10.0.0.112')
        clean_and_save(self.ns_hostip2)
        old_count = Ipaddress.objects.count()
        self.ns_hostip2.delete()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelHostGroupTestCase(TestCase):
    """This class defines the test suite for the HostGroup and HostGroupmember model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test
        self.host_one = Host(name='host1.example.org',
                             contact='mail@example.org')
        self.group_one = HostGroup(hostgroup_name='testgruppe1')
        self.group_two = HostGroup(hostgroup_name='testgruppe2')
        self.group_three = HostGroup(hostgroup_name='testgruppe3')
        self.group_four = HostGroup(hostgroup_name='testgruppe4')

    def test_model_can_create_hostgroup(self):
        old_count = HostGroup.objects.count()
        clean_and_save(self.group_one)
        new_count = HostGroup.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_hostgroup(self):
        clean_and_save(self.group_one)
        old_count = HostGroup.objects.count()
        self.group_one.delete()
        new_count = HostGroup.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_add_host_to_hostgroup(self):
        clean_and_save(self.group_one)
        clean_and_save(self.host_one)
        old_count = self.group_one.hostgroupmember_set.count()
        self.group_one.hostgroupmember_set.create(host=self.host_one)
        self.group_one.save()
        new_count = self.group_one.hostgroupmember_set.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_remove_host_from_hostgroup(self):
        clean_and_save(self.group_one)
        clean_and_save(self.host_one)
        self.group_one.hostgroupmember_set.create(host=self.host_one)
        clean_and_save(self.group_one)
        old_count = self.group_one.hostgroupmember_set.count()
        host_one_membership_object = HostGroupMember.objects.get(host=self.host_one, group=self.group_one)
        host_one_membership_object.delete()
        new_count = self.group_one.hostgroupmember_set.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_add_group_to_group(self):
        clean_and_save(self.group_one)
        clean_and_save(self.group_two)
        old_count = self.group_one.groups.count()
        self.group_one.groups.add(self.group_two)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_remove_group_from_group(self):
        clean_and_save(self.group_one)
        clean_and_save(self.group_two)
        self.group_one.groups.add(self.group_two)
        old_count = self.group_one.groups.count()
        self.group_two.parent.remove(self.group_one)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_group_parent_can_never_be_child_of_child_groupmember(self):
        clean_and_save(self.group_one)
        clean_and_save(self.group_two)
        clean_and_save(self.group_three)
        clean_and_save(self.group_four)
        self.group_one.groups.add(self.group_two)
        self.group_two.groups.add(self.group_three)
        self.group_three.groups.add(self.group_four)
        with self.assertRaises(PermissionDenied) as context:
            self.group_four.groups.add(self.group_one)
