from django.core.exceptions import ValidationError
from django.test import TestCase

from mreg.models import (ForwardZone, Host, Ipaddress, NameServer, Network,
                         ReverseZone, NetGroupRegexPermission, )
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
        with self.assertRaises(PermissionDenied):
            self.ns_hostsample.delete()

    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        with self.assertRaises(PermissionDenied):
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


class NetGroupRegexPermissionTestCase(TestCase):

    def test_model_create(self):
        old_count = NetGroupRegexPermission.objects.count()
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.0/25',
                                       regex=r'.*\.example\.org$')
        clean_and_save(perm)
        self.assertGreater(NetGroupRegexPermission.objects.count(), old_count)

    def test_model_reject_invalid(self):
        # Reject invalid range. Hostbit set.
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.1/25',
                                       regex=r'.*\.example\.org$')
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(str(cm.exception),
                         "{'range': ['10.0.0.1/25 has host bits set']}")
        # Reject invalid regex.
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.0/25',
                                       regex=r'.*\.ex(ample\.org$')
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(str(cm.exception),
                         "{'regex': ['missing ), unterminated subpattern at position 6']}")


    def test_model_clean_permissions(self):
        # Make sure that permissions are removed if a Network with equal
        # or larger range is removed. Removed by code in signals.py.
        self.network_v4 = Network(range='10.0.0.0/24')
        self.network_v6 = Network(range='2001:db8::/64')
        clean_and_save(self.network_v4)
        clean_and_save(self.network_v6)
        v4perm = NetGroupRegexPermission(group='testgroup',
                                         range='10.0.0.0/25',
                                         regex=r'.*\.example\.org$')
        clean_and_save(v4perm)
        v6perm = NetGroupRegexPermission(group='testgroup',
                                         range=self.network_v6.range,
                                         regex=r'.*\.example\.org$')
        clean_and_save(v6perm)
        self.assertEqual(NetGroupRegexPermission.objects.count(), 2)
        self.network_v4.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 1)
        self.assertEqual(NetGroupRegexPermission.objects.first(), v6perm)
        self.network_v6.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 0)
