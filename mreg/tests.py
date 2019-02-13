from django.test import TestCase

from mreg.models import (Cname, HinfoPreset, Host, Ipaddress, NameServer,
                         Naptr, PtrOverride, Srv, Network, Txt, ForwardZone,
                         ReverseZone, ModelChangeLog)


def clean_and_save(entity):
    entity.full_clean()
    entity.save()


class NameServerDeletionTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='ns.example.org',
                                       email='hostmaster@example.org')
        self.zone_1010 = ReverseZone(name='127.in-addr.arpa',
                                     primary_ns='ns.example.org',
                                     email='hostmaster@example.org')
        clean_and_save(self.zone_sample)
        clean_and_save(self.zone_1010)

        self.network_sample = Network(range='129.240.202.0/20',
                                      description='some description',
                                      vlan=123,
                                      dns_delegated=False)
        self.ns_hostsample = Host(name='ns.example.org',
                             contact='mail@example.org')
        clean_and_save(self.ns_hostsample)
        self.ns_hostip = Ipaddress(host=self.ns_hostsample,
                                       ipaddress='129.240.202.111')
        clean_and_save(self.ns_hostip)

        self.ns_sample = NameServer(name='ns.example.org',
                                    ttl=300)
        clean_and_save(self.ns_sample)


    def test_model_cant_delete_ns_host(self):
        """Test that it won't delete nameserver host-object if in use in a zone"""
        old_count = NameServer.objects.count()
        self.ns_hostsample.delete()
        new_count = NameServer.objects.count()
        self.assertEqual(old_count, new_count)


    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        old_count = NameServer.objects.count()
        self.ns_hostip.delete()
        new_count = NameServer.objects.count()
        self.assertEqual(old_count, new_count)


    def test_model_can_delete_ns_hostip(self):
        """Test that the model is able to delete an IP from a nameserver, if nameserver has multiple IPs."""
        self.ns_hostip2 = Ipaddress(host=self.ns_hostsample,
                                       ipaddress='129.240.202.112')
        clean_and_save(self.ns_hostip2)
        old_count = Ipaddress.objects.count()
        self.ns_hostip2.delete()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)