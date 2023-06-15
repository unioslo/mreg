from django.test import TestCase

from rest_framework.exceptions import PermissionDenied

from mreg.models import ForwardZone, Host, Ipaddress, NameServer, Network, ReverseZone

from .base import clean_and_save


class ModelNameServerTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )

        clean_and_save(self.zone_sample)

        self.ns_sample = NameServer(name="ns.example.org", ttl=300)

    def test_model_can_create_ns(self):
        """Test that the model is able to create an Ns."""
        old_count = NameServer.objects.count()
        clean_and_save(self.ns_sample)
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.ns_sample)

    def test_model_can_change_ns(self):
        """Test that the model is able to change an Ns."""
        clean_and_save(self.ns_sample)
        old_name = self.ns_sample.name
        new_name = "new-ns.example.com"
        ns_sample_id = NameServer.objects.get(name=old_name).id
        self.ns_sample.name = new_name
        clean_and_save(self.ns_sample)
        updated_name = NameServer.objects.get(pk=ns_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete an Ns."""
        clean_and_save(self.ns_sample)
        old_count = NameServer.objects.count()
        self.ns_sample.delete()
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)


class NameServerDeletionTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(self.zone_sample)

        self.zone_1010 = ReverseZone(
            name="10.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(self.zone_1010)

        self.network_sample = Network.objects.create(
            network="10.0.0.0/24", description="some description"
        )

        self.ns_hostsample = Host.objects.create(name="ns.example.org")

        self.ns_hostip = Ipaddress.objects.create(
            host=self.ns_hostsample, ipaddress="10.0.0.111"
        )

        self.ns_sample = NameServer.objects.create(name="ns.example.org")
        self.zone_sample.nameservers.add(self.ns_sample)

    def test_model_cant_delete_ns_host(self):
        """Test that it won't delete nameserver host-object if in use in a zone"""
        with self.assertRaises(PermissionDenied):
            self.ns_hostsample.delete()

    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        with self.assertRaises(PermissionDenied):
            self.ns_hostip.delete()

    def test_model_can_delete_ns_hostip(self):
        """Test that the model is able to delete an IP from a nameserver, if
        nameserver has multiple IPs."""
        ip = Ipaddress.objects.create(host=self.ns_hostsample, ipaddress="10.0.0.112")
        old_count = Ipaddress.objects.count()
        ip.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)
