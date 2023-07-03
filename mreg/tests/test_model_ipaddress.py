from django.test import TestCase
from mreg.models.host import Host, Ipaddress

from .base import clean_and_save


class ModelIpaddressTestCase(TestCase):
    """This class defines the test suite for the Ipaddress model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host and sample network to test properly
        self.host = Host.objects.create(name="host.example.org")

        self.ipaddress_sample = Ipaddress(
            host=self.host, ipaddress="192.168.202.123", macaddress="a4:34:d9:0e:88:b9"
        )

        self.ipv6address_sample = Ipaddress(
            host=self.host, ipaddress="2001:db8::beef", macaddress="a4:34:d9:0e:88:b9"
        )

    def test_model_can_create_ipaddress(self):
        """Test that the model is able to create an IP Address."""
        old_count = Ipaddress.objects.count()
        clean_and_save(self.ipaddress_sample)
        new_count = Ipaddress.objects.count()
        self.assertLess(old_count, new_count)
        str(self.ipaddress_sample)

    def test_model_can_create_ipv6address(self):
        """Test that the model is able to create an IPv6 Address."""
        old_count = Ipaddress.objects.count()
        clean_and_save(self.ipv6address_sample)
        new_count = Ipaddress.objects.count()
        self.assertLess(old_count, new_count)

    def test_model_can_change_ipaddress(self):
        """Test that the model is able to change an IP Address."""
        clean_and_save(self.ipaddress_sample)
        new_ipaddress = "192.168.202.124"
        self.ipaddress_sample.ipaddress = new_ipaddress
        clean_and_save(self.ipaddress_sample)
        updated_ipaddress = Ipaddress.objects.get(host=self.host).ipaddress
        self.assertEqual(new_ipaddress, updated_ipaddress)

    def test_model_can_change_ipv6address(self):
        """Test that the model is able to change an IPv6 Address."""
        clean_and_save(self.ipv6address_sample)
        new_ipv6address = "2001:db8::feed"
        self.ipv6address_sample.ipaddress = new_ipv6address
        clean_and_save(self.ipv6address_sample)
        updated_ipv6address = Ipaddress.objects.get(host=self.host).ipaddress
        self.assertEqual(new_ipv6address, updated_ipv6address)

    def test_model_can_delete_ipaddress(self):
        """Test that the model is able to delete an IP Address."""
        clean_and_save(self.ipaddress_sample)
        old_count = Ipaddress.objects.count()
        self.ipaddress_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_delete_ipv6address(self):
        """Test that the model is able to delete an IPv6 Address."""
        clean_and_save(self.ipv6address_sample)
        old_count = Ipaddress.objects.count()
        self.ipv6address_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)
