import ipaddress
import signal

from django.test import TestCase
from mreg.models.network import MAX_UNUSED_LIST, Network, NetworkExcludedRange

from .base import clean_and_save


class ModelNetworkTestCase(TestCase):
    """This class defines the test suite for the Network model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.network_sample = Network(
            network="10.0.0.0/20",
            description="some description",
            vlan=123,
            dns_delegated=False,
            category="so",
            location="Test location",
            frozen=False,
        )
        self.network_ipv6_sample = Network(
            network="2001:db8::/32",
            description="some IPv6 description",
            vlan=123,
            dns_delegated=False,
            category="so",
            location="Test location",
            frozen=False,
        )

    def test_model_can_create_network(self):
        """Test that the model is able to create a Network."""
        old_count = Network.objects.count()
        clean_and_save(self.network_sample)
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.network_sample)

    def test_model_can_create_ipv6_network(self):
        """Test that the model is able to create an IPv6 Network."""
        old_count = Network.objects.count()
        clean_and_save(self.network_ipv6_sample)
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_network(self):
        """Test that the model is able to change a Network."""
        clean_and_save(self.network_sample)
        new_vlan = 321
        network_sample_id = self.network_sample.id
        self.network_sample.vlan = new_vlan
        clean_and_save(self.network_sample)
        updated_vlan = Network.objects.get(pk=network_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_change_ipv6_network(self):
        """Test that the model is able to change an IPv6 Network."""
        clean_and_save(self.network_ipv6_sample)
        new_vlan = 321
        network_ipv6_sample_id = self.network_ipv6_sample.id
        self.network_ipv6_sample.vlan = new_vlan
        clean_and_save(self.network_ipv6_sample)
        updated_vlan = Network.objects.get(pk=network_ipv6_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_delete_network(self):
        """Test that the model is able to delete a Network."""
        clean_and_save(self.network_sample)
        old_count = Network.objects.count()
        self.network_sample.delete()
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_ipv6_network(self):
        """Test that the model is able to delete a Network."""
        clean_and_save(self.network_ipv6_sample)
        old_count = Network.objects.count()
        self.network_ipv6_sample.delete()
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_ipv6_quick_list_unused(self):
        # Github issue https://github.com/unioslo/mreg/issues/435
        n = Network(network="2001:DB8:BAD:BAD::/64", description="a description")
        clean_and_save(n)
        # Create one large excluded range at the start and one at the end
        clean_and_save(
            NetworkExcludedRange(
                network=n,
                start_ip="2001:DB8:BAD:BAD::0",
                end_ip="2001:DB8:BAD:BAD::ffff:ffff:ffff",
            )
        )

        clean_and_save(
            NetworkExcludedRange(
                network=n,
                start_ip="2001:DB8:BAD:BAD:2:0:0:0",
                end_ip="2001:DB8:BAD:BAD:ffff:ffff:ffff:ffff",
            )
        )
        unused_count_should_be = 0x1000000000000 - len(n.get_reserved_ipaddresses())

        def handler(signum, frame):  # pragma: no cover
            raise Exception("timeout")

        signal.signal(signal.SIGALRM, handler)
        signal.alarm(5)
        # The following calls will take too long and cause a timeout exception if they aren't implemented correctly.
        self.assertEqual(len(n.unused_addresses), MAX_UNUSED_LIST)
        self.assertEqual(n.unused_count, unused_count_should_be)
        self.assertNotEqual(n.get_first_unused(), None)
        self.assertNotEqual(n.get_random_unused(), None)
        signal.alarm(0)  # Cancel the timer if no exception happened

    def test_excluded_ranges(self):
        """Test that exclusion of IP address ranges work"""
        clean_and_save(self.network_sample)  # 10.0.0.0/20
        clean_and_save(
            NetworkExcludedRange(
                network=self.network_sample, start_ip="10.0.0.0", end_ip="10.0.0.200"
            )
        )
        ip = self.network_sample.get_first_unused()
        self.assertEqual(str(ip), "10.0.0.201")
        clean_and_save(
            NetworkExcludedRange(
                network=self.network_sample, start_ip="10.0.0.202", end_ip="10.0.15.255"
            )
        )
        unused = self.network_sample.get_unused_ipaddresses()
        self.assertEqual(unused, {ipaddress.IPv4Address("10.0.0.201")})
        ip = self.network_sample.get_random_unused()
        self.assertEqual(str(ip), "10.0.0.201")
