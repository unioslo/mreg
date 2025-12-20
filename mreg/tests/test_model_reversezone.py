from django.core.exceptions import ValidationError
from django.test import TestCase
from mreg.models.host import Host, Ipaddress, PtrOverride
from mreg.models.zone import ReverseZone, ForwardZone

from .base import clean_and_save


class ModelReverseZoneTestCase(TestCase):
    """This class defines the test suite for the ReverseZone model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_v4 = ReverseZone(
            name="0.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        self.zone_v6 = ReverseZone(
            name="8.b.d.0.1.0.0.2.ip6.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )

    def assert_validation_error(self, obj):
        with self.assertRaises(ValidationError):
            obj.full_clean()

    def test_model_can_create_a_ipv4_zone(self):
        """Test that the model is able to create a ipv4 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v4)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.zone_v4)

    def test_model_can_create_a_ipv6_zone(self):
        """Test that the model is able to create a ipv6 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v6)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_reject_invalid_names(self):
        def _assert(name):
            zone = ReverseZone(
                name=name, primary_ns="ns.example.org", email="hostmaster@example.org"
            )
            self.assert_validation_error(zone)

        _assert("x.8.d.0.1.0.0.2.ip6.arpa")
        _assert(
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.0.1.0.0.2.ip6.arpa"
        )

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        clean_and_save(self.zone_v4)
        clean_and_save(self.zone_v6)
        self.zone_v4.delete()
        self.zone_v6.delete()

    def test_model_rfc2317_valid_names(self):
        """Test that the model can handle RFC 2317 zone names"""
        zone_1 = ReverseZone(
            name="0/25.0.0.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        zone_2 = ReverseZone(
            name="0/32.0.1.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(zone_1)
        clean_and_save(zone_2)

    def test_model_rfc2317_invalid_names(self):
        """Test that the model rejects too large delegations.
        RFC 2317 requires maximum of /25"""
        zone = ReverseZone(
            name="0/24.0.0.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        with self.assertRaises(ValidationError) as context:
            clean_and_save(zone)
        self.assertEqual(
            context.exception.messages, ["Maximum CIDR for RFC 2317 is 25"]
        )

    def test_get_ipaddresses_wildcard_rejection(self):
        """Test that hostnames with wildcards are rejected in PTR records."""
        # Create a forward zone and reverse zone
        forward_zone = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(forward_zone)
        
        reverse_zone = ReverseZone(
            name="0.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(reverse_zone)
        
        # Create a host with a wildcard name
        wildcard_host = Host(name="*.example.org", zone=forward_zone)
        clean_and_save(wildcard_host)
        
        # Create an IP address for the wildcard host
        ip = Ipaddress(host=wildcard_host, ipaddress="10.0.1.1")
        clean_and_save(ip)
        
        # Get PTR records from the reverse zone
        result = reverse_zone.get_ipaddresses()
        
        # The wildcard host should not appear in the results (line 222 hit)
        hostnames = [r[2] for r in result]
        self.assertNotIn("*.example.org", hostnames)

    def test_get_ipaddresses_standalone_ptr_override(self):
        """Test that standalone PtrOverride entries are included."""
        # Create zones
        forward_zone = ForwardZone(
            name="example.org",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(forward_zone)
        
        reverse_zone = ReverseZone(
            name="0.10.in-addr.arpa",
            primary_ns="ns.example.org",
            email="hostmaster@example.org",
        )
        clean_and_save(reverse_zone)
        
        # Create a host without any IP addresses
        host = Host(name="external.example.org", zone=forward_zone)
        clean_and_save(host)
        
        # Create a PtrOverride for an IP that doesn't have an Ipaddress object
        ptr = PtrOverride(host=host, ipaddress="10.0.3.1")
        clean_and_save(ptr)
        
        # Get PTR records from the reverse zone
        result = reverse_zone.get_ipaddresses()
        
        # The standalone PtrOverride should appear in the results (line 242 hit)
        ips_and_hosts = [(str(r[0]), r[2]) for r in result]
        self.assertIn(("10.0.3.1", "external.example.org"), ips_and_hosts)
