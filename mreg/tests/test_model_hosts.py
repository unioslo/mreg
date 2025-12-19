# pyright: reportAttributeAccessIssue=false
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from rest_framework.exceptions import NotAcceptable

from mreg.models.host import Host, Ipaddress, BACnetID, PtrOverride, HostGroup
from mreg.models.network import Network
from mreg.models.network_policy import Community, HostCommunityMapping

from .base import clean_and_save


class ModelHostsTestCase(TestCase):
    """This class defines the test suite for the Host model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(
            name="host.example.org",
            ttl=300,
            comment="some comment",
        )

    def assert_validation_error(self, obj):
        with self.assertRaises(ValidationError):
            obj.full_clean()

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Host.objects.count()
        clean_and_save(self.host_one)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)
        str(self.host_one)

    def test_model_can_create_without_contact(self):
        old_count = Host.objects.count()
        host = Host(name="host2.example.org")
        clean_and_save(host)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)

    def test_can_create_wildcard_host(self):
        Host(name="*.example.org").full_clean()
        Host(name="*.sub.example.org").full_clean()

    def test_model_case_insesitive(self):
        """Hosts names must be case insensitive"""
        clean_and_save(self.host_one)
        self.assertEqual(
            self.host_one, Host.objects.get(name=self.host_one.name.upper())
        )
        upper = Host(name=self.host_one.name.upper())
        with self.assertRaises(ValidationError) as context:
            clean_and_save(upper)
        self.assertEqual(
            context.exception.messages, ["Host with this Name already exists."]
        )
        hostname = "UPPERCASE.EXAMPLE.ORG"
        host = Host.objects.create(name=hostname)
        # Must do a refresh_from_db() as host.name is otherwise the unmodfied
        # uppercase hostname.
        host.refresh_from_db()
        self.assertEqual(host.name, hostname.lower())

    def test_reject_bad_host_names(self):
        def _assert(hostname):
            host = Host(name=hostname)
            self.assert_validation_error(host)

        _assert("host..example.org")
        _assert("host.example.org.")
        _assert("host-.example.org")
        _assert(
            "looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.example.org"
        )
        _assert("host*.example.org")
        _assert("host--1.example.org")

    def test_model_can_change_a_host(self):
        """Test that the model is able to change a host."""
        clean_and_save(self.host_one)
        old_name = self.host_one.name
        new_name = "some-new-host.example.org"
        host_sample_id = Host.objects.get(name=old_name).id # type: ignore
        self.host_one.name = new_name
        clean_and_save(self.host_one)
        updated_name = Host.objects.get(pk=host_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_host(self):
        """Test that the model is able to delete a host."""
        clean_and_save(self.host_one)
        old_count = Host.objects.count()
        self.host_one.delete()
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelHostCommunitiesTestCase(TestCase):
    """Test suite for Host community management methods."""

    def setUp(self):
        """Set up test networks, hosts, and communities."""
        # Create networks
        self.network1 = Network.objects.create(network="10.0.1.0/24", description="Test Network 1")
        self.network2 = Network.objects.create(network="10.0.2.0/24", description="Test Network 2")
        
        # Create communities
        self.community1_net1 = Community.objects.create(
            name="community1", description="Community 1 on Network 1", network=self.network1
        )
        self.community2_net1 = Community.objects.create(
            name="community2", description="Community 2 on Network 1", network=self.network1
        )
        self.community1_net2 = Community.objects.create(
            name="community1", description="Community 1 on Network 2", network=self.network2
        )
        
        # Create host with multiple IPs
        self.host = Host.objects.create(name="testhost.example.org", contact="test@example.org")
        self.ip1 = Ipaddress.objects.create(host=self.host, ipaddress="10.0.1.10", macaddress="aa:bb:cc:dd:ee:01")
        self.ip2 = Ipaddress.objects.create(host=self.host, ipaddress="10.0.2.10", macaddress="aa:bb:cc:dd:ee:02")

    def test_add_to_community_with_community_instance_and_ip(self):
        """Test adding host to community using Community instance with explicit IP."""
        self.host.add_to_community(self.community1_net1, self.ip1)
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_with_community_instance_no_ip_single_match(self):
        """Test adding host to community using Community instance without IP (single network match)."""
        # Remove second IP so only one IP matches
        self.ip2.delete()
        
        self.host.add_to_community(self.community1_net1)
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_with_community_instance_no_match(self):
        """Test error when community network doesn't match any host IP."""
        # Create a community on a different network
        network3 = Network.objects.create(network="10.0.3.0/24", description="Test Network 3")
        community3 = Community.objects.create(name="community3", description="Community 3", network=network3)
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(community3)
        self.assertIn("No IP address on host matches the community's network", str(context.exception))

    def test_add_to_community_with_community_instance_multiple_matches(self):
        """Test error when multiple IPs match community network (ambiguous)."""
        # Add another IP on the same network
        _ip3 = Ipaddress.objects.create(host=self.host, ipaddress="10.0.1.11", macaddress="aa:bb:cc:dd:ee:03")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(self.community1_net1)
        self.assertIn("Multiple IP addresses match the community's network", str(context.exception))

    def test_add_to_community_with_community_instance_wrong_ip(self):
        """Test error when provided IP doesn't belong to host."""
        other_host = Host.objects.create(name="other.example.org")
        other_ip = Ipaddress.objects.create(host=other_host, ipaddress="10.0.1.20", macaddress="aa:bb:cc:dd:ee:04")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(self.community1_net1, other_ip)
        self.assertIn("Provided IP address does not belong to this host", str(context.exception))

    def test_add_to_community_with_community_instance_network_mismatch(self):
        """Test error when community network doesn't match provided IP network."""
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(self.community1_net1, self.ip2)  # ip2 is on network2
        self.assertIn("Community network does not match the network of the provided IP address", str(context.exception))

    def test_add_to_community_with_string_and_ip(self):
        """Test adding host to community using string name with explicit IP."""
        self.host.add_to_community("community1", self.ip1)
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_with_string_no_ip_single_match(self):
        """Test adding host to community using string name without IP (single network match)."""
        # Remove second IP so only one IP matches
        self.ip2.delete()
        
        self.host.add_to_community("community1")
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_with_string_wrong_ip(self):
        """Test error when provided IP doesn't belong to host (string community)."""
        other_host = Host.objects.create(name="other.example.org")
        other_ip = Ipaddress.objects.create(host=other_host, ipaddress="10.0.1.20", macaddress="aa:bb:cc:dd:ee:04")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("community1", other_ip)
        self.assertIn("Provided IP address does not belong to this host", str(context.exception))

    def test_add_to_community_with_string_no_network(self):
        """Test error when IP has no network (string community)."""
        # Create IP outside of any network
        orphan_ip = Ipaddress.objects.create(host=self.host, ipaddress="192.168.255.1", macaddress="aa:bb:cc:dd:ee:05")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("community1", orphan_ip)
        self.assertIn("No network found for the provided IP address", str(context.exception))

    def test_add_to_community_with_string_community_not_found(self):
        """Test error when community name not found on network."""
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("nonexistent", self.ip1)
        self.assertIn("No community named 'nonexistent' found", str(context.exception))

    def test_add_to_community_with_string_no_ip_no_match(self):
        """Test error when no host IP matches community name."""
        # Create a community on a different network
        network3 = Network.objects.create(network="10.0.3.0/24", description="Test Network 3")
        Community.objects.create(name="community3", description="Community 3", network=network3)
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("community3")
        self.assertIn("No community named 'community3' found on any IP network for this host", str(context.exception))

    def test_add_to_community_with_string_ambiguous(self):
        """Test error when community name exists on multiple networks."""
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("community1")  # exists on both network1 and network2
        self.assertIn("Community name 'community1' is ambiguous across multiple networks", str(context.exception))

    def test_add_to_community_with_string_ip_as_string(self):
        """Test adding with community name and IP as string."""
        self.host.add_to_community("community1", "10.0.1.10")
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_with_string_ip_string_not_found(self):
        """Test error when IP string doesn't match any host IP."""
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community("community1", "10.0.1.99")
        self.assertIn("No IP address found on this host with the provided value", str(context.exception))

    def test_add_to_community_no_ips(self):
        """Test error when host has no IP addresses."""
        empty_host = Host.objects.create(name="empty.example.org")
        
        with self.assertRaises(NotAcceptable) as context:
            empty_host.add_to_community(self.community1_net1)
        self.assertIn("Host has no IP addresses, cannot add to community", str(context.exception))

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=True)
    def test_add_to_community_mac_required_missing(self):
        """Test error when MAC address is required but missing."""
        # Create IP without MAC
        ip_no_mac = Ipaddress.objects.create(host=self.host, ipaddress="10.0.1.12")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(self.community1_net1, ip_no_mac)
        self.assertIn("The IP must have a MAC address to bind it to a community", str(context.exception))

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=True)
    def test_add_to_community_mac_required_present(self):
        """Test successful add when MAC address is required and present."""
        self.host.add_to_community(self.community1_net1, self.ip1)
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_replaces_existing_on_same_network(self):
        """Test that adding to a new community replaces existing mapping on same network."""
        # First add to community1
        self.host.add_to_community(self.community1_net1, self.ip1)
        
        # Now add to community2 on the same network
        self.host.add_to_community(self.community2_net1, self.ip1)
        
        # Should only have one mapping for this IP
        mappings = HostCommunityMapping.objects.filter(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mappings.count(), 1)
        self.assertEqual(mappings.first().community, self.community2_net1)

    def test_remove_from_community_success(self):
        """Test successfully removing host from community."""
        self.host.add_to_community(self.community1_net1, self.ip1)
        
        self.host.remove_from_community(self.community1_net1, self.ip1)
        
        mapping_exists = HostCommunityMapping.objects.filter(
            host=self.host, ipaddress=self.ip1, community=self.community1_net1
        ).exists()
        self.assertFalse(mapping_exists)

    def test_remove_from_community_not_found(self):
        """Test error when trying to remove non-existent mapping."""
        with self.assertRaises(NotAcceptable) as context:
            self.host.remove_from_community(self.community1_net1, self.ip1)
        self.assertIn("No community mapping exists for this host with the specified criteria", str(context.exception))

    def test_remove_from_community_with_string(self):
        """Test removing host from community using string name."""
        self.host.add_to_community("community1", self.ip1)
        
        self.host.remove_from_community("community1", self.ip1)
        
        mapping_exists = HostCommunityMapping.objects.filter(
            host=self.host, ipaddress=self.ip1, community=self.community1_net1
        ).exists()
        self.assertFalse(mapping_exists)

    def test_add_to_community_instance_ip_not_in_network(self):
        """Test when IP is not in any network (Community instance case)."""
        # Create IP outside of any network
        orphan_ip = Ipaddress.objects.create(host=self.host, ipaddress="192.168.255.1", macaddress="aa:bb:cc:dd:ee:05")
        
        with self.assertRaises(NotAcceptable) as context:
            self.host.add_to_community(self.community1_net1, orphan_ip)
        self.assertIn("No network found for the provided IP address", str(context.exception))

    def test_add_to_community_instance_multiple_ips_one_not_in_network(self):
        """Test multiple IPs where one is not in a network (should skip and find match)."""
        # Add an IP outside of any network
        _orphan_ip = Ipaddress.objects.create(host=self.host, ipaddress="192.168.255.1", macaddress="aa:bb:cc:dd:ee:05")
        # Remove ip2 so we only have ip1 in network1
        self.ip2.delete()
        
        # Should still work because ip1 is in network1
        self.host.add_to_community(self.community1_net1)
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)

    def test_add_to_community_string_multiple_ips_one_not_in_network(self):
        """Test string community with multiple IPs where one is not in a network."""
        # Add an IP outside of any network
        _orphan_ip = Ipaddress.objects.create(host=self.host, ipaddress="192.168.255.1", macaddress="aa:bb:cc:dd:ee:05")
        # Remove ip2 so we only have ip1 in network1
        self.ip2.delete()
        
        # Should still work because ip1 is in network1
        self.host.add_to_community("community1")
        
        mapping = HostCommunityMapping.objects.get(host=self.host, ipaddress=self.ip1)
        self.assertEqual(mapping.community, self.community1_net1)


class ModelPtrOverrideTestCase(TestCase):
    """Test suite for PtrOverride model."""

    def setUp(self):
        """Set up test host."""
        self.host = Host.objects.create(name="test.example.org", contact="test@example.org")

    def test_ptroverride_str(self):
        """Test PtrOverride __str__ method."""
        ptr = PtrOverride.objects.create(host=self.host, ipaddress="10.0.0.1")
        self.assertEqual(str(ptr), "10.0.0.1 -> test.example.org")


class ModelHostGroupTestCase(TestCase):
    """Test suite for HostGroup model."""

    def test_hostgroup_str(self):
        """Test HostGroup __str__ method."""
        group = HostGroup.objects.create(name="testgroup", description="Test Group")
        self.assertEqual(str(group), "testgroup")


class ModelBACnetIDTestCase(TestCase):
    """Test suite for BACnetID model."""

    def setUp(self):
        """Set up test host."""
        self.host = Host.objects.create(name="bacnet.example.org", contact="test@example.org")

    def test_bacnetid_creation(self):
        """Test creating a BACnetID."""
        bacnet = BACnetID.objects.create(id=100, host=self.host)
        self.assertEqual(bacnet.id, 100)
        self.assertEqual(bacnet.host, self.host)
        self.assertEqual(bacnet.hostname, "bacnet.example.org")

    def test_first_unused_id_empty(self):
        """Test finding first unused ID when no IDs exist."""
        first_id = BACnetID.first_unused_id()
        self.assertEqual(first_id, 0)

    def test_first_unused_id_sequential(self):
        """Test finding first unused ID with sequential IDs."""
        host1 = Host.objects.create(name="host1.example.org")
        host2 = Host.objects.create(name="host2.example.org")
        host3 = Host.objects.create(name="host3.example.org")
        
        BACnetID.objects.create(id=0, host=host1)
        BACnetID.objects.create(id=1, host=host2)
        BACnetID.objects.create(id=2, host=host3)
        
        first_id = BACnetID.first_unused_id()
        self.assertEqual(first_id, 3)

    def test_first_unused_id_with_gap(self):
        """Test finding first unused ID when there's a gap."""
        host1 = Host.objects.create(name="host1.example.org")
        host2 = Host.objects.create(name="host2.example.org")
        host3 = Host.objects.create(name="host3.example.org")
        
        BACnetID.objects.create(id=0, host=host1)
        BACnetID.objects.create(id=1, host=host2)
        # Skip 2
        BACnetID.objects.create(id=3, host=host3)
        
        first_id = BACnetID.first_unused_id()
        self.assertEqual(first_id, 2)

    def test_first_unused_id_gap_at_start(self):
        """Test finding first unused ID when gap is at the start."""
        host1 = Host.objects.create(name="host1.example.org")
        host2 = Host.objects.create(name="host2.example.org")
        
        BACnetID.objects.create(id=5, host=host1)
        BACnetID.objects.create(id=10, host=host2)
        
        first_id = BACnetID.first_unused_id()
        self.assertEqual(first_id, 0)
