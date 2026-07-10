from unittest import mock

from django.test import TestCase, override_settings
from rest_framework import serializers

from mreg.api.errors import ValidationError409
from mreg.api.v1.serializers import (
    CommunitySerializer,
    HostSerializer,
    NetworkPolicyAttributeValueSerializer,
    NetworkPolicySerializer,
)
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network
from mreg.models.network_policy import (
    Community,
    NetworkPolicy,
    NetworkPolicyAttribute,
    NetworkPolicyAttributeValue,
)


class CommunitySerializerTests(TestCase):
    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=True)
    def test_global_name_requires_network(self):
        serializer = CommunitySerializer()

        class DummyCommunity:
            def __str__(self):
                return "orphan"

            network = None

        with self.assertRaises(ValueError):
            serializer.get_global_name(DummyCommunity())

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=True)
    def test_global_name_missing_in_network(self):
        network = Network.objects.create(
            network="10.0.0.0/30",
            description="net",
            vlan=1,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
        )
        Community.objects.create(name="first", description="", network=network)
        serializer = CommunitySerializer()
        ghost = Community(name="ghost", description="", network=network)

        with self.assertRaises(ValueError):
            serializer.get_global_name(ghost)

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=True, MREG_MAX_COMMUNITES_PER_NETWORK=1)
    def test_global_name_index_exceeds_max(self):
        network = Network.objects.create(
            network="10.0.0.0/30",
            description="net",
            vlan=1,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
        )
        Community.objects.create(name="first", description="", network=network)
        # Use bulk_create to bypass max-community validation so we can exercise the serializer branch
        (second,) = Community.objects.bulk_create([
            Community(name="second", description="", network=network)
        ])
        serializer = CommunitySerializer()

        with self.assertRaises(ValueError):
            serializer.get_global_name(second)

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=True, MREG_MAX_COMMUNITES_PER_NETWORK=None)
    def test_global_name_default_padding(self):
        network = Network.objects.create(
            network="10.0.0.0/30",
            description="net",
            vlan=1,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
        )
        community = Community.objects.create(name="first", description="", network=network)
        serializer = CommunitySerializer()

        self.assertEqual(serializer.get_global_name(community), "community01")


class HostSerializerTests(TestCase):
    def test_validate_rejects_existing_host(self):
        host = Host.objects.create(name="host.example")
        serializer = HostSerializer(data={"name": host.name})

        with self.assertRaises(ValidationError409):
            serializer.validate({"name": host.name})

    def test_create_uses_deprecated_contact_and_invalid_ip_raises(self):
        serializer = HostSerializer()
        serializer.initial_data = {"contact": "user@example.com"}
        validated_data = {
            "name": "with-invalid-ip",
            "contact": "user@example.com",
            "ipaddress": "not-an-ip",
        }

        with self.assertRaises(serializers.ValidationError):
            serializer.create(validated_data)

    def test_create_adds_contacts_from_string_and_ip(self):
        serializer = HostSerializer()
        serializer.initial_data = {"contacts": "new@example.com"}
        validated_data = {"name": "host-with-contact", "ipaddress": "10.0.0.2"}

        host = serializer.create(validated_data)

        self.assertEqual(host.get_contact_emails(), ["new@example.com"])
        self.assertTrue(Ipaddress.objects.filter(host=host, ipaddress="10.0.0.2").exists())

    def test_create_adds_contacts_from_list(self):
        serializer = HostSerializer()
        serializer.initial_data = {"contacts": ["a@example.com", "b@example.com"]}
        validated_data = {"name": "host-with-contacts-list"}

        host = serializer.create(validated_data)

        self.assertCountEqual(host.get_contact_emails(), ["a@example.com", "b@example.com"])

    def test_create_assigns_community_when_provided(self):
        serializer = HostSerializer()
        serializer._assign_community = mock.Mock()
        serializer.initial_data = {}
        community = Community(name="comm", description="", network=None)

        host = serializer.create({"name": "host-community.example", "communities": community})

        serializer._assign_community.assert_called_once_with(host, community)

    def test_update_replaces_contacts_from_raw_string_and_skips_contact_field(self):
        host = Host.objects.create(name="host-update.example")
        host._add_contact("old@example.com")
        serializer = HostSerializer(instance=host)
        serializer.initial_data = {"contacts": "new@example.com"}
        validated_data = {"contacts": ["should-be-ignored"], "comment": "updated"}

        updated = serializer.update(host, validated_data)

        self.assertEqual(updated.comment, "updated")
        self.assertEqual(updated.get_contact_emails(), ["new@example.com"])

    def test_update_invalid_ip_raises_error(self):
        host = Host.objects.create(name="host-ip.example")
        serializer = HostSerializer(instance=host)
        serializer.initial_data = {}

        with self.assertRaises(serializers.ValidationError):
            serializer.update(host, {"ipaddress": "bad-ip"})

    def test_update_adds_ipaddress(self):
        host = Host.objects.create(name="host-ip-add.example")
        serializer = HostSerializer(instance=host)
        serializer.initial_data = {}

        serializer.update(host, {"ipaddress": "10.0.0.9"})

        self.assertTrue(Ipaddress.objects.filter(host=host, ipaddress="10.0.0.9").exists())

    def test_update_calls_assign_and_unassign_branches(self):
        host = Host.objects.create(name="branch.example")
        serializer = HostSerializer(instance=host)
        serializer._assign_community = mock.Mock()
        serializer._unassign_community = mock.Mock()
        community = Community(name="comm", description="", network=None)

        serializer.initial_data = {}
        serializer.update(host, {"communities": community})
        serializer.update(host, {"communities": []})

        serializer._assign_community.assert_called_once_with(host, community)
        serializer._unassign_community.assert_called_once_with(host, [])

    def test_assign_community_requires_policy(self):
        host = Host.objects.create(name="assign-no-policy.example")
        Ipaddress.objects.create(host=host, ipaddress="10.0.0.3")
        network = Network.objects.create(
            network="10.0.0.0/30",
            description="net",
            vlan=1,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
        )
        community = Community(name="no-policy", description="", network=network)
        community.policy = None
        serializer = HostSerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer._assign_community(host, community)

    def test_assign_community_rejects_incompatible_ip(self):
        host = Host.objects.create(name="assign-fail.example")
        Ipaddress.objects.create(host=host, ipaddress="10.0.1.1")
        policy = NetworkPolicy.objects.create(name="policy-one", description="")
        community_network = Network.objects.create(
            network="10.0.2.0/30",
            description="net2",
            vlan=2,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
            policy=policy,
        )
        community = Community(name="comm", description="", network=community_network)
        community.policy = policy
        serializer = HostSerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer._assign_community(host, community)

    def test_assign_community_adds_mapping(self):
        host = Host.objects.create(name="assign-ok.example")
        Ipaddress.objects.create(host=host, ipaddress="10.0.3.1", macaddress="aa:bb:cc:00:11:22")
        policy = NetworkPolicy.objects.create(name="policy-two", description="")
        network = Network.objects.create(
            network="10.0.3.0/30",
            description="net3",
            vlan=3,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
            policy=policy,
        )
        community = Community.objects.create(name="comm", description="", network=network)
        community.policy = policy
        serializer = HostSerializer()

        serializer._assign_community(host, community)

        self.assertTrue(host.communities.filter(pk=community.pk).exists())

    def test_unassign_community_removes_mapping(self):
        host = Host.objects.create(name="unassign.example")
        Ipaddress.objects.create(host=host, ipaddress="10.0.4.1", macaddress="aa:bb:cc:22:33:44")
        policy = NetworkPolicy.objects.create(name="policy-three", description="")
        network = Network.objects.create(
            network="10.0.4.0/30",
            description="net4",
            vlan=4,
            dns_delegated=False,
            category="cat",
            location="loc",
            frozen=False,
            policy=policy,
        )
        community = Community.objects.create(name="comm", description="", network=network)
        host.add_to_community(community)
        serializer = HostSerializer()

        serializer._unassign_community(host, community)

        self.assertFalse(host.communities.filter(pk=community.pk).exists())


class NetworkPolicyAttributeValueSerializerTests(TestCase):
    def test_create_missing_attribute_raises(self):
        serializer = NetworkPolicyAttributeValueSerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer.create({"name": "missing", "value": True})

    def test_create_without_policy_context_raises(self):
        attr = NetworkPolicyAttribute.objects.create(name="attr", description="")
        serializer = NetworkPolicyAttributeValueSerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer.create({"name": attr.name, "value": True})

    def test_update_missing_attribute_raises(self):
        attr = NetworkPolicyAttribute.objects.create(name="attr", description="")
        policy = NetworkPolicy.objects.create(name="policy", description="")
        value = NetworkPolicyAttributeValue.objects.create(
            policy=policy, attribute=attr, value=False
        )
        serializer = NetworkPolicyAttributeValueSerializer(instance=value)

        with self.assertRaises(serializers.ValidationError):
            serializer.update(value, {"name": "missing", "value": True})

    def test_update_with_existing_attribute_changes_attribute(self):
        attr_one = NetworkPolicyAttribute.objects.create(name="one", description="")
        attr_two = NetworkPolicyAttribute.objects.create(name="two", description="")
        policy = NetworkPolicy.objects.create(name="policy-update-attr", description="")
        value = NetworkPolicyAttributeValue.objects.create(
            policy=policy, attribute=attr_one, value=False
        )
        serializer = NetworkPolicyAttributeValueSerializer(instance=value)

        updated = serializer.update(value, {"name": attr_two.name, "value": True})

        self.assertEqual(updated.attribute, attr_two)
        self.assertTrue(updated.value)


class NetworkPolicySerializerTests(TestCase):
    def test_validate_name_duplicate_on_create(self):
        existing = NetworkPolicy.objects.create(name="dupe", description="")
        serializer = NetworkPolicySerializer(data={"name": existing.name, "description": ""})

        with self.assertRaises(serializers.ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_validate_name_duplicate_on_create_direct(self):
        existing = NetworkPolicy.objects.create(name="dupe-direct", description="")
        serializer = NetworkPolicySerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer.validate_name(existing.name)

    def test_validate_name_duplicate_on_update(self):
        first = NetworkPolicy.objects.create(name="first", description="")
        second = NetworkPolicy.objects.create(name="second", description="")
        serializer = NetworkPolicySerializer(instance=first, data={"name": second.name, "description": ""})

        with self.assertRaises(serializers.ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_validate_name_duplicate_on_update_direct(self):
        first = NetworkPolicy.objects.create(name="first-direct", description="")
        second = NetworkPolicy.objects.create(name="second-direct", description="")
        serializer = NetworkPolicySerializer(instance=first)

        with self.assertRaises(serializers.ValidationError):
            serializer.validate_name(second.name)

    def test_validate_attributes_requires_list(self):
        serializer = NetworkPolicySerializer(
            data={"name": "attr", "description": "", "attributes": "not-a-list"}
        )

        with self.assertRaises(serializers.ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_validate_attributes_requires_list_direct(self):
        serializer = NetworkPolicySerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer.validate_attributes("not-a-list")

    def test_validate_attributes_elements_must_be_dicts(self):
        serializer = NetworkPolicySerializer(
            data={"name": "attr2", "description": "", "attributes": [1, 2]}
        )

        with self.assertRaises(serializers.ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_validate_attributes_elements_must_be_dicts_direct(self):
        serializer = NetworkPolicySerializer()

        with self.assertRaises(serializers.ValidationError):
            serializer.validate_attributes([1, 2])

    def test_validate_attributes_missing_attribute_definitions(self):
        serializer = NetworkPolicySerializer(
            data={
                "name": "attr3",
                "description": "",
                "attributes": [{"name": "missing", "value": True}],
            }
        )

        with self.assertRaises(serializers.ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_update_recreates_attribute_values(self):
        attr_one = NetworkPolicyAttribute.objects.create(name="one", description="")
        attr_two = NetworkPolicyAttribute.objects.create(name="two", description="")
        policy = NetworkPolicy.objects.create(name="policy-update", description="")
        NetworkPolicyAttributeValue.objects.create(policy=policy, attribute=attr_one, value=False)
        serializer = NetworkPolicySerializer(
            instance=policy,
            data={
                "name": policy.name,
                "description": policy.description,
                "attributes": [
                    {"name": attr_one.name, "value": True},
                    {"name": attr_two.name, "value": False},
                ],
            },
            partial=True,
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        values = {
            (v.attribute.name, v.value)
            for v in NetworkPolicyAttributeValue.objects.filter(policy=policy)
        }
        self.assertEqual(values, {("one", True), ("two", False)})
