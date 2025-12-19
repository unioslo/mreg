import urllib.parse

from unittest_parametrize import ParametrizedTestCase, param, parametrize
from django.db import transaction
from django.test import override_settings
from django.contrib.auth.models import Group

from mreg.utils import is_protected_policy_attribute

from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, NetworkPolicyAttributeValue, Community
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network, NetGroupRegexPermission

from .tests import MregAPITestCase

POLICY_ENDPOINT = "/api/v1/networkpolicies/"
ATTRIBUTE_ENDPOINT = "/api/v1/networkpolicyattributes/"
NETWORK_ENDPOINT = "/api/v1/networks/"

class NetworkPolicyTestCase(ParametrizedTestCase, MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.set_client_format_json()

    def _create_network_policy(self, name: str, attributes: list[tuple[str, bool]]) -> NetworkPolicy:
        with transaction.atomic():
            np = NetworkPolicy.objects.create(name=name)
            for attribute in attributes: # pragma: no cover
                NetworkPolicyAttributeValue.objects.create(
                    policy=np, attribute=NetworkPolicyAttribute.objects.get(name=attribute[0]), value=attribute[1]
                )
            return np

    def _delete_network_policy(self, name: str):
        NetworkPolicy.objects.get(name=name).delete()

    def _create_attributes(self, names: list[str]):
        for name in names:
            # Skip protected attributes, they are already created
            if is_protected_policy_attribute(name):
                continue
            self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data={"name": name, "description": f"{name} desc"})

    def _delete_attributes(self, names: list[str]):
        for name in names:
            # Skip protected attributes, they cannot be deleted
            if is_protected_policy_attribute(name):
                continue
            NetworkPolicyAttribute.objects.get(name=name).delete()

    def _create_community(self, name: str, description: str, network: Network) -> Community:
        return Community.objects.create(name=name, description=description, network=network)

    def _get_protected_attribute_isolated(self) -> NetworkPolicyAttribute:
        return NetworkPolicyAttribute.objects.get(name="isolated")
    
    def _get_protected_attribute(self, name: str) -> NetworkPolicyAttribute:
        return NetworkPolicyAttribute.objects.get(name=name)

    def test_isolated_attribute_protected_exists(self):
        """Test that the isolated attribute is protected and exists."""
        self.assertIsNotNone(self._get_protected_attribute_isolated())

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=["isolated"])
    def test_create_attribute_protected_409(self):
        """Test creating a protected network policy attribute."""
        data = {"name": "isolated", "description": "attribute desc"}
        self.assert_post_and_409(ATTRIBUTE_ENDPOINT, data=data)

        data["name"] = data["name"].upper()
        self.assert_post_and_409(ATTRIBUTE_ENDPOINT, data=data)

    def test_delete_attribute_protected_403(self):
        """Test deleting a protected network policy attribute."""
        isolated = self._get_protected_attribute_isolated()
        self.assert_delete_and_403(f"{ATTRIBUTE_ENDPOINT}{isolated.pk}")

    def test_patch_attribute_protected_name_403(self):
        """Test updating a protected network policy attribute."""
        isolated = self._get_protected_attribute_isolated()
        data = {"name": "new_attribute", "description": "new attribute desc"}
        self.assert_patch_and_403(f"{ATTRIBUTE_ENDPOINT}{isolated.pk}", data=data)

    def test_patch_attribute_protected_description_201(self):
        """Test updating a protected network policy attribute."""
        isolated = self._get_protected_attribute_isolated()
        data = {"description": "new attribute desc"}
        self.assert_patch_and_200(f"{ATTRIBUTE_ENDPOINT}{isolated.pk}", data=data)

    def test_create_attribute(self):
        """Test creating a network policy attribute."""
        data = {"name": "attribute", "description": "attribute desc"}
        ret = self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data=data)
        self.assertEqual(ret.json()["name"], "attribute")
        self.assertEqual(ret.json()["description"], "attribute desc")

        self._delete_attributes(["attribute"])

    def test_create_attribute_duplicate_name_409(self):
        """Test creating a network policy attribute with a duplicate name."""
        data = {"name": "attribute", "description": "attribute desc"}
        self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data=data)
        self.assert_post_and_409(ATTRIBUTE_ENDPOINT, data=data)

        data["name"] = data["name"].upper()
        self.assert_post_and_409(ATTRIBUTE_ENDPOINT, data=data)

        self._delete_attributes(["attribute"])

    def test_create_attribute_no_name_400(self):
        """Test creating a network policy attribute without a name."""
        data = {"description": "attribute desc"}
        self.assert_post_and_400(ATTRIBUTE_ENDPOINT, data=data)

    def test_get_attribute(self):
        """Test getting a network policy attribute."""
        data = {"name": "attribute", "description": "attribute desc"}
        ret = self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data=data)
        attribute_id = ret.json()["id"]

        ret = self.assert_get(f"{ATTRIBUTE_ENDPOINT}{attribute_id}")
        self.assertEqual(ret.json()["name"], "attribute")
        self.assertEqual(ret.json()["description"], "attribute desc")

        self._delete_attributes(["attribute"])

    def test_delete_attribute(self):
        """Test deleting a network policy attribute."""
        data = {"name": "attribute", "description": "attribute desc"}
        ret = self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data=data)
        attribute_id = ret.json()["id"]

        self.assert_delete_and_204(f"{ATTRIBUTE_ENDPOINT}{attribute_id}")
    
    def test_patch_attribute(self):
        """Test updating a network policy attribute."""
        data = {"name": "attribute", "description": "attribute desc"}
        ret = self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data=data)
        attribute_id = ret.json()["id"]

        data = {"name": "new_attribute", "description": "new attribute desc"}
        ret = self.assert_patch_and_200(f"{ATTRIBUTE_ENDPOINT}{attribute_id}", data=data)
        self.assertEqual(ret.json()["name"], "new_attribute")
        self.assertEqual(ret.json()["description"], "new attribute desc")

        self._delete_attributes(["new_attribute"])

    def test_get_attribute_not_exists_404(self):
        """Test getting a network policy attribute that does not exist."""
        self.assert_get_and_404(f"{ATTRIBUTE_ENDPOINT}99999999")

    @parametrize(
        ("name", "attributes"),
        [
            param("policy_without_attributes", [], id="test_policy_no_attributes"),
            param("policy_with_t_attribute", [("isolated", True)], id="test_policy_with_t_attribute"),
            param(
                "policy_with_tf_attributes",
                [("isolated", True), ("public", False)],
                id="test_policy_with_tf_attributes",
            ),
            param(
                "policy_with_tft_attributes",
                [("isolated", True), ("public", False), ("private", True)],
                id="test_policy_with_tft_attributes",
            ),
        ],
    )
    def test_create_valid_np(self, name: str, attributes: list[tuple[str, bool]]):
        """Test creating a valid network policy."""
        data = {"name": name, "attributes": [{"name": attr[0], "value": attr[1]} for attr in attributes]}
        attribute_names = [attribute[0] for attribute in attributes]

        # Create the attributes named in the attributes list
        self._create_attributes(attribute_names)

        post_response = self.assert_post_and_201(POLICY_ENDPOINT, data=data)

        self.assertEqual(post_response.json()["name"], name)

        post_attributes = post_response.json()["attributes"]

        if attributes:
            for attribute in attributes:
                element_in_post = next((attr for attr in post_attributes if attr["name"] == attribute[0]), None)
                self.assertIsNotNone(element_in_post, f"Attribute {attribute[0]} not found in response")

                if element_in_post:
                    self.assertEqual(attribute[1], element_in_post["value"])

        location = post_response.headers["Location"]
        self.assertIsNotNone(location, "Location header not set")
        get_response = self.assert_get_and_200(location)

        self.assertEqual(get_response.json()["name"], name)

        self._delete_network_policy(name)
        self._delete_attributes(attribute_names)

    def test_set_description_on_network_policy(self):
        """Test setting a description on a network policy."""
        name = "policy_with_description"
        data = {"name": name, "attributes": []}
        res = self.assert_post_and_201(POLICY_ENDPOINT, data=data)
        id = res.json()["id"]

        data = {"description": "policy description"}
        res = self.assert_patch_and_200(f"{POLICY_ENDPOINT}{id}", data=data)
        self.assertEqual(res.json()["description"], "policy description")

        self._delete_network_policy(name)

    def test_create_policy_no_name_400(self):
        """Test creating a network policy without a name."""
        data = {"attributes": []}
        self.assert_post_and_400(POLICY_ENDPOINT, data=data)

    def test_delete_np(self):
        """Test deleting a network policy."""
        name = "policy_to_delete"
        np = self._create_network_policy(name, [])
        self.assert_delete_and_204(f"{POLICY_ENDPOINT}{np.pk}")

    def test_update_np(self):
        """Test updating a network policy."""
        name = "policy_to_update"
        np = self._create_network_policy(name, [])
        data = {"name": "new_name", "attributes": []}
        ret = self.assert_patch_and_200(f"{POLICY_ENDPOINT}{np.pk}", data=data)
        self.assertEqual(ret.json()["name"], "new_name")
        self._delete_network_policy("new_name")

    def test_duplicate_np_name_409(self):
        """Test creating a network policy with a duplicate name."""
        name = "policy_duplicate"
        data = {"name": name, "attributes": []}
        self.assert_post_and_201(POLICY_ENDPOINT, data=data)
        # Check exact match
        self.assert_post_and_409(POLICY_ENDPOINT, data=data)
        # Check case insensitivity
        data = {"name": name.upper(), "attributes": []}
        self.assert_post_and_409(POLICY_ENDPOINT, data=data)
        self._delete_network_policy(name)

    def test_assign_policy_to_network(self):
        """Test assigning a policy to a network."""
        np = self._create_network_policy("test_policy", [])
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        self.assert_patch_and_204(f"{NETWORK_ENDPOINT}{network.network}", data={"policy": np.pk})
        network = Network.objects.get(pk=network.pk)        
        self.assertEqual(network.policy, np)
    
    def test_delete_policy_from_network(self):
        """Test deleting a policy from a network."""
        np = self._create_network_policy("test_policy", [])
        network = Network.objects.create(network="10.0.0.0/24", description="test_network", policy=np)
        self.assert_patch_and_204(f"{NETWORK_ENDPOINT}{network.network}", data={"policy": None})
        network = Network.objects.get(pk=network.pk)
        self.assertIsNone(network.policy)

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=["isolated"])
    def test_assign_policy_to_network_missing_attributes(self):
        """Test assigning a policy to a network with missing attributes."""
        np = self._create_network_policy("test_policy", [])
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        self.assert_patch_and_406(f"{NETWORK_ENDPOINT}{network.network}", data={"policy": np.pk})
        network.delete()

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=["isolated"])
    def test_patch_network_with_policy_missing_attributes(self):
        """Test updating a network with a policy with missing attributes."""
        np = self._create_network_policy("test_policy", [("isolated", True)])
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        network.policy = np # type: ignore
        network.save()
        np_missing_attribute = self._create_network_policy("test_policy_missing_attribute", [])
        self.assert_patch_and_406(f"{NETWORK_ENDPOINT}{network.network}", data={"policy": np_missing_attribute.pk})
        network.delete()
        np_missing_attribute.delete()

    def test_create_community_ok(self):
        """Test creating a community."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        data = {
            "name": "community",
            "description": "community desc",
        }
        ret = self.assert_post_and_201(f"networks/{network.network}/communities/", data=data)
        community_id = ret.json()["id"]

        location = ret.headers["Location"]
        self.assertIsNotNone(location, "Location header not set")

        path = f"networks/{network.network}/communities/{community_id}"
        self.assertTrue(location.endswith(path))

        get_res = self.assert_get(f"networks/{network.network}/communities/{community_id}")
        self.assertEqual(get_res.json()["name"], "community")
        self.assertEqual(get_res.json()["description"], "community desc")
        self.assertEqual(get_res.json()["network"], network.pk)

        list_res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/")
        self.assertEqual(len(list_res.json()["results"]), 1)

        # This testes the reverse relationship from network to community
        network_res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}")
        self.assertEqual(len(network_res.json()["communities"]), 1)
        self.assertEqual(network_res.json()["communities"][0]["id"], community_id)
        self.assertEqual(network_res.json()["communities"][0]["name"], "community")

        network.delete()
        self.assertFalse(Community.objects.filter(pk=community_id).exists())  # Cascade delete

    def test_create_community_no_name_400(self):
        """Test creating a community without a name."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        data = {
            "description": "community desc",
        }
        self.assert_post_and_400(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)

    @override_settings(MREG_REQUIRE_VLAN_FOR_NETWORK_TO_HAVE_COMMUNITY=True)
    def test_create_community_requires_vlan(self):
        """Test creating a community without a VLAN."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)

        network.vlan = 42
        network.save()

        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)

        network.delete()

    def test_create_community_name_already_exists_in_same_network_409(self):
        """Test creating a community with the same name in different networks works."""
        net1 = Network.objects.create(network="10.0.0.0/24", description="test_network1")
        net2 = Network.objects.create(network="10.0.1.0/24", description="test_network2")

        data = {
            "name": "community",
            "description": "community desc",
        }

        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{net1.network}/communities/", data=data)
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{net2.network}/communities/", data=data)

        self.assert_post_and_409(f"{NETWORK_ENDPOINT}{net1.network}/communities/", data=data)
        self.assert_post_and_409(f"{NETWORK_ENDPOINT}{net2.network}/communities/", data=data)

        net1.delete()
        net2.delete()

    def test_create_community_duplicate_name_same_network_also_case_insensitive_409(self):
        """Test that creating a community with the same name in the same network fails."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)
        self.assert_post_and_409(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)

        data["name"] = data["name"].upper()    
        self.assert_post_and_409(f"{NETWORK_ENDPOINT}{network.network}/communities/", data=data)

        network.delete()

    def test_delete_community(self):
        """Test deleting a community."""
        net = Network.objects.create(network="10.0.0.0/24", description="test_network")
        data = {
            "name": "community",
            "description": "community desc",
        }
        ret = self.assert_post_and_201(f"{NETWORK_ENDPOINT}{net.network}/communities/", data=data)
        community_id = ret.json()["id"]

        self.assert_delete_and_204(f"{NETWORK_ENDPOINT}{net.network}/communities/{community_id}")

        self.assertFalse(Community.objects.filter(pk=community_id).exists())
        net.delete()

    def test_create_community_invalid_network(self):
        """Test creating a community with an invalid network."""
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_404("{NETWORK_ENDPOINT}10.1.0.0/24/communities/", data=data)
        self.assertEqual(Community.objects.count(), 0)

    def test_create_host_with_community_no_network_406(self):
        """Test that adding a community during host creation without IP gives 406."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        community = self._create_community("community", "community desc", network)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
        }
        self.assert_post_and_406("/api/v1/hosts/", data=data)

    def test_get_host_in_community_with_nonexistant_network_404(self):
        """Test getting a host in a community with a nonexistant network."""
        self.assert_get_and_404("{NETWORK_ENDPOINT}192.168.0.0/24/communities/1/hosts/1")

    def test_get_host_in_community_with_nonexistant_community_404(self):
        """Test getting a host in a community with a nonexistant community."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        self.assert_get_and_404(f"{NETWORK_ENDPOINT}{network.network}/communities/999999/hosts/1")
        network.delete()

    def test_get_host_in_community_with_community_not_in_network(self):
        """Test getting a host in a community with a wrong network for community."""
        _, community, _, host, _ = self.create_policy_setup()
        wrong_network = Network.objects.create(network="192.168.0.0/24", description="test_network")
        self.assert_get_and_404(f"{NETWORK_ENDPOINT}{wrong_network.network}/communities/{community.pk}/hosts/{host.pk}")
        wrong_network.delete()

    @override_settings(MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES=["isolated"])
    def test_create_community_network_missing_policy_attribute(self):
        """Test that adding a community during host creation with network missing policy attribute fails."""
        np = self._create_network_policy("empty_policy", [])
        net = Network.objects.create(network="10.0.0.0/24", description="test_network")

        res = self.assert_post_and_406(f"{NETWORK_ENDPOINT}{net.network}/communities/",
                                       data={"name": "community", "description": "community desc"})

        expected_msg = (
            "Network does not have a policy. "
            "The policy must have the following attributes: ['isolated']"
        )
        self.assertEqual(res.json()['errors'][0]['detail'], expected_msg)

        net.policy = np # type: ignore
        net.save()

        res = self.assert_post_and_406(f"{NETWORK_ENDPOINT}{net.network}/communities/",
                                       data={"name": "community", "description": "community desc"})

        expected_msg = (
            "Network policy 'empty_policy' is missing "
            "the following required attributes: ['isolated']"
        )
        self.assertEqual(res.json()['errors'][0]['detail'], expected_msg)

        np.attributes.set([self._get_protected_attribute("isolated")])
        np.save()

        res = self.assert_post(f"{NETWORK_ENDPOINT}{net.network}/communities/",
                               data={"name": "community", "description": "community desc"})
        
        community_id = res.json()["id"]

        self.assert_get(f"{NETWORK_ENDPOINT}{net.network}/communities/{community_id}")

        Community.objects.get(pk=community_id).delete()

        net.delete()
        np.delete()

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_create_host_with_community_wrong_network(self):
        """Test that adding a community during host creation with the wrong network fails.

        In this test, another network has the policy.
        """
        net_empty = Network.objects.create(network="10.0.0.0/24", description="test_network")
        net_policy = Network.objects.create(network="10.0.1.0/24", description="test_network")
        community = self._create_community("community", "community desc", net_policy)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
            "ipaddress": "10.0.0.1",
        }
        # Wrong network, 406.
        self.assert_post_and_406("/api/v1/hosts/", data=data)
        self.assertFalse(Host.objects.filter(name="hostwithcommunity.example.com").exists())

        # Fix the network, all good.
        data['ipaddress'] = "10.0.1.1"
        res = self.assert_post("/api/v1/hosts/", data=data)
        host = self.assert_get(res.headers["Location"])
        Host.objects.get(pk=host.json()["id"]).delete()

        net_empty.delete()
        net_policy.delete()

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_create_host_with_community_ok(self):
        """Test that adding a community during host creation with network and policy."""
        net = Network.objects.create(network="10.0.0.0/24", description="test_network")
        community = self._create_community("community", "community desc", net)

        data = {"name": "hostwithcommunity.example.com", "network_community": community.pk, "network": net.network}
        ret = self.assert_post_and_201("/api/v1/hosts/", data=data)
        ret = self.assert_get(ret.headers["Location"])
        Host.objects.get(pk=ret.json()["id"]).delete()
        net.delete()

    def create_policy_setup(
        self,
        community_name: str = "test_community",
        host_name: str = "hostwithcommunity.example.com",
        ip_address: str = "10.0.0.1",
        network: str = "10.0.0.0/24",
        policy_name: str = "test_policy",
    ):
        np = self._create_network_policy(policy_name, [])
        net = Network.objects.create(network=network, description="test_network", policy=np)
        community = self._create_community(community_name, "community desc", net)
        host = Host.objects.create(name=host_name)
        ip = Ipaddress.objects.create(host=host, ipaddress=ip_address)

        self.addCleanup(host.delete)
        self.addCleanup(ip.delete)
        self.addCleanup(net.delete)
        self.addCleanup(community.delete)
        self.addCleanup(np.delete)

        return np, community, net, host, ip

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_ok(self):
        """Test adding a host to a community."""
        _, community, network, host, _ = self.create_policy_setup()

        data = {"id": host.pk}

        ret = self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")

        ret = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 1)
        self.assertEqual(ret.json()["results"][0]["name"], "hostwithcommunity.example.com")

    def test_add_host_to_community_ip_has_no_mac_406(self):
        """Test adding a host to a community with an IP that has no MAC."""
        _, community, network, host, _ = self.create_policy_setup()
        ip = host.ipaddresses.first() # type: ignore

        # explicit ipaddress
        data = {"id": host.pk, "ipaddress": ip.ipaddress}
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

        # implicit ipaddress
        data = {"id": host.pk}
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

    def test_add_host_to_community_with_nonexistent_network(self):
        """Test adding a host to a community with a nonexistant network."""
        _, community, _, host, _ = self.create_policy_setup()

        data = {"id": host.pk}
        self.assert_post_and_404(f"{NETWORK_ENDPOINT}/10.99.99.00/24/communities/{community.pk}/hosts/", data=data)

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_ok_with_ip(self):
        """Test adding a host to a community with an IP."""
        _, community, network, host, _ = self.create_policy_setup()
        ip = host.ipaddresses.first() # type: ignore

        data = {"id": host.pk, "ipaddress": ip.ipaddress }
        ret = self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")
        self.assertEqual(ret.json()["communities"][0]['ipaddress'], ip.pk)    

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_ok_with_ip_only(self):
        """Test adding a host to a community with an IP only."""
        _, community, network, host, _ = self.create_policy_setup()
        ip = host.ipaddresses.first() # type: ignore

        data = {"ipaddress": ip.ipaddress }
        ret = self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")
        self.assertEqual(ret.json()["communities"][0]['ipaddress'], ip.pk)    

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=True)
    def test_add_host_to_community_ip_has_mac(self):
        """Test adding a host to a community with an IP that has a MAC."""
        _, community, network, host, ip = self.create_policy_setup()
        ip.macaddress = "00:00:00:00:00:00"
        ip.save()

        data = {"id": host.pk, "ipaddress": ip.ipaddress}
        ret = self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")
        self.assertEqual(ret.json()["communities"][0]['ipaddress'], ip.pk)

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_with_ip_only_multiple_uses_of_ip_406(self):
        """Test adding a host to a community with an IP that is used by multiple hosts."""
        _, community, network, host, _ = self.create_policy_setup()
        host2 = Host.objects.create(name="hostwithcommunity2.example.com")
        ip = Ipaddress.objects.create(host=host2, ipaddress=host.ipaddresses.first().ipaddress) # type: ignore

        data = {"ipaddress": ip.ipaddress}
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

        host2.delete()

    def test_add_host_to_community_ip_does_not_exist(self):
        """Test adding a host to a community with an IP that does not exist."""
        _, community, network, host, _ = self.create_policy_setup()

        data = {"id": host.pk, "ipaddress": "10.9.9.9"}
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_with_ip_different_network(self):
        """Test adding a host to a community with an IP that is in a different network than the community"""
        _, community, network, host, _ = self.create_policy_setup()
        network_other = Network.objects.create(network="10.0.1.0/24", description="test_network_other")
        ip = Ipaddress.objects.create(host=host, ipaddress="10.0.1.1")

        data = {"id": host.pk, "ipaddress": ip.ipaddress}
        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

        network_other.delete()
        ip.delete()

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_multiple_communities(self):
        """Test that adding a host to multiple communities using multiple IPs works."""
        _, community1, network1, host, _ = self.create_policy_setup()
        network2 = Network.objects.create(network="10.0.1.0/24", description="test_network2")
        community2 = self._create_community("community_other", "community desc", network1)
        community3 = self._create_community("community_other", "community desc", network2)

        ip1 = host.ipaddresses.first() # type: ignore
        ip2 = Ipaddress.objects.create(host=host, ipaddress="10.0.0.2")
        ip3 = Ipaddress.objects.create(host=host, ipaddress="10.0.1.1")

        data = {"id": host.pk, "ipaddress": ip1.ipaddress}
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network1.network}/communities/{community1.pk}/hosts/", data=data)
        data = {"id": host.pk, "ipaddress": ip2.ipaddress}
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network1.network}/communities/{community2.pk}/hosts/", data=data)
        data = {"id": host.pk, "ipaddress": ip3.ipaddress}
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network2.network}/communities/{community3.pk}/hosts/", data=data)

        host = Host.objects.get(pk=host.pk)
        self.assertEqual(host.communities.count(), 3)
        self.assertIn(community1, host.communities.all())
        self.assertIn(community2, host.communities.all())
        self.assertIn(community3, host.communities.all())

        # check that the IPs are correct
        res = self.assert_get(f"/hosts/{host.name}")
        self.assertEqual(len(res.json()["ipaddresses"]), 3)
        self.assertEqual(len(res.json()["communities"]), 3)
        self.assertEqual(res.json()["communities"][0]["ipaddress"], ip1.pk)
        self.assertEqual(res.json()["communities"][0]["community"]['name'], community1.name)
        self.assertEqual(res.json()["communities"][1]["ipaddress"], ip2.pk)
        self.assertEqual(res.json()["communities"][1]["community"]['name'], community2.name)
        self.assertEqual(res.json()["communities"][2]["ipaddress"], ip3.pk)
        self.assertEqual(res.json()["communities"][2]["community"]['name'], community3.name)

        network2.delete()
        community2.delete()
        community3.delete()        

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_get_individual_host_from_community_ok(self):
        """Test getting a host from a community."""
        _, community, network, host, _ = self.create_policy_setup()
        host.add_to_community(community)

        ret = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/{host.pk}")
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")

    def test_get_individual_host_from_community_host_does_not_exist(self):
        """Test getting a host from a community where host does not exist."""
        _, community, network, _, _ = self.create_policy_setup()

        self.assert_get_and_404(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/99999999")

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_ip_not_in_network(self):
        """Test adding a host to a community when the hosts IP is not in the network for the policy."""
        _, community, network, host, _ = self.create_policy_setup(ip_address="10.0.1.0")

        data = {"id": host.pk}

        self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_to_community_while_already_in_community_in_same_network(self):
        """Test that adding a host to a community when it is already in a community in the same network replaces the old community."""
        _, community, network, host, _ = self.create_policy_setup()
        community_other = self._create_community("community_other", "community desc", network)
        host.add_to_community(community_other)

        data = {"id": host.pk}

        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/", data=data)

        ret = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 1)
        self.assertEqual(ret.json()["results"][0]["name"], "hostwithcommunity.example.com")

        ret = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community_other.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 0)

        community_other.delete()

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_add_host_with_multiple_ips_on_multiple_networks_to_communities(self):
        """Test adding a host with multiple IPs on multiple networks to communities."""
        _, community1, network1, host, _ = self.create_policy_setup()
        network2 = Network.objects.create(network="192.168.0.0/24", description="test_network2")
        community2 = self._create_community("community_other", "community desc", network2)
        ip = Ipaddress.objects.create(host=host, ipaddress="192.168.0.1")

        data = {"id": host.pk}

        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network1.network}/communities/{community1.pk}/hosts/", data=data)
        self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network2.network}/communities/{community2.pk}/hosts/", data=data)

        host = Host.objects.get(pk=host.pk)
        self.assertEqual(host.communities.count(), 2)
        self.assertIn(community1, host.communities.all())
        self.assertIn(community2, host.communities.all())

        network2.delete()
        community2.delete()
        ip.delete()
        host.delete()
    
    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_delete_host_from_community_ok(self):
        """Test deleting a host from a community."""
        _, community, network, host, _ = self.create_policy_setup()
        host.add_to_community(community)

        self.assert_delete_and_204(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/{host.pk}")

        ret = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 0)

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_delete_host_from_community_not_in_community(self):
        """Test deleting a host from a community."""
        _, community, network, host, _ = self.create_policy_setup()
        self.assert_delete_and_404(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/{host.pk}")

        # Add to a different community, just to make sure
        community_other = self._create_community("community_other", "community desc", network)
        host.add_to_community(community_other)

        self.assert_delete_and_404(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}/hosts/{host.pk}")

        community_other.delete()

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_change_ip_of_host_to_outside_of_community_gives_409(self):
        """Test changing the IP of a host to an IP outside the community."""
        _, community, _, host, ip = self.create_policy_setup()
        host.add_to_community(community)        

        data = {"ipaddress": "10.0.1.0"}

        # The IP above does not belong a network, so we get a 404
        self.assert_patch_and_404(f"/api/v1/ipaddresses/{ip.pk}", data=data)

        # Then we create the network, but don't associate it with the policy
        new_network = Network.objects.create(network="10.0.1.0/24", description="test_network")
        # Now we get a 409 as the IP is not in the network associated with the policy
        self.assert_patch_and_409(f"/api/v1/ipaddresses/{ip.pk}", data=data)

        new_network.delete()

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=True)
    @override_settings(MREG_GLOBAL_COMMUNITY_TEMPLATE_PATTERN="community")
    @override_settings(MREG_MAX_COMMUNITES_PER_NETWORK=20) # Also implies one zero-padded index
    def test_community_mapping_enabled(self):
        """Test that the community mapping works."""
        policy, community, network, _, _ = self.create_policy_setup()

        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}")
        self.assertEqual(res.json()['global_name'], "community01")

        community_other = self._create_community("community2", "community desc", network)
        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community_other.pk}")
        self.assertEqual(res.json()['global_name'], "community02")

        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}")
        self.assertEqual(res.json()['global_name'], "community01")

        # Test via direct modification of the object
        policy.community_template_pattern = "test"
        policy.save()

        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}")
        self.assertEqual(res.json()['global_name'], "test01")
        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community_other.pk}")
        self.assertEqual(res.json()['global_name'], "test02")                

        # Test via the API (PATCH request)
        self.assert_patch_and_200(f"{POLICY_ENDPOINT}{policy.pk}", data={"community_template_pattern": "patched"})
        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}")
        self.assertEqual(res.json()['global_name'], "patched01")
        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community_other.pk}")
        self.assertEqual(res.json()['global_name'], "patched02")                

        community_other.delete()


    @parametrize(
        ("community_template_pattern", "return_value"),
        [
            param("community", 201, id="community"),
            param("has_underscore", 201, id="has_underscore"),
            param("has89", 201, id="has_number"),
            param("has-dash", 400, id="has_dash"),
            param("is_longer_than_100_chars_" + "a" * 100, 400, id="too_long"),
            param("has space", 400, id="has_space"),
            param("has@special", 400, id="has_special"),
            param("has#special", 400, id="has_special_2"),
        ]
    )
    def test_community_template_pattern_validation(self, community_template_pattern: str, return_value: int):
        """Test that the community mapping prefix is validated."""
        data = {
            "name": "test",
            "description": "test",
            "community_template_pattern": community_template_pattern,
        }

        if return_value == 201:
            res = self.assert_post_and_201(f"{POLICY_ENDPOINT}", data=data)
            id = res.json()['id']
            self.assert_delete_and_204(f"{POLICY_ENDPOINT}{id}")
        else:
            self.assert_post_and_400(f"{POLICY_ENDPOINT}", data=data)

    def test_community_template_pattern_is_unique(self):
        """Test that the community mapping prefix is unique."""
        pattern = "notunique"    

        data = {
            "name": "test_unique_ok",
            "description": "test",
            "community_template_pattern": pattern,
        }

        res = self.assert_post_and_201(f"{POLICY_ENDPOINT}", data=data)
        id = res.json()['id']

        data['name'] = "test_unique_notok"
        self.assert_post_and_400(f"{POLICY_ENDPOINT}", data=data)
        self.assert_delete_and_204(f"{POLICY_ENDPOINT}{id}")

    @override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=False)
    def test_community_mapping_disabled(self):
        """Test that the community mapping field is None when disabled."""
        _, community, network, _, _ = self.create_policy_setup()

        res = self.assert_get(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}")
        self.assertEqual(res.json()['global_name'], None)

    @override_settings(MREG_MAX_COMMUNITES_PER_NETWORK=1)
    def test_max_communities_per_network(self):
        """Test that we can only have a certain number of communities per network."""
        _, _, network, _, _ = self.create_policy_setup()

        res = self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "c2", "description": "c2desc"})
        self.assertEqual(res.json()['errors'][0]['detail'], f"Network '{network.network}' already has the maximum allowed communities (1).")

    @override_settings(MREG_MAX_COMMUNITES_PER_NETWORK=20)
    def test_max_communities_per_network_set_in_network(self):
        """Test that we can only have a certain number of communities per network."""
        _, _, network, _, _ = self.create_policy_setup()
        network.max_communities = 1
        network.save()

        res = self.assert_post_and_406(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "c2", "description": "c2desc"})
        self.assertEqual(res.json()['errors'][0]['detail'], f"Network '{network.network}' already has the maximum allowed communities (1).")


    @override_settings(MREG_MAX_COMMUNITES_PER_NETWORK=1)
    def test_max_communities_per_network_allows_patch(self):
        """Test that even when we have a full number of communities per network, we can still patch."""
        _, community, network, _, _ = self.create_policy_setup()

        res = self.assert_patch_and_200(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}", data={"description": "new desc"})
        self.assertEqual(res.json()['description'], "new desc")

class NetworkPolicyFilterTestCase(ParametrizedTestCase, MregAPITestCase):
    def setUp(self):
        super().setUp()
        # Create a known set of network policies.
        self.policy1 = NetworkPolicy.objects.create(
            name="PolicyOne", description="The first policy"
        )
        self.policy2 = NetworkPolicy.objects.create(
            name="PolicyTwo", description="The second policy"
        )
        self.policy3 = NetworkPolicy.objects.create(
            name="PolicyThree", description="The third plan"
        )
        self.policy4 = NetworkPolicy.objects.create(
            name="PolicyFourAndOne", description="A combination policy"
        )
        self.policies = [self.policy1, self.policy2, self.policy3, self.policy4]

        # Create networks associated with the policies.
        self.network1 = Network.objects.create(
            network="10.0.0.0/24",
            description="Network with PolicyOne",
            policy=self.policy1,
        )
        self.network2 = Network.objects.create(
            network="10.0.1.0/24",
            description="Network with PolicyTwo",
            policy=self.policy2,
        )
        self.network3 = Network.objects.create(
            network="10.0.2.0/24",
            description="Network with PolicyThree",
            policy=self.policy3,
        )
        self.network4 = Network.objects.create(
            network="10.0.3.0/24",
            description="Network with PolicyFour",
            policy=self.policy4,
        )
        self.networks = [self.network1, self.network2, self.network3, self.network4]

        # Create communities for each network.
        self.community1 = Community.objects.create(
            name="CommunityOne",
            description="Community linked to PolicyOne",
            network=self.network1,
        )
        self.community2 = Community.objects.create(
            name="CommunityTwo",
            description="Community linked to PolicyTwo",
            network=self.network2,
        )
        self.community3 = Community.objects.create(
            name="CommunityThree",
            description="Community linked to PolicyThree",
            network=self.network3,
        )
        self.community4 = Community.objects.create(
            name="CommunityFour",
            description="Community linked to PolicyFour",
            network=self.network4,
        )
        self.communities = [
            self.community1,
            self.community2,
            self.community3,
            self.community4,
        ]

    @parametrize(
        ("query_params", "expected_count"),
        [
            param({"name": "policyone"}, 1, id="exact_name"),
            param({"name__iexact": "PolicyOne"}, 1, id="iexact_name"),
            param({"name__icontains": "one"}, 2, id="icontains_name"),
            param({"name__regex": ".*one.*"}, 2, id="regex_one"),
            param({"description__icontains": "policy"}, 3, id="policy_icontains_description"),
            param({"name": "NonExistent"}, 0, id="nonexistent"),
        ]
    )
    def test_network_policy_filter(self, query_params, expected_count):
        """Test filtering network policies."""
        query_string = urllib.parse.urlencode(query_params)
        url = f"{POLICY_ENDPOINT}?{query_string}"
        response = self.assert_get(url)
        results = response.json().get("results", [])
        self.assertEqual(
            len(results),
            expected_count,
            f"Policy query {query_params} expected {expected_count} results but got {len(results)}",
        )

    @parametrize(
        ("query_params", "expected_count"),
        [
            param({"policy__name__icontains": "one"}, 2, id="name_icontains"),
            param({"policy__name__regex": "^policy.*one$"}, 2, id="name_regex"),
            param({"policy__description__icontains": "policy"}, 3, id="description_icontains"),
        ]
    )
    def test_network_filter_by_policy(self, query_params, expected_count):
        """Test filtering networks by policy."""
        query_string = urllib.parse.urlencode(query_params)
        url = f"{NETWORK_ENDPOINT}?{query_string}"
        response = self.assert_get(url)
        results = response.json().get("results", [])
        self.assertEqual(
            len(results),
            expected_count,
            f"Network query {query_params} expected {expected_count} results but got {len(results)}",
        )

    def test_network_filter_by_policy_id(self):
        """Test filtering networks by policy id."""
        url = f"{NETWORK_ENDPOINT}?policy={self.policy2.pk}"
        response = self.assert_get(url)
        results = response.json().get("results", [])
        self.assertEqual(
            len(results),
            1,
            f"Filtering networks by policy id {self.policy2.pk} expected 1 result but got {len(results)}",
        )

    def tearDown(self):
        for community in self.communities:
            community.delete()
        for network in self.networks:
            network.delete()
        for policy in self.policies:
            policy.delete()

class NetworkPolicyPermissionsTestCase(ParametrizedTestCase, MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.set_client_format_json()

    def grant_user_access_to_network(self, network: Network):
        group, _ = Group.objects.get_or_create(name='testgroup')
        group.user_set.add(self.user)
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range=network.network,
                                               regex=r'^irrelevant$')
        self.addCleanup(group.delete)

    def test_permissions_create_network_policy(self):
        """Test creating a network policy as different users."""
        with self.temporary_client_as_normal_user():
            self.assert_post_and_403(POLICY_ENDPOINT, data={"name": "policy"})
        
        with self.temporary_client_as_network_admin():
            self.assert_post_and_201(POLICY_ENDPOINT, data={"name": "policy"})
        
        NetworkPolicy.objects.get(name="policy").delete()

    def test_permissions_update_network_policy(self):
        """Test updating a network policy as different users."""
        policy = NetworkPolicy.objects.create(name="policy")
        self.addCleanup(policy.delete)
        with self.temporary_client_as_normal_user():
            self.assert_patch_and_403(f"{POLICY_ENDPOINT}{policy.pk}", data={"name": "new_name"})
        
        with self.temporary_client_as_network_admin():
            self.assert_patch_and_200(f"{POLICY_ENDPOINT}{policy.pk}", data={"name": "new_name"})
        
    def test_permissions_delete_network_policy(self):
        """Test deleting a network policy as different users."""
        policy = NetworkPolicy.objects.create(name="policy")
        self.addCleanup(policy.delete)
        with self.temporary_client_as_normal_user():
            self.assert_delete_and_403(f"{POLICY_ENDPOINT}{policy.pk}")
        
        with self.temporary_client_as_network_admin():
            self.assert_delete_and_204(f"{POLICY_ENDPOINT}{policy.pk}")

    def test_permissions_create_community(self):
        """Test creating a community as different users.
        
        Note that users with network permissions should be able to create communities within the network."""
        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        network_other = Network.objects.create(network="10.0.1.0/24", description="test_network_other")
        self.addCleanup(network.delete)
        self.addCleanup(network_other.delete)

        with self.temporary_client_as_network_admin():
            self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "community"})
            Community.objects.get(name="community").delete()

        with self.temporary_client_as_normal_user():
            self.assert_post_and_403(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "community"})
            self.grant_user_access_to_network(network_other)
            self.assert_post_and_403(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "community"})
            self.grant_user_access_to_network(network)            
            self.assert_post_and_201(f"{NETWORK_ENDPOINT}{network.network}/communities/", data={"name": "community"})
            Community.objects.get(name="community").delete()

    def test_permissions_update_community(self):
        """Test updating a community as different users."""

        network = Network.objects.create(network="10.0.0.0/24", description="test_network")
        community = Community.objects.create(name="community", network=network)

        with self.temporary_client_as_network_admin():
            res = self.assert_patch_and_200(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}", data={"name": "new_name"})
            self.assertEqual(res.json()['name'], "new_name")
        
        with self.temporary_client_as_normal_user():
            self.assert_patch_and_403(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}", data={"name": "not_new_name"})
            self.assertEqual(Community.objects.get(pk=community.pk).name, "new_name")

            self.grant_user_access_to_network(network)
            res = self.assert_patch_and_200(f"{NETWORK_ENDPOINT}{network.network}/communities/{community.pk}",
                                            data={"name": "new_name_by_user"})
            self.assertEqual(res.json()['name'], "new_name_by_user")

