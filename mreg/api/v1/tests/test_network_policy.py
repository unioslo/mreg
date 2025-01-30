from unittest_parametrize import ParametrizedTestCase, param, parametrize
from django.db import transaction

from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, NetworkPolicyAttributeValue, Community
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network

from .tests import MregAPITestCase

POLICY_ENDPOINT = "/api/v1/networkpolicies/"
ATTRIBUTE_ENDPOINT = "/api/v1/networkpolicyattributes/"

class NetworkPolicyTestCase(ParametrizedTestCase, MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.set_client_format_json()

    def _create_network_policy(self, name: str, attributes: list[tuple[str, bool]]) -> NetworkPolicy:
        with transaction.atomic():
            np = NetworkPolicy.objects.create(name=name)
            for attribute in attributes:
                NetworkPolicyAttributeValue.objects.create(
                    policy=np, attribute=NetworkPolicyAttribute.objects.get(name=attribute[0]), value=attribute[1]
                )
            return np

    def _delete_network_policy(self, name: str):
        NetworkPolicy.objects.get(name=name).delete()

    def _create_attributes(self, names: list[str]):
        for name in names:
            self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data={"name": name, "description": f"{name} desc"})

    def _delete_attributes(self, names: list[str]):
        for name in names:
            NetworkPolicyAttribute.objects.get(name=name).delete()

    def _create_community(self, name: str, description: str, policy: NetworkPolicy) -> Community:
        return Community.objects.create(name=name, description=description, policy=policy)

    def _delete_community(self, name: str):
        Community.objects.get(name=name).delete()

    def _get_protected_attribute_isolated(self) -> NetworkPolicyAttribute:
        return NetworkPolicyAttribute.objects.get(name="isolated")
    
    def _get_protected_attribute(self, name: str) -> NetworkPolicyAttribute:
        return NetworkPolicyAttribute.objects.get(name=name)

    def _try_get_protected_attribute(self, name: str) -> NetworkPolicyAttribute | None:
        try:
            return self._get_protected_attribute(name)
        except NetworkPolicyAttribute.DoesNotExist:
            return None

    def test_isolated_attribute_protected_exists(self):
        """Test that the isolated attribute is protected and exists."""
        self.assertIsNotNone(self._get_protected_attribute_isolated())
    
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

    def test_create_community_ok(self):
        """Test creating a community."""
        name = "policy_with_community"
        np = self._create_network_policy(name, [])
        data = {
            "name": "community",
            "description": "community desc",
        }
        ret = self.assert_post_and_201(f"{POLICY_ENDPOINT}{np.pk}/communities/", data=data)
        community_id = ret.json()["id"]

        location = ret.headers["Location"]
        self.assertIsNotNone(location, "Location header not set")

        path = f"{POLICY_ENDPOINT}{np.pk}/communities/{community_id}"
        self.assertTrue(location.endswith(path))

        get_res = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}/communities/{community_id}")
        self.assertEqual(get_res.json()["name"], "community")
        self.assertEqual(get_res.json()["description"], "community desc")
        self.assertEqual(get_res.json()["policy"], np.pk)

        list_res = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}/communities/")
        self.assertEqual(len(list_res.json()["results"]), 1)

        policy_res = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}")
        self.assertEqual(len(policy_res.json()["communities"]), 1)
        self.assertEqual(policy_res.json()["communities"][0]["id"], community_id)
        self.assertEqual(policy_res.json()["communities"][0]["name"], "community")

        self._delete_network_policy(name)
        self.assertFalse(Community.objects.filter(pk=community_id).exists())  # Cascade delete

    def test_create_community_name_already_exists_in_same_policy_409(self):
        """Test creating a community with the same name in different policies works."""
        np1 = self._create_network_policy("policy1", [])
        np2 = self._create_network_policy("policy2", [])

        data = {
            "name": "community",
            "description": "community desc",
        }

        self.assert_post_and_201(f"{POLICY_ENDPOINT}{np1.pk}/communities/", data=data)
        self.assert_post_and_201(f"{POLICY_ENDPOINT}{np2.pk}/communities/", data=data)

        np1.delete()
        np2.delete()

    def test_create_community_duplicate_name_same_policy_409(self):
        """Test that creating a community with the same name in the same policy fails."""
        name = "policy_with_community"
        np = self._create_network_policy(name, [])
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_201(f"{POLICY_ENDPOINT}{np.pk}/communities/", data=data)
        self.assert_post_and_409(f"{POLICY_ENDPOINT}{np.pk}/communities/", data=data)

        data["name"] = data["name"].upper()    
        self.assert_post_and_409(f"{POLICY_ENDPOINT}{np.pk}/communities/", data=data)

        self._delete_network_policy(name)

    def test_create_community_name_already_exists_in_different_policy_ok(self):
        """Test creating a community with the same name in a different policy."""
        np1 = self._create_network_policy("policy_with_community1", [])
        np2 = self._create_network_policy("policy_with_community2", [])
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_201(f"{POLICY_ENDPOINT}{np1.pk}/communities/", data=data)
        self.assert_post_and_201(f"{POLICY_ENDPOINT}{np2.pk}/communities/", data=data)

        self._delete_network_policy("policy_with_community1")
        self._delete_network_policy("policy_with_community2")

    def test_delete_community(self):
        """Test deleting a community."""
        name = "policy_with_community"
        np = self._create_network_policy(name, [])
        data = {
            "name": "community",
            "description": "community desc",
        }
        ret = self.assert_post_and_201(f"{POLICY_ENDPOINT}{np.pk}/communities/", data=data)
        community_id = ret.json()["id"]

        self.assert_delete_and_204(f"{POLICY_ENDPOINT}{np.pk}/communities/{community_id}")

        self.assertFalse(Community.objects.filter(pk=community_id).exists())
        self._delete_network_policy(name)

    def test_create_community_invalid_policy(self):
        """Test creating a community with an invalid policy."""
        data = {
            "name": "community",
            "description": "community desc",
        }
        self.assert_post_and_404(f"{POLICY_ENDPOINT}9999/communities/", data=data)
        self.assertEqual(Community.objects.count(), 0)

    def test_create_host_with_community_no_network_406(self):
        """Test that adding a community during host creation without IP gives 406."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
        }
        self.assert_post_and_406("/api/v1/hosts/", data=data)

    def test_create_host_with_community_network_missing_policy(self):
        """Test that adding a community during host creation with network missing policy fails."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)
        # Note, no policy is set on the network
        net = Network.objects.create(network="10.0.0.0/24", description="test_network")

        data = {"name": "hostwithcommunity.example.com", "network_community": community.pk, "network": net.network}
        self.assert_post_and_406("/api/v1/hosts/", data=data)
        net.delete()

    def test_create_host_with_community_network_missing_policy_wrong_network(self):
        """Test that adding a community during host creation with network missing policy fails.

        In this test, another network has the policy.
        """
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)
        net_empty = Network.objects.create(network="10.0.0.0/24", description="test_network")
        net_policy = Network.objects.create(network="10.0.1.0/24", description="test_network", policy=np)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
            "network": net_empty.network,
        }
        self.assert_post_and_406("/api/v1/hosts/", data=data)
        net_empty.delete()
        net_policy.delete()

    def test_create_host_with_community_ok(self):
        """Test that adding a community during host creation with network and policy."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)
        net = Network.objects.create(network="10.0.0.0/24", description="test_network", policy=np)

        data = {"name": "hostwithcommunity.example.com", "network_community": community.pk, "network": net.network}
        ret = self.assert_post_and_201("/api/v1/hosts/", data=data)
        ret = self.assert_get(ret.headers["Location"])
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
        community = self._create_community(community_name, "community desc", np)
        net = Network.objects.create(network=network, description="test_network", policy=np)
        host = Host.objects.create(name=host_name)
        ip = Ipaddress.objects.create(host=host, ipaddress=ip_address)

        self.addCleanup(host.delete)
        self.addCleanup(ip.delete)
        self.addCleanup(net.delete)
        self.addCleanup(community.delete)
        self.addCleanup(np.delete)

        return np, community, net, host, ip

    def test_add_host_to_community_ok(self):
        """Test adding a host to a community."""
        np, community, network, host, _ = self.create_policy_setup()

        data = {"id": host.pk}

        ret = self.assert_post_and_201(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/", data=data)
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")

        ret = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 1)
        self.assertEqual(ret.json()["results"][0]["name"], "hostwithcommunity.example.com")

    def test_get_individual_host_from_community_ok(self):
        """Test getting a host from a community."""
        np, community, _, host, _ = self.create_policy_setup()
        host.set_community(community)

        ret = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/{host.pk}")
        self.assertEqual(ret.json()["name"], "hostwithcommunity.example.com")

    def test_get_individual_host_from_community_host_does_not_exist(self):
        """Test getting a host from a community where host does not exist."""
        np, community, _, _, _ = self.create_policy_setup()

        self.assert_get_and_404(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/99999999")

    def test_add_host_to_community_ip_not_in_network(self):
        """Test adding a host to a community when the hosts IP is not in the network for the policy."""
        np, community, _, host, _ = self.create_policy_setup(ip_address="10.0.1.0")

        data = {"id": host.pk}

        self.assert_post_and_400(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/", data=data)

    def test_delete_host_from_community_ok(self):
        """Test deleting a host from a community."""
        np, community, _, host, _ = self.create_policy_setup()
        host.set_community(community)

        self.assert_delete_and_204(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/{host.pk}")

        ret = self.assert_get(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/")
        self.assertEqual(len(ret.json()["results"]), 0)

    def test_delete_host_from_community_not_in_community(self):
        """Test deleting a host from a community."""
        np, community, _, host, _ = self.create_policy_setup()
        self.assert_delete_and_404(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/{host.pk}")

        # Add to a different community, just to make sure
        community_other = self._create_community("community_other", "community desc", np)
        host.set_community(community_other)

        self.assert_delete_and_404(f"{POLICY_ENDPOINT}{np.pk}/communities/{community.pk}/hosts/{host.pk}")

        community_other.delete()

    def test_change_ip_of_host_to_outside_of_community_gives_409(self):
        """Test changing the IP of a host to an IP outside the community."""
        _, community, _, host, ip = self.create_policy_setup()
        host.set_community(community)

        data = {"ipaddress": "10.0.1.0"}

        # The IP above does not belong a network, so we get a 404
        self.assert_patch_and_404(f"/api/v1/ipaddresses/{ip.pk}", data=data)

        # Then we create the network, but don't associate it with the policy
        new_network = Network.objects.create(network="10.0.1.0/24", description="test_network")
        # Now we get a 409 as the IP is not in the network associated with the policy
        self.assert_patch_and_409(f"/api/v1/ipaddresses/{ip.pk}", data=data)

        new_network.delete()
