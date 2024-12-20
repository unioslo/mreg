from unittest_parametrize import ParametrizedTestCase, param, parametrize
from django.db import transaction

from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, NetworkPolicyAttributeValue, Community
from mreg.models.network import Network

from .tests import MregAPITestCase

POLICY_ENDPOINT = '/api/v1/networkpolicies/'
ATTRIBUTE_ENDPOINT = '/api/v1/networkpolicyattributes/'

class NetworkPolicyTestCase(ParametrizedTestCase, MregAPITestCase):

    def setUp(self):
        super().setUp()
        self.set_client_format_json()

    def _create_network_policy(self, name: str, attributes: list[
        tuple[str, bool
    ]]) -> NetworkPolicy:
        
        with transaction.atomic():
            np = NetworkPolicy.objects.create(name=name)
            for attribute in attributes:
                NetworkPolicyAttributeValue.objects.create(
                    policy=np,
                    attribute=NetworkPolicyAttribute.objects.get(name=attribute[0]),
                    value=attribute[1]
                )
            return np
        
    def _delete_network_policy(self, name: str):
        NetworkPolicy.objects.get(name=name).delete()

    def _create_attributes(self, names: list[str]):
        for name in names:
            self.assert_post_and_201(ATTRIBUTE_ENDPOINT, data={ "name": name, "description": f"{name} desc" })

    def _delete_attributes(self, names: list[str]):
        for name in names:
            NetworkPolicyAttribute.objects.get(name=name).delete()

    def _create_community(self, name: str, description: str, policy: NetworkPolicy) -> Community:
        return Community.objects.create(name=name, description=description, policy=policy)
    
    def _delete_community(self, name: str):
        Community.objects.get(name=name).delete()

    @parametrize(
        ('name', 'attributes'),
        [
            param('policy_without_attributes', [], id='test_policy_no_attributes'),
            param('policy_with_t_attribute', [("isolated", True)], id='test_policy_with_t_attribute'),
            param('policy_with_tf_attributes', [("isolated", True), ("public", False)],
                  id='test_policy_with_tf_attributes'),
            param('policy_with_tft_attributes', [("isolated", True), ("public", False), ("private", True)],
                  id='test_policy_with_tft_attributes'),
        ],
    )
    def test_create_valid_np(self, name: str, attributes: list[tuple[str, bool]]):
        """Test creating a valid network policy."""
        data = {
            "name": name,
            "attributes": [
                {"name": attr[0], "value": attr[1]} for attr in attributes
            ]
        } 
        attribute_names = [attribute[0] for attribute in attributes]

        # Create the attributes named in the attributes list        
        self._create_attributes(attribute_names)

        post_response = self.assert_post_and_201(POLICY_ENDPOINT, data=data)

        self.assertEqual(post_response.json()['name'], name)

        post_attributes = post_response.json()['attributes']

        if attributes:
            for attribute in attributes:
                element_in_post = next((attr for attr in post_attributes if attr['name'] == attribute[0]), None)
                self.assertIsNotNone(element_in_post, f"Attribute {attribute[0]} not found in response")

                if element_in_post:
                    self.assertEqual(attribute[1], element_in_post['value'])
                
        location = post_response.headers['Location']
        self.assertIsNotNone(location, "Location header not set")
        get_response = self.assert_get_and_200(location)

        self.assertEqual(get_response.json()['name'], name)

        self._delete_network_policy(name)
        self._delete_attributes(attribute_names)

    def test_delete_np(self):
        """Test deleting a network policy."""
        name = 'policy_to_delete'
        np = self._create_network_policy(name, [])
        self.assert_delete_and_204(f'{POLICY_ENDPOINT}{np.pk}')

    def test_update_np(self):
        """Test updating a network policy."""
        name = 'policy_to_update'
        np = self._create_network_policy(name, [])
        data = {
            "name": "new_name",
            "attributes": []
        }
        ret = self.assert_patch_and_200(f'{POLICY_ENDPOINT}{np.pk}', data=data)
        self.assertEqual(ret.json()['name'], "new_name")
        self._delete_network_policy("new_name")

    def test_create_community_ok(self):
        """Test creating a community."""
        name = 'policy_with_community'
        np = self._create_network_policy(name, [])
        data = {
            "name": "community",
            "description": "community desc",
            "policy": np.pk
        }
        ret = self.assert_post_and_201(f'{POLICY_ENDPOINT}{np.pk}/communities/', data=data)
        community_id = ret.json()['id']

        get_res = self.assert_get(f'{POLICY_ENDPOINT}{np.pk}/communities/{community_id}')
        self.assertEqual(get_res.json()['name'], "community")
        self.assertEqual(get_res.json()['description'], "community desc")
        self.assertEqual(get_res.json()['policy'], np.pk)

        list_res = self.assert_get(f'{POLICY_ENDPOINT}{np.pk}/communities/')
        self.assertEqual(len(list_res.json()['results']), 1)

        policy_res = self.assert_get(f'{POLICY_ENDPOINT}{np.pk}')
        self.assertEqual(len(policy_res.json()['communities']), 1)
        self.assertEqual(policy_res.json()['communities'][0]['id'], community_id)
        self.assertEqual(policy_res.json()['communities'][0]['name'], "community")

        self._delete_network_policy(name)
        self.assertFalse(Community.objects.filter(pk=community_id).exists()) # Cascade delete
    
    def test_delete_community(self):
        """Test deleting a community."""
        name = 'policy_with_community'
        np = self._create_network_policy(name, [])
        data = {
            "name": "community",
            "description": "community desc",
            "policy": np.pk
        }
        ret = self.assert_post_and_201(f'{POLICY_ENDPOINT}{np.pk}/communities/', data=data)
        community_id = ret.json()['id']

        self.assert_delete_and_204(f'{POLICY_ENDPOINT}{np.pk}/communities/{community_id}')
       
        self.assertFalse(Community.objects.filter(pk=community_id).exists())
        self._delete_network_policy(name)

    def test_create_community_invalid_policy(self):
        """Test creating a community with an invalid policy."""
        data = {
            "name": "community",
            "description": "community desc",
            "policy": 9999
        }
        self.assert_post_and_400(f'{POLICY_ENDPOINT}9999/communities/', data=data)
        self.assertEqual(Community.objects.count(), 0)

    def test_create_host_with_community_no_network(self):
        """Test that adding a community during host creation without IP."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
        }
        self.assert_post_and_406('/api/v1/hosts/', data=data)

    def test_create_host_with_community_network_missing_policy(self):
        """Test that adding a community during host creation with network missing policy fails."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)
        # Note, no policy is set on the network
        net = Network.objects.create(network="10.0.0.0/24", description="test_network")

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
            "network": net.network
        }
        self.assert_post_and_406('/api/v1/hosts/', data=data)
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
            "network": net_empty.network
        }
        self.assert_post_and_406('/api/v1/hosts/', data=data)
        net_empty.delete()
        net_policy.delete()

    def test_create_host_with_community_ok(self):
        """Test that adding a community during host creation with network and policy."""
        np = self._create_network_policy("host_with_community", [])
        community = self._create_community("community", "community desc", np)
        net = Network.objects.create(network="10.0.0.0/24", description="test_network", policy=np)

        data = {
            "name": "hostwithcommunity.example.com",
            "network_community": community.pk,
            "network": net.network
        }
        ret = self.assert_post_and_201('/api/v1/hosts/', data=data)
        ret = self.assert_get(ret.headers['Location'])
        print(ret.json())
        net.delete()