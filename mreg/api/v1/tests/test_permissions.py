from unittest import mock

from django.conf import settings
from django.contrib.auth.models import Group
from django.test import RequestFactory
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient, force_authenticate
from mreg.api.permissions import IsGrantedNetGroupRegexPermission
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network, NetGroupRegexPermission

from .tests import MregAPITestCase


class TestIsGrantedNetGroupRegexPermission(MregAPITestCase):

    @mock.patch('mreg.api.permissions.User.from_request')
    @mock.patch('mreg.api.permissions.IsGrantedNetGroupRegexPermission.has_obj_perm', return_value=False)
    @mock.patch('mreg.api.permissions.IsGrantedNetGroupRegexPermission._get_hostname_and_ips',
                return_value=('hostname', ['ip']))
    def test_unhandled_view(
        self,
        mock_get_hostname_and_ips,
        mock_has_obj_perm,
        mock_user_from_request
    ):
        request = RequestFactory().post('/')
        user = mock.Mock()
        user.group_list = []
        user.is_mreg_superuser = False
        user.is_mreg_admin = False
        request.user = user
        # Make it so every time we call User.from_request, it returns the same user object
        # that we created above.
        mock_user_from_request.return_value = user
        force_authenticate(request, user=user)

        # Mock view that is not an instance of any of the checked classes
        view = mock.Mock()

        # Mock object that doesn't have 'host' attribute
        view.get_object = mock.Mock(return_value=None)

        # Mock serializer with data that doesn't have 'host' or 'ipaddress'
        serializer = mock.Mock()
        serializer.validated_data = {}

        permission = IsGrantedNetGroupRegexPermission()

        with self.assertRaises(PermissionDenied):
            permission.has_create_permission(request, view, serializer)

        with self.assertRaises(PermissionDenied):
            permission.has_update_permission(request, view, serializer)

        with self.assertRaises(PermissionDenied):
            permission.has_destroy_permission(request, view, serializer)


class NetGroupRegexPermissionTestCase(MregAPITestCase):

    data = {'group': 'testgroup', 'range': '10.0.0.0/24',
            'regex': r'.*\.example\.org$'}
    
    def test_create(self):
        self.assert_post('/permissions/netgroupregex/', self.data)

    def test_get(self):
        self.assert_get('/permissions/netgroupregex/')
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        ret2 = self.assert_get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret1.json(), ret2.json())

    def test_get_ordering(self):
        obj1 = self.data
        obj2 = self.data.copy()
        obj2["group"] = 'testgroup2'

        self.assert_post('/permissions/netgroupregex/', obj1)
        self.assert_post('/permissions/netgroupregex/', obj2)
        ret1 = self.assert_get('/permissions/netgroupregex/?ordering=range,group')
        self.assertEqual(ret1.json()['results'][0]['group'], obj1['group'])
        self.assertEqual(ret1.json()['results'][1]['group'], obj2['group'])

    def test_get_at_different_privilege_levels(self):
        """Verify get at different privilege levels."""
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        self.client = self.get_token_client(superuser=False, adminuser=False)
        ret2 = self.assert_get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret1.json(), ret2.json())
        self.client = APIClient()
        self.assert_get_and_401('/permissions/netgroupregex/{}'.format(ret1.json()['id']))

    def test_list(self):
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        data = self.assert_get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 1)
        self.assertEqual(data['results'][0], ret1.json())

    def test_update(self):
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        self.assert_patch('/permissions/netgroupregex/{}'.format(ret1.json()['id']),
                          {'group': 'testgroup2'})
        ret = self.assert_get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret.json()['group'], 'testgroup2')

    # a non-privileged user shouldn't be able to change labels on permissions
    def test_alter_labels(self):
        # create a permission
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        # create a normal label
        self.assert_post('/api/v1/labels/', {'name': 'normal_label', 'description': 'A normal label'})
        # find the id of the label
        response = self.assert_get('/api/v1/labels/name/normal_label')
        labeldata = response.json()
        # switch to a non-privileged client
        self.client = self.get_token_client(superuser=False, adminuser=False)
        # verify that trying to add the label to the permission fails
        self.assert_patch_and_403('/permissions/netgroupregex/{}'.format(ret1.json()['id']),
                                  {'labels': [labeldata['id']]})

    def test_delete(self):
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        data = self.assert_get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 1)
        self.assert_delete('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        data = self.assert_get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 0)


class NetGroupRegexPermissionTestCaseAsAdmin(NetGroupRegexPermissionTestCase):

    def setUp(self):
        self.client = self.get_token_client(superuser=False, adminuser=True)


class ReservedAddressPermissionsTestCase(MregAPITestCase):
    """Test IsGrantedReservedAddressPermission for network and broadcast addresses."""

    def setUp(self):
        super().setUp()
        # Create test networks
        self.network_ipv4 = Network.objects.create(
            network='10.0.0.0/24', 
            description='Test IPv4 network'
        )
        self.network_ipv6 = Network.objects.create(
            network='2001:db8::/64', 
            description='Test IPv6 network'
        )
        
        # Network addresses
        self.ipv4_network_addr = '10.0.0.0'      # network address
        self.ipv4_broadcast_addr = '10.0.0.255'  # broadcast address
        self.ipv4_regular_addr = '10.0.0.10'     # regular address
        
        # IPv6 only has network address (no broadcast)
        self.ipv6_network_addr = '2001:db8::'    # network address
        self.ipv6_regular_addr = '2001:db8::10'  # regular address

    def test_superuser_can_use_reserved_addresses(self):
        """Superusers should be able to use network and broadcast addresses."""
        # Test with IPv4 network address
        data = {'name': 'test-network.example.org', 'ipaddress': self.ipv4_network_addr}
        self.assert_post_and_201('/hosts/', data)
        
        # Test with IPv4 broadcast address
        data = {'name': 'test-broadcast.example.org', 'ipaddress': self.ipv4_broadcast_addr}
        self.assert_post_and_201('/hosts/', data)
        
        # Test with IPv6 network address
        data = {'name': 'test-ipv6-network.example.org', 'ipaddress': self.ipv6_network_addr}
        self.assert_post_and_201('/hosts/', data)

    def test_network_admin_can_use_reserved_addresses(self):
        """Network admins should be able to use reserved addresses."""
        with self.temporary_client_as_network_admin():
            self.add_user_to_groups("NETWORK_ADMIN_GROUP")
            NetGroupRegexPermission.objects.create(
                group=settings.NETWORK_ADMIN_GROUP,
                range=self.network_ipv4.network,
                regex=r'.*\.example\.org$'
            )
            # Test with IPv4 network address
            data = {'name': 'test-network.example.org', 'ipaddress': self.ipv4_network_addr}
            self.assert_post_and_201('/hosts/', data)
            
            # Test with IPv4 broadcast address
            data = {'name': 'test-broadcast.example.org', 'ipaddress': self.ipv4_broadcast_addr}
            self.assert_post_and_201('/hosts/', data)

    def test_regular_user_cannot_use_reserved_addresses(self):
        """Regular users should not be able to use network and broadcast addresses."""
        with self.temporary_client_as_normal_user():       
            # Test with IPv4 network address - should fail
            data = {'name': 'test-network.example.org', 'ipaddress': self.ipv4_network_addr}
            self.assert_post_and_403('/hosts/', data)
            
            # Test with IPv4 broadcast address - should fail
            data = {'name': 'test-broadcast.example.org', 'ipaddress': self.ipv4_broadcast_addr}
            self.assert_post_and_403('/hosts/', data)
            
            # Test with IPv6 network address - should fail
            data = {'name': 'test-ipv6-network.example.org', 'ipaddress': self.ipv6_network_addr}
            self.assert_post_and_403('/hosts/', data)

    def test_regular_user_can_use_normal_addresses(self):
        """Regular users should be able to use normal addresses."""
        with self.temporary_client_as_normal_user():
            # Grant network permissions for regular testing
            group = Group.objects.create(name='testgroup')
            group.user_set.add(self.user)
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='10.0.0.0/24',
                regex=r'.*\.example\.org$'
            )
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='2001:db8::/64',
                regex=r'.*\.example\.org$'
            )
            
            # Test with regular IPv4 address - should work
            data = {'name': 'test-regular.example.org', 'ipaddress': self.ipv4_regular_addr}
            self.assert_post_and_201('/hosts/', data)
            
            # Test with regular IPv6 address - should work
            data = {'name': 'test-regular-ipv6.example.org', 'ipaddress': self.ipv6_regular_addr}
            self.assert_post_and_201('/hosts/', data)

    def test_ipaddress_endpoint_reserved_addresses(self):
        """Test reserved address restrictions on /ipaddresses/ endpoint."""
        # Create a host first
        host = Host.objects.create(name='test.example.org')
        
        # Superuser can create reserved IP addresses
        data = {'host': host.id, 'ipaddress': self.ipv4_network_addr}
        self.assert_post_and_201('/ipaddresses/', data)
        
        # Regular user cannot
        with self.temporary_client_as_normal_user():
            data = {'host': host.id, 'ipaddress': self.ipv4_broadcast_addr}
            self.assert_post_and_403('/ipaddresses/', data)

    def test_ptroverride_endpoint_reserved_addresses(self):
        """Test reserved address restrictions on /ptroverrides/ endpoint."""
        # Create a host first
        host = Host.objects.create(name='test.example.org')
        
        # Superuser can create reserved IP addresses
        data = {'host': host.id, 'ipaddress': self.ipv4_network_addr}
        self.assert_post_and_201('/ptroverrides/', data)
        
        # Regular user cannot
        with self.temporary_client_as_normal_user():
            data = {'host': host.id, 'ipaddress': self.ipv4_broadcast_addr}
            self.assert_post_and_403('/ptroverrides/', data)

    def test_update_to_reserved_address_restricted(self):
        """Test that updating an IP to a reserved address is restricted."""
        # Create host and IP as superuser
        host = Host.objects.create(name='test.example.org')
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_regular_addr)

        data = {'ipaddresses': self.ipv4_network_addr}

        # Regular user cannot update to reserved address
        with self.temporary_client_as_normal_user():
            self.assert_patch_and_403(f'/hosts/{host.name}', data)
            
        # But superuser can
        self.assert_patch_and_204(f"/hosts/{host.name}", data)

    def test_network_outside_mreg_not_restricted(self):
        """Test that IPs in networks not managed by mreg are not restricted."""
        # Create a host in a network outside MREG
        host = Host.objects.create(name="test-external.example.org")
        Ipaddress.objects.create(host=host, ipaddress="192.168.1.123")

        with self.temporary_client_as_normal_user():
            group = Group.objects.create(name='testgroup')
            group.user_set.add(self.user)
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='192.168.1.0/24',
                regex=r'.*\.example\.org$'
            )
            
            # Assign what would be a network address in the context of
            # the given network
            data = {'host': host.id, 'ipaddress': '192.168.1.0'}
            self.assert_post_and_201("/ipaddresses/", data)

    def test_delete_operations_not_restricted(self):
        """Test that delete operations are not restricted by this permission."""
        # Create host with reserved address as superuser
        host = Host.objects.create(name='test.example.org')
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_network_addr)
        
        # Regular user should be able to delete (if they have other necessary permissions)
        # Note: This test might fail due to other permission restrictions, but should not
        # fail specifically due to the reserved address permission
        with self.temporary_client_as_normal_user():
            # Grant the user permission to the host to test deletion specifically
            group = Group.objects.create(name='testgroup')
            group.user_set.add(self.user)
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='10.0.0.0/24',
                regex=r'.*\.example\.org$'
            )
            
            # The delete should work (reserved address permission doesn't apply to deletes)
            self.assert_delete_and_204(f'/ipaddresses/{ip.id}')


class ReservedAddressPermissionsEdgeCasesTestCase(MregAPITestCase):
    """Test edge cases for reserved address permissions."""
    
    def setUp(self):
        super().setUp()
        # Create a /30 network (very small network for edge case testing)
        self.small_network = Network.objects.create(
            network='192.168.1.0/30',
            description='Small test network'
        )
        # In a /30: .0 = network, .1 = first host, .2 = second host, .3 = broadcast
        
    def test_small_network_reserved_addresses(self):
        """Test reserved addresses in very small networks."""
        self.client = self.get_token_client(superuser=False)
        
        # Network address should be restricted
        data = {'name': 'test1.example.org', 'ipaddress': '192.168.1.0'}
        self.assert_post_and_403('/hosts/', data)
        
        # Broadcast address should be restricted  
        data = {'name': 'test2.example.org', 'ipaddress': '192.168.1.3'}
        self.assert_post_and_403('/hosts/', data)

    def test_single_host_network(self):
        """Test /32 networks (single host)."""
        Network.objects.create(
            network='192.168.2.1/32',
            description='Single host network'
        )
        
        
        # In a /32, the network address and the host address are the same
        # This should be restricted for regular users
        with self.temporary_client_as_normal_user():
            data = {'name': 'test.example.org', 'ipaddress': '192.168.2.1'}
            self.assert_post_and_403('/hosts/', data)
        
        # But should work for superusers
        self.assert_post_and_201('/hosts/', data)