from enum import Enum
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import Group
from django.test import RequestFactory
from django.test.client import WSGIRequest
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient, force_authenticate
from mreg.api.permissions import IsGrantedNetGroupRegexPermission, IsGrantedReservedAddressPermission
from mreg.models.auth import User
from mreg.models.host import Host, Ipaddress
from mreg.models.network import Network, NetGroupRegexPermission

from .tests import MregAPITestCase


def get_mock_user(
    superuser: bool = False,
    admin: bool = False,
    network_admin: bool = False,
    hostgroup_admin: bool = False,
    dns_wildcard_admin: bool = False,
    underscore_admin: bool = False,
    hostpolicy_admin: bool = False,
) -> mock.Mock:
    """Helper function to create a mock user with specific permissions."""
    user = mock.Mock(spec=User)
    
    # Ensure all `is_mreg_*` attributes are set to False by default
    group_attrs = {attr: False for attr in dir(User) if attr.startswith("is_mreg_")}

    def set_attr(name: str):
        group_attrs.update({attr: True for attr in dir(User) if name in attr})

    if superuser:
        set_attr("superuser")
    if admin:
        set_attr("admin")
    if network_admin:
        set_attr("network_admin")
    if hostgroup_admin:
        set_attr("hostgroup_admin")
    if dns_wildcard_admin:
        set_attr("dns_wildcard_admin")
    if underscore_admin:
        set_attr("underscore_admin")
    if hostpolicy_admin:
        set_attr("hostpolicy_admin")

    user.configure_mock(**group_attrs)
    user.group_list = []
    return user


def get_mock_request(user: mock.Mock, mock_user_from_request: mock.Mock, path: str = "/") -> WSGIRequest:
    """Helper function to create a mock request with a given user."""
    request = RequestFactory().post(path)
    request.user = user
    # Make it so every time we call User.from_request, it returns the mock user
    mock_user_from_request.return_value = user
    force_authenticate(request, user=user)
    return request


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
        user = get_mock_user()  # Regular user
        request = get_mock_request(user, mock_user_from_request)

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

        class ReservedAddress(str, Enum):
            IPV4_NETWORK = self.ipv4_network_addr
            IPV4_BROADCAST = self.ipv4_broadcast_addr
            IPV6_NETWORK = self.ipv6_network_addr

            @property
            def dns_name(self):
                """Return a DNS name for the reserved address."""
                return f"{self.name.lower().replace('_', '')}.example.org"

        self.reserved_addresses = [
            ReservedAddress.IPV4_NETWORK, 
            ReservedAddress.IPV4_BROADCAST, 
            ReservedAddress.IPV6_NETWORK,
        ]

        # Give network admins permissions for the test networks
        NetGroupRegexPermission.objects.create(
            group=settings.NETWORK_ADMIN_GROUP,
            range=self.network_ipv4.network,
            regex=r'.*\.example\.org$'
        )
        # Give network admins permissions for the test networks
        NetGroupRegexPermission.objects.create(
            group=settings.NETWORK_ADMIN_GROUP,
            range=self.network_ipv6.network,
            regex=r'.*\.example\.org$'
        )

    @mock.patch('mreg.api.permissions.User.from_request')
    @mock.patch('mreg.api.permissions.IsGrantedNetGroupRegexPermission.has_obj_perm', return_value=False)
    @mock.patch('mreg.api.permissions.IsGrantedNetGroupRegexPermission._get_hostname_and_ips',
                return_value=('hostname', ['ip']))
    def test_view_with_ip_data(
        self,
        mock_get_hostname_and_ips,
        mock_has_obj_perm,
        mock_user_from_request
    ):
        """Test that IsGrantedReservedAddressPermission raises PermissionDenied for regular users when
        trying to pass data containing a field named 'ipaddresses' using reserved addresses."""
        user = get_mock_user()  # Regular user
        request = get_mock_request(user, mock_user_from_request)

        view = mock.Mock()
        
        serializer = mock.Mock()
        serializer.validated_data = {"ipaddress": self.ipv4_network_addr}

        permission = IsGrantedReservedAddressPermission()

        with self.assertRaises(PermissionDenied):
            permission.has_create_permission(request, view, serializer)

        with self.assertRaises(PermissionDenied):
            permission.has_update_permission(request, view, serializer)

        # Destroy permissions are routed through `has_permission`, and should pass
        assert permission.has_destroy_permission(request, view, serializer)

    def test_superuser_can_use_reserved_addresses(self):
        """Superusers should be able to use network and broadcast addresses."""
        for addr in self.reserved_addresses:
            data = {'name': addr.dns_name, 'ipaddress': addr.value}
            self.assert_post_and_201('/hosts/', data)


    def test_network_admin_can_use_reserved_addresses(self):
        """Network admins should be able to use reserved addresses."""
        with self.temporary_client_as_network_admin():
            for addr in self.reserved_addresses:
                data = {'name': addr.dns_name, 'ipaddress': addr.value}
                self.assert_post_and_201('/hosts/', data)


    def test_regular_user_cannot_use_reserved_addresses(self):
        """Regular users should not be able to use reserved addresses."""
        with self.temporary_client_as_normal_user():       
            for addr in self.reserved_addresses:
                data = {'name': addr.dns_name, 'ipaddress': addr.value}
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
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_regular_addr)
        
        for address in self.reserved_addresses:
            data = {'host': host.id, 'ipaddress': address}
            # Regular user cannot create reserved IP addresses
            with self.temporary_client_as_normal_user():
                self.assert_post_and_403('/ipaddresses/', data)
            # Network admin can
            with self.temporary_client_as_network_admin():
                self.assert_post_and_201('/ipaddresses/', data)

    def test_post_ptroverride_reserved_addresses(self):
        """Test reserved address restrictions on POST /ptroverrides/ endpoint."""
        host = Host.objects.create(name='test.example.org')
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_regular_addr)
        
        for address in self.reserved_addresses:
            data = {'host': host.id, 'ipaddress': address}
             # Regular user denied
            with self.temporary_client_as_normal_user():
                self.assert_post_and_403('/ptroverrides/', data)
            # Network admin permitted
            with self.temporary_client_as_network_admin():
                self.assert_post_and_201('/ptroverrides/', data)

    def test_patch_hosts_reserved_addresses(self):
        """Test that updating an IP to a reserved address is restricted."""
        host = Host.objects.create(name='test.example.org')
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_regular_addr)

        for address in self.reserved_addresses:
            data = {'ipaddresses': address}
            # Regular user denied
            with self.temporary_client_as_normal_user():
                self.assert_patch_and_403(f'/hosts/{host.name}', data)
            # Network admin permitted
            with self.temporary_client_as_network_admin():
                self.assert_patch_and_204(f'/hosts/{host.name}', data)

    def test_network_outside_mreg_not_restricted(self):
        """Test that IPs in networks not managed by mreg are not restricted."""
        # Create a host in a network outside MREG
        host = Host.objects.create(name="test-external.example.org")
        Ipaddress.objects.create(host=host, ipaddress="192.168.1.123")

        with self.temporary_client_as_normal_user():
            group = Group.objects.create(name='testgroup')
            group.user_set.add(self.user)

            # Assign permissions for IPv4 and IPv6 networks outside MREG
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='192.168.1.0/24',
                regex=r'.*\.example\.org$'
            )
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range='2002:db9::/64',
                regex=r'.*\.example\.org$'
            )
            
            # Assign what would be reserved addresses in the context of the given networks
            addresses = ["192.168.1.0", "192.168.1.255", "2002:db9::"]
            for addr in addresses:
                data = {'host': host.id, 'ipaddress': addr}
                self.assert_post_and_201("/ipaddresses/", data)

    def test_delete_operations_not_restricted(self):
        """Test that delete operations are not restricted by this permission."""
        host = Host.objects.create(name='test.example.org')
        ip = Ipaddress.objects.create(host=host, ipaddress=self.ipv4_network_addr)
        
        with self.temporary_client_as_normal_user():
            group = Group.objects.create(name='testgroup')
            group.user_set.add(self.user)
            NetGroupRegexPermission.objects.create(
                group='testgroup',
                range=self.network_ipv4.network,
                regex=r'.*\.example\.org$'
            )
            
            # The delete should work (reserved address permission doesn't apply to deletes)
            self.assert_delete_and_204(f'/ipaddresses/{ip.id}')

    def test_small_network_reserved_addresses(self):
        """Test reserved addresses in very small networks."""
        # In a /30: .0 = network, .1 = first host, .2 = second host, .3 = broadcast
        Network.objects.create(
            network='192.168.1.0/30',
            description='Small test network'
        )
        NetGroupRegexPermission.objects.create(
            group=settings.NETWORK_ADMIN_GROUP,
            range='192.168.1.0/30',
            regex=r'.*\.example\.org$'
        )
        
        # Network address
        data = {'name': 'test1.example.org', 'ipaddress': '192.168.1.0'}
        with self.temporary_client_as_normal_user():
            self.assert_post_and_403('/hosts/', data)
        with self.temporary_client_as_network_admin():
            self.assert_post_and_201('/hosts/', data)
        
        # Broadcast address
        data = {'name': 'test2.example.org', 'ipaddress': '192.168.1.3'}
        with self.temporary_client_as_normal_user():
            self.assert_post_and_403('/hosts/', data)
        with self.temporary_client_as_network_admin():
            self.assert_post_and_201('/hosts/', data)

    def test_single_host_network(self):
        """Test /32 networks (single host)."""
        Network.objects.create(
            network='192.168.2.1/32',
            description='Single host network'
        )
        NetGroupRegexPermission.objects.create(
            group=settings.NETWORK_ADMIN_GROUP,
            range='192.168.2.1/32',
            regex=r'.*\.example\.org$'
        )
        # In a /32, the network address and the host address are the same
        data = {'name': 'test.example.org', 'ipaddress': '192.168.2.1'}
        with self.temporary_client_as_normal_user():
            self.assert_post_and_403('/hosts/', data)
        with self.temporary_client_as_network_admin():
            self.assert_post_and_201('/hosts/', data)