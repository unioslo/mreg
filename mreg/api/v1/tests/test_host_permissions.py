from django.contrib.auth.models import Group
from rest_framework import exceptions

from mreg.api.permissions import get_settings_groups, user_in_required_group
from mreg.models import ForwardZone, Host, Ipaddress, NetGroupRegexPermission, Network, PtrOverride, User


from .tests import MregAPITestCase


class Internals(MregAPITestCase):
    """Test internal structures in permissions."""
    def test_missing_group_settings(self):
        """Ensure that missing group settings are caught if requested."""
        with self.assertRaises(exceptions.APIException):
            get_settings_groups("NO_SUCH_SETTINGS_GROUP")

    def test_user_in_required_groups(self):
        """Ensure that user_in_required_groups works."""
        testuser, _ = User.objects.get_or_create(username="testuser")
        testgroup, _ = Group.objects.get_or_create(name="testgroup")

        with self.assertRaises(exceptions.APIException):
            user_in_required_group(testuser)

        # Note that required groups contains the names of the groups, not objects.
        # See the User definition in mreg/models_auth.py
        self.assertFalse(user_in_required_group(testuser, required_groups=[testgroup.name]))
        # The caching of group list requires us to manually expunge the cache.
        # This operation has no API, so right no we do it the hard way.
        testuser._group_list = None
        testuser.groups.add(testgroup)
        self.assertTrue(user_in_required_group(testuser, required_groups=[testgroup.name]))

        testuser.delete()
        testgroup.delete()


class HostsNoRights(MregAPITestCase):

    def setUp(self):
        self.client = self.get_token_client(superuser=False)

    def test_can_not_create_change_or_delete_host(self):
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post_and_403('/hosts/', data)
        Host.objects.create(name='host1.example.org')
        self.assert_patch_and_403('/hosts/host1.example.org', {'name': 'host2.example.org'})
        self.assert_delete_and_403('/hosts/host1.example.org')

    def test_client_must_be_logged_in(self):
        self.assert_get('/hosts/')
        self.client.logout()
        self.assert_get_and_401('/hosts/')


class HostBasePermissions(MregAPITestCase):

    def setUp(self):
        self.client = self.get_token_client(superuser=False)
        group = Group.objects.create(name='testgroup')
        group.user_set.add(self.user)
        Network.objects.create(network='10.1.0.0/25')
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='10.0.0.0/25',
                                               regex=r'^ho.*\.example\.org$')
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='10.1.0.0/25',
                                               regex=r'^ho.*\.example\.org$')


class Hosts(HostBasePermissions):

    def test_can_create_change_and_delete_host(self):
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post('/hosts/', data)
        self.assert_patch('/hosts/host1.example.org', {'ttl': '5000'})
        self.assert_patch('/hosts/host1.example.org', {'name': 'host2.example.org'})
        self.assert_delete('/hosts/host2.example.org')

    def test_can_create_host_with_network(self):
        data = {'name': 'host1.example.org', 'network': '10.1.0.0/25'}
        self.assert_post('/hosts/', data)

    def test_can_not_create_host_without_ip(self):
        data = {'name': 'host1.example.org'}
        self.assert_post_and_403('/hosts/', data)

    def test_can_not_create_host_outside_ip_range(self):
        # Make sure no history entires are created during a rejected post
        old_history = self.assert_get('/history/').json()
        data = {'name': 'host1.example.org', 'ipaddress': '11.0.0.1'}
        self.assert_post_and_403('/hosts/', data)
        self.assert_get_and_404('/hosts/' + data['name'])
        new_history = self.assert_get('/history/').json()
        self.assertEqual(old_history, new_history)

    def test_can_not_create_hostname_with_underscore(self):
        data1 = {'name': '_host1.example.org', 'ipaddress': '10.0.0.1'}
        data2 = {'name': 'host2._sub.example.org', 'ipaddress': '10.0.0.2'}
        self.assert_post_and_403('/hosts/', data1)
        self.assert_post_and_403('/hosts/', data2)

    def test_can_not_create_host_with_ip_and_network(self):
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.10', 'network': '10.0.0.0/25'}
        self.assert_post_and_400('/hosts/', data)

    def test_can_not_create_host_with_nonexisting_network(self):
        data = {'name': 'host1.example.org', 'network': '100.0.0.0/25'}
        self.assert_post_and_404('/hosts/', data)

    def test_can_not_create_host_with_erroneous_network(self):
        data = {'name': 'host1.example.org', 'network': '1.2.3.4/0'}
        self.assert_post_and_400('/hosts/', data)

    def test_can_not_change_host_without_ip(self):
        data = {'name': 'host1.example.org'}
        self.client_superuser = self.get_token_client()
        self.client_superuser.post('/api/v1/hosts/', data)
        self.assert_patch_and_403('/api/v1/hosts/host1.example.org', {'ttl': 1000})

    def test_can_not_rename_out_of_permissions(self):
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post('/hosts/', data)
        self.assert_patch_and_403('/hosts/host1.example.org', {'name': 'host1.example.com'})

    def test_can_not_change_host_out_of_permissions(self):
        """Test than one can not change host object without permission
           to the new host object"""

        def _post_and_get(name, ipaddress, client=self.client):
            data = {'name': name, 'ipaddress': ipaddress}
            ret = client.post('/api/v1/hosts/', data)
            return self.assert_get(ret['Location'])

        Network.objects.create(network='10.2.0.0/25')
        client_superuser = self.get_token_client()
        dotorg1 = _post_and_get('host1.example.org', '10.0.0.1')
        dotorg2 = _post_and_get('host2.example.org', '10.0.0.2')
        dotorg3 = _post_and_get('host3.example.org', '10.2.0.3',
                                client=client_superuser)
        dotcom = _post_and_get('host1.example.com', '10.0.0.3',
                               client=client_superuser)
        ip_id = dotorg1.json()['ipaddresses'][0]['id']
        datafail1 = {'host': dotcom.json()['id']}
        datafail2 = {'host': dotorg3.json()['id'], 'ipaddress': '10.0.0.4'}
        dataok = {'host': dotorg2.json()['id']}
        path = f'/api/v1/ipaddresses/{ip_id}'
        path2 = '/api/v1/ipaddresses/'
        self.assert_patch_and_403(path, datafail1)
        self.assert_post_and_403(path2, datafail2)
        self.assert_patch(path, dataok)

    def test_can_not_create_CNAME_outside_permissions(self):
        ForwardZone.objects.create(name='example.org', primary_ns='ns.example.org', email='hostmaster@example.org')
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        ret = self.assert_post('/hosts/', data)
        # read back to get the ID
        host = self.assert_get(ret['Location']).json()
        # try to create a cname that doesn't match the regex in the permission (should fail)
        data = {'name': 'snafu.example.org', 'host': host['id']}
        self.assert_post_and_403('/cnames/', data)
        # try to create the same cname, but with superuser (it should work now)
        super_client = self.get_token_client()
        self.assert_post('/cnames/', data, client=super_client)
        # create a cname that matches the regex, with the ordinary (non-super) user. Should work
        data = {'name': 'host123.example.org', 'host': host['id']}
        self.assert_post('/cnames/', data)


class Ipaddresses(HostBasePermissions):

    def setUp(self):
        super().setUp()
        self.data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.10'}
        self.assert_post('/hosts/', self.data)
        self.host_one = Host.objects.get(name=self.data['name'])
        self.ip_one = Ipaddress.objects.get(host__name=self.data['name'])

    def test_can_add_change_and_delete_ip(self):
        data = {'ipaddress': '10.0.0.11', 'host': self.host_one.id}
        ret = self.assert_post('/ipaddresses/', data).data
        path = f'/ipaddresses/{ret["id"]}'
        self.assert_patch(path, {'ipaddress': '10.0.0.12'})
        self.assert_delete(path)

    def test_can_change_macaddress(self):
        self.assert_patch(f'/ipaddresses/{self.ip_one.id}',
                          {'macaddress': 'aa:bb:cc:dd:ee:ff'})
        self.assert_patch(f'/ipaddresses/{self.ip_one.id}',
                          {'macaddress': ''})

    def test_can_not_use_reserved_ipaddress(self):
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='2001:db8::/64',
                                               regex=r'.*\.example\.org$')
        Network.objects.create(network='10.0.0.0/25')
        Network.objects.create(network='2001:db8::/64')
        ptr = PtrOverride.objects.create(host=self.host_one, ipaddress='10.0.0.20')
        super_client = self.get_token_client()
        admin_client = self.get_token_client(superuser=False, adminuser=True)

        def _assert_host(ip):
            data = {'name': 'host2.example.org', 'ipaddress': ip}
            path = '/api/v1/hosts/'
            self.assert_post_and_403(path, data)
            self.assert_post_and_403(path, data, client=admin_client)
            ret = self.assert_post(path, data, client=super_client)
            self.assert_delete(ret['Location'], client=super_client)

        def _assert_ip(ip):

            def __assert_post(path):
                self.assert_post_and_403(path, data)
                self.assert_post_and_403(path, data, client=admin_client)
                self.assert_post(path, data, client=super_client)

            def __assert_patch(path):
                self.assert_patch_and_403(path, data)
                self.assert_patch_and_403(path, data, client=admin_client)

            data = {'host': self.host_one.id, 'ipaddress': ip}
            __assert_post('/api/v1/ipaddresses/')
            Ipaddress.objects.filter(ipaddress=ip).delete()
            __assert_post('/api/v1/ptroverrides/')
            PtrOverride.objects.filter(ipaddress=ip).delete()
            data = {'ipaddress': ip}
            __assert_patch(f'/api/v1/ipaddresses/{self.ip_one.id}')
            __assert_patch(f'/api/v1/ptroverrides/{ptr.id}')

        def _assert(ip):
            _assert_ip(ip)
            _assert_host(ip)

        _assert('10.0.0.0')
        _assert('10.0.0.1')
        _assert('10.0.0.2')
        _assert('10.0.0.127')
        _assert('2001:db8::')
        _assert('2001:db8::1')
        _assert('2001:db8::2')

    def test_network_admin_can_use_reserved_addresses(self):
        """Members of NETWORK_ADMIN_GROUP can use reserved network addresses"""

        self.client = self.get_token_client(username='networkadmin',
                                            superuser=False, adminuser=True)
        self.add_user_to_groups('NETWORK_ADMIN_GROUP')
        Network.objects.create(network='10.0.0.0/25')
        Network.objects.create(network='2001:db8::/64')

        def _assert_host(ip):
            data = {'name': 'host2.example.org', 'ipaddress': ip}
            path = '/api/v1/hosts/'
            self.assert_post(path, data)
            Host.objects.filter(name=data['name']).delete()

        def _assert_ip(ip):
            path = '/api/v1/ipaddresses/'
            data = {'host': self.host_one.id, 'ipaddress': ip}
            ret = self.assert_post(path, data)
            self.assert_delete(path + str(ret.data['id']))
            path = '/api/v1/ptroverrides/'
            ret = self.assert_post(path, data)
            self.assert_delete(path + str(ret.data['id']))
            data = {'ipaddress': ip}
            self.assert_patch(f'/api/v1/ipaddresses/{self.ip_one.id}', data)

        def _assert(ip):
            _assert_ip(ip)
            _assert_host(ip)

        _assert('10.0.0.0')
        _assert('10.0.0.1')
        _assert('10.0.0.2')
        _assert('10.0.0.127')
        _assert('2001:db8::0')
        _assert('2001:db8::1')
        _assert('2001:db8::2')


class Txts(HostBasePermissions):

    def setUp(self):
        super().setUp()
        self.data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post('/hosts/', self.data)
        self.host_one = Host.objects.get(name=self.data['name'])

    def test_can_add_change_and_delete_txt(self):
        data = {'txt': 'MY TXT', 'host': self.host_one.id}
        ret = self.assert_post('/txts/', data).data
        path = f'/txts/{ret["id"]}'
        self.assert_patch(path, {'txt': 'my new txt'})
        self.assert_delete(path)

    def test_can_not_add_txt_to_host_without_ip(self):
        data = {'txt': 'MY TXT', 'host': self.host_one.id}
        self.host_one.ipaddresses.all().delete()
        self.assert_post_and_403('/txts/', data)


class Underscore(MregAPITestCase):
    """Test that only superusers can create entries with an underscore."""

    def test_can_create_hostname_with_prefix_underscore(self):
        data1 = {'name': '_host1.example.org', 'ipaddress': '10.0.0.1'}
        data2 = {'name': 'host2._sub.example.org', 'ipaddress': '10.0.0.2'}
        self.assert_post('/hosts/', data1)
        self.assert_post('/hosts/', data2)


class Wildcard(MregAPITestCase):
    """Test that only superusers can create entries with a wildcard."""

    def setUp(self):
        self.client = self.get_token_client(superuser=False, adminuser=True)
        self.admin_user = self.user  # keep this user for later, as the next call to get_token_client will overwrite it
        self.super_client = self.get_token_client()

    def test_super_only_create_wildcard(self):
        """Only a super user may do a POST with a wildcard."""
        data1 = {'name': '*.example.org'}
        data2 = {'name': '*.sub.example.org', 'ipaddress': '10.0.0.1'}
        path = '/api/v1/hosts/'
        self.assert_post_and_403(path, data1)
        self.assert_post_and_201(path, data1, self.super_client)
        self.assert_post_and_403(path, data2)
        self.assert_post_and_201(path, data2, self.super_client)

    def test_super_only_rename_to_wildcard(self):
        """Only a super user may rename (patch) a hostname to a wildcard."""
        data = {'name': '*.example.org'}
        path = '/api/v1/hosts/'
        self.assert_post(path, {'name': 'host1.example.org'})
        self.assert_patch_and_403(f'{path}host1.example.org', data)
        self.assert_patch(f'{path}host1.example.org', data, client=self.super_client)

    def test_super_only_delete_wildcard(self):
        self.test_super_only_create_wildcard()
        path = '/api/v1/hosts/*.example.org'
        self.assert_delete_and_403(path)
        self.assert_delete(path, client=self.super_client)

    def test_special_group_members_create_wildcard(self):
        """Members in DNS_WILDCARD_GROUP can create entries with a wildcard, but only below subdomains"""
        self.user = self.admin_user
        self.add_user_to_groups('DNS_WILDCARD_GROUP')
        data1 = {'name': '*.example.org'}  # not allowed
        data2 = {'name': '*.sub.example.org'}  # allowed
        data3 = {'name': '*._sub.example.org'} # try to sneak an underscore in there
        path = '/api/v1/hosts/'
        self.assert_post_and_403(path, data1)
        self.assert_post_and_201(path, data2)
        self.assert_post_and_403(path, data3)
