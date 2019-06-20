from django.contrib.auth.models import Group

from mreg.models import Host, Ipaddress, NetGroupRegexPermission

from .tests import MregAPITestCase


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
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='10.0.0.0/25',
                                               regex=r'.*\.example\.org$')


class Hosts(HostBasePermissions):

    def test_can_create_change_and_delete_host(self):
        data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post('/hosts/', data)
        self.assert_patch('/hosts/host1.example.org', {'ttl': '5000'})
        self.assert_patch('/hosts/host1.example.org', {'name': 'host2.example.org'})
        self.assert_delete('/hosts/host2.example.org')

    def test_can_not_create_host_without_ip(self):
        data = {'name': 'host1.example.org'}
        self.assert_post_and_403('/hosts/', data)

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
        client_superuser = self.get_token_client()
        dotorg1 = _post_and_get('host1.example.org', '10.0.0.1')
        dotorg2 = _post_and_get('host2.example.org', '10.0.0.2')
        dotcom = _post_and_get('host1.example.com', '10.0.0.3',
                               client=client_superuser)
        ip_id = dotorg1.json()['ipaddresses'][0]['id']
        datafail = {'host': dotcom.json()['id']}
        dataok = {'host': dotorg2.json()['id']}
        path = f'/api/v1/ipaddresses/{ip_id}'
        self.assert_patch_and_403(path, datafail)
        self.assert_patch(path, dataok)


class Ipaddresses(HostBasePermissions):

    def setUp(self):
        super().setUp()
        self.data = {'name': 'host1.example.org', 'ipaddress': '10.0.0.1'}
        self.assert_post('/hosts/', self.data)
        self.host_one = Host.objects.get(name=self.data['name'])
        self.ip_one = Ipaddress.objects.get(host__name=self.data['name'])

    def test_can_add_change_and_delete_ip(self):
        data = {'ipaddress': '10.0.0.2', 'host': self.host_one.id}
        ret = self.assert_post('/ipaddresses/', data).data
        path = f'/ipaddresses/{ret["id"]}'
        self.assert_patch(path, {'ipaddress': '10.0.0.3'})
        self.assert_delete(path)

    def test_can_change_macaddress(self):
        self.assert_patch(f'/ipaddresses/{self.ip_one.id}',
                          {'macaddress': 'aa:bb:cc:dd:ee:ff'})
        self.assert_patch(f'/ipaddresses/{self.ip_one.id}',
                          {'macaddress': ''})


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


class Wildcard(MregAPITestCase):
    """Test that only superusers can create entries with a wildcard."""

    def setUp(self):
        self.client = self.get_token_client(superuser=False, adminuser=True)
        self.super_client = self.get_token_client()

    def test_super_only_create_wildcard(self):
        """Only a super user may do a POST with a wildcard."""
        data = {'name': '*.example.org'}
        path = '/api/v1/hosts/'
        self.assert_post_and_403(path, data)
        ret = self.super_client.post(path, data)
        self.assertEqual(ret.status_code, 201)

    def test_super_only_rename_to_wildcard(self):
        """Only a super user may rename (patch) a hostname to a wildcard."""
        data = {'name': '*.example.org'}
        path = '/api/v1/hosts/'
        self.assert_post(path, {'name': 'host1.example.org'})
        self.assert_patch_and_403(f'{path}host1.example.org', data)
        ret = self.super_client.patch(f'{path}host1.example.org', data)
        self.assertEqual(ret.status_code, 204)
