from django.contrib.auth.models import Group

from mreg.models import Host, Ipaddress, NetGroupRegexPermission

from .tests import MregAPITestCase, create_forward_zone


class APISrvsTestCase(MregAPITestCase):
    """Test SRVs"""

    def setUp(self):
        super().setUp()
        self.host_target = Host.objects.create(name='target.example.org')

    def test_srvs_post(self):
        data = {'name': '_test123._tls.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'host': self.host_target.id}
        self.assert_post("/srvs/", data)

    def test_srvs_post_reject_invalid(self):
        data = {'name': '_test._tcp.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'host': self.host_target.id}

        def _assert_400():
            self.assert_post_and_400("/srvs/", fail)
        # Missing name
        fail = data.copy()
        del fail['name']
        _assert_400()
        # Invalid port
        fail = data.copy()
        fail['port'] = -1
        _assert_400()
        # Wrong type
        fail = data.copy()
        fail['name'] = '_test._udp2.example.org'
        _assert_400()

    def test_srvs_list(self):
        self.test_srvs_post()
        ret = self.assert_get("/srvs/")
        self.assertEqual(ret.data['count'], 1)

    def test_srvs_delete(self):
        self.test_srvs_post()
        srvs = self.assert_get("/srvs/").json()['results']
        self.assert_delete("/srvs/{}".format(srvs[0]['id']))
        sshfps = self.assert_get("/srvs/").json()
        self.assertEqual(len(sshfps['results']), 0)

    def test_srvs_zone_autoupdate_add(self):
        zone = create_forward_zone()
        zone.updated = False
        zone.save()
        self.test_srvs_post()
        zone.refresh_from_db()
        self.assertTrue(zone.updated)

    def test_srvs_zone_autoupdate_delete(self):
        zone = create_forward_zone()
        self.test_srvs_post()
        zone.updated = False
        zone.save()
        sshfps = self.assert_get("/srvs/").data['results']
        self.assert_delete("/srvs/{}".format(sshfps[0]['id']))
        zone.refresh_from_db()
        self.assertTrue(zone.updated)


class SrvBasePermissions(MregAPITestCase):

    def setUp(self):
        self.client = self.get_token_client(superuser=False)

        self.host_target = Host.objects.create(name='target.example.org')
        Ipaddress.objects.create(host=self.host_target, ipaddress='10.0.0.20')

        group = Group.objects.create(name='testgroup')
        group.user_set.add(self.user)
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='10.0.0.0/25',
                                               regex=r'.*\.example\.org$')

    def test_can_create_change_and_delete_srv(self):
        data = {'name': '_test123._tls.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'host': self.host_target.id}
        srv_id = self.assert_post("/srvs/", data).json()['id']
        self.assert_patch(f'/srvs/{srv_id}', {'priority': '20'})
        self.assert_patch(f'/srvs/{srv_id}', {'port': '4321'})
        self.assert_delete(f'/srvs/{srv_id}')
