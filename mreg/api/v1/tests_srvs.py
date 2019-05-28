from mreg.models import Host

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
        ret = self.client.post("/srvs/", data)
        self.assertEqual(ret.status_code, 201)

    def test_srvs_post_reject_invalid(self):
        data = {'name': '_test._tcp.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'host': self.host_target.id}

        def _assert_400():
            ret = self.client.post("/srvs/", fail)
            self.assertEqual(ret.status_code, 400)
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
        ret = self.client.get("/srvs/")
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 1)

    def test_srvs_delete(self):
        self.test_srvs_post()
        srvs = self.client.get("/srvs/").json()['results']
        ret = self.client.delete("/srvs/{}".format(srvs[0]['id']))
        self.assertEqual(ret.status_code, 204)
        sshfps = self.client.get("/srvs/").json()
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
        sshfps = self.client.get("/srvs/").data['results']
        self.client.delete("/srvs/{}".format(sshfps[0]['id']))
        zone.refresh_from_db()
        self.assertTrue(zone.updated)
