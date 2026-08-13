from .tests import MregAPITestCase


class NameserversTestCase(MregAPITestCase):
    """Test API for Nameservers"""

    def test_create_and_get_nameservers(self):
        # Create a nameserver
        data = {'name': 'ns.example.org'}
        resp = self.assert_post('/nameservers/', data)
        self.assertEqual(resp.headers["Location"], f"/api/v1/nameservers/{data['name']}")
        
        # Retrieve it
        ret = self.assert_get('/nameservers/').data
        self.assertEqual(ret['count'], 1)
        ns = ret['results'][0]
        self.assertEqual(ns['name'], data['name'])
        self.assertEqual(ns['ttl'], None)

    def test_delete_nameserver(self):
        data = {'name': 'ns.example.org'}
        ret = self.assert_post('/nameservers/', data).data
        self.assert_delete(f"/nameservers/{ret['name']}")
