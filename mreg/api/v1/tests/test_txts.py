from mreg.models import Host

from .tests import MregAPITestCase


class APITxtsTestCase(MregAPITestCase):
    """Test API for TXTs"""

    def setUp(self):
        super().setUp()
        self.host = Host.objects.create(name='host1.example.org')

    def test_create_and_get_txts(self):
        data = {'host': self.host.id,
                'txt': 'TXTs are case sensitive'}
        self.assert_post('/txts/', data)
        ret = self.assert_get('/txts/').data
        self.assertEqual(ret['count'], 1)
        txt = ret['results'][0]
        self.assertEqual(txt['txt'], data['txt'])
        self.assertEqual(txt['host'], data['host'])

    def test_delete_txt(self):
        data = {'host': self.host.id,
                'txt': 'my TXT'}
        ret = self.assert_post('/txts/', data).data
        self.assert_delete(f"/txts/{ret['id']}")
