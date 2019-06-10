from .tests import MregAPITestCase


class APINetGroupRegexPermissionTestCase(MregAPITestCase):

    data = {'group': 'testgroup', 'range': '10.0.0.0/24',
            'regex': r'.*\.example\.org$'}

    def test_create(self):
        self.assert_post('/permissions/netgroupregex/', self.data)

    def test_get(self):
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        ret2 = self.assert_get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret1.json(), ret2.json())

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

    def test_delete(self):
        ret1 = self.assert_post('/permissions/netgroupregex/', self.data)
        data = self.assert_get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 1)
        self.assert_delete('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        data = self.assert_get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 0)
