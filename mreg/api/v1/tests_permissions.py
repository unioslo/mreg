from .tests import MregAPITestCase, clean_and_save


class APINetGroupRegexPermissionTestCase(MregAPITestCase):

    data = {'group': 'testgroup', 'range': '10.0.0.0/24',
            'regex': r'.*\.example\.org$'}

    def test_create(self):
        ret = self.client.post('/permissions/netgroupregex/', self.data)
        self.assertEqual(ret.status_code, 201)

    def test_get(self):
        ret1 = self.client.post('/permissions/netgroupregex/', self.data)
        ret2 = self.client.get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret2.status_code, 200)
        self.assertEqual(ret1.json(), ret2.json())

    def test_list(self):
        ret1 = self.client.post('/permissions/netgroupregex/', self.data)
        ret2 = self.client.get('/permissions/netgroupregex/')
        self.assertEqual(ret2.status_code, 200)
        data = ret2.json()
        self.assertEqual(data['count'], 1)
        self.assertEqual(data['results'][0], ret1.json())

    def test_update(self):
        ret1 = self.client.post('/permissions/netgroupregex/', self.data)
        ret = self.client.patch('/permissions/netgroupregex/{}'.format(ret1.json()['id']),
                                 {'group': 'testgroup2'})
        self.assertEqual(ret.status_code, 204)
        ret = self.client.get('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret.json()['group'], 'testgroup2')

    def test_delete(self):
        ret1 = self.client.post('/permissions/netgroupregex/', self.data)
        data = self.client.get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 1)
        ret = self.client.delete('/permissions/netgroupregex/{}'.format(ret1.json()['id']))
        self.assertEqual(ret.status_code, 204)
        data = self.client.get('/permissions/netgroupregex/').json()
        self.assertEqual(data['count'], 0)
