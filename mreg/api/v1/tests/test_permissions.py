from rest_framework.test import APIClient

from .tests import MregAPITestCase


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
