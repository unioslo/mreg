
from unittest import mock

from django.test import RequestFactory
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient, force_authenticate

from mreg.api.permissions import IsGrantedNetGroupRegexPermission

from .tests import MregAPITestCase


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
        request = RequestFactory().post('/')
        user = mock.Mock()
        user.group_list = []
        user.is_mreg_superuser = False
        user.is_mreg_admin = False
        request.user = user
        # Make it so every time we call User.from_request, it returns the same user object
        # that we created above.
        mock_user_from_request.return_value = user
        force_authenticate(request, user=user)

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
