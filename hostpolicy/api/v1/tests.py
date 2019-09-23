from urllib.parse import urljoin

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.models import Host

from mreg.api.v1.tests.tests import MregAPITestCase


class HostPolicyUniqueNameSpace(MregAPITestCase):

    def test_unique_namespace(self):
        data = {'name': 'test', 'description': 'test'}
        self.assert_post('/api/v1/hostpolicy/atoms/', data)
        self.assert_post_and_400('/api/v1/hostpolicy/roles/', data)


class HostPolicyRoleTestCase(MregAPITestCase):
    """This class defines the test suite for api/hostpolicyroles"""

    basepath = '/api/v1/hostpolicy/roles/'

    def basejoin(self, url):
        return urljoin(self.basepath, url)

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.object_one, _ = HostPolicyRole.objects.get_or_create(name='testpolicy1')
        self.object_two, _ = HostPolicyRole.objects.get_or_create(name='testpolicy2')

    def test_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get(self.basejoin(self.object_one.name))

    def test_list_200_ok(self):
        """List all should return 200"""
        response = self.assert_get(self.basepath)
        data = response.json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['results']), 2)

    def test_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404(self.basejoin('nonexisting'))

    def test_post_201_created(self):
        """"Posting a new should return 201 and location"""
        post_data = {'name': 'newname',
                     'description': 'my description'}
        response = self.assert_post(self.basepath, post_data)
        self.assert_get(response['Location'])
        self.assertEqual(response['Location'], self.basejoin(post_data['name']))

    def test_rename_204_ok(self):
        """Rename should return 204 ok"""
        response = self.assert_patch(self.basejoin(self.object_one.name),
                                     {'name': 'newname'})
        self.assertEqual(response['Location'], self.basejoin('newname'))

    def test_delete_204_ok(self):
        """Delete should return 204 ok"""
        self.assert_delete(self.basejoin(self.object_one.name))

    def test_patch_description_204_ok(self):
        """Patch descriptions should return 204 ok"""
        path = self.basejoin(self.object_one.name)
        self.assert_patch(path,
                          {'description': 'new d€scription'})
        data = self.assert_get(path).json()
        self.assertEqual(data['description'], 'new d€scription')

    def test_create_twice_same_name_409_conflict(self):
        post_data = {'name': 'test', 'description': 'desc'}
        self.assert_post(self.basepath, post_data)
        post_data = {'name': 'TEST', 'description': 'desc'}
        self.assert_post_and_409(self.basepath, post_data)

    def test_rename_to_name_in_use_400_bad_request(self):
        """Rename to a name in use should return 400"""
        self.assert_patch_and_400(self.basejoin(self.object_one.name),
                                  {'name': self.object_two.name})


class HostPolicyAtomTestCase(HostPolicyRoleTestCase):
    """This class defines the test suite for api/hostpolicyroles"""

    basepath = '/api/v1/hostpolicy/atoms/'

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.object_one, _ = HostPolicyAtom.objects.get_or_create(name='testatom1')
        self.object_two, _ = HostPolicyAtom.objects.get_or_create(name='testatom2')


class HostPolicyAdminRights(MregAPITestCase):
    """Test that all of the API for HostPolicy are available for the admin group
       HOSTPOLICYADMIN_GROUP and not only super users."""

    def setUp(self):
        """Create a client with groupadmin and not superuser access"""
        super().setUp()
        self.client = self.get_token_client(superuser=False)
        self.add_user_to_groups('HOSTPOLICYADMIN_GROUP')


class HostPolicyAdminUser(HostPolicyAtomTestCase,
                          HostPolicyRoleTestCase,
                          HostPolicyAdminRights):
    """Test atoms and roles as an admin user"""

    pass


class HostPolicyRoleAtoms(MregAPITestCase):
    """Tests of  atoms in roles """
    basepath = '/api/v1/hostpolicy/roles/'
    m2m_field = 'atoms'
    membercls = HostPolicyAtom

    def baseurl(self, middel):
        return f'{self.basepath}{middel}/{self.m2m_field}/'

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.role_one, _ = HostPolicyRole.objects.get_or_create(name='testrole1')
        self.target_one, _ = self.membercls.objects.get_or_create(name='member1')
        self.m2m_url = self.baseurl(self.role_one.name)

    def test_list_200_ok(self):
        response = self.assert_get(self.m2m_url)
        self.assertEqual(response.json()['results'], [])

    def test_add_to_m2m_field_201_ok(self):
        response = self.assert_post(self.m2m_url,
                                    {'name': self.target_one.name})
        self.assert_get(response['Location'])

    def test_add_twice_to_m2m_field_409_conflict(self):
        self.assert_post(self.m2m_url,
                         {'name': self.target_one.name})
        self.assert_post_and_409(self.m2m_url,
                                 {'name': self.target_one.name})

    def test_add_with_missing_name_400_forbidden(self):
        self.assert_post_and_400(self.m2m_url,
                                 {'name2': 'something'})

    def test_list_with_content_200_ok(self):
        self.test_add_to_m2m_field_201_ok()
        response = self.assert_get(self.m2m_url)
        self.assertEqual(response.json()['results'][0]['name'], self.target_one.name)

    def test_add_to_m2m_field_with_unknown_name_404_not_found(self):
        self.assert_post_and_404(self.m2m_url,
                                 {'name': 'cheese'})

    def test_remove_m2m_member_204_ok(self):
        ret = self.assert_post(self.m2m_url,
                               {'name': self.target_one.name})
        self.assert_delete(ret['Location'])
        # Make sure the m2m member itself is not deleted, just removed from m2m-relation.
        self.target_one.refresh_from_db()
        self.assertEqual(getattr(self.role_one, self.m2m_field).count(), 0)


class HostPolicyRoleAtomsAsAdmin(HostPolicyRoleAtoms,
                                 HostPolicyAdminRights):
    pass


class HostPolicyRoleHosts(HostPolicyRoleAtoms):
    m2m_field = 'hosts'
    membercls = Host


class HostPolicyRoleHostsAsAdmin(HostPolicyRoleHosts,
                                 HostPolicyAdminRights):
    pass


class HostPolicyNoRights(MregAPITestCase):
    """Test that a user with no special rights can not create or alter host policies"""

    basepath = '/api/v1/hostpolicy/roles/'

    def setUp(self):
        self.client = self.get_token_client(superuser=False)
        self.role = HostPolicyRole.objects.create(name='role1')

    def test_can_not_create_or_delete_atom_or_role(self):
        post_data = {'name': 'test1'}
        self.assert_post_and_403('/hostpolicy/atoms/', post_data)
        HostPolicyAtom.objects.create(name='test1')
        self.assert_delete_and_403('/hostpolicy/atoms/test1')
        self.assert_post_and_403('/hostpolicy/roles/', post_data)
        HostPolicyRole.objects.create(name='test2')
        self.assert_delete_and_403('/hostpolicy/roles/test2')

    def test_can_not_alter_m2m_relations(self):
        def _test_m2m_relation(member, m2m_relation):
            path = self.basepath + self.role.name + f"/{m2m_relation}/"
            self.assert_post_and_403(path, {'name': member.name})
            getattr(self.role, m2m_relation).add(member)
            path += member.name
            self.assert_delete_and_403(path)

        _test_m2m_relation(HostPolicyAtom.objects.create(name='atom1'), 'atoms')
        _test_m2m_relation(Host.objects.create(name='host1.example.org'), 'hosts')

    def test_client_must_be_logged_in(self):
        HostPolicyRole.objects.create(name='test1')
        self.assert_get('/hostpolicy/roles/')
        self.assert_get('/hostpolicy/roles/test1')
        self.client.logout()
        self.assert_get_and_401('/hostpolicy/roles/')
        self.assert_get_and_401('/hostpolicy/roles/test1')
