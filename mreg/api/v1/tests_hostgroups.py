from mreg.models import HostGroup
from .tests import MregAPITestCase, clean_and_save

class APIHostGroupsTestCase(MregAPITestCase):
    """This class defines the test suite for api/hostgroups"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one = HostGroup(name='testgroup1')
        clean_and_save(self.hostgroup_one)
        self.hostgroup_two = HostGroup(name='testgroup2')
        clean_and_save(self.hostgroup_two)

    def test_hostgroups_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/hostgroups/%s' % self.hostgroup_one.name)
        self.assertEqual(response.status_code, 200)

    def test_hostgroups_list_200_ok(self):
        """List all hosts should return 200"""
        response = self.client.get('/hostgroups/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['results']), 2)

    def test_hostgroups_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/hostgroups/nonexisting-group')
        self.assertEqual(response.status_code, 404)

    def test_hostgroups_post_201_created(self):
        """"Posting a new host should return 201 and location"""
        post_data = {'name': 'testgroup3'}
        response = self.client.post('/hostgroups/', post_data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/hostgroups/%s' % post_data['name'])
        response = self.client.get('/hostgroups/%s' % post_data['name'])
        self.assertEqual(response.status_code, 200)

    def test_hostgroups_rename_204_ok(self):
        """Rename a group should return 204 ok"""
        response = self.client.patch(f'/hostgroups/{self.hostgroup_one.name}',
                                     {'name': 'newname'})
        self.assertEqual(response['Location'], '/hostgroups/newname')
        self.assertEqual(response.status_code, 204)

    def test_hostgroups_rename_to_name_in_use_400_bad_request(self):
        """Rename a group should return 204 ok"""
        response = self.client.patch(f'/hostgroups/{self.hostgroup_one.name}',
                                     {'name': self.hostgroup_two})
        self.assertEqual(response.status_code, 400)

class APIHostGroupGroupsTestCase(MregAPITestCase):
    """Tests nesting of hostgroups in hostgroups"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one = HostGroup(name='testgroup1')
        clean_and_save(self.hostgroup_one)
        self.hostgroup_two = HostGroup(name='testgroup2')
        clean_and_save(self.hostgroup_two)
        self.hostgroup_three = HostGroup(name='testgroup3')
        clean_and_save(self.hostgroup_three)

    def test_groups_list_200_ok(self):
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [])

    def test_groups_add_group_to_group_201_ok(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_two.name})
        self.assertEqual(response.status_code, 201)

    def test_groups_add_self_to_group_403_forbidden(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_one.name})
        self.assertEqual(response.status_code, 403)

    def test_group_list_with_content_200_ok(self):
        self.test_groups_add_group_to_group_201_ok()
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [{'name': 'testgroup2'}])

    def test_groups_add_invalid_group_to_group_404_not_found(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': 'cheese'})
        self.assertEqual(response.status_code, 404)

    def test_delete_groupmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                         {'name': self.hostgroup_two.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/groups/{self.hostgroup_two.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
