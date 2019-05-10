from django.contrib.auth.models import Group

from mreg.models import Host, HostGroup
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

    def test_hosts_add_host_twice_to_group_409_conflict(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_two.name})
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_two.name})
        self.assertEqual(response.status_code, 409)

    def test_groups_add_self_to_group_403_forbidden(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_one.name})
        self.assertEqual(response.status_code, 403)

    def test_group_list_with_content_200_ok(self):
        self.test_groups_add_group_to_group_201_ok()
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'][0]['name'], 'testgroup2')

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


class APIHostGroupHostsTestCase(MregAPITestCase):
    """Various test for hosts members in a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one = HostGroup(name='testgroup1')
        self.host_one = Host(name='host1.example.org', contact='mail1@example.org')
        clean_and_save(self.hostgroup_one)
        clean_and_save(self.host_one)

    def test_hosts_list_200_ok(self):
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/hosts/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [])

    def test_hosts_add_host_to_group_201_ok(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                                    {'name': self.host_one.name})
        self.assertEqual(response.status_code, 201)

    def test_hosts_add_host_twice_to_group_409_conflict(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                                    {'name': self.host_one.name})
        self.assertEqual(response.status_code, 409)

    def test_add_unknown_host_to_group_404_not_found(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                                    {'name': 'cheese'})
        self.assertEqual(response.status_code, 404)

    def test_delete_hostsmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/hosts/{self.host_one.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)


class APIHostGroupOwnersTestCase(MregAPITestCase):
    """Various test for owners of a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.owner_one = Group(name='testowner')
        self.hostgroup_one = HostGroup(name='testgroup1')
        clean_and_save(self.owner_one)
        clean_and_save(self.hostgroup_one)

    def test_owners_list_200_ok(self):
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/owners/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [])

    def test_owners_add_owner_to_group_201_ok(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                    {'name': self.owner_one.name})
        self.assertEqual(response.status_code, 201)

    def test_owners_add_owner_twice_to_group_409_conflict(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                    {'name': self.owner_one.name})
        self.assertEqual(response.status_code, 409)

    def test_add_unknown_owner_to_group_404_not_found(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                    {'name': 'cheese'})
        self.assertEqual(response.status_code, 404)

    def test_delete_hostsmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/owners/{self.owner_one.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
