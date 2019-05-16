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

    def test_hostgroups_rename_204_ok(self):
        """Rename a group should return 204 ok"""
        response = self.client.patch(f'/hostgroups/{self.hostgroup_one.name}',
                                     {'name': 'newname'})
        self.assertEqual(response['Location'], '/hostgroups/newname')
        self.assertEqual(response.status_code, 204)

    def test_hostgroups_patch_description_204_ok(self):
        """Rename a group should return 204 ok"""
        response = self.client.patch(f'/hostgroups/{self.hostgroup_one.name}',
                                     {'description': 'new d€scription'})
        self.assertEqual(response.status_code, 204)
        response = self.client.get('/hostgroups/%s' % self.hostgroup_one.name)
        self.assertEqual(response.json()['description'], 'new d€scription')

    def test_hostgroup_create_group_twice_409_conflict(self):
        post_data = {'name': 'testgroup'}
        response = self.client.post('/hostgroups/', post_data)
        self.assertEqual(response.status_code, 201)
        post_data = {'name': 'TESTGROUP'}
        response = self.client.post('/hostgroups/', post_data)
        self.assertEqual(response.status_code, 409)

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
        self.hostgroup_one = HostGroup.objects.create(name='testgroup1')
        self.hostgroup_two = HostGroup.objects.create(name='testgroup2')
        self.hostgroup_three = HostGroup.objects.create(name='testgroup3')

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

    def test_groups_add_group_to_group_201_ok(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_two.name})
        self.assertEqual(response.status_code, 201)

    def test_groups_add_missing_name_group_400_forbidden(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name2': 'something'})
        self.assertEqual(response.status_code, 400)

    def test_group_list_with_content_200_ok(self):
        self.test_groups_add_group_to_group_201_ok()
        response = self.client.get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'][0]['name'], 'testgroup2')

    def test_groups_add_invalid_group_to_group_404_not_found(self):
        response = self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': 'cheese'})
        self.assertEqual(response.status_code, 404)

    def test_remove_groupmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                         {'name': self.hostgroup_two.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/groups/{self.hostgroup_two.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
        # Make sure the group itself is not deleted, just removed from m2m-relation.
        self.hostgroup_two.refresh_from_db()
        self.assertEqual(self.hostgroup_one.groups.count(), 0)


class APIHostGroupHostsTestCase(MregAPITestCase):
    """Various test for hosts members in a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one = HostGroup(name='testgroup1')
        self.host_one = Host.objects.create(name='host1.example.org',
                                            contact='mail1@example.org')
        clean_and_save(self.hostgroup_one)

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

    def test_remove_hostsmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/hosts/{self.host_one.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
        # Make sure the host itself is not deleted, just removed from m2m-relation.
        self.host_one.refresh_from_db()
        self.assertEqual(self.hostgroup_one.hosts.count(), 0)


class APIHostGroupOwnersTestCase(MregAPITestCase):
    """Various test for owners of a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.owner_one = Group.objects.create(name='testowner')
        self.hostgroup_one = HostGroup.objects.create(name='testgroup1')

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

    def test_remove_hostsmember_204_ok(self):
        self.client.post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/owners/{self.owner_one.name}'
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
        # Make sure the group itself is not deleted, just removed from m2m-relation.
        self.owner_one.refresh_from_db()
        self.assertEqual(self.hostgroup_one.owners.count(), 0)
