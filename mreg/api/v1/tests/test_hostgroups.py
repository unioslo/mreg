from django.contrib.auth.models import Group

from mreg.models import Host, HostGroup

from .tests import MregAPITestCase


class APIHostGroupsTestCase(MregAPITestCase):
    """This class defines the test suite for api/hostgroups"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one, _ = HostGroup.objects.get_or_create(name='testgroup1')
        self.hostgroup_two, _ = HostGroup.objects.get_or_create(name='testgroup2')
        self.hostgroup_three, _ = HostGroup.objects.get_or_create(name='testgroup3')

    def test_hostgroups_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/hostgroups/%s' % self.hostgroup_one.name)

    def test_hostgroups_list_200_ok(self):
        """List all hosts should return 200"""
        response = self.assert_get('/hostgroups/')
        data = response.json()
        self.assertEqual(data['count'], 3)
        self.assertEqual(len(data['results']), 3)

    def test_hostgroups_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/hostgroups/nonexisting-group')

    def test_hostgroups_post_201_created(self):
        """"Posting a new host should return 201 and location"""
        post_data = {'name': 'new-group'}
        response = self.assert_post('/hostgroups/', post_data)
        self.assert_get(response['Location'])
        self.assertEqual(response['Location'], '/api/v1/hostgroups/%s' % post_data['name'])

    def test_hostgroups_rename_204_ok(self):
        """Rename a group should return 204 ok"""
        response = self.assert_patch(f'/hostgroups/{self.hostgroup_one.name}',
                                     {'name': 'newname'})
        self.assertEqual(response['Location'], '/api/v1/hostgroups/newname')

    def test_hostgroups_delete_204_ok(self):
        """Delete a group should return 204 ok"""
        self.assert_delete(f'/hostgroups/{self.hostgroup_one.name}')

    def test_hostgroups_patch_description_204_ok(self):
        """Rename a group should return 204 ok"""
        self.assert_patch(f'/hostgroups/{self.hostgroup_one.name}',
                          {'description': 'new d€scription'})
        data = self.assert_get('/hostgroups/%s' % self.hostgroup_one.name).json()
        self.assertEqual(data['description'], 'new d€scription')

    def test_hostgroup_create_group_twice_409_conflict(self):
        post_data = {'name': 'testgroup'}
        self.assert_post('/hostgroups/', post_data)
        post_data = {'name': 'TESTGROUP'}
        self.assert_post_and_409('/hostgroups/', post_data)

    def test_hostgroups_rename_to_name_in_use_400_bad_request(self):
        """Rename a group should return 204 ok"""
        self.assert_patch_and_400(f'/hostgroups/{self.hostgroup_one.name}',
                                  {'name': self.hostgroup_two})


class APIHostGroupGroupsTestCase(MregAPITestCase):
    """Tests nesting of hostgroups in hostgroups"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one, _ = HostGroup.objects.get_or_create(name='testgroup1')
        self.hostgroup_two, _ = HostGroup.objects.get_or_create(name='testgroup2')
        self.hostgroup_three, _ = HostGroup.objects.get_or_create(name='testgroup3')

    def test_groups_list_200_ok(self):
        response = self.assert_get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.json()['results'], [])

    def test_groups_add_group_to_group_201_ok(self):
        response = self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                    {'name': self.hostgroup_two.name})
        self.assert_get(response['Location'])

    def test_hosts_add_host_twice_to_group_409_conflict(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                         {'name': self.hostgroup_two.name})
        self.assert_post_and_409(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                 {'name': self.hostgroup_two.name})

    def test_groups_add_missing_name_group_400_forbidden(self):
        self.assert_post_and_400(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                 {'name2': 'something'})

    def test_group_list_with_content_200_ok(self):
        self.test_groups_add_group_to_group_201_ok()
        response = self.assert_get(f'/hostgroups/{self.hostgroup_one.name}/groups/')
        self.assertEqual(response.json()['results'][0]['name'], 'testgroup2')

    def test_groups_add_invalid_group_to_group_404_not_found(self):
        self.assert_post_and_404(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                                 {'name': 'cheese'})

    def test_remove_groupmember_204_ok(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/groups/',
                         {'name': self.hostgroup_two.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/groups/{self.hostgroup_two.name}'
        self.assert_delete(path)
        # Make sure the group itself is not deleted, just removed from m2m-relation.
        self.hostgroup_two.refresh_from_db()
        self.assertEqual(self.hostgroup_one.groups.count(), 0)


class APIHostGroupHostsTestCase(MregAPITestCase):
    """Various test for hosts members in a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.hostgroup_one, _ = HostGroup.objects.get_or_create(name='testgroup1')
        self.host_one, _ = Host.objects.get_or_create(name='host1.example.org')

    def test_hosts_list_200_ok(self):
        response = self.assert_get(f'/hostgroups/{self.hostgroup_one.name}/hosts/')
        self.assertEqual(response.json()['results'], [])

    def test_hosts_add_host_to_group_201_ok(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})

    def test_hosts_add_host_twice_to_group_409_conflict(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})
        self.assert_post_and_409(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                                 {'name': self.host_one.name})

    def test_add_unknown_host_to_group_404_not_found(self):
        self.assert_post_and_404(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                                 {'name': 'cheese'})

    def test_remove_hostsmember_204_ok(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/hosts/',
                         {'name': self.host_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/hosts/{self.host_one.name}'
        self.assert_delete(path)
        # Make sure the host itself is not deleted, just removed from m2m-relation.
        self.host_one.refresh_from_db()
        self.assertEqual(self.hostgroup_one.hosts.count(), 0)


class APIHostGroupOwnersTestCase(MregAPITestCase):
    """Various test for owners of a HostGroup"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.owner_one, _ = Group.objects.get_or_create(name='testowner')
        self.hostgroup_one, _ = HostGroup.objects.get_or_create(name='testgroup1')

    def test_owners_list_200_ok(self):
        def _assert_get(result):
            response = self.assert_get(f'/hostgroups/{self.hostgroup_one.name}/owners/')
            self.assertEqual(response.json()['results'], result)
        _assert_get([])
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        _assert_get([{'name': 'testowner'}])

    def test_owners_add_owner_to_group_201_ok(self):
        response = self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                    {'name': self.owner_one.name})
        self.assert_get(response['Location'])

    def test_owners_add_owner_twice_to_group_409_conflict(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        self.assert_post_and_409(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                 {'name': self.owner_one.name})

    def test_add_unknown_owner_to_group_404_not_found(self):
        self.assert_post_and_404(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                 {'name': 'cheese'})

    def test_remove_hostsmember_204_ok(self):
        self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                         {'name': self.owner_one.name})
        path = f'/hostgroups/{self.hostgroup_one.name}/owners/{self.owner_one.name}'
        self.assert_delete(path)
        # Make sure the group itself is not deleted, just removed from m2m-relation.
        self.owner_one.refresh_from_db()
        self.assertEqual(self.hostgroup_one.owners.count(), 0)

    def test_patch_hostmember_405_method_not_allowed(self):
        data = self.assert_post(f'/hostgroups/{self.hostgroup_one.name}/owners/',
                                {'name': self.owner_one.name})
        self.assert_patch_and_405(data['Location'], {'name': 'newgroupname'})


class GroupAdminTestCase(APIHostGroupsTestCase, APIHostGroupHostsTestCase,
                         APIHostGroupGroupsTestCase, APIHostGroupOwnersTestCase):
    """Test that all of the API for Hostgroups are available for the admin group
       GROUPADMINUSER_GROUP and not only super users."""

    def setUp(self):
        """Create a client with groupadmin and not superuser access"""
        super().setUp()
        self.client = self.get_token_client(superuser=False)
        self.add_user_to_groups('GROUPADMINUSER_GROUP')


class HostGroupOwnerHasRights(APIHostGroupHostsTestCase,
                              APIHostGroupGroupsTestCase):
    """Test that a group owner has some extra rights"""

    def setUp(self):
        super().setUp()
        self.client = self.get_token_client(username='owneruser', superuser=False)
        ownergroup = Group.objects.create(name='ownergroup')
        ownergroup.user_set.add(self.user)
        self.hostgroup_one.owners.add(ownergroup)

    def test_owner_can_patch_description(self):
        self.assert_patch(f'/hostgroups/{self.hostgroup_one.name}',
                          {'description': 'new description'})

    def test_owner_can_not_rename_group(self):
        self.assert_patch_and_403(f'/hostgroups/{self.hostgroup_one.name}',
                                  {'name': 'newname'})


class HostGroupNoRights(MregAPITestCase):
    """Test that a user with no special rights can not create or alter host groups"""

    def setUp(self):
        self.client = self.get_token_client(superuser=False)

    def test_can_not_create_or_delete_hostgroup(self):
        post_data = {'name': 'testgroup1'}
        self.assert_post_and_403('/hostgroups/', post_data)
        HostGroup.objects.create(name='testgroup1')
        self.assert_delete_and_403('/hostgroups/testgroup1')

    def test_can_not_alter_host_members(self):
        hostgroup_one = HostGroup.objects.create(name='testgroup1')
        host_one = Host.objects.create(name='host1.example.org')
        self.assert_post_and_403(f'/hostgroups/{hostgroup_one.name}/hosts/',
                                 {'name': host_one.name})
        hostgroup_one.hosts.add(host_one)
        path = f'/hostgroups/{hostgroup_one.name}/hosts/{host_one.name}'
        self.assert_delete_and_403(path)

    def test_can_not_alter_owners(self):
        hostgroup_one = HostGroup.objects.create(name='testgroup1')
        group_one = Group.objects.create(name='ownergroup')
        self.assert_post_and_403(f'/hostgroups/{hostgroup_one.name}/owners/',
                                 {'name': group_one.name})
        hostgroup_one.owners.add(group_one)
        path = f'/hostgroups/{hostgroup_one.name}/owners/{group_one.name}'
        self.assert_delete_and_403(path)

    def test_client_must_be_logged_in(self):
        HostGroup.objects.create(name='testgroup1')
        self.assert_get('/hostgroups/')
        self.assert_get('/hostgroups/testgroup1')
        self.client.logout()
        self.assert_get_and_401('/hostgroups/')
        self.assert_get_and_401('/hostgroups/testgroup1')


class HostGroupOwnerOfIrrelevantGroup(HostGroupNoRights):
    """Similar to HostGroupNoRights, but let the user be an owner
       of a group not relevant to the tests."""

    def setUp(self):
        self.client = self.get_token_client(superuser=False)
        hostgroup = HostGroup.objects.create(name='irrelevantgroup')
        group = Group.objects.create(name='randomgroup')
        group.user_set.add(self.user)
        hostgroup.owners.add(group)
