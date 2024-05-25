from django.contrib.auth.models import Group

from mreg.api.v1.tests.tests import MregAPITestCase
from mreg.models.host import Host, BACnetID, Ipaddress
from mreg.models.network import Network, NetGroupRegexPermission


class BACnetIDTest(MregAPITestCase):

    basepath = '/api/v1/bacnet/ids/'

    def basejoin(self, path):
        if type(path) != 'str':
            path = str(path)
        return self.basepath + path

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.host_one = Host(name='host1.example.org', contact='mail1@example.org')
        self.host_one.save()
        self.id_one = BACnetID.objects.create(id=BACnetID.first_unused_id(), host=self.host_one)
        self.host_two = Host(name='host2.example.org', contact='mail1@example.org')
        self.host_two.save()

    def test_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get(self.basejoin(self.id_one.id))

    def test_list_200_ok(self):
        """List all should return 200"""
        self.id_two = BACnetID.objects.create(id=BACnetID.first_unused_id(), host=self.host_two)
        response = self.assert_get(self.basepath)
        data = response.json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['results']), 2)

    def test_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404(self.basejoin('nonexisting'))

    def test_post_201_created(self):
        """Posting a new entry should return 201 and location"""
        post_data = {'id': 123, 'host': self.host_two.id}
        response = self.assert_post(self.basepath, post_data)
        self.assert_get(response['Location'])
        self.assertEqual(response['Location'], self.basejoin(str(post_data['id'])))

    def test_post_no_id_201_created(self):
        """Posting a new entry without a specific id value should return 201 and location"""
        post_data = {'host': self.host_two.id}
        response = self.assert_post(self.basepath, post_data)
        response = self.assert_get(response['Location'])
        self.assertIn('id', response.data)
        self.assertEqual(response.data['host'], self.host_two.id)

    def test_post_with_hostname_instead_of_id(self):
        post_data = {'hostname': self.host_two.name}
        response = self.assert_post(self.basepath, post_data)
        response = self.assert_get(response['Location'])
        self.assertIn('id', response.data)
        self.assertEqual(response.data['host'], self.host_two.id)

    def test_post_without_host_400(self):
        """Posting a new entry without specifying a host should return 400 bad request"""
        post_data = {'id': 123}
        self.assert_post_and_400(self.basepath, post_data)

    def test_post_with_invalid_host_400(self):
        """Posting a new entry with a host that doesn't exist should return 400 bad request"""
        post_data = {'id': 123, 'host': 12345678}
        self.assert_post_and_400(self.basepath, post_data)

    def test_post_with_already_used_host_409(self):
        """Posting a new entry with a host that already has another BACnet ID should return 409 conflict"""
        post_data = {'host': self.host_one.id}
        self.assert_post_and_409(self.basepath, post_data)

    def test_post_with_already_used_id_409(self):
        """Posting a new entry with a BACnet ID that's in use should return 409 conflict"""
        post_data = {'id': self.id_one.id, 'host': self.host_two.id}
        self.assert_post_and_409(self.basepath, post_data)

    def test_delete_204_ok(self):
        """Delete should return 204 ok"""
        self.assert_delete(self.basejoin(self.id_one.id))

    def test_patch_405(self):
        """Patch method isn't allowed"""
        patch_data = {'id': self.id_one.id}
        self.assert_patch_and_405(self.basejoin(str(self.id_one.id)), patch_data)

    def test_client_must_be_logged_in(self):
        self.client.logout()
        self.assert_get_and_401(self.basepath)
        self.assert_get_and_401(self.basejoin(self.id_one.id))
        post_data = {'id': 123, 'host': self.host_two.id}
        self.assert_post_and_401(self.basepath, post_data)

    def test_client_must_have_write_access(self):
        self.client = self.get_token_client(superuser=False)
        post_data = {'id': 123, 'host': self.host_two.id}
        self.assert_post_and_403(self.basepath, post_data)

    def test_netgroupregex_permission(self):
        self.client = self.get_token_client(superuser=False)
        group = Group.objects.create(name='testgroup')
        group.user_set.add(self.user)
        Network.objects.create(network='10.1.0.0/25')
        NetGroupRegexPermission.objects.create(group='testgroup',
                                               range='10.1.0.0/25',
                                               regex=r'.*\.example\.org$')
        Ipaddress.objects.create(host=self.host_two, ipaddress='10.1.0.17')
        post_data = {'id': 123, 'host': self.host_two.id}
        self.assert_post(self.basepath, post_data)
