from django.test import TestCase
from mreg.models import Hosts
from rest_framework.test import APIClient


class ModelTestCase(TestCase):
    """This class defines the test suite for the Hosts model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_sample = Hosts(hostid=1,
                                 name='dette-er-en-host',
                                 ipaddress='127.0.0.1',
                                 contact='ulvik@usit.uio.no')

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Hosts.objects.count()
        self.host_sample.save()
        new_count = Hosts.objects.count()
        self.assertNotEqual(old_count, new_count)


class APIHostsTestCase(TestCase):
    """This class defines the test suite for api/hosts"""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_sample = Hosts(hostid=1,
                                 name='dette-er-en-host',
                                 ipaddress='127.0.0.1',
                                 contact='ulvik@usit.uio.no')
        self.patch_data = {'name': 'nytt-navn', 'contact': 'updated@mail.com'}

    def test_hosts_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        self.host_sample.save()
        client = APIClient()
        response = client.patch('/hosts/feil-navn/', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_hosts_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204"""
        self.host_sample.save()
        client = APIClient()
        response = client.patch('/hosts/dette-er-en-host', self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertContains(response['Location'], '/hosts/nytt-navn')



