from django.test import TestCase
from mreg.models import *
from rest_framework.test import APIClient


class ModelHostsTestCase(TestCase):
    """This class defines the test suite for the Host model."""
    def setUp(self):
        """Define the test client and other test variables."""
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Hosts.objects.count()
        self.host_sample.save()
        new_count = Hosts.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_host(self):
        """Test that the model is able to change a host."""
        self.host_sample.save()
        old_name = self.host_sample.name
        new_name = 'some-new-host'
        host_sample_id = Hosts.objects.get(name=old_name).hostid
        self.host_sample.name = new_name
        self.host_sample.save()
        updated_name = Hosts.objects.get(pk=host_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_host(self):
        """Test that the model is able to delete a host."""
        self.host_sample.save()
        old_count = Hosts.objects.count()
        self.host_sample.delete()
        new_count = Hosts.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelZonesTestCase(TestCase):
    """This class defines the test suite for the Zones model."""
    # TODO: test this for sub-zones (usit.uio.no) and "top"-zones (usit.no)
    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = Zones(name='some-zone',
                                 primary_ns='some-ns-server',
                                 email='some.email@some.domain.no',
                                 serialno=1234567890,
                                 refresh=400,
                                 retry=300,
                                 expire=800,
                                 ttl=300)

    def test_model_can_create_a_zone(self):
        """Test that the model is able to create a zone."""
        old_count = Zones.objects.count()
        self.zone_sample.save()
        new_count = Zones.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_zone(self):
        """Test that the model is able to change a zone."""
        self.zone_sample.save()
        old_name = self.zone_sample.name
        new_name = 'some-new-zone'
        zone_sample_id = Zones.objects.get(name=old_name).zoneid
        self.zone_sample.name = new_name
        self.zone_sample.save()
        updated_name = Zones.objects.get(pk=zone_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        self.zone_sample.save()
        old_count = Zones.objects.count()
        self.zone_sample.delete()
        new_count = Zones.objects.count()
        self.assertNotEqual(old_count, new_count)


class APIHostsTestCase(TestCase):
    """This class defines the test suite for api/hosts"""
    def setUp(self):
        """Define the test client and other test variables."""
        self.host_sample = Hosts(name='dette-er-en-host',
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
        """Patching an existing and valid entry should return 204 and Location"""
        self.host_sample.save()
        client = APIClient()
        response = client.patch('/hosts/dette-er-en-host/', self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/hosts/nytt-navn')

