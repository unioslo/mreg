from django.test import TestCase
from mreg.models import *
from rest_framework.test import APIClient
import time


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


class APIZonesTestCase(TestCase):
    """"This class defines the test suite for api/zones """
    def setUp(self):
        """Define the test client ant other variables."""
        self.zone_one = Zones(
            zoneid=1,
            name="matnat.uio.no",
            primary_ns="ns1.uio.no",
            email="hostmaster@uio.no",
            serialno="2018070500",
            refresh=400,
            retry=300,
            expire=800,
            ttl=300
        )
        self.zone_two = Zones(
            zoneid=2,
            name="uv.uio.no",
            primary_ns="ns1.uio.no",
            email="hostmaster@uio.no",
            serialno="2018070501",
            refresh=400,
            retry=300,
            expire=800,
            ttl=300
        )
        self.post_data_with_taken_name = {'name': 'matnat.uio.no', 'ns': ['ns1.uio.no'], 'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 150}
        self.post_data_one = {'name': 'hf.uio.no', 'ns': ['ns1.uio.no'], 'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 150}
        self.post_data_two = {'name': 'sv.uio.no', 'ns': ['ns1.uio.no'], 'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 150}
        self.patch_data_with_name = {'name': 'new-name', 'contact': 'updated@mail.com'}
        self.patch_data_with_serialno_in_use = {'serialno': '2018070500', 'contact': 'updated@mail.com'}
        self.patch_data_with_zoneid_in_use = {'zoneid': '1', 'contact': 'updated@mail.com'}
        self.patch_data = {'refresh': '500', 'expire': '1000'}

    def test_zones_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.zone_one.save()
        client = APIClient()
        response = client.get('/zones/nonexisting.uio.no/')
        self.assertEqual(response.status_code, 404)

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.zone_one.save()
        client = APIClient()
        response = client.get('/zones/matnat.uio.no/')
        self.assertEqual(response.status_code, 200)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        self.zone_one.save()
        client = APIClient()
        response = client.post('/zones/', self.post_data_with_taken_name)
        self.assertEqual(response.status_code, 409)

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201"""
        client = APIClient()
        response = client.post('/zones/', self.post_data_one)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/zones/hf.uio.no')

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        client = APIClient()
        client.post('/zones/', self.post_data_one)
        client.post('/zones/', self.post_data_two)
        response = client.get('/zones/sv.uio.no/')
        self.assertEqual(response.data['serialno'], int("%s%02d" % (time.strftime('%Y%m%d'), 2)))

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        self.zone_one.save()
        client = APIClient()
        response = client.patch('/zones/matnat.uio.no/', self.patch_data_with_name)
        self.assertEqual(response.status_code, 403)

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        self.zone_one.save()
        client = APIClient()
        response = client.patch('/zones/nonexisting.uio.no/', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_zones_patch_409_conflict_zoneid(self):
        """"Patching a entry with a zoneid already in use should return 409"""
        self.zone_one.save()
        client = APIClient()
        response = client.patch('/zones/matnat.uio.no/', self.patch_data_with_zoneid_in_use)
        self.assertEqual(response.status_code, 409)

    def test_zones_patch_409_conflict_serialno(self):
        """"Patching a entry with a serialno already in use should return 409"""
        self.zone_one.save()
        client = APIClient()
        response = client.patch('/zones/matnat.uio.no/', self.patch_data_with_serialno_in_use)
        self.assertEqual(response.status_code, 409)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        self.zone_one.save()
        client = APIClient()
        response = client.patch('/zones/matnat.uio.no/', self.patch_data)
        self.assertEqual(response.status_code, 204)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        self.zone_one.save()
        client = APIClient()
        response = client.delete('/zones/matnat.uio.no/')
        self.assertEqual(response.status_code, 204)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        client = APIClient()
        response = client.delete('/zones/nonexisting.uio.no/')
        self.assertEqual(response.status_code, 404)

    def test_zones_403_forbidden(self):
        """"Deleting an entry with registered entries should require force"""

