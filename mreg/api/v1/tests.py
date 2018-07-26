from django.test import TestCase
from django.utils import timezone
from mreg.models import *
from rest_framework.test import APIClient

import time


class ModelHostsTestCase(TestCase):
    """This class defines the test suite for the Host model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Host.objects.count()
        self.host_one.save()
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_host(self):
        """Test that the model is able to change a host."""
        self.host_one.save()
        old_name = self.host_one.name
        new_name = 'some-new-host'
        host_sample_id = Host.objects.get(name=old_name).hostid
        self.host_one.name = new_name
        self.host_one.save()
        updated_name = Host.objects.get(pk=host_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_host(self):
        """Test that the model is able to delete a host."""
        self.host_one.save()
        old_count = Host.objects.count()
        self.host_one.delete()
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelZonesTestCase(TestCase):
    """This class defines the test suite for the Zones model."""

    # TODO: test this for sub-zones (usit.uio.no) and "top"-zones (usit.no)?
    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = Zone(name='some-zone',
                                primary_ns='some-ns-server',
                                email='some.email@some.domain.no',
                                serialno=1234567890,
                                refresh=400,
                                retry=300,
                                expire=800,
                                ttl=300)

    def test_model_can_create_a_zone(self):
        """Test that the model is able to create a zone."""
        old_count = Zone.objects.count()
        self.zone_sample.save()
        new_count = Zone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_zone(self):
        """Test that the model is able to change a zone."""
        self.zone_sample.save()
        old_name = self.zone_sample.name
        new_name = 'some-new-zone'
        zone_sample_id = Zone.objects.get(name=old_name).zoneid
        self.zone_sample.name = new_name
        self.zone_sample.save()
        updated_name = Zone.objects.get(pk=zone_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        self.zone_sample.save()
        old_count = Zone.objects.count()
        self.zone_sample.delete()
        new_count = Zone.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelNsTestCase(TestCase):
    """This class defines the test suite for the Ns model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = Zone(name='some-zone',
                                primary_ns='some-ns-server',
                                email='some.email@some.domain.no',
                                serialno=1234567890,
                                refresh=400,
                                retry=300,
                                expire=800,
                                ttl=300)

        self.zone_sample.save()

        self.ns_sample = NameServer(name='some-ns-server.uio.no',
                                    ttl=300)

    def test_model_can_create_ns(self):
        """Test that the model is able to create an Ns."""
        old_count = NameServer.objects.count()
        self.ns_sample.save()
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change an Ns."""
        self.ns_sample.save()
        old_name = self.ns_sample.name
        new_name = 'some-new-ns'
        ns_sample_id = NameServer.objects.get(name=old_name).nsid
        self.ns_sample.name = new_name
        self.ns_sample.save()
        updated_name = NameServer.objects.get(pk=ns_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete an Ns."""
        self.ns_sample.save()
        old_count = NameServer.objects.count()
        self.ns_sample.delete()
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelSubnetsTestCase(TestCase):
    """This class defines the test suite for the Subnets model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.subnet_sample = Subnet(range='129.240.202.0/20',
                                    description='some description',
                                    vlan=123,
                                    dns_delegated=False,
                                    category='so',
                                    location='silurveien',
                                    frozen=False)

    def test_model_can_create_ns(self):
        """Test that the model is able to create a Subnet."""
        old_count = Subnet.objects.count()
        self.subnet_sample.save()
        new_count = Subnet.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change a Subnet."""
        self.subnet_sample.save()
        new_vlan = 321
        subnet_sample_id = self.subnet_sample.subnetid
        self.subnet_sample.vlan = new_vlan
        self.subnet_sample.save()
        updated_vlan = Subnet.objects.get(pk=subnet_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete a Subnet."""
        self.subnet_sample.save()
        old_count = Subnet.objects.count()
        self.subnet_sample.delete()
        new_count = Subnet.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelIpaddressTestCase(TestCase):
    """This class defines the test suite for the Ipaddress model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host and sample subnet to test properly
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.subnet_sample = Subnet(range='129.240.202.0/20',
                                    description='some description',
                                    vlan=123,
                                    dns_delegated=False)

        self.host_one.save()
        # self.subnet_sample.save() # Needed when subnet ForeignKey is implemented.

        self.ipaddress_sample = Ipaddress(hostid=Host.objects.get(name='some-host'),
                                          ipaddress='129.240.202.123',
                                          macaddress='a4:34:d9:0e:88:b9')

    def test_model_can_create_ipaddress(self):
        """Test that the model is able to create an IP Address."""
        old_count = Ipaddress.objects.count()
        self.ipaddress_sample.save()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ipaddress(self):
        """Test that the model is able to change an IP Address."""
        self.ipaddress_sample.save()
        new_ipaddress = '129.240.202.124'
        self.ipaddress_sample.ipaddress = new_ipaddress
        self.ipaddress_sample.save()
        updated_ipaddress = Ipaddress.objects.filter(hostid__name='some-host')[0].ipaddress
        self.assertEqual(new_ipaddress, updated_ipaddress)

    def test_model_can_delete_ipaddress(self):
        """Test that the model is able to delete an IP Address."""
        self.ipaddress_sample.save()
        old_count = Ipaddress.objects.count()
        self.ipaddress_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelPtrOverrideTestCase(TestCase):
    """This class defines the test suite for the PtrOverride model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()

        self.ptr_sample = PtrOverride(hostid=Host.objects.get(name='some-host'),
                                      ipaddress='129.240.202.123')

    def test_model_can_create_ptr(self):
        """Test that the model is able to create a PTR Override."""
        old_count = PtrOverride.objects.count()
        self.ptr_sample.save()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ptr(self):
        """Test that the model is able to change a PTR Override."""
        self.ptr_sample.save()
        new_ptr = '129.240.202.124'
        self.ptr_sample.ipaddress = new_ptr
        self.ptr_sample.save()
        updated_ptr = PtrOverride.objects.filter(hostid__name='some-host')[0].ipaddress
        self.assertEqual(new_ptr, updated_ptr)

    def test_model_can_delete_ptr(self):
        """Test that the model is able to delete a PTR Override."""
        self.ptr_sample.save()
        old_count = PtrOverride.objects.count()
        self.ptr_sample.delete()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelTxtTestCase(TestCase):
    """This class defines the test suite for the Txt model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()

        self.txt_sample = Txt(hostid=Host.objects.get(name='some-host'),
                              txt='some-text')

    def test_model_can_create_txt(self):
        """Test that the model is able to create a txt entry."""
        old_count = Txt.objects.count()
        self.txt_sample.save()
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_txt(self):
        """Test that the model is able to change a txt entry."""
        self.txt_sample.save()
        new_txt = 'some-new-text'
        txt_sample_id = self.txt_sample.txtid
        self.txt_sample.txt = new_txt
        self.txt_sample.save()
        updated_txt = Txt.objects.get(pk=txt_sample_id).txt
        self.assertEqual(new_txt, updated_txt)

    def test_model_can_delete_txt(self):
        """Test that the model is able to delete a txt entry."""
        self.txt_sample.save()
        old_count = Txt.objects.count()
        self.txt_sample.delete()
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelCnameTestCase(TestCase):
    """This class defines the test suite for the Cname model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()

        self.cname_sample = Cname(hostid=Host.objects.get(name='some-host'),
                                  cname='some-cname',
                                  ttl=300)

    def test_model_can_create_cname(self):
        """Test that the model is able to create a cname entry."""
        old_count = Cname.objects.count()
        self.cname_sample.save()
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_cname(self):
        """Test that the model is able to change a cname entry."""
        self.cname_sample.save()
        new_cname = 'some-new-cname'
        self.cname_sample.cname = new_cname
        self.cname_sample.save()
        updated_cname = Cname.objects.filter(hostid__name='some-host')[0].cname
        self.assertEqual(new_cname, updated_cname)

    def test_model_can_delete_cname(self):
        """Test that the model is able to delete a cname entry."""
        self.cname_sample.save()
        old_count = Cname.objects.count()
        self.cname_sample.delete()
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelNaptrTestCase(TestCase):
    """This class defines the test suite for the Naptr model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()

        self.naptr_sample = Naptr(hostid=Host.objects.get(name='some-host'),
                                  preference=1,
                                  orderv=1,
                                  flag='A',
                                  service='_abc_tcp_def',
                                  regex='^naptrregex',
                                  replacement='some replacement')

    def test_model_can_create_naptr(self):
        """Test that the model is able to create a naptr entry."""
        old_count = Naptr.objects.count()
        self.naptr_sample.save()
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_naptr(self):
        """Test that the model is able to change a naptr entry."""
        self.naptr_sample.save()
        new_flag = 'U'
        self.naptr_sample.flag = new_flag
        self.naptr_sample.save()
        updated_flag = Naptr.objects.get(pk=self.naptr_sample.naptrid).flag
        self.assertEqual(new_flag, updated_flag)

    def test_model_can_delete_naptr(self):
        """Test that the model is able to delete a naptr entry."""
        self.naptr_sample.save()
        old_count = Naptr.objects.count()
        self.naptr_sample.delete()
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelSrvTestCase(TestCase):
    """This class defines the test suite for the Srv model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()

        self.srv_sample = Srv(service='_abc_udp_def',
                              priority=3,
                              weight=1,
                              port=5433,
                              ttl=300,
                              target='some-target')

    def test_model_can_create_srv(self):
        """Test that the model is able to create a srv entry."""
        old_count = Srv.objects.count()
        self.srv_sample.save()
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_srv(self):
        """Test that the model is able to change a srv entry."""
        self.srv_sample.save()
        new_port = 5434
        self.srv_sample.port = new_port
        self.srv_sample.save()
        updated_port = Srv.objects.get(pk=self.srv_sample.srvid).port
        self.assertEqual(new_port, updated_port)

    def test_model_can_delete_srv(self):
        """Test that the model is able to delete a srv entry."""
        self.srv_sample.save()
        old_count = Srv.objects.count()
        self.srv_sample.delete()
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelChangeLogsTestCase(TestCase):
    """This class defines the test suite for the ModelChangeLogs model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')
        self.host_one.save()

        self.log_data = {'hostid': self.host_one.hostid,
                         'name': self.host_one.name,
                         'contact': self.host_one.contact,
                         'ttl': self.host_one.ttl,
                         'loc': self.host_one.loc,
                         'comment': self.host_one.comment}

        self.log_entry_one = ModelChangeLog(table_name='Hosts',
                                            table_row=self.host_one.hostid,
                                            data=self.log_data,
                                            action='saved',
                                            timestamp=timezone.now())

    def test_model_can_create_a_log_entry(self):
        """Test that the model is able to create a host."""
        old_count = ModelChangeLog.objects.count()
        self.log_entry_one.save()
        new_count = ModelChangeLog.objects.count()
        self.assertNotEqual(old_count, new_count)


class APIHostsTestCase(TestCase):
    """This class defines the test suite for api/hosts"""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='skrutrekker.uio.no', contact='ulvik@usit.uio.no')
        self.host_two = Host(name='maursluker.uio.no', contact='ulvik@usit.uio.no')
        self.patch_data = {'name': 'nytt-navn', 'contact': 'updated@mail.com'}
        self.patch_data_name = {'name': 'maursluker.uio.no', 'contact': 'updated@mail.com'}
        self.post_data = {'name': 'hiquality.uio.no', "ipaddress": '127.0.0.2', 'contact': 'hostmaster@uio.no'}
        self.post_data_name = {'name': 'skrutrekker.uio.no', "ipaddress": '127.0.0.2', 'contact': 'hostmaster@uio.no'}
        self.host_one.save()
        self.host_two.save()
        self.client = APIClient()

    def test_hosts_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/hosts/%s' % self.host_one.name)
        self.assertEqual(response.status_code, 200)

    def test_hosts_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/hosts/nonexistent.uio.no')
        self.assertEqual(response.status_code, 404)

    def test_hosts_post_201_created(self):
        """"Posting a new host should return 201 and location"""
        response = self.client.post('/hosts/', self.post_data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/hosts/%s' % self.post_data['name'])

    def test_hosts_post_409_conflict_name(self):
        """"Posting a new host with a name already in use should return 409"""
        response = self.client.post('/hosts/', self.post_data_name)
        self.assertEqual(response.status_code, 409)

    def test_hosts_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/hosts/%s' % self.patch_data['name'])

    def test_hosts_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_hosts_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/hosts/feil-navn/', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_hosts_patch_409_conflict_name(self):
        """Patching an entry with a name that already exists should return 409"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, {'name': self.host_two.name})
        self.assertEqual(response.status_code, 409)

    def test_hosts_patch_409_conflict_hostid(self):
        """"Patching a host with a name already in use should return 409"""
        response = self.client.get('/hosts/%s' % self.host_one.name)
        response = self.client.patch('/hosts/%s' % self.host_one.name, {'hostid': response.data['hostid']})
        self.assertEqual(response.status_code, 409)


class APIZonesTestCase(TestCase):
    """"This class defines the test suite for api/zones """

    def setUp(self):
        """Define the test client and other variables."""
        self.zone_one = Zone(
            name="matnat.uio.no",
            primary_ns="ns1.uio.no",
            email="hostmaster@uio.no",
            serialno="2018070500",
            refresh=400,
            retry=300,
            expire=800,
            ttl=300
        )
        self.host_one = Host(name='ns1.uio.no', contact='hostmaster@uio.no')
        self.host_two = Host(name='ns2.uio.no', contact='hostmaster@uio.no')
        self.host_three = Host(name='ns3.uio.no', contact='hostmaster@uio.no')
        self.ns_one = NameServer(name='ns1.uio.no', ttl=400)
        self.ns_two = NameServer(name='ns2.uio.no', ttl=400)
        self.post_data_one = {'name': 'hf.uio.no', 'primary_ns': ['ns1.uio.no', 'ns2.uio.no'],
                              'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 350}
        self.post_data_two = {'name': 'sv.uio.no', 'primary_ns': ['ns1.uio.no', 'ns2.uio.no'],
                              'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 350}
        self.patch_data = {'refresh': '500', 'expire': '1000'}
        self.host_one.save()
        self.host_two.save()
        self.ns_one.save()
        self.ns_two.save()
        self.zone_one.save()
        self.client = APIClient()

    def test_zones_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/zones/nonexisting.uio.no')
        self.assertEqual(response.status_code, 404)

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        self.assertEqual(response.status_code, 200)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        response = self.client.post('/zones/', {'name': response.data['name']})
        self.assertEqual(response.status_code, 409)

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201 and location"""
        response = self.client.post('/zones/', self.post_data_one)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/zones/%s' % self.post_data_one['name'])

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        self.client.post('/zones/', self.post_data_one)
        self.client.post('/zones/', self.post_data_two)
        response_one = self.client.get('/zones/%s' % self.post_data_one['name'])
        response_two = self.client.get('/zones/%s' % self.post_data_two['name'])
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'] - 1)

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        response = self.client.patch('/zones/%s' % self.zone_one.name, {'name': response.data['name']})
        self.assertEqual(response.status_code, 403)

    def test_zones_patch_403_forbidden_primary_ns(self):
        """Trying to patch the primary_ns to be a nameserver that isn't in the nameservers list should return 403"""
        response = self.client.post('/zones/', self.post_data_two)
        self.assertEqual(response.status_code, 201)
        response = self.client.patch('/zones/%s' % self.post_data_two['name'], {'primary_ns': self.host_three.name})
        self.assertEqual(response.status_code, 403)

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        response = self.client.patch('/zones/nonexisting.uio.no', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_zones_patch_409_conflict_zoneid(self):
        """"Patching a entry with a zoneid already in use should return 409"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        response = self.client.patch('/zones/%s' % self.zone_one.name, {'zoneid': response.data['zoneid']})
        self.assertEqual(response.status_code, 409)

    def test_zones_patch_409_conflict_serialno(self):
        """"Patching a entry with a serialno already in use should return 409"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        response = self.client.patch('/zones/%s' % self.zone_one.name, {'serialno': response.data['serialno']})
        self.assertEqual(response.status_code, 409)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        response = self.client.patch('/zones/%s' % self.zone_one.name, self.patch_data)
        self.assertEqual(response.status_code, 204)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        response = self.client.delete('/zones/%s' % self.zone_one.name)
        self.assertEqual(response.status_code, 204)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        response = self.client.delete('/zones/nonexisting.uio.no')
        self.assertEqual(response.status_code, 404)

    def test_zones_403_forbidden(self):
        # TODO: jobb skal gjøres her
        """"Deleting an entry with registered entries should require force"""


class APIZonesNsTestCase(TestCase):
    """"This class defines the test suite for api/zones/<name>/nameservers/ """

    def setUp(self):
        """Define the test client and other variables."""
        self.post_data = {'name': 'hf.uio.no', 'primary_ns': ['ns2.uio.no'],
                          'email': 'hostmaster@uio.no', 'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 350}
        self.ns_one = Host(name='ns1.uio.no', contact='chipotle.uio.no')
        self.ns_two = Host(name='ns2.uio.no', contact='maursluker.uio.no')
        self.ns_one.save()
        self.ns_two.save()
        self.client = APIClient()

    def test_zones_ns_get_200_ok(self):
        """"Getting the list of nameservers of a existing zone should return 200"""
        self.client.post('/zones/', self.post_data)
        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.status_code, 200)

    def test_zones_ns_get_404_not_found(self):
        """"Getting the list of nameservers of a non-existing zone should return 404"""
        response = self.client.delete('/zones/nonexisting.uio.no/nameservers/')
        self.assertEqual(response.status_code, 404)

    def test_zones_ns_patch_204_no_content(self):
        """"Patching the list of nameservers with an existing nameserver should return 204"""
        self.client.post('/zones/', self.post_data)
        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})
        self.assertEqual(response.status_code, 204)

    def test_zones_ns_patch_400_bad_request(self):
        """"Patching the list of nameservers with a bad request body should return 404"""
        self.client.post('/zones/', self.post_data)
        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'garbage': self.ns_one.name})
        self.assertEqual(response.status_code, 400)

    def test_zones_ns_patch_404_not_found(self):
        """"Patching the list of nameservers with a non-existing nameserver should return 404"""
        self.client.post('/zones/', self.post_data)
        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': ['nonexisting-ns.uio.no']})
        self.assertEqual(response.status_code, 404)

    def test_zones_ns_delete_204_no_content_zone(self):
        """Deleting a nameserver from an existing zone should return 204"""

        # TODO: This test needs some cleanup and work. See comments
        self.client.post('/zones/', self.post_data)

        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})
        self.assertEqual(response.status_code, 204)

        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.status_code, 200)

        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': self.ns_two.name})
        self.assertEqual(response.status_code, 204)

        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.data, self.post_data['primary_ns'])


class APIIPaddressesTestCase(TestCase):
    """This class defines the test suite for api/ipaddresses"""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_two = Host(name='some-other-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 56 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.host_one.save()
        self.host_two.save()

        self.ipaddress_one = Ipaddress(hostid=self.host_one,
                                       ipaddress='129.240.111.111')

        self.ipaddress_two = Ipaddress(hostid=self.host_two,
                                       ipaddress='129.240.111.112')

        self.ipaddress_one.save()
        self.ipaddress_two.save()

        self.post_data_ip = {'ipaddress': '129.240.203.197'}

        self.post_data_full = {'hostid': self.host_one.hostid,
                               'ipaddress': '129.240.203.197'}
        self.post_data_full_conflict = {'hostid': self.host_one.hostid,
                                        'ipaddress': '129.240.111.112'}
        self.patch_data_ip = {'ipaddress': '129.240.203.198'}

        self.client = APIClient()

    def test_ipaddress_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/ipaddresses/%s' % self.ipaddress_one.ipaddress)
        self.assertEqual(response.status_code, 200)

    def test_ipaddress_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/ipaddresses/193.101.168.2')
        self.assertEqual(response.status_code, 404)

    def test_ipaddress_post_201_created(self):
        """"Posting a new ip should return 201 and location"""
        response = self.client.post('/ipaddresses/', self.post_data_full)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/ipaddresses/%s' % self.post_data_full['ipaddress'])

    def test_ipaddress_post_409_conflict_ip(self):
        """"Posting a new ipaddress with an ip already in use should return 409"""
        response = self.client.post('/ipaddresses/', self.post_data_full_conflict)
        self.assertEqual(response.status_code, 409)

    def test_ipaddress_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.ipaddress, self.patch_data_ip)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/ipaddresses/%s' % self.patch_data_ip['ipaddress'])

    def test_ipaddress_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.ipaddress,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_ipaddress_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/ipaddresses/193.101.168.2', self.patch_data_ip)
        self.assertEqual(response.status_code, 404)

    def test_ipaddress_patch_409_conflict_ip(self):
        """Patching an entry with an ip that already exists should return 409"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.ipaddress,
                                     {'ipaddress': self.ipaddress_two.ipaddress})
        self.assertEqual(response.status_code, 409)


class APISubnetsTestCase(TestCase):
    """"This class defines the test suite for api/subnets """
    def setUp(self):
        """Define the test client and other variables."""
        self.subnet_sample = Subnet(range='129.240.204.0/24',
                                    description='some description',
                                    vlan=123,
                                    dns_delegated=False,
                                    category='so',
                                    location='silurveien',
                                    frozen=False)
        self.subnet_sample_two = Subnet(range='129.240.205.0/28',
                                        description='some description',
                                        vlan=135,
                                        dns_delegated=False,
                                        category='so',
                                        location='silurveien',
                                        frozen=False)

        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')
        self.host_one.save()
        self.subnet_sample.save()
        self.subnet_sample_two.save()

        self.patch_data = {
            'description': 'Test subnet',
            'vlan': '435',
            'dns_delegated': 'False',
            'category': 'si',
            'location': 'new-location'
        }

        self.patch_data_vlan = {'vlan': '435'}
        self.patch_data_range = {'range': '129.240.205.0/28'}

        self.post_data = {
            'range': '192.0.2.0/29',
            'description': 'Test subnet',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_bad_ip = {
            'range': '192.0.2.0.95/29',
            'description': 'Test subnet',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_bad_mask = {
            'range': '192.0.2.0/2549',
            'description': 'Test subnet',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_overlap = {
            'range': '129.240.205.0/29',
            'description': 'Test subnet',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.client = APIClient()

    def test_subnets_post_201_created(self):
        """Posting a subnet should return 201"""
        response = self.client.post('/subnets/', self.post_data)
        self.assertEqual(response.status_code, 201)

    def test_subnets_post_400_bad_request_ip(self):
        """Posting a subnet with a range that has a malformed IP should return 400"""
        response = self.client.post('/subnets/', self.post_data_bad_ip)
        self.assertEqual(response.status_code, 400)

    def test_subnets_post_400_bad_request_mask(self):
        """Posting a subnet with a range that has a malformed mask should return 400"""
        response = self.client.post('/subnets/', self.post_data_bad_mask)
        self.assertEqual(response.status_code, 400)

    def test_subnets_get_200_ok(self):
        """GET on an existing ip-range should return 200 OK."""
        response = self.client.get('/subnets/%s' % self.subnet_sample.range)
        self.assertEqual(response.status_code, 200)

    def test_subnets_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.client.patch('/subnets/%s' % self.subnet_sample.range, self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/subnets/%s' % self.subnet_sample.range)

    def test_subnets_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/subnets/%s' % self.subnet_sample.range,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_subnets_patch_403_forbidden_range(self):
        """Patching an entry with a range should return 403"""
        response = self.client.patch('/subnets/%s' % self.subnet_sample.range, data=self.patch_data_range)
        self.assertEqual(response.status_code, 403)

    def test_subnets_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/subnets/193.101.168.0/29', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_subnets_get_usedlist_200_ok(self):
        """GET on /subnets/<ip/mask> with QUERY_STRING header 'used_list' should return 200 ok and data."""
        ip_sample = Ipaddress(hostid=self.host_one, ipaddress='129.240.204.17')
        ip_sample.save()

        response = self.client.get('/subnets/%s?used_list' % self.subnet_sample.range)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['129.240.204.17'])

    def test_subnets_delete_204_no_content(self):
        """Deleting an existing entry with no adresses in use should return 204"""
        response = self.client.post('/subnets/', self.post_data)
        self.assertEqual(response.status_code, 201)
        response = self.client.delete('/subnets/%s' % self.post_data['range'])
        self.assertEqual(response.status_code, 204)

    def test_subnets_delete_409_conflict(self):
        """Deleting an existing entry with  adresses in use should return 409"""
        response = self.client.post('/subnets/', self.post_data)
        self.assertEqual(response.status_code, 201)

        ip_sample = Ipaddress(hostid=self.host_one, ipaddress='192.0.2.1')
        ip_sample.save()

        response = self.client.delete('/subnets/%s' % self.post_data['range'])
        self.assertEqual(response.status_code, 409)


class APIModelChangeLogsTestCase(TestCase):
    """This class defines the test suite for api/history """

    def setUp(self):
        """Define the test client and other variables."""
        self.host_one = Host(name='some-host',
                             contact='some.email@some.domain.no',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')
        self.host_one.save()

        self.log_data = {'hostid': self.host_one.hostid,
                         'name': self.host_one.name,
                         'contact': self.host_one.contact,
                         'ttl': self.host_one.ttl,
                         'loc': self.host_one.loc,
                         'comment': self.host_one.comment}

        self.log_entry_one = ModelChangeLog(table_name='hosts',
                                            table_row=self.host_one.hostid,
                                            data=self.log_data,
                                            action='saved',
                                            timestamp=timezone.now())
        self.log_entry_one.save()
        self.client = APIClient()

    def test_history_get_200_OK(self):
        """Get on /history/ should return a list of table names that have entries, and 200 OK."""
        response = self.client.get('/history/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('hosts', response.data)

    def test_history_host_get_200_OK(self):
        """Get on /history/hosts/<pk> should return a list of dicts containing entries for that host"""
        response = self.client.get('/history/hosts/{}'.format(self.host_one.hostid))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)
