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
    # TODO: test this for sub-zones (usit.uio.no) and "top"-zones (usit.no)?
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
        
    
class ModelNsTestCase(TestCase):
    """This class defines the test suite for the Ns model."""

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

        self.zone_sample.save()

        self.ns_sample = Ns(zoneid=Zones.objects.get(name='some-zone'),
                            name='some-ns-server.uio.no',
                            ttl=300)

    def test_model_can_create_ns(self):
        """Test that the model is able to create an Ns."""
        old_count = Ns.objects.count()
        self.ns_sample.save()
        new_count = Ns.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change an Ns."""
        self.ns_sample.save()
        old_name = self.ns_sample.name
        new_name = 'some-new-ns'
        ns_sample_id = Ns.objects.get(name=old_name).nsid
        self.ns_sample.name = new_name
        self.ns_sample.save()
        updated_name = Ns.objects.get(pk=ns_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete an Ns."""
        self.ns_sample.save()
        old_count = Ns.objects.count()
        self.ns_sample.delete()
        new_count = Ns.objects.count()
        self.assertNotEqual(old_count, new_count)
        

class ModelSubnetsTestCase(TestCase):
    """This class defines the test suite for the Subnets model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.subnet_sample = Subnets(range='129.240.202.0/20',
                                     description='some description',
                                     vlan=123,
                                     dns_delegated=False)

    def test_model_can_create_ns(self):
        """Test that the model is able to create a Subnet."""
        old_count = Subnets.objects.count()
        self.subnet_sample.save()
        new_count = Subnets.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change a Subnet."""
        self.subnet_sample.save()
        new_vlan = 321
        subnet_sample_id = self.subnet_sample.subnetid
        self.subnet_sample.vlan = new_vlan
        self.subnet_sample.save()
        updated_vlan = Subnets.objects.get(pk=subnet_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete a Subnet."""
        self.subnet_sample.save()
        old_count = Subnets.objects.count()
        self.subnet_sample.delete()
        new_count = Subnets.objects.count()
        self.assertNotEqual(old_count, new_count)
        
        
class ModelIpaddressTestCase(TestCase):
    """This class defines the test suite for the Ipaddress model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host and sample subnet to test properly
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.subnet_sample = Subnets(range='129.240.202.0/20',
                                     description='some description',
                                     vlan=123,
                                     dns_delegated=False)

        self.host_sample.save()
        #self.subnet_sample.save() # Needed when subnet ForeignKey is implemented.

        self.ipaddress_sample = Ipaddress(hostid=Hosts.objects.get(name='some-host'),
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
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.host_sample.save()

        self.ptr_sample = PtrOverride(hostid=Hosts.objects.get(name='some-host'),
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
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.host_sample.save()

        self.txt_sample = Txt(hostid=Hosts.objects.get(name='some-host'),
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
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.host_sample.save()

        self.cname_sample = Cname(hostid=Hosts.objects.get(name='some-host'),
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
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.host_sample.save()

        self.naptr_sample = Naptr(hostid=Hosts.objects.get(name='some-host'),
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
        self.host_sample = Hosts(name='some-host',
                                 contact='some.email@some.domain.no',
                                 ttl=300,
                                 loc='23 58 23 N 10 43 50 E 80m',
                                 comment='some comment')

        self.host_sample.save()

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

    def test_hosts_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        self.host_sample.save()
        client = APIClient()
        response = client.patch('/hosts/dette-er-en-host/', data={'this': 'is', 'so': 'wrong'})
        resp = client.get('/hosts/dette-er-en-host/')
        host = Hosts.objects.get(contact='ulvik@usit.uio.no')
        print(host.name)
        self.assertEqual(response.status_code, 400)
