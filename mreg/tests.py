from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from mreg.models import (ForwardZone, Host, Ipaddress, NameServer, Network, ReverseZone,
                         PtrOverride, Txt, Sshfp, Cname, Naptr, Srv, ModelChangeLog)
from rest_framework.exceptions import PermissionDenied


def clean_and_save(entity):
    entity.full_clean()
    entity.save()


class ModelChangeLogTestCase(TestCase):
    """This class defines the test suite for the ModelChangeLog model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')
        clean_and_save(self.host_one)

        self.log_data = {'id': self.host_one.id,
                         'name': self.host_one.name,
                         'contact': self.host_one.contact,
                         'ttl': self.host_one.ttl,
                         'loc': self.host_one.loc,
                         'comment': self.host_one.comment}

        self.log_entry_one = ModelChangeLog(table_name='Hosts',
                                            table_row=self.host_one.id,
                                            data=self.log_data,
                                            action='saved',
                                            timestamp=timezone.now())

    def test_model_can_create_a_log_entry(self):
        """Test that the model is able to create a host."""
        old_count = ModelChangeLog.objects.count()
        clean_and_save(self.log_entry_one)
        new_count = ModelChangeLog.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelSrvTestCase(TestCase):
    """This class defines the test suite for the Srv model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        clean_and_save(self.host_one)

        self.srv_sample = Srv(name='_abc._udp.example.org',
                              priority=3,
                              weight=1,
                              port=5433,
                              ttl=300,
                              target='some-target')

    def test_model_can_create_srv(self):
        """Test that the model is able to create a srv entry."""
        old_count = Srv.objects.count()
        clean_and_save(self.srv_sample)
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_srv(self):
        """Test that the model is able to change a srv entry."""
        clean_and_save(self.srv_sample)
        new_port = 5434
        self.srv_sample.port = new_port
        clean_and_save(self.srv_sample)
        updated_port = Srv.objects.get(pk=self.srv_sample.id).port
        self.assertEqual(new_port, updated_port)

    def test_model_can_delete_srv(self):
        """Test that the model is able to delete a srv entry."""
        clean_and_save(self.srv_sample)
        old_count = Srv.objects.count()
        self.srv_sample.delete()
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelNaptrTestCase(TestCase):
    """This class defines the test suite for the Naptr model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        clean_and_save(self.host_one)

        self.naptr_sample = Naptr(host=Host.objects.get(name='some-host.example.org'),
                                  preference=1,
                                  order=1,
                                  flag='a',
                                  service='SER+VICE',
                                  regex='^naptrregex',
                                  replacement='some replacement')

    def test_model_can_create_naptr(self):
        """Test that the model is able to create a naptr entry."""
        old_count = Naptr.objects.count()
        clean_and_save(self.naptr_sample)
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_naptr(self):
        """Test that the model is able to change a naptr entry."""
        clean_and_save(self.naptr_sample)
        new_flag = 'u'
        self.naptr_sample.flag = new_flag
        clean_and_save(self.naptr_sample)
        updated_flag = Naptr.objects.get(pk=self.naptr_sample.id).flag
        self.assertEqual(new_flag, updated_flag)

    def test_model_can_delete_naptr(self):
        """Test that the model is able to delete a naptr entry."""
        clean_and_save(self.naptr_sample)
        old_count = Naptr.objects.count()
        self.naptr_sample.delete()
        new_count = Naptr.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelCnameTestCase(TestCase):
    """This class defines the test suite for the Cname model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org')

        clean_and_save(self.host_one)

        self.cname_sample = Cname(host=Host.objects.get(name='some-host.example.org'),
                                  name='some-cname.example.org',
                                  ttl=300)

    def test_model_can_create_cname(self):
        """Test that the model is able to create a cname entry."""
        old_count = Cname.objects.count()
        clean_and_save(self.cname_sample)
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_cname(self):
        """Test that the model is able to change a cname entry."""
        clean_and_save(self.cname_sample)
        new_cname = 'some-new-cname.example.org'
        self.cname_sample.name = new_cname
        clean_and_save(self.cname_sample)
        updated_cname = Cname.objects.filter(host__name='some-host.example.org')[0].name
        self.assertEqual(new_cname, updated_cname)

    def test_model_can_delete_cname(self):
        """Test that the model is able to delete a cname entry."""
        clean_and_save(self.cname_sample)
        old_count = Cname.objects.count()
        self.cname_sample.delete()
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelHostsTestCase(TestCase):
    """This class defines the test suite for the Host model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Host.objects.count()
        clean_and_save(self.host_one)
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_host(self):
        """Test that the model is able to change a host."""
        clean_and_save(self.host_one)
        old_name = self.host_one.name
        new_name = 'some-new-host.example.org'
        host_sample_id = Host.objects.get(name=old_name).id
        self.host_one.name = new_name
        clean_and_save(self.host_one)
        updated_name = Host.objects.get(pk=host_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_host(self):
        """Test that the model is able to delete a host."""
        clean_and_save(self.host_one)
        old_count = Host.objects.count()
        self.host_one.delete()
        new_count = Host.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_host_can_alter_loc(self):
        """
        Test that the model can validate and store all examples
        from RFC1876, section 4 "Example data".
        """
        clean_and_save(self.host_one)
        for loc in ('42 21 54 N 71 06 18 W -24m 30m',
                    '42 21 43.952 N 71 5 6.344 W -24m 1m 200m',
                    '52 14 05 N 00 08 50 E 10m',
                    '32 7 19 S 116 2 25 E 10m',
                    '42 21 28.764 N 71 00 51.617 W -44m 2000m'):
            self.host_one.loc = loc
            clean_and_save(self.host_one)


class ModelNameServerTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='some-ns-server.example.org',
                                       email='hostmaster@example.org')

        clean_and_save(self.zone_sample)

        self.ns_sample = NameServer(name='some-ns-server.example.org',
                                    ttl=300)

    def test_model_can_create_ns(self):
        """Test that the model is able to create an Ns."""
        old_count = NameServer.objects.count()
        clean_and_save(self.ns_sample)
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change an Ns."""
        clean_and_save(self.ns_sample)
        old_name = self.ns_sample.name
        new_name = 'some-new-ns.example.com'
        ns_sample_id = NameServer.objects.get(name=old_name).id
        self.ns_sample.name = new_name
        clean_and_save(self.ns_sample)
        updated_name = NameServer.objects.get(pk=ns_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete an Ns."""
        clean_and_save(self.ns_sample)
        old_count = NameServer.objects.count()
        self.ns_sample.delete()
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelNetworkTestCase(TestCase):
    """This class defines the test suite for the Network model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.network_sample = Network(range='10.0.0.0/20',
                                    description='some description',
                                    vlan=123,
                                    dns_delegated=False,
                                    category='so',
                                    location='Test location',
                                    frozen=False)

    def test_model_can_create_ns(self):
        """Test that the model is able to create a Network."""
        old_count = Network.objects.count()
        clean_and_save(self.network_sample)
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ns(self):
        """Test that the model is able to change a Network."""
        clean_and_save(self.network_sample)
        new_vlan = 321
        network_sample_id = self.network_sample.id
        self.network_sample.vlan = new_vlan
        clean_and_save(self.network_sample)
        updated_vlan = Network.objects.get(pk=network_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_delete_ns(self):
        """Test that the model is able to delete a Network."""
        clean_and_save(self.network_sample)
        old_count = Network.objects.count()
        self.network_sample.delete()
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelIpaddressTestCase(TestCase):
    """This class defines the test suite for the Ipaddress model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host and sample network to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        self.network_sample = Network(range='129.240.202.0/20',
                                    description='some description',
                                    vlan=123,
                                    dns_delegated=False)

        clean_and_save(self.host_one)
        # clean_and_save(self.network_sample) # Needed when network ForeignKey is implemented.

        self.ipaddress_sample = Ipaddress(host=Host.objects.get(name='some-host.example.org'),
                                          ipaddress='129.240.202.123',
                                          macaddress='a4:34:d9:0e:88:b9')

    def test_model_can_create_ipaddress(self):
        """Test that the model is able to create an IP Address."""
        old_count = Ipaddress.objects.count()
        clean_and_save(self.ipaddress_sample)
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ipaddress(self):
        """Test that the model is able to change an IP Address."""
        clean_and_save(self.ipaddress_sample)
        new_ipaddress = '129.240.202.124'
        self.ipaddress_sample.ipaddress = new_ipaddress
        clean_and_save(self.ipaddress_sample)
        updated_ipaddress = Ipaddress.objects.filter(host__name='some-host.example.org')[0].ipaddress
        self.assertEqual(new_ipaddress, updated_ipaddress)

    def test_model_can_delete_ipaddress(self):
        """Test that the model is able to delete an IP Address."""
        clean_and_save(self.ipaddress_sample)
        old_count = Ipaddress.objects.count()
        self.ipaddress_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelPtrOverrideTestCase(TestCase):
    """This class defines the test suite for the PtrOverride model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test
        self.host_one = Host(name='host1.example.org',
                             contact='mail@example.org')
        self.host_two = Host(name='host2.example.org',
                        contact='mail@example.org')

        clean_and_save(self.host_one)
        clean_and_save(self.host_two)

        self.ptr_sample = PtrOverride(host=Host.objects.get(name='host1.example.org'),
                                      ipaddress='10.0.0.2')

    def test_model_can_create_ptr(self):
        """Test that the model is able to create a PTR Override."""
        old_count = PtrOverride.objects.count()
        clean_and_save(self.ptr_sample)
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_ptr(self):
        """Test that the model is able to change a PTR Override."""
        clean_and_save(self.ptr_sample)
        new_ptr = '10.0.0.3'
        self.ptr_sample.ipaddress = new_ptr
        clean_and_save(self.ptr_sample)
        updated_ptr = PtrOverride.objects.filter(host__name='host1.example.org').first().ipaddress
        self.assertEqual(new_ptr, updated_ptr)

    def test_model_can_delete_ptr(self):
        """Test that the model is able to delete a PTR Override."""
        clean_and_save(self.ptr_sample)
        old_count = PtrOverride.objects.count()
        self.ptr_sample.delete()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)


    def test_model_updated_by_added_ip(self):
        """Test to check that an PtrOverride is added when two hosts share the same ip.
           Also makes sure that the PtrOverride points to the first host which held the ip."""
        initial_count = PtrOverride.objects.count()
        ip_one = Ipaddress(host=self.host_one, ipaddress='10.0.0.1')
        clean_and_save(ip_one)
        one_count = PtrOverride.objects.count()
        ip_two = Ipaddress(host=self.host_two, ipaddress='10.0.0.1')
        clean_and_save(ip_two)
        ptr =  PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '10.0.0.1')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(PtrOverride.objects.count(), 1)

    def test_model_add_and_remove_ip(self):
        """Test to check that an PtrOverride is added when two hosts share the same ip.
           Also makes sure that the PtrOverride points to the first host which held the ip."""
        initial_count = PtrOverride.objects.count()
        ip_one = Ipaddress(host=self.host_one, ipaddress='10.0.0.1')
        clean_and_save(ip_one)
        one_count = PtrOverride.objects.count()
        ip_two = Ipaddress(host=self.host_two, ipaddress='10.0.0.1')
        clean_and_save(ip_two)
        two_count = PtrOverride.objects.count()
        ptr =  PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '10.0.0.1')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(two_count, 1)
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)

    def test_model_two_ips_no_ptroverrides(self):
        """When three or more hosts all have the same ipaddress and the first host
        host, e.g. the one with the PtrOverride, is deleted, a new PtrOverride is
        not created automatically.
        """
        def _add_ip(host, ipaddress):
            ip = Ipaddress(host=host, ipaddress=ipaddress)
            clean_and_save(ip)
        _add_ip(self.host_one, '10.0.0.1')
        _add_ip(self.host_two, '10.0.0.1')
        host_three = Host(name='host3.example.org',
                        contact='mail@example.org')

        clean_and_save(host_three)
        _add_ip(host_three, '10.0.0.1')
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)
        self.assertEqual(Ipaddress.objects.filter(ipaddress='10.0.0.1').count(), 2)


class ModelTxtTestCase(TestCase):
    """This class defines the test suite for the Txt model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        clean_and_save(self.host_one)

        self.txt_sample = Txt(host=Host.objects.get(name='some-host.example.org'),
                              txt='some-text')

    def test_model_can_create_txt(self):
        """Test that the model is able to create a txt entry."""
        old_count = Txt.objects.count()
        clean_and_save(self.txt_sample)
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_txt(self):
        """Test that the model is able to change a txt entry."""
        clean_and_save(self.txt_sample)
        new_txt = 'some-new-text'
        txt_sample_id = self.txt_sample.id
        self.txt_sample.txt = new_txt
        clean_and_save(self.txt_sample)
        updated_txt = Txt.objects.get(pk=txt_sample_id).txt
        self.assertEqual(new_txt, updated_txt)

    def test_model_can_delete_txt(self):
        """Test that the model is able to delete a txt entry."""
        clean_and_save(self.txt_sample)
        old_count = Txt.objects.count()
        self.txt_sample.delete()
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelSshfpTestCase(TestCase):
    """This class defines the test suite for the Sshfp model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test properly
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')

        clean_and_save(self.host_one)

        self.sshfp_sample = Sshfp(host=Host.objects.get(name='some-host.example.org'),
                              algorithm=1, hash_type=1, fingerprint='01234567890abcdef')

    def test_model_can_create_sshfp(self):
        """Test that the model is able to create an sshfp entry."""
        old_count = Sshfp.objects.count()
        clean_and_save(self.sshfp_sample)
        new_count = Sshfp.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_sshfp(self):
        """Test that the model is able to change an sshfp entry."""
        clean_and_save(self.sshfp_sample)
        new_fingerprint = 'fedcba9876543210'
        sshfp_sample_id = self.sshfp_sample.id
        self.sshfp_sample.fingerprint = new_fingerprint
        clean_and_save(self.sshfp_sample)
        updated_fingerprint = Sshfp.objects.get(pk=sshfp_sample_id).fingerprint
        self.assertEqual(new_fingerprint, updated_fingerprint)

    def test_model_can_delete_sshfp(self):
        """Test that the model is able to delete an sshfp entry."""
        clean_and_save(self.sshfp_sample)
        old_count = Sshfp.objects.count()
        self.sshfp_sample.delete()
        new_count = Sshfp.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelForwardZoneTestCase(TestCase):
    """This class defines the test suite for the ForwardZone model."""

    # TODO: test this for sub-zones (sub.example.org)
    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='ns.example.org',
                                       email='hostmaster@example.org',
                                       serialno=1234567890,
                                       refresh=400,
                                       retry=300,
                                       expire=800,
                                       ttl=300)

    def test_model_can_create_a_zone(self):
        """Test that the model is able to create a zone."""
        old_count = ForwardZone.objects.count()
        clean_and_save(self.zone_sample)
        new_count = ForwardZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_a_zone(self):
        """Test that the model is able to change a zone."""
        clean_and_save(self.zone_sample)
        old_name = self.zone_sample.name
        new_name = 'example.com'
        zone_sample_id = ForwardZone.objects.get(name=old_name).id
        self.zone_sample.name = new_name
        clean_and_save(self.zone_sample)
        updated_name = ForwardZone.objects.get(pk=zone_sample_id).name
        self.assertEqual(new_name, updated_name)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        clean_and_save(self.zone_sample)
        old_count = ForwardZone.objects.count()
        self.zone_sample.delete()
        new_count = ForwardZone.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelReverseZoneTestCase(TestCase):
    """This class defines the test suite for the ReverseZone model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_v4 = ReverseZone(name='0.10.in-addr.arpa',
                                   primary_ns='ns.example.org',
                                   email='hostmaster@example.org')
        self.zone_v6 = ReverseZone(name='8.b.d.0.1.0.0.2.ip6.arpa',
                                   primary_ns='ns.example.org',
                                   email='hostmaster@example.org')

    def test_model_can_create_a_ipv4_zone(self):
        """Test that the model is able to create a ipv4 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v4)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_create_a_ipv6_zone(self):
        """Test that the model is able to create a ipv6 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v6)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_a_zone(self):
        """Test that the model is able to delete a zone."""
        clean_and_save(self.zone_v4)
        clean_and_save(self.zone_v6)
        self.zone_v4.delete()
        self.zone_v6.delete()

    def test_model_rfc2317_valid_names(self):
        """Test that the model can handle RFC 2317 zone names"""
        zone_1 = ReverseZone(name='0/25.0.0.10.in-addr.arpa',
                             primary_ns='ns.example.org',
                             email='hostmaster@example.org')
        zone_2 = ReverseZone(name='0/32.0.1.10.in-addr.arpa',
                             primary_ns='ns.example.org',
                             email='hostmaster@example.org')
        clean_and_save(zone_1)
        clean_and_save(zone_2)

    def test_model_rfc2317_invalid_names(self):
        """Test that the model rejects too large delegations.
           RFC 2317 requires maximum of /25"""
        zone = ReverseZone(name='0/24.0.0.10.in-addr.arpa',
                           primary_ns='ns.example.org',
                           email='hostmaster@example.org')
        with self.assertRaises(ValidationError) as context:
            clean_and_save(zone)
        self.assertEqual(context.exception.messages,
                         ['Maximum CIDR for RFC 2317 is 25'])


class NameServerDeletionTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='ns.example.org',
                                       email='hostmaster@example.org')
        clean_and_save(self.zone_sample)

        self.zone_1010 = ReverseZone(name='10.10.in-addr.arpa',
                                     primary_ns='ns.example.org',
                                     email='hostmaster@example.org')
        clean_and_save(self.zone_1010)

        self.network_sample = Network(range='10.0.0.0/24',
                                      description='some description')
        clean_and_save(self.network_sample)

        self.ns_hostsample = Host(name='ns.example.org',
                                  contact='mail@example.org')
        clean_and_save(self.ns_hostsample)

        self.ns_hostip = Ipaddress(host=self.ns_hostsample,
                                   ipaddress='10.0.0.111')
        clean_and_save(self.ns_hostip)

        self.ns_sample = NameServer(name='ns.example.org',
                                    ttl=300)
        clean_and_save(self.ns_sample)
        self.zone_sample.nameservers.add(self.ns_sample)
        self.zone_sample.save()

    def test_model_cant_delete_ns_host(self):
        """Test that it won't delete nameserver host-object if in use in a zone"""
        with self.assertRaises(PermissionDenied) as context:
            self.ns_hostsample.delete()

    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        with self.assertRaises(PermissionDenied) as context:
            self.ns_hostip.delete()

    def test_model_can_delete_ns_hostip(self):
        """Test that the model is able to delete an IP from a nameserver, if nameserver has multiple IPs."""
        self.ns_hostip2 = Ipaddress(host=self.ns_hostsample,
                                    ipaddress='10.0.0.112')
        clean_and_save(self.ns_hostip2)
        old_count = Ipaddress.objects.count()
        self.ns_hostip2.delete()
        new_count = Ipaddress.objects.count()
        self.assertNotEqual(old_count, new_count)
