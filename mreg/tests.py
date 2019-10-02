from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from rest_framework.exceptions import PermissionDenied

from .models import (Cname, ForwardZone, Host, HostGroup, Ipaddress,
                     Loc, ModelChangeLog, NameServer, Naptr,
                     NetGroupRegexPermission, Network, PtrOverride,
                     ReverseZone, Srv, Sshfp, Txt)


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
                             comment='some comment')
        clean_and_save(self.host_one)

        self.log_data = {'id': self.host_one.id,
                         'name': self.host_one.name,
                         'contact': self.host_one.contact,
                         'ttl': self.host_one.ttl,
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
        self.host_target = Host.objects.create(name='target.example.org')
        self.srv_sample = Srv(name='_abc._udp.example.org',
                              priority=3,
                              weight=1,
                              port=5433,
                              ttl=300,
                              host=self.host_target)

    def test_model_can_create_srv(self):
        """Test that the model is able to create a srv entry."""
        old_count = Srv.objects.count()
        clean_and_save(self.srv_sample)
        new_count = Srv.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.srv_sample)

    def test_can_create_various_service_names(self):
        def _create(name):
            srv = Srv(name=name,
                      priority=3,
                      weight=1,
                      port=5433,
                      host=self.host_target)
            clean_and_save(srv)
        # Two underscores in _service
        _create('_test_underscore._tls.example.org')
        # Hypen
        _create('_test_underscore-hypen._tls.example.org')
        # short serivce
        _create('_gc._tcp.example.org')

    def test_reject_various_service_names(self):
        def _create(name):
            srv = Srv(name=name,
                      priority=3,
                      weight=1,
                      port=5433,
                      host=self.host_target)
            with self.assertRaises(ValidationError):
                clean_and_save(srv)
        # Two underscores after each other
        _create('_test__underscore._tls.example.org')
        # No leading underscore
        _create('opsmissingunderscore._tls.example.org')
        # No traling underscore
        _create('_underscoreinbothends_._tls.example.org')
        # Trailing hypen
        _create('_hypten-._tls.example.org')

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
        host = Host.objects.create(name='host.example.org')
        self.naptr_sample = Naptr(host=host,
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
        str(self.naptr_sample)

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
        host = Host.objects.create(name='host.example.org')
        self.cname_sample = Cname(host=host,
                                  name='some-cname.example.org',
                                  ttl=300)

    def test_model_can_create_cname(self):
        """Test that the model is able to create a cname entry."""
        old_count = Cname.objects.count()
        clean_and_save(self.cname_sample)
        new_count = Cname.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.cname_sample)

    def test_model_can_change_cname(self):
        """Test that the model is able to change a cname entry."""
        clean_and_save(self.cname_sample)
        new_cname = 'some-new-cname.example.org'
        self.cname_sample.name = new_cname
        clean_and_save(self.cname_sample)
        updated_cname = Cname.objects.filter(host__name='host.example.org')[0].name
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
        self.host_one = Host(name='host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             comment='some comment')

    def assert_validation_error(self, obj):
        with self.assertRaises(ValidationError):
            obj.full_clean()

    def test_model_can_create_a_host(self):
        """Test that the model is able to create a host."""
        old_count = Host.objects.count()
        clean_and_save(self.host_one)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)
        str(self.host_one)

    def test_model_can_create_without_contact(self):
        old_count = Host.objects.count()
        host = Host(name='host2.example.org')
        clean_and_save(host)
        new_count = Host.objects.count()
        self.assertLess(old_count, new_count)

    def test_can_create_wildcard_host(self):
        Host(name='*.example.org').full_clean()
        Host(name='*.sub.example.org').full_clean()

    def test_model_case_insesitive(self):
        """Hosts names must be case insensitive"""
        clean_and_save(self.host_one)
        self.assertEqual(self.host_one, Host.objects.get(name=self.host_one.name.upper()))
        upper = Host(name=self.host_one.name.upper(), contact=self.host_one.contact)
        with self.assertRaises(ValidationError) as context:
            clean_and_save(upper)
        self.assertEqual(context.exception.messages,
                         ['Host with this Name already exists.'])
        hostname = 'UPPERCASE.EXAMPLE.ORG'
        host = Host.objects.create(name=hostname, contact='mail@example.org')
        # Must do a refresh_from_db() as host.name is otherwise the unmodfied
        # uppercase hostname.
        host.refresh_from_db()
        self.assertEqual(host.name, hostname.lower())

    def test_reject_bad_host_names(self):
        def _assert(hostname):
            host = Host(name=hostname)
            self.assert_validation_error(host)

        _assert('host..example.org')
        _assert('host.example.org.')
        _assert('host-.example.org')
        _assert('looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.example.org')
        _assert('host*.example.org')

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


class LocTestCase(TestCase):


    def test_validate_loc(self):
        """
        Test that the model can validate and store all examples
        from RFC1876, section 4 "Example data".
        """
        host = Host.objects.create(name='host.example.org')
        for loc in ('42 21 54 N 71 06 18 W -24m 30m',
                    '42 21 43.952 N 71 5 6.344 W -24m 1m 200m',
                    '52 14 05 N 00 08 50 E 10m',
                    '32 7 19 S 116 2 25 E 10m',
                    '42 21 28.764 N 71 00 51.617 W -44m 2000m'):
            l = Loc(host=host, loc=loc)
            clean_and_save(l)
            l.delete()


class ModelNameServerTestCase(TestCase):
    """This class defines the test suite for the NameServer model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.zone_sample = ForwardZone(name='example.org',
                                       primary_ns='ns.example.org',
                                       email='hostmaster@example.org')

        clean_and_save(self.zone_sample)

        self.ns_sample = NameServer(name='ns.example.org',
                                    ttl=300)

    def test_model_can_create_ns(self):
        """Test that the model is able to create an Ns."""
        old_count = NameServer.objects.count()
        clean_and_save(self.ns_sample)
        new_count = NameServer.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.ns_sample)

    def test_model_can_change_ns(self):
        """Test that the model is able to change an Ns."""
        clean_and_save(self.ns_sample)
        old_name = self.ns_sample.name
        new_name = 'new-ns.example.com'
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
        self.network_sample = Network(network='10.0.0.0/20',
                                      description='some description',
                                      vlan=123,
                                      dns_delegated=False,
                                      category='so',
                                      location='Test location',
                                      frozen=False)
        self.network_ipv6_sample = Network(network='2001:db8::/32',
                                           description='some IPv6 description',
                                           vlan=123,
                                           dns_delegated=False,
                                           category='so',
                                           location='Test location',
                                           frozen=False)

    def test_model_can_create_network(self):
        """Test that the model is able to create a Network."""
        old_count = Network.objects.count()
        clean_and_save(self.network_sample)
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.network_sample)

    def test_model_can_create_ipv6_network(self):
        """Test that the model is able to create an IPv6 Network."""
        old_count = Network.objects.count()
        clean_and_save(self.network_ipv6_sample)
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_change_network(self):
        """Test that the model is able to change a Network."""
        clean_and_save(self.network_sample)
        new_vlan = 321
        network_sample_id = self.network_sample.id
        self.network_sample.vlan = new_vlan
        clean_and_save(self.network_sample)
        updated_vlan = Network.objects.get(pk=network_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_change_ipv6_network(self):
        """Test that the model is able to change an IPv6 Network."""
        clean_and_save(self.network_ipv6_sample)
        new_vlan = 321
        network_ipv6_sample_id = self.network_ipv6_sample.id
        self.network_ipv6_sample.vlan = new_vlan
        clean_and_save(self.network_ipv6_sample)
        updated_vlan = Network.objects.get(pk=network_ipv6_sample_id).vlan
        self.assertEqual(new_vlan, updated_vlan)

    def test_model_can_delete_network(self):
        """Test that the model is able to delete a Network."""
        clean_and_save(self.network_sample)
        old_count = Network.objects.count()
        self.network_sample.delete()
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_ipv6_network(self):
        """Test that the model is able to delete a Network."""
        clean_and_save(self.network_ipv6_sample)
        old_count = Network.objects.count()
        self.network_ipv6_sample.delete()
        new_count = Network.objects.count()
        self.assertNotEqual(old_count, new_count)


class ModelIpaddressTestCase(TestCase):
    """This class defines the test suite for the Ipaddress model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host and sample network to test properly
        self.host = Host.objects.create(name='host.example.org')

        self.ipaddress_sample = Ipaddress(host=self.host,
                                          ipaddress='192.168.202.123',
                                          macaddress='a4:34:d9:0e:88:b9')

        self.ipv6address_sample = Ipaddress(host=self.host,
                                            ipaddress='2001:db8::beef',
                                            macaddress='a4:34:d9:0e:88:b9')

    def test_model_can_create_ipaddress(self):
        """Test that the model is able to create an IP Address."""
        old_count = Ipaddress.objects.count()
        clean_and_save(self.ipaddress_sample)
        new_count = Ipaddress.objects.count()
        self.assertLess(old_count, new_count)
        str(self.ipaddress_sample)

    def test_model_can_create_ipv6address(self):
        """Test that the model is able to create an IPv6 Address."""
        old_count = Ipaddress.objects.count()
        clean_and_save(self.ipv6address_sample)
        new_count = Ipaddress.objects.count()
        self.assertLess(old_count, new_count)

    def test_model_can_change_ipaddress(self):
        """Test that the model is able to change an IP Address."""
        clean_and_save(self.ipaddress_sample)
        new_ipaddress = '192.168.202.124'
        self.ipaddress_sample.ipaddress = new_ipaddress
        clean_and_save(self.ipaddress_sample)
        updated_ipaddress = Ipaddress.objects.get(host=self.host).ipaddress
        self.assertEqual(new_ipaddress, updated_ipaddress)

    def test_model_can_change_ipv6address(self):
        """Test that the model is able to change an IPv6 Address."""
        clean_and_save(self.ipv6address_sample)
        new_ipv6address = '2001:db8::feed'
        self.ipv6address_sample.ipaddress = new_ipv6address
        clean_and_save(self.ipv6address_sample)
        updated_ipv6address = Ipaddress.objects.get(host=self.host).ipaddress
        self.assertEqual(new_ipv6address, updated_ipv6address)

    def test_model_can_delete_ipaddress(self):
        """Test that the model is able to delete an IP Address."""
        clean_and_save(self.ipaddress_sample)
        old_count = Ipaddress.objects.count()
        self.ipaddress_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_delete_ipv6address(self):
        """Test that the model is able to delete an IPv6 Address."""
        clean_and_save(self.ipv6address_sample)
        old_count = Ipaddress.objects.count()
        self.ipv6address_sample.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)


class ModelPtrOverrideTestCase(TestCase):
    """This class defines the test suite for the PtrOverride model."""

    def setUp(self):
        """Define the test client and other test variables."""
        # Needs sample host to test
        self.host_one = Host.objects.create(name='host1.example.org')
        self.host_two = Host.objects.create(name='host2.example.org')

        self.ptr_sample = PtrOverride(host=self.host_one, ipaddress='10.0.0.2')
        self.ptr_ipv6_sample = PtrOverride(host=self.host_one,
                                           ipaddress='2001:db8::beef')

    def test_model_can_create_ptr(self):
        """Test that the model is able to create a PTR Override."""
        old_count = PtrOverride.objects.count()
        clean_and_save(self.ptr_sample)
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.ptr_sample)

    def test_model_can_create_ipv6_ptr(self):
        """Test that the model is able to create an IPv6 PTR Override."""
        old_count = PtrOverride.objects.count()
        clean_and_save(self.ptr_ipv6_sample)
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_reject_invalid_create_ptr(self):
        """Test that the model rejects invalid ipaddress."""
        ptr = PtrOverride(host=self.host_one, ipaddress='10.0.0.0.400')
        with self.assertRaises(ValidationError):
            ptr.full_clean()
        ptr = PtrOverride(host=self.host_one, ipaddress='10.0.0.400')
        with self.assertRaises(ValidationError):
            ptr.full_clean()

    def test_model_reject_invalid_ipv6_create_ptr(self):
        """Test that the model rejects invalid ipaddress."""
        ptr = PtrOverride(host=self.host_one, ipaddress='2001:db8::::1')
        with self.assertRaises(ValidationError):
            ptr.full_clean()
        ptr = PtrOverride(host=self.host_one, ipaddress='2001:db8::abcx')
        with self.assertRaises(ValidationError):
            ptr.full_clean()

    def test_model_can_change_ptr(self):
        """Test that the model is able to change a PTR Override."""
        clean_and_save(self.ptr_sample)
        new_ptr = '10.0.0.3'
        self.ptr_sample.ipaddress = new_ptr
        clean_and_save(self.ptr_sample)
        self.ptr_sample.refresh_from_db()
        self.assertEqual(new_ptr, self.ptr_sample.ipaddress)

    def test_model_can_change_ipv6_ptr(self):
        """Test that the model is able to change an IPv6 PTR Override."""
        clean_and_save(self.ptr_ipv6_sample)
        new_ipv6_ptr = '2011:db8::feed'
        self.ptr_ipv6_sample.ipaddress = new_ipv6_ptr
        clean_and_save(self.ptr_ipv6_sample)
        self.ptr_ipv6_sample.refresh_from_db()
        self.assertEqual(new_ipv6_ptr, self.ptr_ipv6_sample.ipaddress)

    def test_model_can_delete_ptr(self):
        """Test that the model is able to delete a PTR Override."""
        clean_and_save(self.ptr_sample)
        old_count = PtrOverride.objects.count()
        self.ptr_sample.delete()
        new_count = PtrOverride.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_delete_ipv6_ptr(self):
        """Test that the model is able to delete an IPv6 PTR Override."""
        clean_and_save(self.ptr_ipv6_sample)
        old_count = PtrOverride.objects.count()
        self.ptr_ipv6_sample.delete()
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
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '10.0.0.1')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(PtrOverride.objects.count(), 1)

    def test_model_updated_by_added_ipv6(self):
        """Test to check that an PtrOverride is added when two hosts share the
           same ipv6.  Also makes sure that the PtrOverride points to the first
           host which held the ipv6."""

        initial_count = PtrOverride.objects.count()
        ipv6_one = Ipaddress(host=self.host_one, ipaddress='2001:db8::4')
        clean_and_save(ipv6_one)
        one_count = PtrOverride.objects.count()
        ipv6_two = Ipaddress(host=self.host_two, ipaddress='2001:db8::4')
        clean_and_save(ipv6_two)
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '2001:db8::4')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(PtrOverride.objects.count(), 1)

    def test_model_add_and_remove_ip(self):
        """Test to check that an PtrOverride is added when two hosts share the same ip.
           Also makes sure that the PtrOverride points to the first host which held the ip.
           Also makes sure that the PtrOverride is deleted when the host is deleted."""
        initial_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_one, ipaddress='10.0.0.1')
        one_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_two, ipaddress='10.0.0.1')
        two_count = PtrOverride.objects.count()
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '10.0.0.1')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(two_count, 1)
        self.host_two.delete()
        self.assertEqual(PtrOverride.objects.count(), 1)
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)

    def test_model_add_and_remove_ipv6(self):
        """Test to check that an PtrOverride is added when two hosts share the same ipv6.
           Also makes sure that the PtrOverride points to the first host which held the ipv6.
           Also makes sure that the PtrOverride is deleted when the host is deleted."""
        initial_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_one, ipaddress='2001:db8::4')
        one_count = PtrOverride.objects.count()
        Ipaddress.objects.create(host=self.host_two, ipaddress='2001:db8::4')
        two_count = PtrOverride.objects.count()
        ptr = PtrOverride.objects.first()
        self.assertEqual(ptr.host, self.host_one)
        self.assertEqual(ptr.ipaddress, '2001:db8::4')
        self.assertEqual(initial_count, 0)
        self.assertEqual(initial_count, one_count)
        self.assertEqual(two_count, 1)
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)

    def test_model_two_ips_no_ptroverrides(self):
        """When three or more hosts all have the same ipaddress and the first host,
        e.g. the one with the PtrOverride, is deleted, a new PtrOverride is
        not created automatically.
        """
        def _add_ip(host, ipaddress):
            Ipaddress.objects.create(host=host, ipaddress=ipaddress)
        _add_ip(self.host_one, '10.0.0.1')
        _add_ip(self.host_two, '10.0.0.1')
        host_three = Host.objects.create(name='host3.example.org')
        _add_ip(host_three, '10.0.0.1')
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)
        self.assertEqual(Ipaddress.objects.filter(ipaddress='10.0.0.1').count(), 2)

    def test_model_two_ipv6s_no_ptroverrides(self):
        """When three or more hosts all have the same IPv6 address and the first host,
        e.g. the one with the PtrOverride, is deleted, a new PtrOverride is
        not created automatically.
        """
        def _add_ip(host, ipaddress):
            Ipaddress.objects.create(host=host, ipaddress=ipaddress)
        _add_ip(self.host_one, '2001:db8::4')
        _add_ip(self.host_two, '2001:db8::4')
        host_three = Host.objects.create(name='host3.example.org')
        _add_ip(host_three, '2001:db8::4')
        self.host_one.delete()
        self.assertEqual(PtrOverride.objects.count(), 0)
        self.assertEqual(Ipaddress.objects.filter(ipaddress='2001:db8::4').count(), 2)

    def test_ptr_not_removed_on_ipaddress_object_change(self):
        """Make sure the PtrOverride is not removed when an Ipaddress is changed, e.g.
           updated mac address."""
        ip1 = Ipaddress.objects.create(host=self.host_one, ipaddress='10.0.0.1')
        Ipaddress.objects.create(host=self.host_two, ipaddress='10.0.0.1')
        ip1.macaddress = 'aa:bb:cc:dd:ee:ff'
        ip1.save()
        self.assertEqual(PtrOverride.objects.count(), 1)


class ModelTxtTestCase(TestCase):
    """This class defines the test suite for the Txt model."""

    def setUp(self):
        """Define the test client and other test variables."""
        host = Host.objects.create(name='host.example.org')
        self.txt_sample = Txt(host=host, txt='some-text')

    def test_model_can_create_txt(self):
        """Test that the model is able to create a txt entry."""
        old_count = Txt.objects.count()
        clean_and_save(self.txt_sample)
        new_count = Txt.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.txt_sample)

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
        host = Host.objects.create(name='host.example.org')
        self.sshfp_sample = Sshfp(host=host, algorithm=1, hash_type=1,
                                  fingerprint='01234567890abcdef')

    def test_model_can_create_sshfp(self):
        """Test that the model is able to create an sshfp entry."""
        old_count = Sshfp.objects.count()
        clean_and_save(self.sshfp_sample)
        new_count = Sshfp.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.sshfp_sample)

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
                                       soa_ttl=300,
                                       default_ttl=1000)

    def test_model_can_create_a_zone(self):
        """Test that the model is able to create a zone."""
        old_count = ForwardZone.objects.count()
        clean_and_save(self.zone_sample)
        new_count = ForwardZone.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.zone_sample)

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

    def test_update_serialno(self):
        """Force update by setting serialno_updated_at in the past"""
        zone = ForwardZone(name='example.org', primary_ns='ns.example.org',
                           email='hostmaster@example.org')
        zone.save()
        zone.serialno_updated_at = timezone.now() - timedelta(minutes=10)
        old_serial = zone.serialno
        zone.save()
        zone.update_serialno()
        self.assertLess(old_serial, zone.serialno)
        # Will not update serialno just becase updated = True, requires a timedelta
        old_serial = zone.serialno
        self.updated = True
        zone.update_serialno()
        zone.save()
        zone.refresh_from_db()
        self.assertEqual(old_serial, zone.serialno)
        self.assertFalse(zone.updated)
        # Make sure the serialno does not wrap, but instead keeps stays the same
        zone.serialno += 98
        self.assertEqual(zone.serialno % 100, 99)
        self.updated = True
        zone.serialno_updated_at = timezone.now() - timedelta(minutes=10)
        old_serial = zone.serialno
        zone.update_serialno()
        self.assertEqual(old_serial, zone.serialno)


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

    def assert_validation_error(self, obj):
        with self.assertRaises(ValidationError):
            obj.full_clean()

    def test_model_can_create_a_ipv4_zone(self):
        """Test that the model is able to create a ipv4 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v4)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)
        str(self.zone_v4)

    def test_model_can_create_a_ipv6_zone(self):
        """Test that the model is able to create a ipv6 zone."""
        old_count = ReverseZone.objects.count()
        clean_and_save(self.zone_v6)
        new_count = ReverseZone.objects.count()
        self.assertNotEqual(old_count, new_count)

    def test_reject_invalid_names(self):

        def _assert(name):
            zone = ReverseZone(name=name, primary_ns='ns.example.org',
                               email='hostmaster@example.org')
            self.assert_validation_error(zone)

        _assert('x.8.d.0.1.0.0.2.ip6.arpa')
        _assert('0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.0.1.0.0.2.ip6.arpa')

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

        self.network_sample = Network.objects.create(network='10.0.0.0/24',
                                                     description='some description')

        self.ns_hostsample = Host.objects.create(name='ns.example.org')

        self.ns_hostip = Ipaddress.objects.create(host=self.ns_hostsample,
                                                  ipaddress='10.0.0.111')

        self.ns_sample = NameServer.objects.create(name='ns.example.org')
        self.zone_sample.nameservers.add(self.ns_sample)

    def test_model_cant_delete_ns_host(self):
        """Test that it won't delete nameserver host-object if in use in a zone"""
        with self.assertRaises(PermissionDenied):
            self.ns_hostsample.delete()

    def test_model_cant_delete_ns_hostip(self):
        """Test that it won't delete nameserver with only 1 IP if in use in a zone"""
        with self.assertRaises(PermissionDenied):
            self.ns_hostip.delete()

    def test_model_can_delete_ns_hostip(self):
        """Test that the model is able to delete an IP from a nameserver, if
        nameserver has multiple IPs."""
        ip = Ipaddress.objects.create(host=self.ns_hostsample, ipaddress='10.0.0.112')
        old_count = Ipaddress.objects.count()
        ip.delete()
        new_count = Ipaddress.objects.count()
        self.assertGreater(old_count, new_count)


class ModelHostGroupTestCase(TestCase):
    """This class defines the test suite for the HostGroup model."""

    def setUp(self):
        """Define the test client and other test variables."""
        self.group_one = HostGroup(name='group1')
        self.group_two = HostGroup(name='group2')
        self.group_three = HostGroup(name='group3')
        self.group_four = HostGroup(name='group4')
        self.host_one = Host.objects.create(name='host1.example.org')
        clean_and_save(self.group_one)
        clean_and_save(self.group_two)
        clean_and_save(self.group_three)
        clean_and_save(self.group_four)

    def test_model_can_create_hostgroup(self):
        old_count = HostGroup.objects.count()
        group = HostGroup(name='testing')
        clean_and_save(group)
        new_count = HostGroup.objects.count()
        self.assertLess(old_count, new_count)
        str(group)

    def test_model_can_delete_hostgroup(self):
        old_count = HostGroup.objects.count()
        self.group_one.delete()
        new_count = HostGroup.objects.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_add_host_to_hostgroup(self):
        old_count = self.group_one.hosts.count()
        self.group_one.hosts.add(self.host_one)
        new_count = self.group_one.hosts.count()
        self.assertLess(old_count, new_count)

    def test_model_can_remove_host_from_hostgroup(self):
        self.group_one.hosts.add(self.host_one)
        old_count = self.group_one.hosts.count()
        self.group_one.hosts.remove(self.host_one)
        new_count = self.group_one.hosts.count()
        self.assertGreater(old_count, new_count)

    def test_model_can_add_group_to_group(self):
        old_count = self.group_one.groups.count()
        self.group_one.groups.add(self.group_two)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_remove_group_from_group(self):
        self.group_one.groups.add(self.group_two)
        old_count = self.group_one.groups.count()
        self.group_two.parent.remove(self.group_one)
        new_count = self.group_one.groups.count()
        self.assertNotEqual(old_count, new_count)

    def test_model_can_not_be_own_child(self):
        with self.assertRaises(PermissionDenied):
            self.group_one.groups.add(self.group_one)

    def test_model_can_not_be_own_grandchild(self):
        self.group_one.groups.add(self.group_two)
        with self.assertRaises(PermissionDenied):
            self.group_two.groups.add(self.group_one)

    def test_model_group_parent_can_never_be_child_of_child_groupmember(self):
        self.group_one.groups.add(self.group_two)
        self.group_two.groups.add(self.group_three)
        self.group_three.groups.add(self.group_four)
        with self.assertRaises(PermissionDenied):
            self.group_four.groups.add(self.group_one)

    def test_model_altered_updated_at_group_changes(self):
        group1_updated_at = self.group_one.updated_at
        group2_updated_at = self.group_two.updated_at
        self.group_one.groups.add(self.group_two)
        self.group_one.refresh_from_db()
        self.group_two.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)
        self.assertEqual(group2_updated_at, self.group_two.updated_at)

    def test_model_altered_updated_at_on_hosts_add(self):
        group1_updated_at = self.group_one.updated_at
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)

    def test_model_altered_updated_at_on_host_rename(self):
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        group1_updated_at = self.group_one.updated_at
        self.host_one.name = 'newname'
        self.host_one.save()
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)

    def test_model_altered_updated_at_on_host_delete(self):
        self.group_one.hosts.add(self.host_one)
        self.group_one.refresh_from_db()
        group1_updated_at = self.group_one.updated_at
        self.host_one.delete()
        self.group_one.refresh_from_db()
        self.assertLess(group1_updated_at, self.group_one.updated_at)


class NetGroupRegexPermissionTestCase(TestCase):

    def create_sample_permission(self):
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.0/25',
                                       regex=r'.*\.example\.org$')
        clean_and_save(perm)
        return perm

    def test_model_create(self):
        old_count = NetGroupRegexPermission.objects.count()
        perm = self.create_sample_permission()
        self.assertGreater(NetGroupRegexPermission.objects.count(), old_count)
        str(perm)

    def test_model_find_perm(self):
        perm = self.create_sample_permission()
        find_perm = NetGroupRegexPermission.find_perm
        qs = find_perm(('randomgroup', 'testgroup',), 'www.example.org', '10.0.0.1')
        self.assertEqual(qs.first(), perm)
        qs = find_perm('testgroup', 'www.example.org', ('2.2.2.2', '10.0.0.1',))
        self.assertEqual(qs.first(), perm)

    def test_model_invalid_find_perm(self):
        def _assert(groups, hostname, ips):
            with self.assertRaises(ValueError):
                find_perm(groups, hostname, ips)
        find_perm = NetGroupRegexPermission.find_perm
        # hostname is not a string
        _assert('testgroup', ('www.example.org', ), '10.0.0.1')
        # group is not string/tuple/list
        _assert({'name': 'testgroup'}, 'www.example.org', '10.0.0.1')
        _assert('testgroup', 'www.example.org', None)

    def test_model_reject_invalid(self):
        # Reject invalid range. Hostbit set.
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.1/25',
                                       regex=r'.*\.example\.org$')
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(str(cm.exception),
                         "{'range': ['10.0.0.1/25 has host bits set']}")
        # Reject invalid regex.
        perm = NetGroupRegexPermission(group='testgroup',
                                       range='10.0.0.0/25',
                                       regex=r'.*\.ex(ample\.org$')
        with self.assertRaises(ValidationError) as cm:
            clean_and_save(perm)
        self.assertEqual(str(cm.exception),
                         "{'regex': ['missing ), unterminated subpattern at position 6']}")

    def test_model_clean_permissions(self):
        # Make sure that permissions are removed if a Network with equal
        # or larger network is removed. Removed by code in signals.py.
        self.network_v4 = Network(network='10.0.0.0/24')
        self.network_v6 = Network(network='2001:db8::/64')
        clean_and_save(self.network_v4)
        clean_and_save(self.network_v6)
        v4perm = NetGroupRegexPermission(group='testgroup',
                                         range='10.0.0.0/25',
                                         regex=r'.*\.example\.org$')
        clean_and_save(v4perm)
        v6perm = NetGroupRegexPermission(group='testgroup',
                                         range=self.network_v6.network,
                                         regex=r'.*\.example\.org$')
        clean_and_save(v6perm)
        self.assertEqual(NetGroupRegexPermission.objects.count(), 2)
        self.network_v4.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 1)
        self.assertEqual(NetGroupRegexPermission.objects.first(), v6perm)
        self.network_v6.delete()
        self.assertEqual(NetGroupRegexPermission.objects.count(), 0)
