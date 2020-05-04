from unittest import skip

from mreg.models import (ForwardZone, Host, NameServer, ReverseZone)
from mreg.utils import create_serialno

from .tests import clean_and_save, MregAPITestCase


class ForwardZonesTestCase(MregAPITestCase):
    """"This class defines the test suite for forward zones API """

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.zone_one = ForwardZone(
            name="example.org",
            primary_ns="ns1.example.org",
            email="hostmaster@example.org")
        self.host_one = Host(name='ns1.example.org', contact="hostmaster@example.org")
        self.host_two = Host(name='ns2.example.org', contact="hostmaster@example.org")
        self.host_three = Host(name='ns3.example.org', contact="hostmaster@example.org")
        self.ns_one = NameServer(name='ns1.example.org', ttl=400)
        self.ns_two = NameServer(name='ns2.example.org', ttl=400)
        self.post_data_one = {'name': 'example.com',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org",
                              'refresh': 400, 'retry': 300, 'expire': 800, 'soa_ttl': 350}
        self.post_data_two = {'name': 'example.net',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org"}
        self.patch_data = {'refresh': '500', 'expire': '1000'}
        clean_and_save(self.host_one)
        clean_and_save(self.host_two)
        clean_and_save(self.ns_one)
        clean_and_save(self.ns_two)
        clean_and_save(self.zone_one)

    def test_zones_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/zones/forward/nonexisting.example.org')

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/zones/forward/%s' % self.zone_one.name)

    def test_zones_list_200_ok(self):
        """Listing all zones should return 200"""
        response = self.assert_get('/zones/forward/')
        results = response.json()['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], self.zone_one.name)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        response = self.assert_get('/zones/forward/%s' % self.zone_one.name)
        self.assert_post_and_409('/zones/forward/', {'name': response.data['name']})

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201 and location"""
        response = self.assert_post('/zones/forward/', self.post_data_one)
        self.assertEqual(response['Location'], '/api/v1/zones/forward/%s' % self.post_data_one['name'])

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        self.assert_post('/zones/forward/', self.post_data_one)
        self.assert_post('/zones/forward/', self.post_data_two)
        response_one = self.assert_get('/zones/forward/%s' % self.post_data_one['name'])
        response_two = self.assert_get('/zones/forward/%s' % self.post_data_two['name'])
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'])
        self.assertEqual(response_one.data['serialno'], create_serialno())

    def test_zones_patch_serialno(self):
        """Make sure that the zone's serialno_updated_at field is updated when
        the serialno is updated"""
        response = self.assert_post('/zones/forward/', self.post_data_one)
        old_data = self.assert_get(response['Location']).data
        self.assert_patch(response['Location'], data={'serialno': 1000000000})
        new_data = self.assert_get(response['Location']).data
        self.assertLess(old_data['serialno_updated_at'], new_data['serialno_updated_at'])

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        response = self.assert_get('/zones/forward/%s' % self.zone_one.name)
        self.assert_patch_and_403('/zones/forward/%s' % self.zone_one.name,
                                  {'name': response.data['name']})

    def test_zones_patch_403_forbidden_primary_ns(self):
        """Trying to patch the primary_ns to be a nameserver that isn't in the nameservers list should return 403"""
        self.assert_post('/zones/forward/', self.post_data_two)
        self.assert_patch_and_403('/zones/forward/%s' % self.post_data_two['name'],
                                  {'primary_ns': self.host_three.name})

    def test_zones_patch_403_forbidden_nameservers(self):
        """Trying to patch the nameservers directly is not allowed."""
        self.assert_post('/zones/forward/', self.post_data_two)
        self.assert_patch_and_403('/zones/forward/%s' % self.post_data_two['name'],
                                  {'nameservers': self.host_three.name})

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        self.assert_patch_and_404("/zones/forward/nonexisting.example.org", self.patch_data)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        self.assert_patch('/zones/forward/%s' % self.zone_one.name, self.patch_data)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        # must delete the hosts in that zone first, to allow deletion of the zone.
        self.host_one.delete()
        self.host_two.delete()
        self.assert_delete('/zones/forward/%s' % self.zone_one.name)

    def test_zones_delete_with_hosts_403_forbidden(self):
        """"Deleting an existing zone with Hosts should return 403"""
        self.assert_post('/hosts/', {'name': 'host.example.org'})
        self.assert_delete_and_403('/zones/forward/%s' % self.zone_one.name)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        self.assert_delete_and_404("/zones/forward/nonexisting.example.org")

    def test_zone_by_hostname_404_not_found(self):
        self.assert_get_and_404('/zones/forward/hostname/invalid.example.wrongtld')

    def test_zone_by_hostname_200_ok(self):
        def _test(hostname, zone, zonetype):
            data = self.assert_get(f'/zones/forward/hostname/{hostname}').json()
            self.assertEqual(data[zonetype]['name'], zone)
        _test('host.example.org', 'example.org', 'zone')
        _test('example.org', 'example.org', 'zone')


class ReverseZonesTestCase(MregAPITestCase):
    """"This class defines the test suite for reverse zones API """

    basepath = '/api/v1/zones/reverse/'

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.zone_one = ReverseZone.objects.create(
            name="0.0.10.in-addr.arpa",
            primary_ns="ns1.example.org",
            email="hostmaster@example.org")
        self.host_one = Host(name='ns1.example.org', contact="hostmaster@example.org")
        self.host_two = Host(name='ns2.example.org', contact="hostmaster@example.org")
        self.host_three = Host(name='ns3.example.org', contact="hostmaster@example.org")
        self.ns_one = NameServer(name='ns1.example.org', ttl=400)
        self.ns_two = NameServer(name='ns2.example.org', ttl=400)
        self.post_data_one = {'name': '0.10.in-addr.arpa',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org",
                              'refresh': 400, 'retry': 300, 'expire': 800,
                              'soa_ttl': 350, 'default_ttl': 1000}
        self.post_data_two = {'name': '0.16.172.in-addr.arpa',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org"}
        self.patch_data = {'refresh': '500', 'expire': '1000'}
        clean_and_save(self.host_one)
        clean_and_save(self.host_two)
        clean_and_save(self.ns_one)
        clean_and_save(self.ns_two)

    def test_zones_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404(self.basepath + '1.10.in-addr.arpa')
        self.assert_get_and_404(self.basepath + '0.8.b.d.0.1.0.0.2.ip6.arpa')

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get(self.basepath + self.zone_one.name)

    def test_zones_list_200_ok(self):
        """Listing all zones should return 200"""
        response = self.assert_get(self.basepath)
        results = response.json()['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], self.zone_one.name)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        response = self.assert_get(self.basepath + self.zone_one.name)
        self.assert_post_and_409(self.basepath, {'name': response.data['name']})

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201 and location"""
        response = self.assert_post(self.basepath, self.post_data_one)
        self.assertEqual(response['Location'], '/api/v1/zones/reverse/%s' % self.post_data_one['name'])

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        self.assert_post(self.basepath, self.post_data_one)
        self.assert_post(self.basepath, self.post_data_two)
        response_one = self.assert_get(self.basepath + self.post_data_one['name'])
        response_two = self.assert_get(self.basepath + self.post_data_two['name'])
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'])
        self.assertEqual(response_one.data['serialno'], create_serialno())

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        response = self.assert_get(self.basepath + self.zone_one.name)
        self.assert_patch_and_403(self.basepath + self.zone_one.name,
                                  {'name': response.data['name']})

    def test_zones_patch_403_forbidden_primary_ns(self):
        """Trying to patch the primary_ns to be a nameserver that isn't in the nameservers list should return 403"""
        self.assert_post(self.basepath, self.post_data_two)
        self.assert_patch_and_403(self.basepath + self.post_data_two['name'],
                                  {'primary_ns': self.host_three.name})

    def test_zones_patch_403_forbidden_nameservers(self):
        """Trying to patch the nameservers directly is not allowed."""
        self.assert_post(self.basepath, self.post_data_two)
        self.assert_patch_and_403(self.basepath + self.post_data_two['name'],
                                  {'nameservers': self.host_three.name})

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        self.assert_patch_and_404(self.basepath + '1.11.in-addr.arpa', self.patch_data)
        self.assert_patch_and_404(self.basepath + '0.8.b.d.0.1.0.0.2.ip6.arpa', self.patch_data)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        self.assert_patch(self.basepath + self.zone_one.name, self.patch_data)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        self.assert_delete(self.basepath + self.zone_one.name)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        self.assert_delete_and_404(self.basepath + '1.11.in-addr.arpa')


class ZonesForwardDelegationTestCase(MregAPITestCase):
    """ This class defines test testsuite for api/zones/forward/<name>/delegations/
    """

    zonepath = '/api/v1/zones/forward/'

    @staticmethod
    def del_path(parentzone):
        return f'/api/v1/zones/forward/{parentzone}/delegations/'

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.data_exampleorg = {'name': 'example.org',
                                'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                                'email': "hostmaster@example.org"}
        self.assert_post(self.zonepath, self.data_exampleorg)

    def test_list_empty_delegation_200_ok(self):
        response = self.assert_get(self.del_path('example.org'))
        self.assertEqual(response.data['results'], [])

    def test_delegate_forward_201_ok(self):
        path = self.del_path('example.org')
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org'],
                'comment': 'delegated to Mr. Anderson'}
        response = self.assert_post(path, data)
        self.assertEqual(response['Location'], f"{path}delegated.example.org")

    def test_delegate_forward_zonefiles_200_ok(self):
        self.test_delegate_forward_201_ok()
        self.assert_get('/zonefiles/example.org')

    def test_delegate_forward_patch_403_only_path_comment(self):
        path = self.del_path('example.org')
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        response = self.assert_post(path, data)
        self.assert_patch(response['Location'], {'comment': 'new comment'})
        self.assert_patch_and_403(response['Location'], {'name': 'notallowed.example.org'})

    def test_delegate_forward_badname_400_bad_request(self):
        path = self.del_path('example.org')
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_no_ns_400_bad_request(self):
        path = self.del_path('example.org')
        bad = {'name': 'delegated.example.org',
               'nameservers': []}
        self.assert_post_and_400(path, bad)
        bad = {'name': 'delegated.example.org'}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_duplicate_ns_400_bad_request(self):
        path = self.del_path('example.org')
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1.example.org', 'ns1.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_invalid_ns_400_bad_request(self):
        path = self.del_path('example.org')
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1', ]}
        self.assert_post_and_400(path, bad)
        bad = {'name': 'delegated.example.org',
               'nameservers': ['2"#¤2342.tld', ]}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_nameservers_list_200_ok(self):
        path = self.del_path('example.org')
        self.test_delegate_forward_201_ok()
        response = self.assert_get(f"{path}delegated.example.org")
        nameservers = [i['name'] for i in response.json()['nameservers']]
        self.assertEqual(len(nameservers), 2)
        for ns in nameservers:
            self.assertTrue(NameServer.objects.filter(name=ns).exists())

    def test_forward_list_delegations_200_ok(self):
        path = self.del_path('example.org')
        self.test_delegate_forward_201_ok()
        response = self.assert_get(path)
        self.assertEqual(response.data['count'], 1)
        results = response.data['results']
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['name'], 'delegated.example.org')

    def test_forward_delete_delegation_204_ok(self):
        self.test_forward_list_delegations_200_ok()
        path = "/api/v1/zones/forward/example.org/delegations/delegated.example.org"
        self.assertEqual(NameServer.objects.count(), 3)
        response = self.assert_delete(path)
        self.assertEqual(response['Location'], path)
        self.assertEqual(NameServer.objects.count(), 2)
        path = "/zones/forward/example.org/delegations/"
        response = self.assert_get(path)
        self.assertEqual(response.data['results'], [])

    def test_zone_by_hostname_404_not_found(self):
        self.test_delegate_forward_201_ok()
        self.assert_get_and_404('/zones/forward/hostname/invalid.example.wrongtld')

    def test_zone_by_hostname_200_ok(self):
        self.test_delegate_forward_201_ok()

        def _test(hostname, zone, zonetype):
            data = self.assert_get(f'/zones/forward/hostname/{hostname}').json()
            self.assertEqual(data[zonetype]['name'], zone)

        _test('host.example.org', 'example.org', 'zone')
        _test('example.org', 'example.org', 'zone')
        _test('host.delegated.example.org', 'delegated.example.org', 'delegation')
        _test('delegated.example.org', 'delegated.example.org', 'delegation')

    def test_delegation_patch_modifies_zone_updated_at(self):
        # add a delegation
        path = self.del_path('example.org')
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        self.assert_post(path, data)
        # get the "before" timestamp
        data = self.assert_get(self.zonepath + 'example.org').json()
        before = data['updated_at']
        # patch the delegation
        self.assert_patch(path + "delegated.example.org", {'comment': 'new comment'})
        # get the "after" timestamp
        data = self.assert_get(self.zonepath + 'example.org').json()
        after = data['updated_at']
        # the timestamp should have been updated
        self.assertLess(before, after)

    def test_hosts_in_delegation_get_zone_none(self):
        """ Hosts in a delegation shall get zone == None, not the parentzone. #362 """
        # add a delegation
        path = self.del_path('example.org')
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        self.assert_post(path, data)
        # add a host in the delegation
        self.assert_post_and_201('/hosts/', {"name": "foo.delegated.example.org",
                      "ipaddress": "10.10.0.1", "contact": "mail@delegated.example.org"})
        # load the host object and verify that its zone is None
        host = Host.objects.get(name="foo.delegated.example.org")
        self.assertTrue(host.zone is None)


class ZonesReverseDelegationTestCase(MregAPITestCase):
    """ This class defines test testsuite for api/zones/reverse/<name>/delegations/
    """

    zonepath = '/api/v1/zones/reverse/'

    @staticmethod
    def del_path(parentzone):
        return f'/api/v1/zones/reverse/{parentzone}/delegations/'

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.data_rev1010 = {'name': '10.10.in-addr.arpa',
                             'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                             'email': "hostmaster@example.org"}
        self.data_revdb8 = {'name': '8.b.d.0.1.0.0.2.ip6.arpa',
                            'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                            'email': "hostmaster@example.org"}

        self.del_101010 = {'name': '10.10.10.in-addr.arpa',
                           'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.del_10101010 = {'name': '10.10.10.10.in-addr.arpa',
                             'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.del_2001db810 = {'name': '0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
                              'nameservers': ['ns1.example.org', 'ns2.example.org']}

        self.assert_post(self.zonepath, self.data_rev1010)
        self.assert_post(self.zonepath, self.data_revdb8)

    def test_get_delegation_200_ok(self):
        def assertempty(data):
            path = self.del_path(data['name'])
            response = self.assert_get(path)
            self.assertEqual(response.data['count'], 0)
            self.assertEqual(response.data['results'], [])
        for data in ('rev1010', 'revdb8'):
            assertempty(getattr(self, f"data_{data}"))

    def test_delegate_ipv4_201_ok(self):
        path = self.del_path('10.10.in-addr.arpa')
        response = self.assert_post(path, self.del_101010)
        self.assertEqual(response['Location'], f"{path}10.10.10.in-addr.arpa")
        response = self.assert_post(path, self.del_10101010)
        self.assertEqual(response['Location'], f"{path}10.10.10.10.in-addr.arpa")
        self.assert_get(response['Location'])

    def test_delegate_ipv4_zonefiles_200_ok(self):
        self.test_delegate_ipv4_201_ok()
        self.assert_get('/zonefiles/10.10.in-addr.arpa')

    def test_delegate_ipv4_badname_400_bad_request(self):
        path = self.del_path('10.10.in-addr.arpa')
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_ipv4_invalid_zone_400_bad_request(self):
        def _assert(data):
            self.assert_post_and_400(path, data)

        path = self.del_path('10.10.in-addr.arpa')
        bad1 = {'name': '300.10.10.in-addr.arpa',
                'nameservers': ['ns1.example.org', 'ns2.example.org']}
        bad2 = {'name': '10.10.10.10.10.in-addr.arpa',
                'nameservers': ['ns1.example.org', 'ns2.example.org']}
        bad3 = {'name': 'foo.10.10.in-addr.arpa',
                'nameservers': ['ns1.example.org', 'ns2.example.org']}
        _assert(bad1)
        _assert(bad2)
        _assert(bad3)

    def test_delegate_ipv4_wrong_inet_400_bad_request(self):
        path = self.del_path('10.10.in-addr.arpa')
        bad = {'name': '0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_duplicate_409_conflict(self):
        path = self.del_path('10.10.in-addr.arpa')
        self.assert_post(path, self.del_101010)
        self.assert_post_and_409(path, self.del_101010)

    def test_delegate_ipv6_201_ok(self):
        path = self.del_path('8.b.d.0.1.0.0.2.ip6.arpa')
        response = self.assert_post(path, self.del_2001db810)
        self.assertEqual(response['Location'], f"{path}{self.del_2001db810['name']}")
        self.assert_get(response['Location'])

    def test_delegate_ipv6_zonefiles_200_ok(self):
        self.test_delegate_ipv6_201_ok()
        self.assert_get('/zonefiles/8.b.d.0.1.0.0.2.ip6.arpa')

    def test_delegate_ipv6_badname_400_bad_request(self):
        path = self.del_path('8.b.d.0.1.0.0.2.ip6.arpa')
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_ipv6_wrong_inet_400_bad_request(self):
        path = self.del_path('8.b.d.0.1.0.0.2.ip6.arpa')
        bad = {'name': '10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)


class ForwardZonesNsTestCase(MregAPITestCase):
    """"This class defines the test suite for api/zones/<name>/nameservers/ """

    zonepath = '/api/v1/zones/forward/'

    @staticmethod
    def ns_path(zone):
        return f'/api/v1/zones/forward/{zone}/nameservers'

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.post_data = {'name': 'example.org', 'primary_ns': ['ns2.example.org'],
                          'email': "hostmaster@example.org"}
        self.ns_one = Host.objects.create(name='ns1.example.org')
        self.ns_two = Host.objects.create(name='ns2.example.org')

    def test_zones_ns_get_200_ok(self):
        """"Getting the list of nameservers of a existing zone should return 200"""
        self.assertEqual(NameServer.objects.count(), 0)
        self.assert_post(self.zonepath, self.post_data)
        self.assertEqual(NameServer.objects.count(), 1)
        self.assert_get(self.ns_path(self.post_data['name']))

    def test_zones_ns_create_and_get_reversezone_200_ok(self):
        """Create a reverse zone and make sure we can get its nameservers"""
        data = {'name': '10.in-addr.arpa', 'primary_ns': ['ns2.example.org'],
                'email': "hostmaster@example.org"}
        self.assertEqual(NameServer.objects.count(), 0)
        self.assert_post(self.zonepath, data)
        self.assertEqual(NameServer.objects.count(), 1)
        self.assert_get(self.ns_path(data['name']))

    def test_zones_ns_get_404_not_found(self):
        """"Getting the list of nameservers of a non-existing zone should return 404"""
        self.assert_get_and_404(self.ns_path('example.com'))

    def test_zones_ns_patch_204_no_content(self):
        """"Patching the list of nameservers with an existing nameserver should return 204"""
        self.assert_post(self.zonepath, self.post_data)
        self.assert_patch(self.ns_path(self.post_data['name']),
                          {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})

    def test_zones_ns_patch_400_bad_request(self):
        """"Patching the list of nameservers with a bad request body should return 400"""
        self.assert_post(self.zonepath, self.post_data)
        self.assert_patch_and_400(self.ns_path(self.post_data['name']),
                                  {'garbage': self.ns_one.name})

    @skip("Not testable, yet")
    def test_zones_ns_patch_404_not_found(self):
        """"Patching the list of nameservers with a non-existing nameserver should return 404"""
        self.assert_post(self.zonepath, self.post_data)
        self.assert_patch_and_404(self.ns_path(self.post_data['name']),
                                  {'primary_ns': ['nonexisting-ns.example.org']})
        # XXX: This is now valid, as the NS might point to a server in a zone which we
        # don't control. Might be possible to check if the attempted NS is in a
        # zone we control and then be stricter.

    def test_zones_ns_delete_204_no_content_zone(self):
        """Deleting a nameserver from an existing zone should return 204"""
        self.assertFalse(NameServer.objects.exists())
        self.assert_post(self.zonepath, self.post_data)
        self.assert_patch(self.ns_path(self.post_data['name']),
                          {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})
        self.assertEqual(NameServer.objects.count(), 2)
        self.assert_get(self.ns_path(self.post_data['name']))
        self.assert_patch(self.ns_path(self.post_data['name']),
                          {'primary_ns': self.ns_two.name})
        self.assertEqual(NameServer.objects.count(), 1)
        response = self.assert_get(self.ns_path(self.post_data['name']))
        self.assertEqual(response.data, self.post_data['primary_ns'])
        # Before we can delete the zone, we must delete any hosts in the zone.
        # Nameservers must be removed from the zone before they can be deleted.
        self.assert_patch(self.ns_path(self.post_data['name']),
                          {'primary_ns': 'another.server.somewhere.com'})
        self.ns_one.delete()
        self.ns_two.delete()
        self.assert_delete(self.zonepath + self.post_data['name'])
        self.assertFalse(NameServer.objects.exists())


class ZoneRFC2317(MregAPITestCase):
    """This class tests RFC 2317 delegations."""

    zonepath = '/api/v1/zones/reverse/'

    def setUp(self):
        super().setUp()
        self.data = {'name': '128/25.0.0.10.in-addr.arpa',
                     'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                     'email': "hostmaster@example.org"}

    def test_create_and_get_rfc_2317_zone(self):
        # Create and get zone for 10.0.0.128/25
        response = self.assert_post(self.zonepath, self.data)
        self.assertEqual(response["location"], self.zonepath + '128/25.0.0.10.in-addr.arpa')
        self.assert_get(response["location"])

    def test_add_rfc2317_delegation_for_existing_zone(self):
        zone = {'name': '0.10.in-addr.arpa',
                'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                'email': "hostmaster@example.org"}
        self.assert_post(self.zonepath, zone)
        delegation = {'name': '128/25.0.0.10.in-addr.arpa',
                      'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post(self.zonepath + '0.10.in-addr.arpa/delegations/', delegation)

    def test_delete_rfc2317_zone(self):
        self.assert_post(self.zonepath, self.data)
        self.assert_delete(self.zonepath + '128/25.0.0.10.in-addr.arpa')
