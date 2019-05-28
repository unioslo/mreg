from datetime import timedelta
from operator import itemgetter

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone

from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from mreg.models import (ForwardZone, Host, Ipaddress, ModelChangeLog,
                         NameServer, Network, PtrOverride, ReverseZone, Txt)
from mreg.utils import create_serialno


class MissingSettings(Exception):
    pass


class MregAPITestCase(APITestCase):

    def setUp(self):
        self.client = self.get_token_client()

    def get_token_client(self, superuser=True, adminuser=False):
        self.user, created = get_user_model().objects.get_or_create(username='nobody')
        token, created = Token.objects.get_or_create(user=self.user)
        if superuser:
            self.add_user_to_groups('SUPERUSER_GROUP')
        if adminuser:
            self.add_user_to_groups('ADMINUSER_GROUP')
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        return client

    def add_user_to_groups(self, group_setting_name):
        groups = getattr(settings, group_setting_name, None)
        if groups is None:
            raise MissingSettings(f"{group_setting_name} not set")
        if not isinstance(groups, (list, tuple)):
            groups = (groups, )
        for groupname in groups:
            group, created = Group.objects.get_or_create(name=groupname)
            group.user_set.add(self.user)
            group.save()


def clean_and_save(entity):
    entity.full_clean()
    entity.save()


def create_forward_zone(name='example.org', primary_ns='ns.example.org',
                        email='hostmaster@example.org'):
    return ForwardZone.objects.create(name=name, primary_ns=primary_ns, email=email)


def create_reverse_zone(name='10.10.in-addr.arpa', primary_ns='ns.example.org',
                        email='hostmaster@example.org'):
    return ReverseZone.objects.create(name=name, primary_ns=primary_ns, email=email)


class APITokenAutheticationTestCase(MregAPITestCase):
    """Test various token authentication operations."""

    def test_logout(self):
        ret = self.client.get("/zones/")
        self.assertEqual(ret.status_code, 200)
        ret = self.client.post("/api/token-logout/")
        self.assertEqual(ret.status_code, 200)
        ret = self.client.get("/zones/")
        self.assertEqual(ret.status_code, 401)

    def test_logout_without_authentication(self):
        self.client = APIClient()
        ret = self.client.post("/api/token-logout/")
        self.assertEqual(ret.status_code, 401)

    def test_force_expire(self):
        ret = self.client.get("/zones/")
        self.assertEqual(ret.status_code, 200)
        user = get_user_model().objects.get(username='nobody')
        token = Token.objects.get(user=user)
        EXPIRE_HOURS = getattr(settings, 'REST_FRAMEWORK_TOKEN_EXPIRE_HOURS', 8)
        token.created = timezone.now() - timedelta(hours=EXPIRE_HOURS)
        token.save()
        ret = self.client.get("/zones/")
        self.assertEqual(ret.status_code, 401)


class APIAutoupdateZonesTestCase(MregAPITestCase):
    """This class tests the autoupdate of zones' updated_at whenever
       various models are added/deleted/renamed/changed etc."""

    def setUp(self):
        """Add the a couple of zones and hosts for used in testing."""
        super().setUp()
        self.host1 = {"name": "host1.example.org",
                      "ipaddress": "10.10.0.1",
                      "contact": "mail@example.org"}
        self.delegation = {"name": "delegated.example.org",
                           "nameservers": "ns.example.org"}
        self.subzone = {"name": "sub.example.org",
                        "email": "hostmaster@example.org",
                        "primary_ns": "ns.example.org"}
        self.zone_exampleorg = create_forward_zone()
        self.zone_examplecom = create_forward_zone(name='example.com')
        self.zone_1010 = create_reverse_zone()

    def test_add_host(self):
        old_org_updated_at = self.zone_exampleorg.updated_at
        old_1010_updated_at = self.zone_1010.updated_at
        self.client.post('/hosts/', self.host1)
        self.zone_exampleorg.refresh_from_db()
        self.zone_1010.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)
        self.assertTrue(self.zone_1010.updated)
        self.assertGreater(self.zone_exampleorg.updated_at, old_org_updated_at)
        self.assertGreater(self.zone_1010.updated_at, old_1010_updated_at)

    def test_rename_host(self):
        self.client.post('/hosts/', self.host1)
        self.zone_exampleorg.refresh_from_db()
        self.zone_examplecom.refresh_from_db()
        self.zone_1010.refresh_from_db()
        old_org_updated_at = self.zone_exampleorg.updated_at
        old_com_updated_at = self.zone_examplecom.updated_at
        old_1010_updated_at = self.zone_1010.updated_at
        self.client.patch('/hosts/host1.example.org',
                          {"name": "host1.example.com"})
        self.zone_exampleorg.refresh_from_db()
        self.zone_examplecom.refresh_from_db()
        self.zone_1010.refresh_from_db()
        self.assertTrue(self.zone_examplecom.updated)
        self.assertTrue(self.zone_exampleorg.updated)
        self.assertTrue(self.zone_1010.updated)
        self.assertGreater(self.zone_examplecom.updated_at, old_com_updated_at)
        self.assertGreater(self.zone_exampleorg.updated_at, old_org_updated_at)
        self.assertGreater(self.zone_1010.updated_at, old_1010_updated_at)

    def test_change_soa(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        ret = self.client.patch('/zones/example.org', {'ttl': 1000})
        self.assertEqual(ret.status_code, 204)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_changed_nameservers(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        ret = self.client.patch('/zones/example.org/nameservers',
                                {'primary_ns': 'ns2.example.org'})
        self.assertEqual(ret.status_code, 204)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_added_subzone(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.client.post("/zones/", self.subzone)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_removed_subzone(self):
        self.client.post("/zones/", self.subzone)
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.client.delete("/zones/sub.example.org")
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_add_delegation(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        ret = self.client.post("/zones/example.org/delegations/", self.delegation)
        self.assertEqual(ret.status_code, 201)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_remove_delegation(self):
        self.client.post("/zones/example.org/delegations/", self.delegation)
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.client.delete("/zones/example.org/delegations/delegated.example.org")
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)


class APIAutoupdateHostZoneTestCase(MregAPITestCase):
    """This class tests that a Host's zone attribute is correct and updated
       when renaming etc.
       """

    def setUp(self):
        """Add the a couple of zones and hosts for used in testing."""
        super().setUp()
        self.zone_org = create_forward_zone(name='example.org')
        self.zone_long = create_forward_zone(name='longexample.org')
        self.zone_sub = create_forward_zone(name='sub.example.org')
        self.zone_com = create_forward_zone(name='example.com')
        self.zone_1010 = create_reverse_zone(name='10.10.in-addr.arpa')

        self.org_host1 = {"name": "host1.example.org",
                          "ipaddress": "10.10.0.1",
                          "contact": "mail@example.org"}
        self.org_host2 = {"name": "example.org",
                          "ipaddress": "10.10.0.2",
                          "contact": "mail@example.org"}
        self.sub_host1 = {"name": "host1.sub.example.org",
                          "ipaddress": "10.20.0.1",
                          "contact": "mail@example.org"}
        self.sub_host2 = {"name": "sub.example.org",
                          "ipaddress": "10.20.0.1",
                          "contact": "mail@example.org"}
        self.long_host1 = {"name": "host1.longexample.org",
                           "ipaddress": "10.30.0.1",
                           "contact": "mail@example.org"}
        self.long_host2 = {"name": "longexample.org",
                           "ipaddress": "10.30.0.2",
                           "contact": "mail@example.org"}

    def test_add_host_known_zone(self):
        res = self.client.post("/hosts/", self.org_host1)
        self.assertEqual(res.status_code, 201)
        res = self.client.post("/hosts/", self.org_host2)
        self.assertEqual(res.status_code, 201)
        res = self.client.post("/hosts/", self.sub_host1)
        self.assertEqual(res.status_code, 201)
        res = self.client.post("/hosts/", self.sub_host2)
        self.assertEqual(res.status_code, 201)
        res = self.client.post("/hosts/", self.long_host1)
        self.assertEqual(res.status_code, 201)
        res = self.client.post("/hosts/", self.long_host2)
        self.assertEqual(res.status_code, 201)

        res = self.client.get("/hosts/{}".format(self.org_host1['name']))
        self.assertEqual(res.json()['zone'], self.zone_org.id)
        res = self.client.get("/hosts/{}".format(self.org_host2['name']))
        self.assertEqual(res.json()['zone'], self.zone_org.id)
        res = self.client.get("/hosts/{}".format(self.sub_host1['name']))
        self.assertEqual(res.json()['zone'], self.zone_sub.id)
        res = self.client.get("/hosts/{}".format(self.sub_host2['name']))
        self.assertEqual(res.json()['zone'], self.zone_sub.id)
        res = self.client.get("/hosts/{}".format(self.long_host1['name']))
        self.assertEqual(res.json()['zone'], self.zone_long.id)
        res = self.client.get("/hosts/{}".format(self.long_host2['name']))
        self.assertEqual(res.json()['zone'], self.zone_long.id)

    def test_add_to_nonexistent(self):
        data = {"name": "host1.example.net",
                "ipaddress": "10.10.0.10",
                "contact": "mail@example.org"}
        res = self.client.post("/hosts/", data)
        self.assertEqual(res.status_code, 201)
        res = self.client.get(f"/hosts/{data['name']}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['zone'], None)

    def test_rename_host_to_valid_zone(self):
        self.client.post('/hosts/', self.org_host1)
        self.client.patch('/hosts/host1.example.org',
                          {"name": "host1.example.com"})
        res = self.client.get(f"/hosts/host1.example.com")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['zone'], self.zone_com.id)

    def test_rename_host_to_unknown_zone(self):
        self.client.post('/hosts/', self.org_host1)
        self.client.patch('/hosts/host1.example.org',
                          {"name": "host1.example.net"})
        res = self.client.get(f"/hosts/host1.example.net")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['zone'], None)


class APIHostsTestCase(MregAPITestCase):
    """This class defines the test suite for api/hosts"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.host_one = Host(name='host1.example.org', contact='mail1@example.org')
        self.host_two = Host(name='host2.example.org', contact='mail2@example.org')
        self.patch_data = {'name': 'new-name1.example.com', 'contact': 'updated@mail.com'}
        self.patch_data_name = {'name': 'host2.example.org', 'contact': 'updated@mail.com'}
        self.post_data = {'name': 'new-name2.example.org', "ipaddress": '127.0.0.2',
                          'contact': 'hostmaster@example.org'}
        self.post_data_name = {'name': 'host1.example.org', "ipaddress": '127.0.0.2',
                               'contact': 'hostmaster@example.org'}
        self.zone_sample = create_forward_zone()
        clean_and_save(self.host_one)
        clean_and_save(self.host_two)

    def test_hosts_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/hosts/%s' % self.host_one.name)
        self.assertEqual(response.status_code, 200)

    def test_hosts_get_case_insensitive_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/hosts/%s' % self.host_one.name.upper())
        self.assertEqual(response.status_code, 200)

    def test_hosts_list_200_ok(self):
        """List all hosts should return 200"""
        response = self.client.get('/hosts/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['results']), 2)

    def test_hosts_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/hosts/nonexistent.example.org')
        self.assertEqual(response.status_code, 404)

    def test_hosts_post_201_created(self):
        """"Posting a new host should return 201 and location"""
        response = self.client.post('/hosts/', self.post_data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/hosts/%s' % self.post_data['name'])

    def test_hosts_post_case_insenstive_201_created(self):
        """"Posting a new host should return 201 and location"""
        data = self.post_data
        data['name'] = data['name'].upper()
        response = self.client.post('/hosts/', data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], '/hosts/%s' % self.post_data['name'])

    def test_hosts_post_400_invalid_ip(self):
        """"Posting a new host with an invalid IP should return 400"""
        post_data = {'name': 'failing.example.org', 'ipaddress': '300.400.500.600',
                     'contact': 'fail@example.org'}
        response = self.client.post('/hosts/', post_data)
        self.assertEqual(response.status_code, 400)
        response = self.client.get('/hosts/failing.example.org')
        self.assertEqual(response.status_code, 404)

    def test_hosts_post_409_conflict_name(self):
        """"Posting a new host with a name already in use should return 409"""
        response = self.client.post('/hosts/', self.post_data_name)
        self.assertEqual(response.status_code, 409)

    def test_hosts_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/hosts/%s' % self.patch_data['name'])

    def test_hosts_patch_without_name_204_no_content(self):
        """Patching an existing entry without having name in patch should
        return 204"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, {"ttl": 5000})
        self.assertEqual(response.status_code, 204)

    def test_hosts_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_hosts_patch_400_bad_ttl(self):
        """Patching with invalid ttl should return 400"""
        def _test_ttl(ttl):
            response = self.client.patch('/hosts/%s' % self.host_one.name, data={'ttl': ttl})
            self.assertEqual(response.status_code, 400)
        _test_ttl(100)
        _test_ttl(100000)

    def test_hosts_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/hosts/feil-navn/', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_hosts_patch_409_conflict_name(self):
        """Patching an entry with a name that already exists should return 409"""
        response = self.client.patch('/hosts/%s' % self.host_one.name, {'name': self.host_two.name})
        self.assertEqual(response.status_code, 409)


class APIHostsAutoTxtRecords(MregAPITestCase):

    data = {'name': 'host.example.org', 'contact': 'mail@example.org'}
    settings.TXT_AUTO_RECORDS = {'example.org': ('test1', 'test2')}

    def test_no_zone_no_txts_added(self):
        self.assertFalse(Txt.objects.exists())
        response = self.client.post('/hosts/', self.data)
        self.assertEqual(response.status_code, 201)
        self.assertFalse(Txt.objects.exists())

    def test_zone_txts_added(self):
        self.assertFalse(Txt.objects.exists())
        ForwardZone.objects.create(name='example.org',
                                   primary_ns='ns1.example.org',
                                   email='hostmaster@example.org')
        self.client.post('/hosts/', self.data)
        response = self.client.get('/hosts/%s' % self.data['name']).json()
        txts = tuple(map(itemgetter('txt'), response['txts']))
        self.assertEqual(txts, list(settings.TXT_AUTO_RECORDS.values())[0])


class APIHostsIdna(MregAPITestCase):

    data_v4 = {'name': 'æøå.example.org', "ipaddress": '10.10.0.1'}

    def _add_data(self, data):
        self.client.post('/hosts/', data)

    def test_hosts_idna_forward(self):
        """Test that a hostname outside ASCII 128 is handled properly"""
        zone = create_forward_zone()
        self._add_data(self.data_v4)
        response = self.client.get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c                     IN A      10.10.0.1' in response.data)

    def test_hosts_idna_reverse_v4(self):
        zone = create_reverse_zone()
        self._add_data(self.data_v4)
        response = self.client.get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c.example.org.' in response.data)

    def test_hosts_idna_reverse_v6(self):
        zone = create_reverse_zone('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        data = {'name': 'æøå.example.org', "ipaddress": '2001:db8::1'}
        self._add_data(data)
        response = self.client.get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c.example.org.' in response.data)


class APIHinfoTestCase(MregAPITestCase):
    """Test HinfoPresets and hinfo field on Host"""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_hinfopresets_post_201_ok(self):
        data = {'cpu': 'cpuname', 'os': 'superos'}
        ret = self.client.post('/hinfopresets/', data)
        self.assertEqual(ret.status_code, 201)

    def test_hinfopresets_list(self):
        self.test_hinfopresets_post_201_ok()
        ret = self.client.get('/hinfopresets/')
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 1)

    def test_hinfopresets_post_must_have_both_fields_400_bad_request(self):
        ret = self.client.post('/hinfopresets/', {'cpu': 'cpuname'})
        self.assertEqual(ret.json(), {'os': ['This field is required.']})
        self.assertEqual(ret.status_code, 400)
        ret = self.client.post('/hinfopresets/', {'os': 'superos'})
        self.assertEqual(ret.status_code, 400)

    def test_patch_add_hinfo_to_host_204_ok(self):
        data = {'cpu': 'cpuname', 'os': 'superos'}
        ret = self.client.post('/hinfopresets/', data)
        hinfoid = ret.json()['id']
        ret = self.client.patch(f'/hosts/{self.host.name}', {'hinfo': hinfoid})
        self.assertEqual(ret.status_code, 204)
        self.host.refresh_from_db()
        self.assertEqual(self.host.hinfo.id, hinfoid)

    def test_patch_remove_hinfo_to_host_204_ok(self):
        ret = self.client.patch(f'/hosts/{self.host.name}', {'hinfo': ''})
        self.assertEqual(ret.status_code, 204)
        self.host.refresh_from_db()
        self.assertEqual(self.host.hinfo, None)

    def test_patch_add_invalid_hinfo_to_host_400_bad_request(self):
        ret = self.client.patch(f'/hosts/{self.host.name}', {'hinfo': 12345788})
        self.assertEqual(ret.status_code, 400)


class APIMxTestcase(MregAPITestCase):
    """Test MX records."""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_mx_post(self):
        data = {'host': self.host.id,
                'priority': 10,
                'mx': 'smtp.example.org'}
        ret = self.client.post("/mxs/", data)
        self.assertEqual(ret.status_code, 201)

    def test_mx_post_reject_invalid(self):
        # priority is an 16 bit uint, e.g. 0..65535.
        data = {'host': self.host.id,
                'priority': -1,
                'mx': 'smtp.example.org'}
        ret = self.client.post("/mxs/", data)
        self.assertEqual(ret.status_code, 400)
        data = {'host': self.host.id,
                'priority': 1000000,
                'mx': 'smtp.example.org'}
        ret = self.client.post("/mxs/", data)
        self.assertEqual(ret.status_code, 400)
        data = {'host': self.host.id,
                'priority': 1000,
                'mx': 'invalidhostname'}
        ret = self.client.post("/mxs/", data)
        self.assertEqual(ret.status_code, 400)

    def test_mx_list(self):
        self.test_mx_post()
        ret = self.client.get("/mxs/")
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 1)

    def test_mx_delete(self):
        self.test_mx_post()
        mxs = self.client.get("/mxs/").json()['results']
        ret = self.client.delete("/mxs/{}".format(mxs[0]['id']))
        self.assertEqual(ret.status_code, 204)
        mxs = self.client.get("/mxs/").json()
        self.assertEqual(len(mxs['results']), 0)

    def test_mx_zone_autoupdate_add(self):
        self.zone.updated = False
        self.zone.save()
        self.test_mx_post()
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_mx_zone_autoupdate_delete(self):
        self.test_mx_post()
        self.zone.updated = False
        self.zone.save()
        mxs = self.client.get("/mxs/").data['results']
        self.client.delete("/mxs/{}".format(mxs[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)


class APINaptrTestCase(MregAPITestCase):

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_naptr_post(self):
        data = {'host': self.host.id,
                'preference': 10,
                'order': 20,
                'flag': 'a',
                'service': 'SERVICE',
                'regex': r'1(.*@example.org)',
                'replacement': 'replacement.example.org'
                }
        ret = self.client.post("/naptrs/", data)
        self.assertEqual(ret.status_code, 201)

    def test_naptr_list(self):
        self.test_naptr_post()
        ret = self.client.get("/naptrs/")
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 1)

    def test_naptr_delete(self):
        self.test_naptr_post()
        naptrs = self.client.get("/naptrs/").json()['results']
        ret = self.client.delete("/naptrs/{}".format(naptrs[0]['id']))
        self.assertEqual(ret.status_code, 204)
        naptrs = self.client.get("/naptrs/").json()
        self.assertEqual(len(naptrs['results']), 0)

    def test_naptr_zone_autoupdate_add(self):
        self.zone.updated = False
        self.zone.save()
        self.test_naptr_post()
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_naptr_zone_autoupdate_delete(self):
        self.test_naptr_post()
        self.zone.updated = False
        self.zone.save()
        naptrs = self.client.get("/naptrs/").data['results']
        self.client.delete("/naptrs/{}".format(naptrs[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)


class APIPtrOverrideTestcase(MregAPITestCase):
    """Test PtrOverride records."""

    def setUp(self):
        super().setUp()
        self.host_data = {'name': 'ns1.example.org',
                          'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

        self.ptr_override_data = {'host': self.host.id,
                                  'ipaddress': '10.0.0.2'}

        self.ptr_override_ipv6_data = {'host': self.host.id,
                                       'ipaddress': '2001:db8::beef'}

        self.client.post('/ptroverrides/', self.ptr_override_data)
        self.ptr_override = PtrOverride.objects.get(ipaddress=self.ptr_override_data['ipaddress'])
        self.client.post('/ptroverrides/', self.ptr_override_ipv6_data)
        self.ptr_ipv6_override = PtrOverride.objects.get(ipaddress=self.ptr_override_ipv6_data['ipaddress'])

        self.ptr_override_patch_data = {'host': self.host.id,
                                        'ipaddress': '10.0.0.3'}

        self.ptr_override_ipv6_patch_data = {'host': self.host.id,
                                             'ipaddress': '2001:db8::feed'}

        self.zone = ReverseZone.objects.create(name="0.10.in-addr.arpa",
                                               primary_ns="ns1.example.org",
                                               email="hostmaster@example.org")
        self.ipv6_zone = ReverseZone.objects.create(name="8.b.d.0.1.0.0.2.ip6.arpa",
                                                    primary_ns="ns1.example.org",
                                                    email="hostmaster@example.org")

    def test_ptr_override_post_201(self):
        ptr_override_data = {'host': self.host.id,
                             'ipaddress': '10.0.0.4'}
        ret = self.client.post("/ptroverrides/", ptr_override_data)
        self.assertEqual(ret.status_code, 201)

    def test_ptr_override_ipv6_post_201(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3'}
        ret = self.client.post("/ptroverrides/", ptr_override_ipv6_data)
        self.assertEqual(ret.status_code, 201)

    def test_ptr_override_delete_204(self):
        ptr_override_data = {'host': self.host.id,
                             'ipaddress': '10.0.0.4'}
        self.client.post("/ptroverrides/", ptr_override_data)
        ptroverrides = self.client.get("/ptroverrides/").json()['results']
        old_count = len(ptroverrides)
        ret = self.client.delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        self.assertEqual(ret.status_code, 204)
        ptroverrides = self.client.get("/ptroverrides/").json()['results']
        new_count = len(ptroverrides)
        self.assertLess(new_count, old_count)

    def test_ptr_override_ipv6_delete_204(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3'}
        self.client.post("/ptroverrides/", ptr_override_ipv6_data)
        ptroverrides = self.client.get("/ptroverrides/").json()['results']
        old_count = len(ptroverrides)
        ret = self.client.delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        self.assertEqual(ret.status_code, 204)
        ptroverrides = self.client.get("/ptroverrides/").json()['results']
        new_count = len(ptroverrides)
        self.assertLess(new_count, old_count)

    def test_ptr_override_patch_204(self):
        ret = self.client.patch("/ptroverrides/%s" % self.ptr_override.id, self.ptr_override_patch_data)
        self.assertEqual(ret.status_code, 204)

    def test_ptr_override_ipv6_patch_204(self):
        ret = self.client.patch("/ptroverrides/%s" % self.ptr_ipv6_override.id, self.ptr_override_ipv6_patch_data)
        self.assertEqual(ret.status_code, 204)

    ''' This test crashes the database and is commented out
        until the underlying problem has been fixed
    def test_ptr_override_reject_invalid_ipv4_400(self):
        ptr_override_data = {'host': self.host.id,
                             'ipaddress': '10.0.0.400'}
        ret = self.client.post("/ptroverrides/", ptr_override_data)
        self.assertEqual(ret.status_code, 400)
    '''

    def test_ptr_override_reject_invalid_ipv6_400(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3zzz'}
        ret = self.client.post("/ptroverrides/", ptr_override_ipv6_data)
        self.assertEqual(ret.status_code, 400)

    def test_ptr_override_reject_nonexisting_host_400(self):
        ptr_override_bad_data = {'host': -1, 'ipaddress': '10.0.0.7'}
        ret = self.client.post("/ptroverrides/", ptr_override_bad_data)
        self.assertEqual(ret.status_code, 400)

    def test_ptr_override_zone_autoupdate_add(self):
        self.zone.updated = False
        self.zone.save()
        self.test_ptr_override_post_201()
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_ptr_override_zone_autoupdate_delete(self):
        self.test_ptr_override_post_201()
        self.zone.updated = False
        self.zone.save()
        ptroverrides = self.client.get("/ptroverrides/").data['results']
        self.client.delete("/ptroverrides/{}".format(ptroverrides[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_ptr_override_ipv6_zone_autoupdate_add(self):
        self.ipv6_zone.updated = False
        self.ipv6_zone.save()
        self.test_ptr_override_ipv6_post_201()
        self.ipv6_zone.refresh_from_db()
        self.assertTrue(self.ipv6_zone.updated)

    def test_ptr_override_ipv6_zone_autoupdate_delete(self):
        self.test_ptr_override_ipv6_post_201()
        self.ipv6_zone.updated = False
        self.ipv6_zone.save()
        ptroverrides = self.client.get("/ptroverrides/").data['results']
        self.client.delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        self.ipv6_zone.refresh_from_db()
        self.assertTrue(self.ipv6_zone.updated)

    def test_ptr_override_reject_taken_ip_400(self):
        new_host_data = {'name': 'ns2.example.org',
                         'contact': 'mail@example.org'}
        self.client.post('/hosts/', new_host_data)
        new_host = Host.objects.get(name=new_host_data['name'])
        ptr_override_data = {'host': new_host.id,
                             'ipaddress': self.ptr_override_data['ipaddress']}
        ret = self.client.post("/ptroverrides/", ptr_override_data)
        self.assertEqual(ret.status_code, 400)

    def test_ptr_override_reject_taken_ipv6_400(self):
        new_host_data = {'name': 'ns2.example.org',
                         'contact': 'mail@example.org'}
        self.client.post('/hosts/', new_host_data)
        new_host = Host.objects.get(name=new_host_data['name'])
        ptr_override_ipv6_data = {'host': new_host.id,
                                  'ipaddress': self.ptr_override_ipv6_data['ipaddress']}
        ret = self.client.post("/ptroverrides/", ptr_override_ipv6_data)
        self.assertEqual(ret.status_code, 400)

    def test_ptr_override_list(self):
        ret = self.client.get("/ptroverrides/")
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 2)

    def test_ptr_override_create_new_host(self):
        # Adding a new host with already existing IP should
        # create a PtrOverride for it
        ret = self.client.get("/ptroverrides/")
        old_count = ret.data['count']
        host_data = {'name': 'ns3.example.org',
                     'contact': 'mail@example.org',
                     'ipaddress': '10.0.0.5'}
        host2_data = {'name': 'ns4.example.org',
                      'contact': 'mail@example.org',
                      'ipaddress': '10.0.0.5'}
        self.client.post('/hosts/', host_data)
        ret = self.client.get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertEqual(new_count, old_count)
        self.client.post('/hosts/', host2_data)
        ret = self.client.get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertGreater(new_count, old_count)
        # Now check that the last PtrOverride
        # points to the first host holding the IP
        ptr_override = ret.data['results'][-1]
        self.assertEqual(ptr_override['ipaddress'], '10.0.0.5')
        ret = self.client.get('/hosts/?name=ns3.example.org')
        host_id = ret.data['results'][0]['id']
        self.assertEqual(ptr_override['host'], host_id)

    def test_ptr_override_ipv6_create_new_host(self):
        # Adding a new host with already existing IPv6 should
        # create a PtrOverride for it
        ret = self.client.get("/ptroverrides/")
        old_count = ret.data['count']
        host_ipv6_data = {'name': 'ns3.example.org',
                          'contact': 'mail@example.org',
                          'ipaddress': '2001:db8::7'}
        host2_ipv6_data = {'name': 'ns4.example.org',
                           'contact': 'mail@example.org',
                           'ipaddress': '2001:db8::7'}
        self.client.post('/hosts/', host_ipv6_data)
        ret = self.client.get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertEqual(new_count, old_count)
        self.client.post('/hosts/', host2_ipv6_data)
        ret = self.client.get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertGreater(new_count, old_count)
        # Now check that the last PtrOverride
        # points to the first host holding the IP
        ptr_override = ret.data['results'][-1]
        self.assertEqual(ptr_override['ipaddress'], '2001:db8::7')
        ret = self.client.get('/hosts/?name=ns3.example.org')
        host_id = ret.data['results'][0]['id']
        self.assertEqual(ptr_override['host'], host_id)

    def test_ptr_override_delete_with_host(self):
        # Deleting a host with assigned PtrOverrides should
        # delete the PtrOverrides too
        ret = self.client.get("/ptroverrides/")
        self.assertEqual(ret.data['count'], 2)
        ret = self.client.delete("/hosts/{}".format(self.host.name))
        ret = self.client.get("/ptroverrides/")
        self.assertEqual(ret.data['count'], 0)


class APISshfpTestcase(MregAPITestCase):
    """Test SSHFP records."""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'ns1.example.org',
                          'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_sshfp_post(self):
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        ret = self.client.post("/sshfps/", data)
        self.assertEqual(ret.status_code, 201)

    def test_sshfp_post_reject_invalid(self):
        # Invalid fingerprint, algorithm, hash_type
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': 'beefistasty'}
        ret = self.client.post("/sshfps/", data)
        self.assertEqual(ret.status_code, 400)
        data = {'host': self.host.id,
                'algorithm': 0,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        ret = self.client.post("/sshfps/", data)
        self.assertEqual(ret.status_code, 400)
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 3,
                'fingerprint': '0123456789abcdef'}
        ret = self.client.post("/sshfps/", data)
        self.assertEqual(ret.status_code, 400)

    def test_sshfp_list(self):
        self.test_sshfp_post()
        ret = self.client.get("/sshfps/")
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret.data['count'], 1)

    def test_sshfp_delete(self):
        self.test_sshfp_post()
        sshfps = self.client.get("/sshfps/").json()['results']
        ret = self.client.delete("/sshfps/{}".format(sshfps[0]['id']))
        self.assertEqual(ret.status_code, 204)
        sshfps = self.client.get("/sshfps/").json()
        self.assertEqual(len(sshfps['results']), 0)

    def test_sshfp_zone_autoupdate_add(self):
        self.zone.updated = False
        self.zone.save()
        self.test_sshfp_post()
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_sshfp_zone_autoupdate_delete(self):
        self.test_sshfp_post()
        self.zone.updated = False
        self.zone.save()
        sshfps = self.client.get("/sshfps/").data['results']
        self.client.delete("/sshfps/{}".format(sshfps[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)


class APIForwardZonesTestCase(MregAPITestCase):
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
                              'refresh': 400, 'retry': 300, 'expire': 800, 'ttl': 350}
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
        response = self.client.get('/zones/nonexisting.example.org')
        self.assertEqual(response.status_code, 404)

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/zones/%s' % self.zone_one.name)
        self.assertEqual(response.status_code, 200)

    def test_zones_list_200_ok(self):
        """Listing all zones should return 200"""
        response = self.client.get('/zones/')
        self.assertEqual(response.json()[0]['name'], self.zone_one.name)
        self.assertEqual(len(response.json()), 1)
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
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'])
        self.assertEqual(response_one.data['serialno'], create_serialno())

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
        response = self.client.patch("/zones/nonexisting.example.org", self.patch_data)
        self.assertEqual(response.status_code, 404)

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
        response = self.client.delete("/zones/nonexisting.example.org")
        self.assertEqual(response.status_code, 404)

    def test_zones_403_forbidden(self):
        # TODO: jobb skal gjøres her
        """"Deleting an entry with registered entries should require force"""

    def test_zone_by_hostname_404_not_found(self):
        response = self.client.get('/zones/hostname/invalid.example.wrongtld')
        self.assertEqual(response.status_code, 404)

    def test_zone_by_hostname_200_ok(self):
        def _test(hostname, zone, zonetype):
            response = self.client.get(f'/zones/hostname/{hostname}')
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data[zonetype]['name'], zone)
        _test('host.example.org', 'example.org', 'zone')
        _test('example.org', 'example.org', 'zone')


class APIZonesForwardDelegationTestCase(MregAPITestCase):
    """ This class defines test testsuite for api/zones/<name>/delegations/
        But only for ForwardZones.
    """

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.data_exampleorg = {'name': 'example.org',
                                'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                                'email': "hostmaster@example.org"}
        self.client.post("/zones/", self.data_exampleorg)

    def test_list_empty_delegation_200_ok(self):
        response = self.client.get("/zones/example.org/delegations/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['results'], [])

    def test_delegate_forward_201_ok(self):
        path = "/zones/example.org/delegations/"
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        response = self.client.post(path, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], f"{path}delegated.example.org")

    def test_delegate_forward_zonefiles_200_ok(self):
        self.test_delegate_forward_201_ok()
        response = self.client.get('/zonefiles/example.org')
        self.assertEqual(response.status_code, 200)

    def test_delegate_forward_badname_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_forward_no_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': []}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)
        bad = {'name': 'delegated.example.org'}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_forward_duplicate_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1.example.org', 'ns1.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_forward_invalid_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1', ]}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)
        bad = {'name': 'delegated.example.org',
               'nameservers': ['2"#¤2342.tld', ]}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_forward_nameservers_list_200_ok(self):
        path = "/zones/example.org/delegations/"
        self.test_delegate_forward_201_ok()
        response = self.client.get(f"{path}delegated.example.org")
        self.assertEqual(response.status_code, 200)
        nameservers = [i['name'] for i in response.json()['nameservers']]
        self.assertEqual(len(nameservers), 2)
        for ns in nameservers:
            self.assertTrue(NameServer.objects.filter(name=ns).exists())

    def test_forward_list_delegations_200_ok(self):
        path = "/zones/example.org/delegations/"
        self.test_delegate_forward_201_ok()
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)
        results = response.data['results']
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['name'], 'delegated.example.org')

    def test_forward_delete_delegattion_204_ok(self):
        self.test_forward_list_delegations_200_ok()
        path = "/zones/example.org/delegations/delegated.example.org"
        self.assertEqual(NameServer.objects.count(), 3)
        response = self.client.delete(path)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], path)
        self.assertEqual(NameServer.objects.count(), 2)
        path = "/zones/example.org/delegations/"
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['results'], [])

    def test_zone_by_hostname_404_not_found(self):
        self.test_delegate_forward_201_ok()
        response = self.client.get('/zones/hostname/invalid.example.wrongtld')
        self.assertEqual(response.status_code, 404)

    def test_zone_by_hostname_200_ok(self):
        self.test_delegate_forward_201_ok()

        def _test(hostname, zone, zonetype):
            response = self.client.get(f'/zones/hostname/{hostname}')
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data[zonetype]['name'], zone)

        _test('host.example.org', 'example.org', 'zone')
        _test('example.org', 'example.org', 'zone')
        _test('host.delegated.example.org', 'delegated.example.org', 'delegation')
        _test('delegated.example.org', 'delegated.example.org', 'delegation')


class APIZonesReverseDelegationTestCase(MregAPITestCase):
    """ This class defines test testsuite for api/zones/<name>/delegations/
        But only for ReverseZones.
    """

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

        self.client.post("/zones/", self.data_rev1010)
        self.client.post("/zones/", self.data_revdb8)

    def test_get_delegation_200_ok(self):
        def assertempty(data):
            response = self.client.get(f"/zones/{data['name']}/delegations/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data['count'], 0)
            self.assertEqual(response.data['results'], [])
        for data in ('rev1010', 'revdb8'):
            assertempty(getattr(self, f"data_{data}"))

    def test_delegate_ipv4_201_ok(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        response = self.client.post(path, self.del_101010)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], f"{path}10.10.10.in-addr.arpa")
        response = self.client.post(path, self.del_10101010)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], f"{path}10.10.10.10.in-addr.arpa")
        response = self.client.get(response['Location'])
        self.assertEqual(response.status_code, 200)

    def test_delegate_ipv4_zonefiles_200_ok(self):
        self.test_delegate_ipv4_201_ok()
        response = self.client.get('/zonefiles/10.10.in-addr.arpa')
        self.assertEqual(response.status_code, 200)

    def test_delegate_ipv4_badname_400_bad_request(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_ipv4_invalid_zone_400_bad_request(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        bad = {'name': '300.10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)
        bad = {'name': '10.10.10.10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)
        bad = {'name': 'foo.10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_ipv4_wrong_inet_400_bad_request(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        bad = {'name': '0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_duplicate_409_conflict(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        response = self.client.post(path, self.del_101010)
        self.assertEqual(response.status_code, 201)
        response = self.client.post(path, self.del_101010)
        self.assertEqual(response.status_code, 409)

    def test_delegate_ipv6_201_ok(self):
        path = "/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        response = self.client.post(path, self.del_2001db810)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Location'], f"{path}{self.del_2001db810['name']}")
        response = self.client.get(response['Location'])
        self.assertEqual(response.status_code, 200)

    def test_delegate_ipv6_zonefiles_200_ok(self):
        self.test_delegate_ipv6_201_ok()
        response = self.client.get('/zonefiles/8.b.d.0.1.0.0.2.ip6.arpa')
        self.assertEqual(response.status_code, 200)

    def test_delegate_ipv6_badname_400_bad_request(self):
        path = "/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)

    def test_delegate_ipv6_wrong_inet_400_bad_request(self):
        path = "/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        bad = {'name': '10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post(path, bad)
        self.assertEqual(response.status_code, 400)


class APIZonesNsTestCase(MregAPITestCase):
    """"This class defines the test suite for api/zones/<name>/nameservers/ """

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.post_data = {'name': 'example.org', 'primary_ns': ['ns2.example.org'],
                          'email': "hostmaster@example.org"}
        self.ns_one = Host(name='ns1.example.org', contact='mail@example.org')
        self.ns_two = Host(name='ns2.example.org', contact='mail@example.org')
        clean_and_save(self.ns_one)
        clean_and_save(self.ns_two)

    def test_zones_ns_get_200_ok(self):
        """"Getting the list of nameservers of a existing zone should return 200"""
        self.assertEqual(NameServer.objects.count(), 0)
        self.client.post('/zones/', self.post_data)
        self.assertEqual(NameServer.objects.count(), 1)
        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.status_code, 200)

    def test_zones_ns_get_404_not_found(self):
        """"Getting the list of nameservers of a non-existing zone should return 404"""
        response = self.client.delete('/zones/example.com/nameservers/')
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
                                     {'primary_ns': ['nonexisting-ns.example.org']})
        # XXX: This is now valid, as the NS might point to a server in a zone which we
        # don't control. Might be possible to check if the attempted NS is in a
        # zone we control and then be stricter.
        return
        self.assertEqual(response.status_code, 404)

    def test_zones_ns_delete_204_no_content_zone(self):
        """Deleting a nameserver from an existing zone should return 204"""
        self.assertFalse(NameServer.objects.exists())
        # TODO: This test needs some cleanup and work. See comments
        self.client.post('/zones/', self.post_data)

        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})
        self.assertEqual(response.status_code, 204)
        self.assertEqual(NameServer.objects.count(), 2)

        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.status_code, 200)

        response = self.client.patch('/zones/%s/nameservers' % self.post_data['name'],
                                     {'primary_ns': self.ns_two.name})
        self.assertEqual(response.status_code, 204)
        self.assertEqual(NameServer.objects.count(), 1)

        response = self.client.get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.data, self.post_data['primary_ns'])
        response = self.client.delete('/zones/%s' % self.post_data['name'])
        self.assertEqual(response.status_code, 204)
        self.assertFalse(NameServer.objects.exists())


class APIZoneRFC2317(MregAPITestCase):
    """This class tests RFC 2317 delegations."""

    def setUp(self):
        super().setUp()
        self.data = {'name': '128/25.0.0.10.in-addr.arpa',
                     'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                     'email': "hostmaster@example.org"}

    def test_create_and_get_rfc_2317_zone(self):
        # Create and get zone for 10.0.0.128/25
        response = self.client.post("/zones/", self.data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response["location"], "/zones/128/25.0.0.10.in-addr.arpa")
        response = self.client.get(response["location"])
        self.assertEqual(response.status_code, 200)

    def test_add_rfc2317_delegation_for_existing_zone(self):
        zone = {'name': '0.10.in-addr.arpa',
                'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                'email': "hostmaster@example.org"}
        response = self.client.post("/zones/", zone)
        self.assertEqual(response.status_code, 201)
        delegation = {'name': '128/25.0.0.10.in-addr.arpa',
                      'nameservers': ['ns1.example.org', 'ns2.example.org']}
        response = self.client.post("/zones/0.10.in-addr.arpa/delegations/", delegation)
        self.assertEqual(response.status_code, 201)

    def test_delete_rfc2317_zone(self):
        self.client.post("/zones/", self.data)
        response = self.client.delete("/zones/128/25.0.0.10.in-addr.arpa")
        self.assertEqual(response.status_code, 204)


class APIIPaddressesTestCase(MregAPITestCase):
    """This class defines the test suite for api/ipaddresses"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org')

        self.host_two = Host(name='some-other-host.example.org',
                             contact='mail@example.com')

        clean_and_save(self.host_one)
        clean_and_save(self.host_two)

        self.ipaddress_one = Ipaddress(host=self.host_one,
                                       ipaddress='192.168.111.111')

        self.ipaddress_two = Ipaddress(host=self.host_two,
                                       ipaddress='192.168.111.112')

        self.ipv6address_one = Ipaddress(host=self.host_one,
                                         ipaddress='2001:db8::beef')

        self.ipv6address_two = Ipaddress(host=self.host_two,
                                         ipaddress='2001:db8::feed')

        clean_and_save(self.ipaddress_one)
        clean_and_save(self.ipaddress_two)

        clean_and_save(self.ipv6address_one)
        clean_and_save(self.ipv6address_two)

        self.post_data_full = {'host': self.host_one.id,
                               'ipaddress': '192.168.203.197'}
        self.post_data_full_conflict = {'host': self.host_one.id,
                                        'ipaddress': self.ipaddress_one.ipaddress}
        self.post_data_full_duplicate_ip = {'host': self.host_two.id,
                                            'ipaddress': self.ipaddress_one.ipaddress}
        self.patch_data_ip = {'ipaddress': '192.168.203.198'}
        self.patch_bad_ip = {'ipaddress': '192.168.300.1'}

    def test_ipaddress_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/ipaddresses/%s' % self.ipaddress_one.id)
        self.assertEqual(response.status_code, 200)

    def test_ipv6address_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        response = self.client.get('/ipaddresses/%s' % self.ipv6address_one.id)
        self.assertEqual(response.status_code, 200)

    def test_ipaddress_list_200_ok(self):
        """List all ipaddress should return 200"""
        response = self.client.get('/ipaddresses/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 4)
        self.assertEqual(len(data['results']), 4)

    def test_ipaddress_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/ipaddresses/193.101.168.2')
        self.assertEqual(response.status_code, 404)

    def test_ipv6address_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        response = self.client.get('/ipaddresses/2001:db8::8')
        self.assertEqual(response.status_code, 404)

    def test_ipaddress_post_201_created(self):
        """"Posting a new ip should return 201"""
        response = self.client.post('/ipaddresses/', self.post_data_full)
        self.assertEqual(response.status_code, 201)

    def test_ipv6address_post_201_created(self):
        """"Posting a new IPv6 should return 201"""
        post_ipv6_data_full = {'host': self.host_one.id,
                               'ipaddress': '2001:db8::8'}
        response = self.client.post('/ipaddresses/', post_ipv6_data_full)
        self.assertEqual(response.status_code, 201)

    def test_ipaddress_post_400_conflict_ip(self):
        """"Posting an existing ip for a host should return 400"""
        response = self.client.post('/ipaddresses/', self.post_data_full_conflict)
        self.assertEqual(response.status_code, 400)

    def test_ipv6address_post_400_conflict_ip(self):
        """"Posting an existing IPv6 for a host should return 400"""
        post_ipv6_data_full_conflict = {'host': self.host_one.id,
                                        'ipaddress': self.ipv6address_one.ipaddress}
        response = self.client.post('/ipaddresses/', post_ipv6_data_full_conflict)
        self.assertEqual(response.status_code, 400)

    def test_ipaddress_post_201_two_hosts_share_ip(self):
        """"Posting a new ipaddress with an ip already in use should return 201"""
        response = self.client.post('/ipaddresses/', self.post_data_full_duplicate_ip)
        self.assertEqual(response.status_code, 201)

    def test_ipv6address_post_201_two_hosts_share_ip(self):
        """"Posting a new ipaddress with an IPv6 already in use should return 201"""
        post_ipv6_data_full_duplicate_ip = {'host': self.host_two.id,
                                            'ipaddress': self.ipv6address_one.ipaddress}
        response = self.client.post('/ipaddresses/', post_ipv6_data_full_duplicate_ip)
        self.assertEqual(response.status_code, 201)

    def test_ipaddress_patch_200_ok(self):
        """Patching an existing and valid entry should return 200"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id, self.patch_data_ip)
        self.assertEqual(response.status_code, 204)

    def test_ipv6address_patch_200_ok(self):
        """Patching an existing and valid entry should return 200"""
        patch_data_ipv6 = {'ipaddress': '2001:db8::9'}
        response = self.client.patch('/ipaddresses/%s' % self.ipv6address_one.id, patch_data_ipv6)
        self.assertEqual(response.status_code, 204)

    def test_ipaddress_patch_204_own_ip(self):
        """Patching an entry with its own ip should return 204"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     {'ipaddress': str(self.ipaddress_one.ipaddress)})
        self.assertEqual(response.status_code, 204)

    def test_ipv6address_patch_204_own_ip(self):
        """Patching an entry with its own IPv6 should return 204"""
        response = self.client.patch('/ipaddresses/%s' % self.ipv6address_one.id,
                                     {'ipaddress': str(self.ipv6address_one.ipaddress)})
        self.assertEqual(response.status_code, 204)

    def test_ipaddress_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_ipv6address_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/ipaddresses/%s' % self.ipv6address_one.id,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_ipaddress_patch_400_bad_ip(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id, self.patch_bad_ip)
        self.assertEqual(response.status_code, 400)

    def test_ipv6address_patch_400_bad_ip(self):
        """Patching with invalid data should return 400"""
        patch_bad_ipv6 = {'ipaddress': '2001:db8::zzzz'}
        response = self.client.patch('/ipaddresses/%s' % self.ipv6address_one.id, patch_bad_ipv6)
        self.assertEqual(response.status_code, 400)

    def test_ipaddress_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/ipaddresses/1234567890', self.patch_data_ip)
        self.assertEqual(response.status_code, 404)


class APIMACaddressTestCase(MregAPITestCase):
    """This class defines the test suite for api/ipaddresses with macadresses"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.host_one = Host.objects.create(name='host1.example.org')
        self.ipaddress_one = Ipaddress.objects.create(host=self.host_one,
                                                      ipaddress='10.0.0.10',
                                                      macaddress='aa:bb:cc:00:00:10')

    def test_mac_post_ip_with_mac_201_ok(self):
        """Post a new IP with MAC should return 201 ok."""
        post_data_full = {'host': self.host_one.id,
                          'ipaddress': '10.0.0.12',
                          'macaddress': 'aa:bb:cc:00:00:12'}
        response = self.client.post('/ipaddresses/', post_data_full)
        self.assertEqual(response.status_code, 201)

    def test_mac_post_conflict_ip_and_mac_400_bad_request(self):
        """"Posting an existing IP and mac IP a host should return 400."""
        post_data_full_conflict = {'host': self.host_one.id,
                                   'ipaddress': self.ipaddress_one.ipaddress,
                                   'macaddress': self.ipaddress_one.macaddress}
        response = self.client.post('/ipaddresses/', post_data_full_conflict)
        self.assertEqual(response.status_code, 400)

    def test_mac_patch_mac_200_ok(self):
        """Patch an IP with a new mac should return 200 ok."""
        patch_mac = {'macaddress': 'aa:bb:cc:00:00:ff'}
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     patch_mac)
        self.assertEqual(response.status_code, 204)

    def test_mac_remove_mac_200_ok(self):
        """Patch an IP to remove MAC should return 200 ok."""
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     {'macaddress': ''})
        self.assertEqual(response.status_code, 204)

    def test_mac_patch_mac_in_use_400_bad_request(self):
        """Patch an IP with a MAC in use should return 400 bad request."""
        host_two = Host.objects.create(name='host2.example.org')
        ipaddress_two = Ipaddress.objects.create(host=host_two,
                                                 ipaddress='10.0.0.11',
                                                 macaddress='aa:bb:cc:00:00:11')
        patch_mac_in_use = {'macaddress': ipaddress_two.macaddress}
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     patch_mac_in_use)
        self.assertEqual(response.status_code, 400)

    def test_mac_patch_invalid_mac_400_bad_request(self):
        """ Patch an IP with invalid MAC should return 400 bad request."""
        for mac in ('00:00:00:00:00:XX', '00:00:00:00:00', 'AA:BB:cc:dd:ee:ff'):
            response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                         {'macaddress': mac})
            self.assertEqual(response.status_code, 400)

    def test_mac_patch_ip_and_mac_200_ok(self):
        """Patch an IP with a new IP and MAC should return 200 ok."""
        patch_ip_and_mac = {'ipaddress': '10.0.0.13',
                            'macaddress': 'aa:bb:cc:00:00:ff'}
        response = self.client.patch('/ipaddresses/%s' % self.ipaddress_one.id,
                                     patch_ip_and_mac)
        self.assertEqual(response.status_code, 204)

    def test_mac_with_network(self):
        self.network_one = Network.objects.create(network='10.0.0.0/24')
        self.test_mac_post_ip_with_mac_201_ok()
        self.test_mac_patch_ip_and_mac_200_ok()
        self.test_mac_patch_mac_200_ok()

    def test_get_dhcphost_v4(self):
        self.test_mac_with_network()
        dhcpall = self.client.get('/dhcphosts/ipv4/')
        self.assertEqual(dhcpall.status_code, 200)
        dhcpv4 = self.client.get(f'/dhcphosts/{self.network_one.network}')
        self.assertEqual(dhcpv4.status_code, 200)
        self.assertEqual(len(dhcpv4.json()), 2)
        self.assertEqual(Ipaddress.objects.exclude(macaddress='').count(), 2)
        self.assertEqual(dhcpall.json(), dhcpv4.json())
        self.assertEqual(sorted(dhcpall.json()[0].keys()),
                         ['host__name', 'host__zone__name', 'ipaddress', 'macaddress'])

    def test_get_dhcphost_v6(self):
        Ipaddress.objects.create(host=self.host_one,
                                 ipaddress='2001:db8::1',
                                 macaddress='aa:bb:cc:00:00:10')
        dhcpall = self.client.get('/dhcphosts/ipv6/')
        self.assertEqual(dhcpall.status_code, 200)
        dhcprange = self.client.get('/dhcphosts/2001:db8::/64')
        self.assertEqual(dhcprange.status_code, 200)
        self.assertEqual(len(dhcpall.json()), 1)
        self.assertEqual(dhcprange.json(), dhcpall.json())

    def test_get_dhcphost_ipv6byipv4(self):
        # Create an ipaddress without, but will test that we get the
        # ipv4-address' mac.
        Ipaddress.objects.create(host=self.host_one,
                                 ipaddress='2001:db8::1')
        dhcpall = self.client.get('/dhcphosts/ipv6byipv4/')
        self.assertEqual(dhcpall.status_code, 200)
        dhcprange = self.client.get('/dhcphosts/ipv6byipv4/10.0.0.0/24')
        self.assertEqual(dhcprange.status_code, 200)
        self.assertEqual(dhcprange.json(), dhcpall.json())
        self.assertEqual(len(dhcpall.json()), 1)
        data = dhcpall.json()[0]
        self.assertEqual(list(data.keys()),
                         ['host__name', 'host__zone__name', 'ipaddress', 'macaddress'])
        self.assertEqual(data['macaddress'], self.ipaddress_one.macaddress)
        self.assertEqual(data['host__name'], self.host_one.name)

    def test_get_dhcphost_invalid_network(self):
        dhcpall = self.client.get('/dhcphosts/300.10.10.0/24')
        self.assertEqual(dhcpall.status_code, 400)

    def test_mac_with_network_vlan(self):
        Network.objects.create(network='10.0.0.0/24', vlan=10)
        Network.objects.create(network='10.0.1.0/24', vlan=10)
        Network.objects.create(network='2001:db8:1::/64', vlan=10)
        self.test_mac_post_ip_with_mac_201_ok()
        self.test_mac_patch_ip_and_mac_200_ok()
        self.test_mac_patch_mac_200_ok()
        # Make sure it is allowed to add a mac to both IPv4 and IPv6
        # addresses on the same vlan
        response = self.client.post('/ipaddresses/',
                                    {'host': self.host_one.id,
                                     'ipaddress': '10.0.1.10',
                                     'macaddress': '11:22:33:44:55:66'})
        self.assertEqual(response.status_code, 201)
        response = self.client.post('/ipaddresses/',
                                    {'host': self.host_one.id,
                                     'ipaddress': '2001:db8:1::10',
                                     'macaddress': '11:22:33:44:55:66'})
        self.assertEqual(response.status_code, 201)


class APICnamesTestCase(MregAPITestCase):
    """This class defines the test suite for api/cnames """
    def setUp(self):
        super().setUp()
        self.zone_one = create_forward_zone()
        self.zone_two = create_forward_zone(name='example.net')

        self.post_host_one = {'name': 'host1.example.org',
                              'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.post_host_one)
        self.host_one = self.client.get('/hosts/%s' % self.post_host_one['name']).data
        self.post_host_two = {'name': 'host2.example.org',
                              'contact': 'mail@example.org'}
        self.client.post('/hosts/', self.post_host_two)
        self.host_two = self.client.get('/hosts/%s' % self.post_host_two['name']).data

        self.post_data = {'name': 'host-alias.example.org',
                          'host': self.host_one['id'],
                          'ttl': 5000}

    def test_cname_post_201_ok(self):
        """ Posting a cname should return 201 OK"""
        response = self.client.post('/cnames/', self.post_data)
        self.assertEqual(response.status_code, 201)

    def test_cname_get_200_ok(self):
        """GET on an existing cname should return 200 OK."""
        self.client.post('/cnames/', self.post_data)
        response = self.client.get('/cnames/%s' % self.post_data['name'])
        self.assertEqual(response.status_code, 200)

    def test_cname_list_200_ok(self):
        """GET without name should return a list and 200 OK."""
        self.client.post('/cnames/', self.post_data)
        response = self.client.get('/cnames/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(len(response.data['results']), 1)

    def test_cname_empty_list_200_ok(self):
        """GET without name should return a list and 200 OK."""
        response = self.client.get('/cnames/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 0)
        self.assertEqual(response.data['results'], [])

    def test_cname_post_hostname_in_use_400_bad_request(self):
        response = self.client.post('/cnames/', {'host': self.host_one['id'],
                                                 'name': self.host_two['name']})
        self.assertEqual(response.status_code, 400)

    def test_cname_post_nonexistent_host_400_bad_request(self):
        """Adding a cname with a unknown host will return 400 bad request."""
        response = self.client.post('/cnames/', {'host': 1,
                                                 'name': 'alias.example.org'})
        self.assertEqual(response.status_code, 400)

    def test_cname_post_name_not_in_a_zone_400_bad_requst(self):
        """Add a cname with a name without an existing zone if forbidden"""
        response = self.client.post('/cnames/', {'host': self.host_one['id'],
                                                 'name': 'host.example.com'})
        self.assertEqual(response.status_code, 400)

    def test_cname_patch_204_ok(self):
        """ Patching a cname should return 204 OK"""
        self.client.post('/cnames/', self.post_data)
        response = self.client.patch('/cnames/%s' % self.post_data['name'],
                                     {'ttl': '500',
                                      'name': 'new-alias.example.org'})
        self.assertEqual(response.status_code, 204)


class APINetworksTestCase(MregAPITestCase):
    """"This class defines the test suite for api/networks """
    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.network_sample = Network(network='10.0.0.0/24',
                                      description='some description',
                                      vlan=123,
                                      dns_delegated=False,
                                      category='so',
                                      location='Location 1',
                                      frozen=False)
        self.network_ipv6_sample = Network(network='2001:db8::/32',
                                           description='some IPv6 description',
                                           vlan=123,
                                           dns_delegated=False,
                                           category='so',
                                           location='Location 1',
                                           frozen=False)
        # Second samples are needed for the overlap tests
        self.network_sample_two = Network(network='10.0.1.0/28',
                                          description='some description',
                                          vlan=135,
                                          dns_delegated=False,
                                          category='so',
                                          location='Location 2',
                                          frozen=False)

        self.network_ipv6_sample_two = Network(network='2001:db8:8000::/33',
                                               description='some IPv6 description',
                                               vlan=135,
                                               dns_delegated=False,
                                               category='so',
                                               location='Location 2',
                                               frozen=False)

        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org')
        clean_and_save(self.host_one)
        clean_and_save(self.network_sample)
        clean_and_save(self.network_ipv6_sample)
        clean_and_save(self.network_sample_two)
        clean_and_save(self.network_ipv6_sample_two)

        self.patch_data = {
            'description': 'Test network',
            'vlan': '435',
            'dns_delegated': 'False',
            'category': 'si',
            'location': 'new-location'
        }
        self.patch_ipv6_data = {
            'description': 'Test IPv6 network',
            'vlan': '435',
            'dns_delegated': 'False',
            'category': 'si',
            'location': 'new-location'
        }

        self.patch_data_vlan = {'vlan': '435'}
        self.patch_data_network = {'network': '10.0.0.0/28'}
        self.patch_ipv6_data_network = {'network': '2001:db8::/64'}
        self.patch_data_network_overlap = {'network': '10.0.1.0/29'}
        self.patch_ipv6_data_network_overlap = {'network': '2001:db8:8000::/34'}

        self.post_data = {
            'network': '192.0.2.0/29',
            'description': 'Test network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_ipv6_data = {
            'network': 'beef:feed::/32',
            'description': 'Test IPv6 network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_bad_ip = {
            'network': '192.0.2.0.95/29',
            'description': 'Test network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_ipv6_data_bad_ip = {
            'network': 'beef:good::/32',
            'description': 'Test IPv6 network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_bad_mask = {
            'network': '192.0.2.0/2549',
            'description': 'Test network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_ipv6_data_bad_mask = {
            'network': 'beef:feed::/129',
            'description': 'Test IPv6 network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_data_overlap = {
            'network': '10.0.1.0/29',
            'description': 'Test network',
            'vlan': '435',
            'dns_delegated': 'False',
        }
        self.post_ipv6_data_overlap = {
            'network': '2001:db8:8000::/34',
            'description': 'Test IPv6 network',
            'vlan': '435',
            'dns_delegated': 'False',
        }

    def test_networks_post_201_created(self):
        """Posting a network should return 201"""
        response = self.client.post('/networks/', self.post_data)
        self.assertEqual(response.status_code, 201)

    def test_ipv6_networks_post_201_created(self):
        """Posting an IPv6 network should return 201"""
        response = self.client.post('/networks/', self.post_ipv6_data)
        self.assertEqual(response.status_code, 201)

    def test_networks_post_400_bad_request_ip(self):
        """Posting a network with a network that has a malformed IP should return 400"""
        response = self.client.post('/networks/', self.post_data_bad_ip)
        self.assertEqual(response.status_code, 400)

    def test_ipv6_networks_post_400_bad_request_ip(self):
        """Posting an IPv6 network with a network that has a malformed IP should return 400"""
        response = self.client.post('/networks/', self.post_ipv6_data_bad_ip)
        self.assertEqual(response.status_code, 400)

    def test_networks_post_400_bad_request_mask(self):
        """Posting a network with a network that has a malformed mask should return 400"""
        response = self.client.post('/networks/', self.post_data_bad_mask)
        self.assertEqual(response.status_code, 400)

    def test_ipv6_networks_post_400_bad_request_mask(self):
        """Posting an IPv6 network with a network that has a malformed mask should return 400"""
        response = self.client.post('/networks/', self.post_ipv6_data_bad_mask)
        self.assertEqual(response.status_code, 400)

    def test_networks_post_409_overlap_conflict(self):
        """Posting a network with a network which overlaps existing should return 409"""
        response = self.client.post('/networks/', self.post_data_overlap)
        self.assertEqual(response.status_code, 409)

    def test_ipv6_networks_post_409_overlap_conflict(self):
        """Posting an IPv6 network with a network which overlaps existing should return 409"""
        response = self.client.post('/networks/', self.post_ipv6_data_overlap)
        self.assertEqual(response.status_code, 409)

    def test_networks_get_200_ok(self):
        """GET on an existing ip-network should return 200 OK."""
        response = self.client.get('/networks/%s' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)

    def test_ipv6_networks_get_200_ok(self):
        """GET on an existing ipv6-network should return 200 OK."""
        response = self.client.get('/networks/%s' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)

    def test_networks_list_200_ok(self):
        """GET without name should return a list and 200 OK."""
        response = self.client.get('/networks/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 4)
        self.assertEqual(len(response.data['results']), 4)

    def test_networks_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.client.patch('/networks/%s' % self.network_sample.network, self.patch_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/networks/%s' % self.network_sample.network)

    def test_ipv6_networks_patch_204_no_content(self):
        """Patching an existing and valid IPv6 entry should return 204 and Location"""
        response = self.client.patch('/networks/%s' % self.network_ipv6_sample.network, self.patch_ipv6_data)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/networks/%s' % self.network_ipv6_sample.network)

    def test_networks_patch_204_non_overlapping_network(self):
        """Patching an entry with a non-overlapping network should return 204"""
        response = self.client.patch('/networks/%s' % self.network_sample.network, data=self.patch_data_network)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/networks/%s' % self.patch_data_network['network'])

    def test_ipv6_networks_patch_204_non_overlapping_network(self):
        """Patching an entry with a non-overlapping IPv6 network should return 204"""
        response = self.client.patch('/networks/%s' % self.network_ipv6_sample.network,
                                     data=self.patch_ipv6_data_network)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response['Location'], '/networks/%s' % self.patch_ipv6_data_network['network'])

    def test_networks_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        response = self.client.patch('/networks/%s' % self.network_sample.network,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_ipv6_networks_patch_400_bad_request(self):
        """Patching with invalid IPv6 data should return 400"""
        response = self.client.patch('/networks/%s' % self.network_ipv6_sample.network,
                                     data={'this': 'is', 'so': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_networks_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        response = self.client.patch('/networks/193.101.168.0/29', self.patch_data)
        self.assertEqual(response.status_code, 404)

    def test_ipv6_networks_patch_404_not_found(self):
        """Patching a non-existing IPv6 entry should return 404"""
        response = self.client.patch('/networks/3000:4000:5000:6000::/64', self.patch_ipv6_data)
        self.assertEqual(response.status_code, 404)

    def test_networks_patch_409_forbidden_network(self):
        """Patching an entry with an overlapping network should return 409"""
        response = self.client.patch('/networks/%s' % self.network_sample.network,
                                     data=self.patch_data_network_overlap)
        self.assertEqual(response.status_code, 409)

    def test_ipv6_networks_patch_409_forbidden_network(self):
        """Patching an IPv6 entry with an overlapping network should return 409"""
        response = self.client.patch('/networks/%s' % self.network_ipv6_sample.network,
                                     data=self.patch_ipv6_data_network_overlap)
        self.assertEqual(response.status_code, 409)

    def test_networks_get_network_by_ip_200_ok(self):
        """GET on an ip in a known network should return 200 OK."""
        response = self.client.get('/networks/ip/10.0.0.5')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['network'], str(self.network_sample.network))

    def test_ipv6_networks_get_network_by_ip_200_ok(self):
        """GET on an IPv6 in a known network should return 200 OK."""
        response = self.client.get('/networks/ip/2001:db8::12')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['network'], str(self.network_ipv6_sample.network))

    def test_networks_get_network_by_invalid_ip_400_bad_request(self):
        """GET on an IP in a invalid network should return 400 bad request."""
        response = self.client.get('/networks/ip/10.0.0.0.1')
        self.assertEqual(response.status_code, 400)

    def test_networks_get_network_unknown_by_ip_404_not_found(self):
        """GET on an IP in a unknown network should return 404 not found."""
        response = self.client.get('/networks/ip/127.0.0.1')
        self.assertEqual(response.status_code, 404)

    def test_ipv6_networks_get_network_unknown_by_ip_404_not_found(self):
        """GET on an IPv6 in a unknown network should return 404 not found."""
        response = self.client.get('/networks/ip/7000:8000:9000:a000::feed')
        self.assertEqual(response.status_code, 404)

    def test_networks_get_usedcount_200_ok(self):
        """GET on /networks/<ip/mask>/used_count return 200 ok and data."""
        ip_sample = Ipaddress(host=self.host_one, ipaddress='10.0.0.17')
        clean_and_save(ip_sample)

        response = self.client.get('/networks/%s/used_count' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, 1)

    def test_ipv6_networks_get_usedcount_200_ok(self):
        """GET on /networks/<ipv6/mask>/used_count return 200 ok and data."""
        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='2001:db8::beef')
        clean_and_save(ipv6_sample)

        response = self.client.get('/networks/%s/used_count' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, 1)

    def test_networks_get_usedlist_200_ok(self):
        """GET on /networks/<ip/mask>/used_list should return 200 ok and data."""
        ip_sample = Ipaddress(host=self.host_one, ipaddress='10.0.0.17')
        clean_and_save(ip_sample)

        response = self.client.get('/networks/%s/used_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['10.0.0.17'])

    def test_networks_get_host_list_200_ok(self):
        Ipaddress.objects.create(host=self.host_one, ipaddress='10.0.0.17')

        response = self.client.get('/networks/%s/used_host_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'10.0.0.17': ['some-host.example.org']})

    def test_ipv6_networks_get_usedlist_200_ok(self):
        """GET on /networks/<ipv6/mask>/used_list should return 200 ok and data."""
        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='2001:db8::beef')
        clean_and_save(ipv6_sample)

        response = self.client.get('/networks/%s/used_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['2001:db8::beef'])

    def test_ipv6_networks_get_host_list_200_ok(self):
        Ipaddress.objects.create(host=self.host_one, ipaddress='2001:db8::beef')

        response = self.client.get('/networks/%s/used_host_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'2001:db8::beef': ['some-host.example.org']})

    def test_networks_get_unusedcount_200_ok(self):
        """GET on /networks/<ip/mask>/unused_count should return 200 ok and data."""
        ip_sample = Ipaddress(host=self.host_one, ipaddress='10.0.0.17')
        clean_and_save(ip_sample)

        response = self.client.get('/networks/%s/unused_count' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, 250)

    def test_ipv6_networks_get_unusedcount_200_ok(self):
        """GET on /networks/<ipv6/mask>/unused_count should return 200 ok and data."""
        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='2001:db8::beef')
        clean_and_save(ipv6_sample)

        response = self.client.get('/networks/%s/unused_count' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        # Only the first 4000 addresses for IPv6 are returned, :1 and :2 and :3 are reserved
        self.assertEqual(response.data, 3997)

    def test_networks_get_unusedlist_200_ok(self):
        """GET on /networks/<ip/mask>/unused_list should return 200 ok and data."""
        ip_sample = Ipaddress(host=self.host_one, ipaddress='10.0.0.17')
        clean_and_save(ip_sample)

        response = self.client.get('/networks/%s/unused_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 250)

    def test_ipv6_networks_get_unusedlist_200_ok(self):
        """GET on /networks/<ipv6/mask>/unused_list should return 200 ok and data."""
        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='2001:db8::beef')
        clean_and_save(ipv6_sample)

        response = self.client.get('/networks/%s/unused_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 3997)

    def test_networks_get_first_unused_200_ok(self):
        """GET on /networks/<ip/mask>/first_unused should return 200 ok and data."""
        ip_sample = Ipaddress(host=self.host_one, ipaddress='10.0.0.17')
        clean_and_save(ip_sample)

        response = self.client.get('/networks/%s/first_unused' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, '10.0.0.4')

    def test_ipv6_networks_get_first_unused_200_ok(self):
        """GET on /networks/<ipv6/mask>/first_unused should return 200 ok and data."""
        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='2001:db8::beef')
        clean_and_save(ipv6_sample)

        response = self.client.get('/networks/%s/first_unused' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, '2001:db8::4')

    def test_networks_get_first_unued_on_full_network_404_not_found(self):
        """GET first unused IP on a full network should return 404 not found."""
        data = {
            'network': '172.16.0.0/30',
            'description': 'Tiny network',
        }
        response = self.client.post('/networks/', data)
        self.assertEqual(response.status_code, 201)
        response = self.client.get('/networks/%s/first_unused' % data['network'])
        self.assertEqual(response.status_code, 404)

    def test_networks_get_ptroverride_list(self):
        """GET on /networks/<ip/mask>/ptroverride_list should return 200 ok and data."""
        response = self.client.get('/networks/%s/ptroverride_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])
        ptr = PtrOverride(host=self.host_one, ipaddress='10.0.0.10')
        clean_and_save(ptr)
        response = self.client.get('/networks/%s/ptroverride_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['10.0.0.10'])

    def test_ipv6_networks_get_ptroverride_list(self):
        """GET on /networks/<ipv6/mask>/ptroverride_list should return 200 ok and data."""
        response = self.client.get('/networks/%s/ptroverride_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])
        ptr = PtrOverride(host=self.host_one, ipaddress='2001:db8::feed')
        clean_and_save(ptr)
        response = self.client.get('/networks/%s/ptroverride_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['2001:db8::feed'])

    def test_networks_get_reserved_list(self):
        """GET on /networks/<ip/mask>/reserverd_list should return 200 ok and data."""
        response = self.client.get('/networks/%s/reserved_list' % self.network_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['10.0.0.0', '10.0.0.1',
                         '10.0.0.2', '10.0.0.3', '10.0.0.255'])

    def test_ipv6_networks_get_reserved_list(self):
        """GET on /networks/<ipv6/mask>/reserverd_list should return 200 ok and data."""
        response = self.client.get('/networks/%s/reserved_list' % self.network_ipv6_sample.network)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, ['2001:db8::', '2001:db8::1',
                         '2001:db8::2', '2001:db8::3'])

    def test_networks_delete_204_no_content(self):
        """Deleting an existing entry with no adresses in use should return 204"""
        response = self.client.post('/networks/', self.post_data)
        self.assertEqual(response.status_code, 201)
        response = self.client.delete('/networks/%s' % self.post_data['network'])
        self.assertEqual(response.status_code, 204)

    def test_ipv6_networks_delete_204_no_content(self):
        """Deleting an existing IPv6 entry with no adresses in use should return 204"""
        response = self.client.post('/networks/', self.post_ipv6_data)
        self.assertEqual(response.status_code, 201)
        response = self.client.delete('/networks/%s' % self.post_ipv6_data['network'])
        self.assertEqual(response.status_code, 204)

    def test_networks_delete_409_conflict(self):
        """Deleting an existing entry with  adresses in use should return 409"""
        response = self.client.post('/networks/', self.post_data)
        self.assertEqual(response.status_code, 201)

        ip_sample = Ipaddress(host=self.host_one, ipaddress='192.0.2.1')
        clean_and_save(ip_sample)

        response = self.client.delete('/networks/%s' % self.post_data['network'])
        self.assertEqual(response.status_code, 409)

    def test_ipv6_networks_delete_409_conflict(self):
        """Deleting an existing IPv6 entry with adresses in use should return 409"""
        response = self.client.post('/networks/', self.post_ipv6_data)
        self.assertEqual(response.status_code, 201)

        ipv6_sample = Ipaddress(host=self.host_one, ipaddress='beef:feed::beef')
        clean_and_save(ipv6_sample)

        response = self.client.delete('/networks/%s' % self.post_ipv6_data['network'])
        self.assertEqual(response.status_code, 409)


class APIModelChangeLogsTestCase(MregAPITestCase):
    """This class defines the test suite for api/history """

    def setUp(self):
        """Define the test client and other variables."""
        super().setUp()
        self.host_one = Host(name='some-host.example.org',
                             contact='mail@example.org',
                             ttl=300,
                             loc='23 58 23 N 10 43 50 E 80m',
                             comment='some comment')
        clean_and_save(self.host_one)

        self.log_data = {'host': self.host_one.id,
                         'name': self.host_one.name,
                         'contact': self.host_one.contact,
                         'ttl': self.host_one.ttl,
                         'loc': self.host_one.loc,
                         'comment': self.host_one.comment}

        self.log_entry_one = ModelChangeLog(table_name='hosts',
                                            table_row=self.host_one.id,
                                            data=self.log_data,
                                            action='saved',
                                            timestamp=timezone.now())
        clean_and_save(self.log_entry_one)

    def test_history_get_200_OK(self):
        """Get on /history/ should return a list of table names that have entries, and 200 OK."""
        response = self.client.get('/history/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('hosts', response.data)

    def test_history_host_get_200_OK(self):
        """Get on /history/hosts/<pk> should return a list of dicts containing entries for that host"""
        response = self.client.get('/history/hosts/{}'.format(self.host_one.id))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)
