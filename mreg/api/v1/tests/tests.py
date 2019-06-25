from datetime import timedelta
from operator import itemgetter
from unittest import skip

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

    def get_token_client(self, username=None, superuser=True, adminuser=False):
        if username is None:
            if superuser:
                username = 'superuser'
            elif adminuser:
                username = 'adminuser'
            else:
                username = 'nobody'
        self.user, created = get_user_model().objects.get_or_create(username=username)
        self.user.groups.clear()
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

    @staticmethod
    def _create_path(path):
        if path.startswith('/api/'):
            return path
        elif path.startswith('/'):
            return f'/api/v1/{path[1:]}'
        return f'/api/v1/{path}'

    def _assert_delete_and_status(self, path, status_code):
        response = self.client.delete(self._create_path(path))
        self.assertEqual(response.status_code, status_code)
        return response

    def _assert_get_and_status(self, path, status_code):
        response = self.client.get(self._create_path(path))
        self.assertEqual(response.status_code, status_code)
        return response

    def _assert_patch_and_status(self, path, status_code, data=None):
        response = self.client.patch(self._create_path(path), data)
        self.assertEqual(response.status_code, status_code)
        return response

    def _assert_post_and_status(self, path, status_code, data=None):
        response = self.client.post(self._create_path(path), data)
        self.assertEqual(response.status_code, status_code)
        return response

    def assert_delete(self, path):
        return self.assert_delete_and_204(path)

    def assert_delete_and_204(self, path):
        return self._assert_delete_and_status(path, 204)

    def assert_delete_and_403(self, path):
        return self._assert_delete_and_status(path, 403)

    def assert_delete_and_404(self, path):
        return self._assert_delete_and_status(path, 404)

    def assert_delete_and_409(self, path):
        return self._assert_delete_and_status(path, 409)

    def assert_get(self, path):
        return self.assert_get_and_200(path)

    def assert_get_and_200(self, path):
        return self._assert_get_and_status(path, 200)

    def assert_get_and_400(self, path):
        return self._assert_get_and_status(path, 400)

    def assert_get_and_401(self, path):
        return self._assert_get_and_status(path, 401)

    def assert_get_and_404(self, path):
        return self._assert_get_and_status(path, 404)

    def assert_patch(self, path, data=None):
        return self.assert_patch_and_204(path, data)

    def assert_patch_and_204(self, path, data=None):
        return self._assert_patch_and_status(path, 204, data)

    def assert_patch_and_400(self, path, data=None):
        return self._assert_patch_and_status(path, 400, data)

    def assert_patch_and_403(self, path, data=None):
        return self._assert_patch_and_status(path, 403, data)

    def assert_patch_and_404(self, path, data=None):
        return self._assert_patch_and_status(path, 404, data)

    def assert_patch_and_405(self, path, data=None):
        return self._assert_patch_and_status(path, 405, data)

    def assert_patch_and_409(self, path, data=None):
        return self._assert_patch_and_status(path, 409, data)

    def assert_post(self, path, data=None):
        return self.assert_post_and_201(path, data)

    def assert_post_and_200(self, path, data=None):
        return self._assert_post_and_status(path, 200, data)

    def assert_post_and_201(self, path, data=None):
        return self._assert_post_and_status(path, 201, data)

    def assert_post_and_400(self, path, data=None):
        return self._assert_post_and_status(path, 400, data)

    def assert_post_and_401(self, path, data=None):
        return self._assert_post_and_status(path, 401, data)

    def assert_post_and_403(self, path, data=None):
        return self._assert_post_and_status(path, 403, data)

    def assert_post_and_404(self, path, data=None):
        return self._assert_post_and_status(path, 404, data)

    def assert_post_and_409(self, path, data=None):
        return self._assert_post_and_status(path, 409, data)


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
        self.assert_get("/zones/")
        self.assert_post_and_200("/api/token-logout/")
        self.assert_get_and_401("/zones/")

    def test_logout_without_authentication(self):
        self.client = APIClient()
        self.assert_post_and_401("/api/token-logout/")

    def test_force_expire(self):
        self.assert_get("/zones/")
        token = Token.objects.get(user=self.user)
        EXPIRE_HOURS = getattr(settings, 'REST_FRAMEWORK_TOKEN_EXPIRE_HOURS', 8)
        token.created = timezone.now() - timedelta(hours=EXPIRE_HOURS)
        token.save()
        self.assert_get_and_401("/zones/")

    def test_is_active_false(self):
        self.assert_get("/zones/")
        self.user.is_active = False
        self.user.save()
        self.assert_get_and_401("/zones/")

    def test_is_deleted(self):
        self.assert_get("/zones/")
        self.user.delete()
        self.assert_get_and_401("/zones/")


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
        self.assert_post_and_201('/hosts/', self.host1)
        self.zone_exampleorg.refresh_from_db()
        self.zone_1010.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)
        self.assertTrue(self.zone_1010.updated)
        self.assertGreater(self.zone_exampleorg.updated_at, old_org_updated_at)
        self.assertGreater(self.zone_1010.updated_at, old_1010_updated_at)

    def test_rename_host(self):
        self.assert_post('/hosts/', self.host1)
        self.zone_exampleorg.refresh_from_db()
        self.zone_examplecom.refresh_from_db()
        self.zone_1010.refresh_from_db()
        old_org_updated_at = self.zone_exampleorg.updated_at
        old_com_updated_at = self.zone_examplecom.updated_at
        old_1010_updated_at = self.zone_1010.updated_at
        ret = self.assert_patch_and_204('/hosts/host1.example.org',
                                        {"name": "host1.example.com"})
        self.assert_get(ret['Location'])
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
        self.assert_patch_and_204('/zones/example.org', {'default_ttl': 1000})
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_changed_nameservers(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.assert_patch_and_204('/zones/example.org/nameservers',
                                  {'primary_ns': 'ns2.example.org'})
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_added_subzone(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.assert_post_and_201("/zones/", self.subzone)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_removed_subzone(self):
        self.assert_post_and_201("/zones/", self.subzone)
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.assert_delete_and_204("/zones/sub.example.org")
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_add_delegation(self):
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.assert_post_and_201("/zones/example.org/delegations/", self.delegation)
        self.zone_exampleorg.refresh_from_db()
        self.assertTrue(self.zone_exampleorg.updated)

    def test_remove_delegation(self):
        self.assert_post_and_201("/zones/example.org/delegations/", self.delegation)
        self.zone_exampleorg.updated = False
        self.zone_exampleorg.save()
        self.assert_delete_and_204("/zones/example.org/delegations/delegated.example.org")
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
        def _add(host):
            self.assert_post_and_201('/hosts/', host)

        def _check_zone_id(hostname, zone):
            res = self.assert_get(f'/hosts/{hostname}')
            self.assertEqual(res.json()['zone'], zone.id)

        _add(self.org_host1)
        _add(self.org_host2)
        _add(self.sub_host1)
        _add(self.sub_host2)
        _add(self.long_host1)
        _add(self.long_host2)

        _check_zone_id(self.org_host1['name'], self.zone_org)
        _check_zone_id(self.org_host2['name'], self.zone_org)
        _check_zone_id(self.sub_host1['name'], self.zone_sub)
        _check_zone_id(self.sub_host2['name'], self.zone_sub)
        _check_zone_id(self.long_host1['name'], self.zone_long)
        _check_zone_id(self.long_host2['name'], self.zone_long)

    def test_add_to_nonexistent(self):
        data = {"name": "host1.example.net",
                "ipaddress": "10.10.0.10",
                "contact": "mail@example.org"}
        self.assert_post_and_201("/hosts/", data)
        res = self.assert_get(f"/hosts/{data['name']}")
        self.assertEqual(res.json()['zone'], None)

    def test_rename_host_to_valid_zone(self):
        self.assert_post_and_201('/hosts/', self.org_host1)
        self.assert_patch_and_204('/hosts/host1.example.org',
                                  {"name": "host1.example.com"})
        res = self.assert_get(f"/hosts/host1.example.com")
        self.assertEqual(res.json()['zone'], self.zone_com.id)

    def test_rename_host_to_unknown_zone(self):
        self.assert_post_and_201('/hosts/', self.org_host1)
        self.assert_patch_and_204('/hosts/host1.example.org',
                                  {"name": "host1.example.net"})
        res = self.assert_get(f"/hosts/host1.example.net")
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
        self.assert_get('/hosts/%s' % self.host_one.name)

    def test_hosts_get_case_insensitive_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/hosts/%s' % self.host_one.name.upper())

    def test_hosts_list_200_ok(self):
        """List all hosts should return 200"""
        response = self.assert_get('/hosts/')
        data = response.json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['results']), 2)

    def test_hosts_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/hosts/nonexistent.example.org')

    def test_hosts_post_201_created(self):
        """"Posting a new host should return 201 and location"""
        response = self.assert_post_and_201('/hosts/', self.post_data)
        self.assertEqual(response['Location'], '/api/v1/hosts/%s' % self.post_data['name'])

    def test_hosts_post_case_insenstive_201_created(self):
        """"Posting a new host should return 201 and location"""
        data = self.post_data
        data['name'] = data['name'].upper()
        response = self.assert_post_and_201('/hosts/', data)
        self.assertEqual(response['Location'], '/api/v1/hosts/%s' % self.post_data['name'])

    def test_hosts_post_400_invalid_ip(self):
        """"Posting a new host with an invalid IP should return 400"""
        post_data = {'name': 'failing.example.org', 'ipaddress': '300.400.500.600',
                     'contact': 'fail@example.org'}
        self.assert_post_and_400('/hosts/', post_data)
        self.assert_get_and_404('/hosts/failing.example.org')

    def test_hosts_post_409_conflict_name(self):
        """"Posting a new host with a name already in use should return 409"""
        self.assert_post_and_409('/hosts/', self.post_data_name)

    def test_hosts_post_409_conflict_cname(self):
        """"Posting a new host with a name already in use as cname should return 409"""
        cname_data = {'name': 'host3.example.org', 'host': self.host_one.id}
        self.assert_post_and_201('/cnames/', cname_data)
        conflicting_host_data = {'name': 'host3.example.org', 'ipaddress': '127.0.0.3',
                                 'contact': 'hostmaster@example.org'}
        self.assert_post_and_409('/hosts/', conflicting_host_data)

    def test_hosts_patch_204_no_content(self):
        """Patching an existing and valid entry should return 204 and Location"""
        response = self.assert_patch_and_204('/hosts/%s' % self.host_one.name, self.patch_data)
        self.assertEqual(response['Location'], '/api/v1/hosts/%s' % self.patch_data['name'])

    def test_hosts_patch_without_name_204_no_content(self):
        """Patching an existing entry without having name in patch should
        return 204"""
        self.assert_patch_and_204('/hosts/%s' % self.host_one.name, {"ttl": 5000})

    def test_hosts_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        self.assert_patch_and_400('/hosts/%s' % self.host_one.name, data={'this': 'is', 'so': 'wrong'})

    def test_hosts_patch_400_bad_ttl(self):
        """Patching with invalid ttl should return 400"""
        def _test_ttl(ttl):
            self.assert_patch_and_400('/hosts/%s' % self.host_one.name, data={'ttl': ttl})
        _test_ttl(100)
        _test_ttl(100000)

    def test_hosts_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        self.assert_patch_and_404('/hosts/feil-navn/', self.patch_data)

    def test_hosts_patch_409_conflict_name(self):
        """Patching an entry with a name that already exists should return 409"""
        self.assert_patch_and_409('/hosts/%s' % self.host_one.name, {'name': self.host_two.name})

    def test_hosts_patch_409_conflict_cname(self):
        """"Patching an entry host with a name already in use as cname should return 409"""
        cname_data = {'name': 'host3.example.org', 'host': self.host_one.id}
        self.assert_post_and_201('/cnames/', cname_data)
        conflicting_host_data = {'name': 'host3.example.org'}
        self.assert_patch_and_409('/hosts/%s' % self.host_one.name, conflicting_host_data)


class APIHostsTestCaseAsAdminuser(APIHostsTestCase):
    """Same tests as in APIHostsTestCase, only test as admin and not super"""

    def setUp(self):
        super().setUp()
        self.client = self.get_token_client(superuser=False, adminuser=True)


class APIHostsAutoTxtRecords(MregAPITestCase):

    data = {'name': 'host.example.org', 'contact': 'mail@example.org'}
    settings.TXT_AUTO_RECORDS = {'example.org': ('test1', 'test2')}

    def test_no_zone_no_txts_added(self):
        self.assertFalse(Txt.objects.exists())
        self.assert_post_and_201('/hosts/', self.data)
        self.assertFalse(Txt.objects.exists())

    def test_zone_txts_added(self):
        self.assertFalse(Txt.objects.exists())
        ForwardZone.objects.create(name='example.org',
                                   primary_ns='ns1.example.org',
                                   email='hostmaster@example.org')
        self.assert_post_and_201('/hosts/', self.data)
        response = self.assert_get('/hosts/%s' % self.data['name']).json()
        txts = tuple(map(itemgetter('txt'), response['txts']))
        self.assertEqual(txts, list(settings.TXT_AUTO_RECORDS.values())[0])


class APIHostsIdna(MregAPITestCase):

    data_v4 = {'name': 'æøå.example.org', "ipaddress": '10.10.0.1'}

    def _add_data(self, data):
        self.assert_post_and_201('/hosts/', data)

    def test_hosts_idna_forward(self):
        """Test that a hostname outside ASCII 128 is handled properly"""
        zone = create_forward_zone()
        self._add_data(self.data_v4)
        response = self.assert_get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c                     IN A      10.10.0.1' in response.data)

    def test_hosts_idna_reverse_v4(self):
        zone = create_reverse_zone()
        self._add_data(self.data_v4)
        response = self.assert_get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c.example.org.' in response.data)

    def test_hosts_idna_reverse_v6(self):
        zone = create_reverse_zone('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        data = {'name': 'æøå.example.org', "ipaddress": '2001:db8::1'}
        self._add_data(data)
        response = self.assert_get(f'/zonefiles/{zone.name}')
        self.assertTrue('xn--5cab8c.example.org.' in response.data)


class APIHinfoTestCase(MregAPITestCase):
    """Test HinfoPresets and hinfo field on Host"""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.assert_post_and_201('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_hinfopresets_post_201_ok(self):
        data = {'cpu': 'cpuname', 'os': 'superos'}
        self.assert_post_and_201('/hinfopresets/', data)

    def test_hinfopresets_list(self):
        self.test_hinfopresets_post_201_ok()
        ret = self.assert_get('/hinfopresets/')
        self.assertEqual(ret.data['count'], 1)

    def test_hinfopresets_post_must_have_both_fields_400_bad_request(self):
        ret = self.assert_post_and_400('/hinfopresets/', {'cpu': 'cpuname'})
        self.assertEqual(ret.json(), {'os': ['This field is required.']})
        self.assert_post_and_400('/hinfopresets/', {'os': 'superos'})

    def test_patch_add_hinfo_to_host_204_ok(self):
        data = {'cpu': 'cpuname', 'os': 'superos'}
        ret = self.assert_post_and_201('/hinfopresets/', data)
        hinfoid = ret.json()['id']
        self.assert_patch_and_204(f'/hosts/{self.host.name}', {'hinfo': hinfoid})
        self.host.refresh_from_db()
        self.assertEqual(self.host.hinfo.id, hinfoid)

    def test_patch_remove_hinfo_to_host_204_ok(self):
        self.assert_patch_and_204(f'/hosts/{self.host.name}', {'hinfo': ''})
        self.host.refresh_from_db()
        self.assertEqual(self.host.hinfo, None)

    def test_patch_add_invalid_hinfo_to_host_400_bad_request(self):
        self.assert_patch_and_400(f'/hosts/{self.host.name}', {'hinfo': 12345788})


class APIMxTestcase(MregAPITestCase):
    """Test MX records."""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.assert_post_and_201('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_mx_post(self):
        data = {'host': self.host.id,
                'priority': 10,
                'mx': 'smtp.example.org'}
        self.assert_post_and_201("/mxs/", data)

    def test_mx_post_reject_invalid(self):
        # priority is an 16 bit uint, e.g. 0..65535.
        data = {'host': self.host.id,
                'priority': -1,
                'mx': 'smtp.example.org'}
        self.assert_post_and_400("/mxs/", data)
        data = {'host': self.host.id,
                'priority': 1000000,
                'mx': 'smtp.example.org'}
        self.assert_post_and_400("/mxs/", data)
        data = {'host': self.host.id,
                'priority': 1000,
                'mx': 'invalidhostname'}
        self.assert_post_and_400("/mxs/", data)

    def test_mx_list(self):
        self.test_mx_post()
        ret = self.assert_get("/mxs/")
        self.assertEqual(ret.data['count'], 1)

    def test_mx_delete(self):
        self.test_mx_post()
        mxs = self.assert_get("/mxs/").json()['results']
        self.assert_delete_and_204("/mxs/{}".format(mxs[0]['id']))
        mxs = self.assert_get("/mxs/").json()
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
        mxs = self.assert_get("/mxs/").data['results']
        self.assert_delete_and_204("/mxs/{}".format(mxs[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)


class APINaptrTestCase(MregAPITestCase):

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'host.example.org',
                          'contact': 'mail@example.org'}
        self.assert_post_and_201('/hosts/', self.host_data)
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
        self.assert_post_and_201("/naptrs/", data)

    def test_naptr_list(self):
        self.test_naptr_post()
        ret = self.assert_get("/naptrs/")
        self.assertEqual(ret.data['count'], 1)

    def test_naptr_delete(self):
        self.test_naptr_post()
        naptrs = self.assert_get("/naptrs/").json()['results']
        self.assert_delete_and_204("/naptrs/{}".format(naptrs[0]['id']))
        naptrs = self.assert_get("/naptrs/").json()
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
        naptrs = self.assert_get("/naptrs/").data['results']
        self.assert_delete("/naptrs/{}".format(naptrs[0]['id']))
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.updated)

    def test_naptr_post_409_conflict_cname(self):
        cname_data = {'name': 'replacement.example.org', "host": self.host.id}
        self.assert_post_and_201('/cnames/', cname_data)
        conflicting_naptr_data = {'host': self.host.id,
                'preference': 10,
                'order': 20,
                'flag': 'a',
                'service': 'SERVICE',
                'regex': r'1(.*@example.org)',
                'replacement': 'replacement.example.org'
                }
        self.assert_post_and_409('/naptrs/', conflicting_naptr_data)

    def test_naptr_patch_409_conflict_cname(self):
        cname_data = {'name': 'replacement1.example.org', "host": self.host.id}
        self.assert_post_and_201('/cnames/', cname_data)
        self.test_naptr_post()
        naptrs = self.assert_get("/naptrs/").json()['results']
        conflicting_naptr_data = {'replacement': 'replacement1.example.org'}
        self.assert_patch_and_409("/naptrs/{}".format(naptrs[0]['id']), conflicting_naptr_data)


class APIPtrOverrideTestcase(MregAPITestCase):
    """Test PtrOverride records."""

    def setUp(self):
        super().setUp()
        self.host_data = {'name': 'ns1.example.org',
                          'contact': 'mail@example.org'}
        self.assert_post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

        self.ptr_override_data = {'host': self.host.id,
                                  'ipaddress': '10.0.0.2'}

        self.ptr_override_ipv6_data = {'host': self.host.id,
                                       'ipaddress': '2001:db8::beef'}

        self.assert_post('/ptroverrides/', self.ptr_override_data)
        self.ptr_override = PtrOverride.objects.get(ipaddress=self.ptr_override_data['ipaddress'])
        self.assert_post('/ptroverrides/', self.ptr_override_ipv6_data)
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
        self.assert_post("/ptroverrides/", ptr_override_data)

    def test_ptr_override_ipv6_post_201(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3'}
        self.assert_post("/ptroverrides/", ptr_override_ipv6_data)

    def test_ptr_override_delete_204(self):
        ptr_override_data = {'host': self.host.id,
                             'ipaddress': '10.0.0.4'}
        self.assert_post("/ptroverrides/", ptr_override_data)
        ptroverrides = self.assert_get("/ptroverrides/").json()['results']
        old_count = len(ptroverrides)
        self.assert_delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        ptroverrides = self.assert_get("/ptroverrides/").json()['results']
        new_count = len(ptroverrides)
        self.assertLess(new_count, old_count)

    def test_ptr_override_ipv6_delete_204(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3'}
        self.assert_post("/ptroverrides/", ptr_override_ipv6_data)
        ptroverrides = self.assert_get("/ptroverrides/").json()['results']
        old_count = len(ptroverrides)
        self.assert_delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        ptroverrides = self.assert_get("/ptroverrides/").json()['results']
        new_count = len(ptroverrides)
        self.assertLess(new_count, old_count)

    def test_ptr_override_patch_204(self):
        self.assert_patch("/ptroverrides/%s" % self.ptr_override.id, self.ptr_override_patch_data)

    def test_ptr_override_ipv6_patch_204(self):
        self.assert_patch("/ptroverrides/%s" % self.ptr_ipv6_override.id, self.ptr_override_ipv6_patch_data)

    @skip("This test crashes the database and is skipped "
          "until the underlying problem has been fixed")
    def test_ptr_override_reject_invalid_ipv4_400(self):
        ptr_override_data = {'host': self.host.id,
                             'ipaddress': '10.0.0.400'}
        self.assert_post_and_400("/ptroverrides/", ptr_override_data)

    def test_ptr_override_reject_invalid_ipv6_400(self):
        ptr_override_ipv6_data = {'host': self.host.id,
                                  'ipaddress': '2001:db8::3zzz'}
        self.assert_post_and_400("/ptroverrides/", ptr_override_ipv6_data)

    def test_ptr_override_reject_nonexisting_host_400(self):
        ptr_override_bad_data = {'host': -1, 'ipaddress': '10.0.0.7'}
        self.assert_post_and_400("/ptroverrides/", ptr_override_bad_data)

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
        ptroverrides = self.assert_get("/ptroverrides/").data['results']
        self.assert_delete("/ptroverrides/{}".format(ptroverrides[0]['id']))
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
        ptroverrides = self.assert_get("/ptroverrides/").data['results']
        self.assert_delete("/ptroverrides/{}".format(ptroverrides[-1]['id']))
        self.ipv6_zone.refresh_from_db()
        self.assertTrue(self.ipv6_zone.updated)

    def test_ptr_override_reject_taken_ip_400(self):
        new_host_data = {'name': 'ns2.example.org',
                         'contact': 'mail@example.org'}
        self.assert_post('/hosts/', new_host_data)
        new_host = Host.objects.get(name=new_host_data['name'])
        ptr_override_data = {'host': new_host.id,
                             'ipaddress': self.ptr_override_data['ipaddress']}
        self.assert_post_and_400("/ptroverrides/", ptr_override_data)

    def test_ptr_override_reject_taken_ipv6_400(self):
        new_host_data = {'name': 'ns2.example.org',
                         'contact': 'mail@example.org'}
        self.assert_post('/hosts/', new_host_data)
        new_host = Host.objects.get(name=new_host_data['name'])
        ptr_override_ipv6_data = {'host': new_host.id,
                                  'ipaddress': self.ptr_override_ipv6_data['ipaddress']}
        self.assert_post_and_400("/ptroverrides/", ptr_override_ipv6_data)

    def test_ptr_override_list(self):
        ret = self.assert_get("/ptroverrides/")
        self.assertEqual(ret.data['count'], 2)

    def test_ptr_override_create_new_host(self):
        # Adding a new host with already existing IP should
        # create a PtrOverride for it
        ret = self.assert_get("/ptroverrides/")
        old_count = ret.data['count']
        host_data = {'name': 'ns3.example.org',
                     'contact': 'mail@example.org',
                     'ipaddress': '10.0.0.5'}
        host2_data = {'name': 'ns4.example.org',
                      'contact': 'mail@example.org',
                      'ipaddress': '10.0.0.5'}
        self.assert_post('/hosts/', host_data)
        ret = self.assert_get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertEqual(new_count, old_count)
        self.assert_post('/hosts/', host2_data)
        ret = self.assert_get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertGreater(new_count, old_count)
        # Now check that the last PtrOverride
        # points to the first host holding the IP
        ptr_override = ret.data['results'][-1]
        self.assertEqual(ptr_override['ipaddress'], '10.0.0.5')
        ret = self.assert_get('/hosts/?name=ns3.example.org')
        host_id = ret.data['results'][0]['id']
        self.assertEqual(ptr_override['host'], host_id)

    def test_ptr_override_ipv6_create_new_host(self):
        # Adding a new host with already existing IPv6 should
        # create a PtrOverride for it
        ret = self.assert_get("/ptroverrides/")
        old_count = ret.data['count']
        host_ipv6_data = {'name': 'ns3.example.org',
                          'contact': 'mail@example.org',
                          'ipaddress': '2001:db8::7'}
        host2_ipv6_data = {'name': 'ns4.example.org',
                           'contact': 'mail@example.org',
                           'ipaddress': '2001:db8::7'}
        self.assert_post('/hosts/', host_ipv6_data)
        ret = self.assert_get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertEqual(new_count, old_count)
        self.assert_post('/hosts/', host2_ipv6_data)
        ret = self.assert_get("/ptroverrides/")
        new_count = ret.data['count']
        self.assertGreater(new_count, old_count)
        # Now check that the last PtrOverride
        # points to the first host holding the IP
        ptr_override = ret.data['results'][-1]
        self.assertEqual(ptr_override['ipaddress'], '2001:db8::7')
        ret = self.assert_get('/hosts/?name=ns3.example.org')
        host_id = ret.data['results'][0]['id']
        self.assertEqual(ptr_override['host'], host_id)

    def test_ptr_override_delete_with_host(self):
        # Deleting a host with assigned PtrOverrides should
        # delete the PtrOverrides too
        ret = self.assert_get("/ptroverrides/")
        self.assertEqual(ret.data['count'], 2)
        self.assert_delete("/hosts/{}".format(self.host.name))
        ret = self.assert_get("/ptroverrides/")
        self.assertEqual(ret.data['count'], 0)


class APISshfpTestcase(MregAPITestCase):
    """Test SSHFP records."""

    def setUp(self):
        super().setUp()
        self.zone = create_forward_zone()
        self.host_data = {'name': 'ns1.example.org',
                          'contact': 'mail@example.org'}
        self.assert_post('/hosts/', self.host_data)
        self.host = Host.objects.get(name=self.host_data['name'])

    def test_sshfp_post(self):
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        self.assert_post("/sshfps/", data)

    def test_sshfp_post_reject_invalid(self):
        # Invalid fingerprint, algorithm, hash_type
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': 'beefistasty'}
        self.assert_post_and_400("/sshfps/", data)
        data = {'host': self.host.id,
                'algorithm': 0,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        self.assert_post_and_400("/sshfps/", data)
        data = {'host': self.host.id,
                'algorithm': 1,
                'hash_type': 3,
                'fingerprint': '0123456789abcdef'}
        self.assert_post_and_400("/sshfps/", data)

    def test_sshfp_list(self):
        self.test_sshfp_post()
        ret = self.assert_get("/sshfps/")
        self.assertEqual(ret.data['count'], 1)

    def test_sshfp_delete(self):
        self.test_sshfp_post()
        sshfps = self.assert_get("/sshfps/").json()['results']
        self.assert_delete("/sshfps/{}".format(sshfps[0]['id']))
        sshfps = self.assert_get("/sshfps/").json()
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
        sshfps = self.assert_get("/sshfps/").data['results']
        self.assert_delete("/sshfps/{}".format(sshfps[0]['id']))
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
        self.assert_get_and_404('/zones/nonexisting.example.org')

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/zones/%s' % self.zone_one.name)

    def test_zones_list_200_ok(self):
        """Listing all zones should return 200"""
        response = self.assert_get('/zones/')
        self.assertEqual(response.json()[0]['name'], self.zone_one.name)
        self.assertEqual(len(response.json()), 1)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        response = self.assert_get('/zones/%s' % self.zone_one.name)
        self.assert_post_and_409('/zones/', {'name': response.data['name']})

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201 and location"""
        response = self.assert_post('/zones/', self.post_data_one)
        self.assertEqual(response['Location'], '/api/v1/zones/%s' % self.post_data_one['name'])

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        self.assert_post('/zones/', self.post_data_one)
        self.assert_post('/zones/', self.post_data_two)
        response_one = self.assert_get('/zones/%s' % self.post_data_one['name'])
        response_two = self.assert_get('/zones/%s' % self.post_data_two['name'])
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'])
        self.assertEqual(response_one.data['serialno'], create_serialno())

    def test_zones_patch_serialno(self):
        """Make sure that the zone's serialno_updated_at field is updated when
        the serialno is updated"""
        response = self.assert_post('/zones/', self.post_data_one)
        old_data = self.assert_get(response['Location']).data
        self.assert_patch(response['Location'], data={'serialno': 1000000000})
        new_data = self.assert_get(response['Location']).data
        self.assertLess(old_data['serialno_updated_at'], new_data['serialno_updated_at'])

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        response = self.assert_get('/zones/%s' % self.zone_one.name)
        self.assert_patch_and_403('/zones/%s' % self.zone_one.name,
                                  {'name': response.data['name']})

    def test_zones_patch_403_forbidden_primary_ns(self):
        """Trying to patch the primary_ns to be a nameserver that isn't in the nameservers list should return 403"""
        self.assert_post('/zones/', self.post_data_two)
        self.assert_patch_and_403('/zones/%s' % self.post_data_two['name'],
                                  {'primary_ns': self.host_three.name})

    def test_zones_patch_403_forbidden_nameservers(self):
        """Trying to patch the nameservers directly is not allowed."""
        self.assert_post('/zones/', self.post_data_two)
        self.assert_patch_and_403('/zones/%s' % self.post_data_two['name'],
                                  {'nameservers': self.host_three.name})

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        self.assert_patch_and_404("/zones/nonexisting.example.org", self.patch_data)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        self.assert_patch('/zones/%s' % self.zone_one.name, self.patch_data)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        self.assert_delete('/zones/%s' % self.zone_one.name)

    def test_zones_delete_with_hosts_403_forbidden(self):
        """"Deleting an existing zone with Hosts should return 403"""
        self.assert_post('/hosts/', {'name': 'host.example.org'})
        self.assert_delete_and_403('/zones/%s' % self.zone_one.name)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        self.assert_delete_and_404("/zones/nonexisting.example.org")

    def test_zone_by_hostname_404_not_found(self):
        self.assert_get_and_404('/zones/hostname/invalid.example.wrongtld')

    def test_zone_by_hostname_200_ok(self):
        def _test(hostname, zone, zonetype):
            data = self.assert_get(f'/zones/hostname/{hostname}').json()
            self.assertEqual(data[zonetype]['name'], zone)
        _test('host.example.org', 'example.org', 'zone')
        _test('example.org', 'example.org', 'zone')


class APIReverseZonesTestCase(MregAPITestCase):
    """"This class defines the test suite for reverse zones API """

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
        self.post_data_one = {'name': 'example.com',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org",
                              'refresh': 400, 'retry': 300, 'expire': 800,
                              'soa_ttl': 350, 'default_ttl': 1000}
        self.post_data_two = {'name': 'example.net',
                              'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                              'email': "hostmaster@example.org"}
        self.patch_data = {'refresh': '500', 'expire': '1000'}
        clean_and_save(self.host_one)
        clean_and_save(self.host_two)
        clean_and_save(self.ns_one)
        clean_and_save(self.ns_two)

    def test_zones_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/zones/1.10.in-addr.arpa')
        self.assert_get_and_404('/zones/0.8.b.d.0.1.0.0.2.ip6.arpa')

    def test_zones_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/zones/%s' % self.zone_one.name)

    def test_zones_list_200_ok(self):
        """Listing all zones should return 200"""
        response = self.assert_get('/zones/')
        self.assertEqual(response.json()[0]['name'], self.zone_one.name)
        self.assertEqual(len(response.json()), 1)

    def test_zones_post_409_name_conflict(self):
        """"Posting a entry that uses a name that is already taken should return 409"""
        response = self.assert_get('/zones/%s' % self.zone_one.name)
        self.assert_post_and_409('/zones/', {'name': response.data['name']})

    def test_zones_post_201_created(self):
        """"Posting a new zone should return 201 and location"""
        response = self.assert_post('/zones/', self.post_data_one)
        self.assertEqual(response['Location'], '/api/v1/zones/%s' % self.post_data_one['name'])

    def test_zones_post_serialno(self):
        """serialno should be based on the current date and a sequential number"""
        self.assert_post('/zones/', self.post_data_one)
        self.assert_post('/zones/', self.post_data_two)
        response_one = self.assert_get('/zones/%s' % self.post_data_one['name'])
        response_two = self.assert_get('/zones/%s' % self.post_data_two['name'])
        self.assertEqual(response_one.data['serialno'], response_two.data['serialno'])
        self.assertEqual(response_one.data['serialno'], create_serialno())

    def test_zones_patch_403_forbidden_name(self):
        """"Trying to patch the name of an entry should return 403"""
        response = self.assert_get('/zones/%s' % self.zone_one.name)
        self.assert_patch_and_403('/zones/%s' % self.zone_one.name,
                                  {'name': response.data['name']})

    def test_zones_patch_403_forbidden_primary_ns(self):
        """Trying to patch the primary_ns to be a nameserver that isn't in the nameservers list should return 403"""
        self.assert_post('/zones/', self.post_data_two)
        self.assert_patch_and_403('/zones/%s' % self.post_data_two['name'],
                                  {'primary_ns': self.host_three.name})

    def test_zones_patch_403_forbidden_nameservers(self):
        """Trying to patch the nameservers directly is not allowed."""
        self.assert_post('/zones/', self.post_data_two)
        self.assert_patch_and_403('/zones/%s' % self.post_data_two['name'],
                                  {'nameservers': self.host_three.name})

    def test_zones_patch_404_not_found(self):
        """"Patching a non-existing entry should return 404"""
        self.assert_patch_and_404('/zones/1.11.in-addr.arpa', self.patch_data)
        self.assert_patch_and_404('/zones/0.8.b.d.0.1.0.0.2.ip6.arpa', self.patch_data)

    def test_zones_patch_204_no_content(self):
        """"Patching an existing entry with valid data should return 204"""
        self.assert_patch('/zones/%s' % self.zone_one.name, self.patch_data)

    def test_zones_delete_204_no_content(self):
        """"Deleting an existing entry with no conflicts should return 204"""
        self.assert_delete('/zones/%s' % self.zone_one.name)

    def test_zones_404_not_found(self):
        """"Deleting a non-existing entry should return 404"""
        self.assert_delete_and_404('/zones/1.11.in-addr.arpa')


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
        self.assert_post("/zones/", self.data_exampleorg)

    def test_list_empty_delegation_200_ok(self):
        response = self.assert_get("/zones/example.org/delegations/")
        self.assertEqual(response.data['results'], [])

    def test_delegate_forward_201_ok(self):
        path = "/api/v1/zones/example.org/delegations/"
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        response = self.assert_post(path, data)
        self.assertEqual(response['Location'], f"{path}delegated.example.org")

    def test_delegate_forward_zonefiles_200_ok(self):
        self.test_delegate_forward_201_ok()
        self.assert_get('/zonefiles/example.org')

    def test_delegate_forward_patch_403_method_not_allowed(self):
        path = "/zones/example.org/delegations/"
        data = {'name': 'delegated.example.org',
                'nameservers': ['ns1.example.org', 'ns1.delegated.example.org']}
        response = self.assert_post(path, data)
        self.assert_patch_and_405(response['Location'], {'name': 'notallowed.example.org'})

    def test_delegate_forward_badname_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_no_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': []}
        self.assert_post_and_400(path, bad)
        bad = {'name': 'delegated.example.org'}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_duplicate_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1.example.org', 'ns1.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_invalid_ns_400_bad_request(self):
        path = "/zones/example.org/delegations/"
        bad = {'name': 'delegated.example.org',
               'nameservers': ['ns1', ]}
        self.assert_post_and_400(path, bad)
        bad = {'name': 'delegated.example.org',
               'nameservers': ['2"#¤2342.tld', ]}
        self.assert_post_and_400(path, bad)

    def test_delegate_forward_nameservers_list_200_ok(self):
        path = "/zones/example.org/delegations/"
        self.test_delegate_forward_201_ok()
        response = self.assert_get(f"{path}delegated.example.org")
        nameservers = [i['name'] for i in response.json()['nameservers']]
        self.assertEqual(len(nameservers), 2)
        for ns in nameservers:
            self.assertTrue(NameServer.objects.filter(name=ns).exists())

    def test_forward_list_delegations_200_ok(self):
        path = "/zones/example.org/delegations/"
        self.test_delegate_forward_201_ok()
        response = self.assert_get(path)
        self.assertEqual(response.data['count'], 1)
        results = response.data['results']
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['name'], 'delegated.example.org')

    def test_forward_delete_delegation_204_ok(self):
        self.test_forward_list_delegations_200_ok()
        path = "/api/v1/zones/example.org/delegations/delegated.example.org"
        self.assertEqual(NameServer.objects.count(), 3)
        response = self.assert_delete(path)
        self.assertEqual(response['Location'], path)
        self.assertEqual(NameServer.objects.count(), 2)
        path = "/zones/example.org/delegations/"
        response = self.assert_get(path)
        self.assertEqual(response.data['results'], [])

    def test_zone_by_hostname_404_not_found(self):
        self.test_delegate_forward_201_ok()
        self.assert_get_and_404('/zones/hostname/invalid.example.wrongtld')

    def test_zone_by_hostname_200_ok(self):
        self.test_delegate_forward_201_ok()

        def _test(hostname, zone, zonetype):
            data = self.assert_get(f'/zones/hostname/{hostname}').json()
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

        self.assert_post("/zones/", self.data_rev1010)
        self.assert_post("/zones/", self.data_revdb8)

    def test_get_delegation_200_ok(self):
        def assertempty(data):
            response = self.assert_get(f"/zones/{data['name']}/delegations/")
            self.assertEqual(response.data['count'], 0)
            self.assertEqual(response.data['results'], [])
        for data in ('rev1010', 'revdb8'):
            assertempty(getattr(self, f"data_{data}"))

    def test_delegate_ipv4_201_ok(self):
        path = "/api/v1/zones/10.10.in-addr.arpa/delegations/"
        response = self.assert_post(path, self.del_101010)
        self.assertEqual(response['Location'], f"{path}10.10.10.in-addr.arpa")
        response = self.assert_post(path, self.del_10101010)
        self.assertEqual(response['Location'], f"{path}10.10.10.10.in-addr.arpa")
        self.assert_get(response['Location'])

    def test_delegate_ipv4_zonefiles_200_ok(self):
        self.test_delegate_ipv4_201_ok()
        self.assert_get('/zonefiles/10.10.in-addr.arpa')

    def test_delegate_ipv4_badname_400_bad_request(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_ipv4_invalid_zone_400_bad_request(self):
        def _assert(data):
            self.assert_post_and_400(path, data)

        path = "/zones/10.10.in-addr.arpa/delegations/"
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
        path = "/zones/10.10.in-addr.arpa/delegations/"
        bad = {'name': '0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_duplicate_409_conflict(self):
        path = "/zones/10.10.in-addr.arpa/delegations/"
        self.assert_post(path, self.del_101010)
        self.assert_post_and_409(path, self.del_101010)

    def test_delegate_ipv6_201_ok(self):
        path = "/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        response = self.assert_post(path, self.del_2001db810)
        self.assertEqual(response['Location'], f"{path}{self.del_2001db810['name']}")
        self.assert_get(response['Location'])

    def test_delegate_ipv6_zonefiles_200_ok(self):
        self.test_delegate_ipv6_201_ok()
        self.assert_get('/zonefiles/8.b.d.0.1.0.0.2.ip6.arpa')

    def test_delegate_ipv6_badname_400_bad_request(self):
        path = "/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        bad = {'name': 'delegated.example.com',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)

    def test_delegate_ipv6_wrong_inet_400_bad_request(self):
        path = "/zones/8.b.d.0.1.0.0.2.ip6.arpa/delegations/"
        bad = {'name': '10.10.in-addr.arpa',
               'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post_and_400(path, bad)


class APIZonesNsTestCase(MregAPITestCase):
    """"This class defines the test suite for api/zones/<name>/nameservers/ """

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
        self.assert_post('/zones/', self.post_data)
        self.assertEqual(NameServer.objects.count(), 1)
        self.assert_get('/zones/%s/nameservers' % self.post_data['name'])

    def test_zones_ns_create_and_get_reversezone_200_ok(self):
        """Create a reverse zone and make sure we can get its nameservers"""
        data = {'name': '10.in-addr.arpa', 'primary_ns': ['ns2.example.org'],
                'email': "hostmaster@example.org"}
        self.assertEqual(NameServer.objects.count(), 0)
        self.assert_post('/zones/', data)
        self.assertEqual(NameServer.objects.count(), 1)
        self.assert_get('/zones/%s/nameservers' % data['name'])

    def test_zones_ns_get_404_not_found(self):
        """"Getting the list of nameservers of a non-existing zone should return 404"""
        self.assert_get_and_404('/zones/example.com/nameservers/')

    def test_zones_ns_patch_204_no_content(self):
        """"Patching the list of nameservers with an existing nameserver should return 204"""
        self.assert_post('/zones/', self.post_data)
        self.assert_patch('/zones/%s/nameservers' % self.post_data['name'],
                          {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})

    def test_zones_ns_patch_400_bad_request(self):
        """"Patching the list of nameservers with a bad request body should return 400"""
        self.assert_post('/zones/', self.post_data)
        self.assert_patch_and_400('/zones/%s/nameservers' % self.post_data['name'],
                                  {'garbage': self.ns_one.name})

    @skip("Not testable, yet")
    def test_zones_ns_patch_404_not_found(self):
        """"Patching the list of nameservers with a non-existing nameserver should return 404"""
        self.assert_post('/zones/', self.post_data)
        self.assert_patch_and_404('/zones/%s/nameservers' % self.post_data['name'],
                                  {'primary_ns': ['nonexisting-ns.example.org']})
        # XXX: This is now valid, as the NS might point to a server in a zone which we
        # don't control. Might be possible to check if the attempted NS is in a
        # zone we control and then be stricter.

    def test_zones_ns_delete_204_no_content_zone(self):
        """Deleting a nameserver from an existing zone should return 204"""
        self.assertFalse(NameServer.objects.exists())
        self.assert_post('/zones/', self.post_data)
        self.assert_patch('/zones/%s/nameservers' % self.post_data['name'],
                          {'primary_ns': self.post_data['primary_ns'] + [self.ns_one.name]})
        self.assertEqual(NameServer.objects.count(), 2)
        self.assert_get('/zones/%s/nameservers' % self.post_data['name'])
        self.assert_patch('/zones/%s/nameservers' % self.post_data['name'],
                          {'primary_ns': self.ns_two.name})
        self.assertEqual(NameServer.objects.count(), 1)
        response = self.assert_get('/zones/%s/nameservers' % self.post_data['name'])
        self.assertEqual(response.data, self.post_data['primary_ns'])
        self.assert_delete('/zones/%s' % self.post_data['name'])
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
        response = self.assert_post("/zones/", self.data)
        self.assertEqual(response["location"], "/api/v1/zones/128/25.0.0.10.in-addr.arpa")
        self.assert_get(response["location"])

    def test_add_rfc2317_delegation_for_existing_zone(self):
        zone = {'name': '0.10.in-addr.arpa',
                'primary_ns': ['ns1.example.org', 'ns2.example.org'],
                'email': "hostmaster@example.org"}
        self.assert_post("/zones/", zone)
        delegation = {'name': '128/25.0.0.10.in-addr.arpa',
                      'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post("/zones/0.10.in-addr.arpa/delegations/", delegation)

    def test_delete_rfc2317_zone(self):
        self.assert_post("/zones/", self.data)
        self.assert_delete("/zones/128/25.0.0.10.in-addr.arpa")


class APIIPaddressesTestCase(MregAPITestCase):
    """This class defines the test suite for api/ipaddresses"""

    def setUp(self):
        """Define the test client and other test variables."""
        super().setUp()
        self.host_one = Host.objects.create(name='host1.example.org')
        self.host_two = Host.objects.create(name='host2.example.org')

        self.ipaddress_one = Ipaddress.objects.create(host=self.host_one,
                                                      ipaddress='192.168.111.111')

        self.ipaddress_two = Ipaddress.objects.create(host=self.host_two,
                                                      ipaddress='192.168.111.112')

        self.ipv6address_one = Ipaddress.objects.create(host=self.host_one,
                                                        ipaddress='2001:db8::beef')

        self.ipv6address_two = Ipaddress.objects.create(host=self.host_two,
                                                        ipaddress='2001:db8::feed')

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
        self.assert_get('/ipaddresses/%s' % self.ipaddress_one.id)

    def test_ipv6address_get_200_ok(self):
        """"Getting an existing entry should return 200"""
        self.assert_get('/ipaddresses/%s' % self.ipv6address_one.id)

    def test_ipaddress_list_200_ok(self):
        """List all ipaddress should return 200"""
        data = self.assert_get('/ipaddresses/').json()
        self.assertEqual(data['count'], 4)
        self.assertEqual(len(data['results']), 4)

    def test_ipaddress_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/ipaddresses/193.101.168.2')

    def test_ipv6address_get_404_not_found(self):
        """"Getting a non-existing entry should return 404"""
        self.assert_get_and_404('/ipaddresses/2001:db8::8')

    def test_ipaddress_post_201_created(self):
        """"Posting a new ip should return 201"""
        self.assert_post('/ipaddresses/', self.post_data_full)

    def test_ipv6address_post_201_created(self):
        """"Posting a new IPv6 should return 201"""
        post_ipv6_data_full = {'host': self.host_one.id,
                               'ipaddress': '2001:db8::8'}
        self.assert_post('/ipaddresses/', post_ipv6_data_full)

    def test_ipaddress_post_400_conflict_ip(self):
        """"Posting an existing ip for a host should return 400"""
        self.assert_post_and_400('/ipaddresses/', self.post_data_full_conflict)

    def test_ipv6address_post_400_conflict_ip(self):
        """"Posting an existing IPv6 for a host should return 400"""
        post_ipv6_data_full_conflict = {'host': self.host_one.id,
                                        'ipaddress': self.ipv6address_one.ipaddress}
        self.assert_post_and_400('/ipaddresses/', post_ipv6_data_full_conflict)

    def test_ipaddress_post_201_two_hosts_share_ip(self):
        """"Posting a new ipaddress with an ip already in use should return 201"""
        self.assert_post('/ipaddresses/', self.post_data_full_duplicate_ip)

    def test_ipv6address_post_201_two_hosts_share_ip(self):
        """"Posting a new ipaddress with an IPv6 already in use should return 201"""
        post_ipv6_data_full_duplicate_ip = {'host': self.host_two.id,
                                            'ipaddress': self.ipv6address_one.ipaddress}
        self.assert_post('/ipaddresses/', post_ipv6_data_full_duplicate_ip)

    def test_ipaddress_patch_204_ok(self):
        """Patching an existing and valid entry should return 204"""
        self.assert_patch('/ipaddresses/%s' % self.ipaddress_one.id, self.patch_data_ip)

    def test_ipv6address_patch_204_ok(self):
        """Patching an existing and valid entry should return 204"""
        patch_data_ipv6 = {'ipaddress': '2001:db8::9'}
        self.assert_patch('/ipaddresses/%s' % self.ipv6address_one.id, patch_data_ipv6)

    def test_ipaddress_patch_204_own_ip(self):
        """Patching an entry with its own ip should return 204"""
        self.assert_patch('/ipaddresses/%s' % self.ipaddress_one.id,
                          {'ipaddress': str(self.ipaddress_one.ipaddress)})

    def test_ipv6address_patch_204_own_ip(self):
        """Patching an entry with its own IPv6 should return 204"""
        self.assert_patch('/ipaddresses/%s' % self.ipv6address_one.id,
                          {'ipaddress': str(self.ipv6address_one.ipaddress)})

    def test_ipaddress_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        self.assert_patch_and_400('/ipaddresses/%s' % self.ipaddress_one.id,
                                  {'this': 'is', 'so': 'wrong'})

    def test_ipv6address_patch_400_bad_request(self):
        """Patching with invalid data should return 400"""
        self.assert_patch_and_400('/ipaddresses/%s' % self.ipv6address_one.id,
                                  {'this': 'is', 'so': 'wrong'})

    def test_ipaddress_patch_400_bad_ip(self):
        """Patching with invalid data should return 400"""
        self.assert_patch_and_400('/ipaddresses/%s' % self.ipaddress_one.id, self.patch_bad_ip)

    def test_ipv6address_patch_400_bad_ip(self):
        """Patching with invalid data should return 400"""
        patch_bad_ipv6 = {'ipaddress': '2001:db8::zzzz'}
        self.assert_patch_and_400('/ipaddresses/%s' % self.ipv6address_one.id, patch_bad_ipv6)

    def test_ipaddress_patch_404_not_found(self):
        """Patching a non-existing entry should return 404"""
        self.assert_patch_and_404('/ipaddresses/1234567890', self.patch_data_ip)


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
        self.assert_post('/ipaddresses/', post_data_full)

    def test_mac_post_conflict_ip_and_mac_400_bad_request(self):
        """"Posting an existing IP and mac IP a host should return 400."""
        post_data_full_conflict = {'host': self.host_one.id,
                                   'ipaddress': self.ipaddress_one.ipaddress,
                                   'macaddress': self.ipaddress_one.macaddress}
        self.assert_post_and_400('/ipaddresses/', post_data_full_conflict)

    def test_mac_patch_mac_204_ok(self):
        """Patch an IP with a new mac should return 204 ok."""
        patch_mac = {'macaddress': 'aa:bb:cc:00:00:ff'}
        self.assert_patch('/ipaddresses/%s' % self.ipaddress_one.id,
                          patch_mac)

    def test_mac_remove_mac_204_ok(self):
        """Patch an IP to remove MAC should return 204 ok."""
        self.assert_patch('/ipaddresses/%s' % self.ipaddress_one.id,
                          {'macaddress': ''})

    def test_mac_patch_mac_in_use_400_bad_request(self):
        """Patch an IP with a MAC in use should return 400 bad request."""
        host_two = Host.objects.create(name='host2.example.org')
        ipaddress_two = Ipaddress.objects.create(host=host_two,
                                                 ipaddress='10.0.0.11',
                                                 macaddress='aa:bb:cc:00:00:11')
        patch_mac_in_use = {'macaddress': ipaddress_two.macaddress}
        self.assert_patch_and_400('/ipaddresses/%s' % self.ipaddress_one.id,
                                  patch_mac_in_use)

    def test_mac_patch_invalid_mac_400_bad_request(self):
        """ Patch an IP with invalid MAC should return 400 bad request."""
        def _assert(mac):
            self.assert_patch_and_400('/ipaddresses/%s' % self.ipaddress_one.id,
                                      {'macaddress': mac})
        _assert('00:00:00:00:00:XX')
        _assert('00:00:00:00:00')
        _assert('AA:BB:cc:dd:ee:ff')

    def test_mac_patch_ip_and_mac_204_ok(self):
        """Patch an IP with a new IP and MAC should return 204 ok."""
        patch_ip_and_mac = {'ipaddress': '10.0.0.13',
                            'macaddress': 'aa:bb:cc:00:00:ff'}
        self.assert_patch('/ipaddresses/%s' % self.ipaddress_one.id,
                          patch_ip_and_mac)

    def test_mac_with_network(self):
        self.network_one = Network.objects.create(network='10.0.0.0/24')
        self.test_mac_post_ip_with_mac_201_ok()
        self.test_mac_patch_ip_and_mac_204_ok()
        self.test_mac_patch_mac_204_ok()

    def test_get_dhcphost_v4(self):
        self.test_mac_with_network()
        dhcpall = self.assert_get('/dhcphosts/ipv4/')
        dhcpv4 = self.assert_get(f'/dhcphosts/{self.network_one.network}')
        self.assertEqual(len(dhcpv4.json()), 2)
        self.assertEqual(Ipaddress.objects.exclude(macaddress='').count(), 2)
        self.assertEqual(dhcpall.json(), dhcpv4.json())
        self.assertEqual(sorted(dhcpall.json()[0].keys()),
                         ['host__name', 'host__zone__name', 'ipaddress', 'macaddress'])

    def test_get_dhcphost_v6(self):
        Ipaddress.objects.create(host=self.host_one,
                                 ipaddress='2001:db8::1',
                                 macaddress='aa:bb:cc:00:00:10')
        dhcpall = self.assert_get('/dhcphosts/ipv6/')
        dhcprange = self.assert_get('/dhcphosts/2001:db8::/64')
        self.assertEqual(len(dhcpall.json()), 1)
        self.assertEqual(dhcprange.json(), dhcpall.json())

    def test_get_dhcphost_ipv6byipv4(self):
        # Create an ipaddress without, but will test that we get the
        # ipv4-address' mac.
        Ipaddress.objects.create(host=self.host_one,
                                 ipaddress='2001:db8::1')
        dhcpall = self.assert_get('/dhcphosts/ipv6byipv4/')
        dhcprange = self.assert_get('/dhcphosts/ipv6byipv4/10.0.0.0/24')
        self.assertEqual(dhcprange.json(), dhcpall.json())
        self.assertEqual(len(dhcpall.json()), 1)
        data = dhcpall.json()[0]
        self.assertEqual(list(data.keys()),
                         ['host__name', 'host__zone__name', 'ipaddress', 'macaddress'])
        self.assertEqual(data['macaddress'], self.ipaddress_one.macaddress)
        self.assertEqual(data['host__name'], self.host_one.name)

    def test_get_dhcphost_invalid_network(self):
        self.assert_get_and_400('/dhcphosts/300.10.10.0/24')

    def test_mac_with_network_vlan(self):
        Network.objects.create(network='10.0.0.0/24', vlan=10)
        Network.objects.create(network='10.0.1.0/24', vlan=10)
        Network.objects.create(network='2001:db8:1::/64', vlan=10)
        self.test_mac_post_ip_with_mac_201_ok()
        self.test_mac_patch_ip_and_mac_204_ok()
        self.test_mac_patch_mac_204_ok()
        # Make sure it is allowed to add a mac to both IPv4 and IPv6
        # addresses on the same vlan
        self.assert_post('/ipaddresses/',
                         {'host': self.host_one.id,
                          'ipaddress': '10.0.1.10',
                          'macaddress': '11:22:33:44:55:66'})
        self.assert_post('/ipaddresses/',
                         {'host': self.host_one.id,
                          'ipaddress': '2001:db8:1::10',
                          'macaddress': '11:22:33:44:55:66'})


class APICnamesTestCase(MregAPITestCase):
    """This class defines the test suite for api/cnames """
    def setUp(self):
        super().setUp()
        self.zone_one = create_forward_zone()
        self.zone_two = create_forward_zone(name='example.net')

        self.post_host_one = {'name': 'host1.example.org',
                              'contact': 'mail@example.org'}
        self.client.post('/api/v1/hosts/', self.post_host_one)
        self.host_one = self.client.get('/api/v1/hosts/%s' % self.post_host_one['name']).data
        self.post_host_two = {'name': 'host2.example.org',
                              'contact': 'mail@example.org'}
        self.client.post('/api/v1/hosts/', self.post_host_two)
        self.host_two = self.client.get('/api/v1/hosts/%s' % self.post_host_two['name']).data

        self.post_data = {'name': 'host-alias.example.org',
                          'host': self.host_one['id'],
                          'ttl': 5000}

    def test_cname_post_201_ok(self):
        """ Posting a cname should return 201 OK"""
        self.assert_post('/cnames/', self.post_data)

    def test_cname_get_200_ok(self):
        """GET on an existing cname should return 200 OK."""
        self.test_cname_post_201_ok()
        self.assert_get('/cnames/%s' % self.post_data['name'])

    def test_cname_list_200_ok(self):
        """GET without name should return a list and 200 OK."""
        self.test_cname_post_201_ok()
        response = self.assert_get('/cnames/')
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(len(response.data['results']), 1)

    def test_cname_empty_list_200_ok(self):
        """GET without name should return a list and 200 OK."""
        response = self.assert_get('/cnames/')
        self.assertEqual(response.data['count'], 0)
        self.assertEqual(response.data['results'], [])

    def test_cname_post_hostname_in_use_400_bad_request(self):
        self.assert_post_and_400('/cnames/', {'host': self.host_one['id'],
                                              'name': self.host_two['name']})

    def test_cname_post_nonexistent_host_400_bad_request(self):
        """Adding a cname with a unknown host will return 400 bad request."""
        self.assert_post_and_400('/cnames/', {'host': 1,
                                              'name': 'alias.example.org'})

    def test_cname_post_name_not_in_a_zone_400_bad_requst(self):
        """Add a cname with a name without an existing zone if forbidden"""
        self.assert_post_and_400('/cnames/', {'host': self.host_one['id'],
                                              'name': 'host.example.com'})

    def test_cname_patch_204_ok(self):
        """ Patching a cname should return 204 OK"""
        self.test_cname_post_201_ok()
        self.assert_patch('/cnames/%s' % self.post_data['name'],
                          {'ttl': '500',
                           'name': 'new-alias.example.org'})


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
        response = self.assert_get('/history/')
        self.assertIn('hosts', response.data)

    def test_history_host_get_200_OK(self):
        """Get on /history/hosts/<pk> should return a list of dicts containing entries for that host"""
        response = self.assert_get('/history/hosts/{}'.format(self.host_one.id))
        self.assertIsInstance(response.data, list)
