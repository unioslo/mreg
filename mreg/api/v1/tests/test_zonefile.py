from mreg.models import ForwardZone, Host, Ipaddress, ReverseZone

from .tests import MregAPITestCase


class APIZonefileTestCase(MregAPITestCase):

    def setUp(self):
        super().setUp()
        self.forward = self.create_forward_zone('example.org')

        for name, ips in (('example.org', ('10.10.0.1', )),
                          ('ns1.example.org', ('10.10.0.2', '2001:db8::2')),
                          ('host1.example.org', ('10.10.1.10', '2001:db8:0:1::10')),
                          ('høst2.example.org', ('10.10.1.10', '2001:db8:0:1::10')),
                          ):
            ret = self._add_host(name, ip=ips[0])
            info = self.assert_get(ret['Location']).json()
            for ip in ips[1:]:
                Ipaddress.objects.create(host=Host.objects.get(id=info['id']),
                                         ipaddress=ip)

    def _add_host(self, name, ip=None):
        data = {'name': name, 'ipaddress': ip}
        return self.assert_post('/hosts/', data)

    def _create_zone(self, name, zonetype,
                     primary_ns=['ns1.example.org', 'ns2.example.org'],
                     email='hostmaster@example.org'):
        data = locals().copy()
        del data['self']
        del data['zonetype']
        self.assert_post(f'/zones/{zonetype}/', data)

    def create_forward_zone(self, name, **kwargs):
        self._create_zone(name, 'forward', **kwargs)
        return ForwardZone.objects.get(name=name)

    def create_reverse_zone(self, name, **kwargs):
        self._create_zone(name, 'reverse', **kwargs)
        return ReverseZone.objects.get(name=name)

    def _get_zone(self, zone):
        response = self.assert_get(f"/zonefiles/{zone.name}")
        return response.data

    def test_get_forward(self):
        subname = f'subzone.{self.forward.name}'
        ns1 = f'ns1.{subname}'
        self.create_forward_zone(subname,
                                 primary_ns=[subname, ns1, 'ns1.example.org'])
        self._get_zone(self.forward)
        # Fix subzone NS error
        self._add_host(subname, ip='10.10.1.100')
        self._add_host(ns1, ip='10.10.1.101')
        self._get_zone(self.forward)

        # Finally add lots of entries to make sure we test everything when getting the zonefile.
        host1 = Host.objects.get(name='host1.example.org')
        host2 = Host.objects.create(name='hostæøå1.example.com')
        data = {'name': 'host-alias.example.org',
                'host': host1.id,
                'ttl': 5000}
        self.assert_post("/cnames/", data)
        data = {'name': 'extærnal-alias.example.org',
                'host': host2.id}
        self.assert_post("/cnames/", data)
        data = {'host': host1.id,
                'priority': 10,
                'mx': 'smtp.example.org'}
        self.assert_post("/mxs/", data)
        data = {'host': host1.id,
                'cpu': 'supercpu',
                'os': 'operating system'}
        self.assert_post("/hinfos/", data)
        data = {'host': host1.id,
                'loc': '23 58 23 N 10 43 50 E 80m'}
        self.assert_post("/locs/", data)
        data = {'host': host1.id,
                'preference': 10,
                'order': 20,
                'flag': 'a',
                'service': 'SERVICE',
                'regex': r'1(.*@example.org)',
                'replacement': 'replacementhost.example.org'
                }
        self.assert_post("/naptrs/", data)
        data = {'host': host1.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        self.assert_post("/sshfps/", data)
        data = {'name': '_test123._tls.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'host': host1.id}
        self.assert_post("/srvs/", data)
        data = {'name': '_test123._tls.example.org',
                'priority': 10,
                'weight': 10,
                'port': '1234',
                'host': host2.id}
        self.assert_post("/srvs/", data)
        self._get_zone(self.forward)

    def test_get_nonexistent(self):
        self.assert_get_and_404("/zonefiles/ops")

    def test_srvs_outside_zone(self):
        example_com = self.create_forward_zone('example.com')
        host = Host.objects.get(name='host1.example.org')
        data = {'name': '_test123._tls.example.com',
                'priority': 10,
                'weight': 10,
                'port': '1234',
                'host': host.id}
        self.assert_post("/srvs/", data)
        ret = self._get_zone(self.forward)
        self.assertNotIn(data['name'], ret)
        ret = self._get_zone(example_com)
        shortform = data['name'].replace('.example.com', '')
        self.assertIn(shortform, ret)

    def test_long_txts(self):
        # Check RFC 4408 section 3.1.3 style TXTs: long strings splitted in 255 character chunks
        host = Host.objects.get(name='host1.example.org')
        # 260 chars
        long_txt = "o"*260
        data = {'txt': long_txt,
                'host': host.id}
        self.assert_post("/txts/", data)
        ret = self._get_zone(self.forward)
        # make sure the 260 chars are splitted in 255 chars with a space and then the rest
        self.assertIn(f'{"o"*255} ooooo', ret)

    def test_get_reverse_zones(self):
        rev_v4 = self.create_reverse_zone('10.10.in-addr.arpa')
        self.create_reverse_zone('10.10.10.in-addr.arpa')
        rev_v6 = self.create_reverse_zone('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        self.create_reverse_zone('0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        self._get_zone(rev_v4)
        self._get_zone(rev_v6)

    def test_reverse_exclude_addresses(self):
        """Addresses in delegations or sub zones should not be in the reverse zone."""
        rev_v4 = self.create_reverse_zone('10.10.in-addr.arpa')
        self.create_reverse_zone('10.10.10.in-addr.arpa')
        delegation = {'name': '20.10.10.in-addr.arpa',
                      'nameservers': ['ns1.example.org', 'ns2.example.org']}
        self.assert_post(f'/api/v1/zones/reverse/{rev_v4.name}/delegations/', delegation)
        self._add_host('in-sub-zone.example.org', '10.10.10.10')
        self._add_host('in-delegation.example.org', '10.10.20.20')
        ret = self._get_zone(rev_v4)
        self.assertNotIn('in-sub-zone.example.org', ret)
        self.assertNotIn('in-delegation.example.org', ret)

    def test_excluding_private_addresses(self):
        """Addresses in the private address spaces defined in RFC 1918 can be excluded from the zone files."""
        # test with some private and non-private addresses
        testhosts = [
            {'name': 'alpha', 'ip': '10.0.0.4', 'private': True},
            {'name': 'bravo', 'ip': '172.16.0.4', 'private': True},
            {'name': 'charlie', 'ip': '192.168.0.4', 'private': True},
            {'name': 'delta', 'ip': '129.240.130.240', 'private': False},
            {'name': 'echo', 'ip': '2001:700:100:4003::29', 'private': False}
        ]
        for h in testhosts:
            self._add_host('{}.{}'.format(h['name'], self.forward.name), h['ip'])
        # get the forward zone file, verify it contains both private and non-private addresses
        data = self._get_zone(self.forward)
        for h in testhosts:
            self.assertIn(h['ip'], data)
        # get the forward zone file but with private addresses excluded, verify it contains only public addresses
        response = self.assert_get(f"/zonefiles/{self.forward.name}?excludePrivate=yes")
        data = response.data
        for h in testhosts:
            if h['private']:
                self.assertNotIn(h['ip'], data)
            else:
                self.assertIn(h['ip'], data)
