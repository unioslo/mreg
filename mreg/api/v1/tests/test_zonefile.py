from mreg.models import ForwardZone, Hinfo, Host, Ipaddress, ReverseZone

from .tests import MregAPITestCase, clean_and_save


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
        clean_and_save(host1)
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

    def test_get_reverse_zones(self):
        rev_v4 = self.create_reverse_zone('10.10.in-addr.arpa')
        rev_v6 = self.create_reverse_zone('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        self._get_zone(rev_v4)
        self._get_zone(rev_v6)
