from rest_framework.test import APIClient

from mreg.models import Host, HinfoPreset, Ipaddress, ForwardZone, ReverseZone
from .tests import MregAPITestCase, clean_and_save

class APIZonefileTestCase(MregAPITestCase):

    def setUp(self):
        super().setUp()
        self.forward = self.create_forward_zone('example.org')

        for name, ips in (('example.org', ('10.10.0.1', )),
                          ('ns1.example.org', ('10.10.0.2', '2001:db8::2')),
                          ('host1.example.org', ('10.10.1.10', '2001:db8:0:1::10')),
                          ('host2.example.org', ('10.10.1.10', '2001:db8:0:1::10')),
                         ):
            ret = self._add_host(name, ip=ips[0])
            info = self.client.get(ret['Location']).json()
            for ip in ips[1:]:
                Ipaddress.objects.create(host=Host.objects.get(id=info['id']),
                                         ipaddress=ip)
    
    def _add_host(self, name, ip=None):
        data = {'name': name, 'ipaddress': ip}
        return self.client.post('/hosts/', data)

    def _create_zone(self, name,
                     primary_ns=['ns1.example.org', 'ns2.example.org'],
                     email='hostmaster@example.org'):
        data = locals().copy()
        del data['self'] 
        self.client.post('/zones/', data)

    def create_forward_zone(self, name, **kwargs):
        self._create_zone(name, **kwargs)
        return ForwardZone.objects.get(name=name)

    def create_reverse_zone(self, name, **kwargs):
        self._create_zone(name, **kwargs)
        return ReverseZone.objects.get(name=name)

    def _get_zone(self, zone):
        response = self.client.get(f"/zonefiles/{zone.name}")
        self.assertEqual(response.status_code, 200)
        return response.data

    def test_get_forward(self):
        subname = f'subzone.{self.forward.name}'
        ns1 = f'ns1.{subname}'
        self.create_forward_zone(subname,
                                 primary_ns=[subname, ns1, 'ns1.example.org'])
        self._get_zone(self.forward)
        ## Fix subzone NS error
        self._add_host(subname, ip='10.10.1.100')
        self._add_host(ns1, ip='10.10.1.101')
        self._get_zone(self.forward)

        # Finally add lots of entries to make sure we test everything when getting the zonefile.
        host1 = Host.objects.get(name='host1.example.org')
        host1.loc = '23 58 23 N 10 43 50 E 80m'
        hinfo = HinfoPreset.objects.create(cpu='supercpu', os='operative system')
        host1.hinfo = hinfo
        clean_and_save(host1)
        host2 = Host.objects.create(name='host1.example.com')
        data = {'name': 'host-alias.example.org',
                'host': host1.id,
                'ttl': 5000 }
        self.client.post("/cnames/", data)
        data = {'name': 'external-alias.example.org',
                'host': host2.id}
        self.client.post("/cnames/", data)
        data = {'host': host1.id,
                'priority': 10,
                'mx': 'smtp.example.org'}
        ret = self.client.post("/mxs/", data)
        data = {'host': host1.id,
                'preference': 10,
                'order': 20,
                'flag': 'a',
                'service': 'SERVICE',
                'regex': r'1(.*@example.org)',
                'replacement': 'replacementhost.example.org'
        }
        ret = self.client.post("/naptrs/", data)
        data = {'host': host1.id,
                'algorithm': 1,
                'hash_type': 1,
                'fingerprint': '0123456789abcdef'}
        ret = self.client.post("/sshfps/", data)
        data = {'name': '_test123._tls.example.org',
                'priority': 10,
                'weight': 20,
                'port': '1234',
                'target': 'target.example.org'}
        self.client.post("/srvs/", data)
        self._get_zone(self.forward)

    def test_get_nonexistent(self):
        response = self.client.get("/zonefiles/ops")
        self.assertEqual(response.status_code, 404)

    def test_get_reverse_zones(self):
        rev_v4 = self.create_reverse_zone('10.10.in-addr.arpa')
        rev_v6 = self.create_reverse_zone('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
        self._get_zone(rev_v4)
        self._get_zone(rev_v6)

