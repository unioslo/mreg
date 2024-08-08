from typing import List
from itertools import chain

from unittest_parametrize import ParametrizedTestCase, param, parametrize

from mreg.models.host import Host, Ipaddress
from mreg.models.resource_records import Cname

from .tests import MregAPITestCase

def create_hosts(name: str, count: int) -> List[Host]:
    """Create hosts."""

    hosts: List[Host] = []
    for i in range(count):
        hosts.append(Host.objects.create(
            name=f"{name}{i}.example.com".replace("_", ""),
            contact="admin@example.com",
            ttl=3600,
            comment="Test host",
        ))

    return hosts

def create_cnames(hosts: List[Host]) -> List[Cname]:
    """Create cnames."""

    cnames: List[Cname] = []
    for host in hosts:
        cnames.append(Cname.objects.create(
            host=host,
            name=f"cname.{host.name}",
            ttl=3600,
        ))

    return cnames

def create_ipaddresses(hosts: List[Host]) -> List[Ipaddress]:
    """Create ipaddresses."""

    ipaddresses: List[Ipaddress] = []
    for i, host in enumerate(hosts):
        ipaddresses.append(Ipaddress.objects.create(
            host=host,
            ipaddress=f"10.0.0.{i}",
        ))

    return ipaddresses

class FilterTestCase(ParametrizedTestCase, MregAPITestCase):
    """Test filtering."""

    # endpoint, query_key, target, expected_hits
    #
    # NOTE: The generated hostnames are UNIQUE across every test case!
    # The format is: f"{endpoint}{query_key}{i}.example.com".replace("_", "")
    # where i is the index of the hostname (and we make three for each test).
    @parametrize(
        ("endpoint", "query_key", "target", "expected_hits"),
        [
            # Direct host filtering
            param("hosts", "name", "hostsname0.example.com", 1, id="hosts_name"),
            param("hosts", "name__contains", "namecontains1", 1, id="hosts_name__contains"),
            param("hosts", "name__icontains", "nameicontains2", 1, id="hosts_name__icontains"),
            param("hosts", "name__iexact", "nameiexact2.example.com", 1, id="hosts_name__iexact"),
            param("hosts", "name__startswith", "namestartswith1", 1, id="hosts_name__startswith"),
            param("hosts", "name__endswith", "endswith0.example.com", 1, id="hosts_name__endswith"),
            param("hosts", "name_regex", "nameregex[0-9].example.com", 3, id="hosts_name__regex"),

            # Reverse through Ipaddress
            param("hosts", "ipaddresses__ipaddress", "10.0.0.1", 1, id="hosts_ipaddresses__ipaddress"),

            # Reverse through Cname
            param("hosts", "cnames__name", "cname.hostscnamesname0.example.com", 1, id="hosts_cnames__name"),
            param("hosts", "cnames__name__regex", "cname.*regex[0-1].example.com", 2, id="host_cnames__regex"),
            param("hosts", "cnames__name__endswith", "with0.example.com", 1, id="hosts_cnames__endswith"),

            # Indirectly through Ipaddress
            param("ipaddresses", "host__name", "ipaddresseshostname0.example.com", 1, id="ipaddresses_host__name"),
            param("ipaddresses", "host__name__contains", "contains1", 1, id="ipaddresses_host__contains"),

            # Indirectly through Cname
            param("cnames", "host__name", "cnameshostname1.example.com", 1, id="cnames_host__name"),
            param("cnames", "host__name__icontains", "cnameshostnameicontains", 3, id="cnames_host__icontains"),
            param("cnames", "host__name__iexact", "cnameshostnameiexact1.example.com", 1, id="cnames_host__iexact"),
            param("cnames", "host__name__startswith", "cnameshostnamestartswith", 3, id="cnames_host__startswith"),
            param("cnames", "host__name__endswith", "endswith2.example.com", 1, id="cnames_host__endswith"),
            param("cnames", "host__name__regex", "cnameshostnameregex[0-9]", 3, id="cnames_host__regex"),
        ],
    )
    def test_filtering_for_host(self, endpoint: str, query_key: str, target: str, expected_hits: str) -> None:
        """Test filtering on host."""

        generate_count = 3
        msg_prefix = f"{endpoint} : {query_key} -> {target} => "

        hosts = create_hosts(f"{endpoint}{query_key}", generate_count)
        cnames = create_cnames(hosts)
        ipadresses = create_ipaddresses(hosts)

        response = self.client.get(f"/api/v1/{endpoint}/?{query_key}={target}")
        self.assertEqual(response.status_code, 200, msg=f"{msg_prefix} {response.content}")
        data = response.json()
        self.assertEqual(data["count"], expected_hits, msg=f"{msg_prefix} {data}")

        for obj in chain(ipadresses, cnames, hosts):
            obj.delete()


