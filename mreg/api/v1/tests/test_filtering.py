from typing import List

from unittest_parametrize import ParametrizedTestCase, param, parametrize

from mreg.models.host import Host
from mreg.models.resource_records import Cname

from .tests import MregAPITestCase


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
            param("hosts", "name", "hostsname0.example.com", 1, id="hosts_name"),
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

        hosts: List[Host] = []
        cnames: List[Cname] = []
        for i in range(generate_count):
            hostname = f"{endpoint}{query_key}{i}.example.com".replace("_", "")
            hosts.append(
                Host.objects.create(
                    name=hostname,
                    contact="admin@example.com",
                    ttl=3600,
                    comment="Test host",
                )
            )

        for i in range(generate_count):
            cname = f"cname.{endpoint}{query_key}{i}.example.com".replace("_", "")
            cnames.append(Cname.objects.create(host=hosts[i], name=cname, ttl=3600))

        hostname = hosts[0].name
        response = self.client.get(f"/api/v1/{endpoint}/?{query_key}={target}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], expected_hits, msg=f"{msg_prefix} {data}")

        for host in hosts:
            host.delete()

        for cname in cnames:
            cname.delete()
