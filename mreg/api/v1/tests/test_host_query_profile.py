"""Host/community query samples, with no fixed query-count budgets.

The populated fixture originated in PR #635. The repeated membership-query
problem was identified in https://github.com/unioslo/mreg/pull/635#issuecomment-5914275961.
These tests assert that larger pages do not add queries. The external CI
profiler captures their requests without endpoint-specific instrumentation.
"""

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from hostpolicy.models import HostPolicyRole
from mreg.models.host import BACnetID, Host, HostContact, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import Network
from mreg.models.network_policy import Community, HostCommunityMapping
from mreg.models.resource_records import Cname, Hinfo, Loc, Mx, Naptr, Srv, Sshfp, Txt

from .tests import MregAPITestCase

NUM_NETWORKS = 2
COMMUNITIES_PER_NETWORK = 2
NUM_HOSTS = 100


@override_settings(MREG_MAP_GLOBAL_COMMUNITY_NAMES=False)
class HostQueryProfileTestCase(MregAPITestCase):
    def setUp(self):
        super().setUp()
        self.set_client_format_json()
        self._seed_dataset()

    def _seed_dataset(self):
        networks = [Network.objects.create(network=f"10.0.{i}.0/24", description=f"query profile network {i}") for i in range(NUM_NETWORKS)]
        communities = []
        for network in networks:
            for _ in range(COMMUNITIES_PER_NETWORK):
                communities.append(Community.objects.create(name=f"comm{len(communities)}", description="", network=network))
        hosts = Host.objects.bulk_create(Host(name=f"host{i:03d}.example.org") for i in range(NUM_HOSTS))
        ipaddresses = Ipaddress.objects.bulk_create(
            Ipaddress(
                host=host,
                ipaddress=f"10.0.{i % NUM_NETWORKS}.{(i // NUM_NETWORKS) + 2}",
            )
            for i, host in enumerate(hosts)
        )

        # Resource records for every host, so that all prefetched relations
        # return data and the benchmark reflects a fully populated page.
        Hinfo.objects.bulk_create(Hinfo(host=host, cpu="x86", os="linux") for host in hosts)
        Loc.objects.bulk_create(Loc(host=host, loc="52 22 23.71 N 4 53 32.79 W 0.00m") for host in hosts)
        Cname.objects.bulk_create(
            Cname(host=host, name=f"cname-{i:03d}-{suffix}.example.org")
            for i, host in enumerate(hosts)
            for suffix in ("a", "b")
        )
        Mx.objects.bulk_create(Mx(host=host, priority=10, mx="mail.example.org") for host in hosts)
        Txt.objects.bulk_create(
            Txt(host=host, txt=f"record {suffix} of host {i:03d}")
            for i, host in enumerate(hosts)
            for suffix in (1, 2)
        )
        Sshfp.objects.bulk_create(
            Sshfp(host=host, algorithm=algorithm, hash_type=1, fingerprint="ab" * 16)
            for host in hosts
            for algorithm in (1, 2)
        )
        Srv.objects.bulk_create(
            Srv(host=host, name=f"_bench{i:03d}._tcp.example.org", priority=0, weight=0, port=5060)
            for i, host in enumerate(hosts)
        )
        Naptr.objects.bulk_create(
            Naptr(host=host, preference=10, order=100, flag="U", service="SIP+D2U", regex="", replacement=".")
            for host in hosts
        )
        PtrOverride.objects.bulk_create(
            PtrOverride(host=host, ipaddress=ipaddresses[i].ipaddress) for i, host in enumerate(hosts)
        )
        BACnetID.objects.bulk_create(BACnetID(id=1000 + i, host=host) for i, host in enumerate(hosts))

        # Shared related objects, attached to every host through the M2M
        # through tables (direct inserts skip m2m_changed signals).
        group = HostGroup.objects.create(name="query-profile-group", description="for query profile tests")
        HostGroup.hosts.through.objects.bulk_create(
            HostGroup.hosts.through(hostgroup_id=group.pk, host_id=host.pk) for host in hosts
        )
        role = HostPolicyRole.objects.create(name="query-profile-role")
        HostPolicyRole.hosts.through.objects.bulk_create(
            HostPolicyRole.hosts.through(hostpolicyrole_id=role.pk, host_id=host.pk) for host in hosts
        )
        contact = HostContact.objects.create(email="query-profile@example.org")
        Host.contacts.through.objects.bulk_create(
            Host.contacts.through(host_id=host.pk, hostcontact_id=contact.pk) for host in hosts
        )

        mappings = []
        for i, host in enumerate(hosts):
            net_index = i % NUM_NETWORKS
            net_communities = communities[net_index * COMMUNITIES_PER_NETWORK : (net_index + 1) * COMMUNITIES_PER_NETWORK]
            for community in net_communities:
                mappings.append(HostCommunityMapping(host=host, ipaddress=ipaddresses[i], community=community))
        HostCommunityMapping.objects.bulk_create(mappings)
        self.first_host_name = hosts[0].name
        self.first_community_id = communities[0].pk

    def _count_get(self, path: str, *, expected_results: int | None = None) -> int:
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(self._create_path(path), format=self.format.value)
        self.assertEqual(response.status_code, 200)
        if expected_results is not None:
            self.assertEqual(len(response.json()["results"]), expected_results)
        return len(queries)

    def test_host_list_query_count(self):
        small = self._count_get("hosts/?page_size=1", expected_results=1)
        full = self._count_get("hosts/", expected_results=NUM_HOSTS)
        self.assertLessEqual(full, small)

    def test_host_detail_query_count(self):
        path = f"hosts/{self.first_host_name}"
        full = self._count_get(path)
        HostCommunityMapping.objects.filter(host__name=self.first_host_name).first().delete()
        small = self._count_get(path)
        self.assertLessEqual(full, small)

    def test_network_community_list_query_count(self):
        path = "networks/10.0.0.0/24/communities/"
        small = self._count_get(path + "?page_size=1", expected_results=1)
        full = self._count_get(path, expected_results=COMMUNITIES_PER_NETWORK)
        self.assertLessEqual(full, small)

    def test_network_community_host_list_query_count(self):
        path = f"networks/10.0.0.0/24/communities/{self.first_community_id}/hosts/"
        small = self._count_get(path + "?page_size=1", expected_results=1)
        full = self._count_get(path, expected_results=NUM_HOSTS // NUM_NETWORKS)
        self.assertLessEqual(full, small)
