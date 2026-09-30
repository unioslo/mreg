"""Query-profile regression tests for the host list and detail endpoints.

GET /hosts/ serializes each host on the page with every related collection
in HostSerializer: ip addresses, the resource records (cnames, mxs, txts,
srvs, naptrs, sshfps, ptr overrides, hinfo, loc, bacnet id), hostgroups,
policy roles, contacts and community mappings.  _host_prefetcher in
mreg/api/v1/views.py exists to keep all of that at a constant number of
queries per page.  Any related object the serializers touch that the
prefetcher does not cover (an unfetched FK or reverse relation) becomes one
extra query per serialized object instead, which is how N+1 regressions
creep in.  These tests pin the exact number of queries executed for a
deterministic dataset that populates every prefetched relation, so such
regressions fail loudly instead of slipping through review.

The dataset is one full page (StandardResultsSetPagination.page_size) of
hosts, each with a representative set of resource records and community
mappings.

Note that the pinned list count is dominated by
CommunitySerializer.get_hosts, which issues one query per serialized
community mapping even with perfect prefetching.

Benchmark mode:
    Run with MREG_BENCH_OUT=/path/to/bench.json to skip the assertions and
    instead write measurements (query counts, per-table query attribution
    and median wall time over MREG_BENCH_RUNS requests) to a JSON file.
    This allows comparing the query profile between two revisions, e.g.
    the branch under test and the commit it started from:

        git worktree add ../mreg-base <base-commit>
        # (uv sync in both worktrees, copy this file into the base worktree)
        MREG_BENCH_OUT=base.json uv run manage.py test \
            mreg.api.v1.tests.test_host_query_profile
        MREG_BENCH_OUT=branch.json uv run manage.py test \
            mreg.api.v1.tests.test_host_query_profile

Diagnosing a failure:
    The assertion message includes a per-table attribution of the
    executed queries.  A table with a per-object count (many identical
    queries, one sample) points at an unfetched relation; a table that
    appears once is a prefetch for a relation that was added to the
    serializer.  To inspect the actual SQL statements, re-run the same
    test with MREG_BENCH_OUT=<path>; benchmark mode skips the assertions
    and writes the full attribution with sample SQL per table.
"""

import json
import os
import re
import time
from typing import Any, NamedTuple

from django.db import connection
from django.test.utils import CaptureQueriesContext

from hostpolicy.models import HostPolicyRole

from mreg.models.host import BACnetID, Host, HostContact, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import Network
from mreg.models.network_policy import Community, HostCommunityMapping
from mreg.models.resource_records import Cname, Hinfo, Loc, Mx, Naptr, Srv, Sshfp, Txt

from .tests import MregAPITestCase

# Benchmark mode: write measurements to this file instead of asserting.
BENCH_OUT = os.environ.get("MREG_BENCH_OUT")
BENCH_RUNS = int(os.environ.get("MREG_BENCH_RUNS", "5"))

# Dataset shape.  One full page of hosts, every prefetched relation populated.
NUM_NETWORKS = 2
COMMUNITIES_PER_NETWORK = 2
NUM_HOSTS = 100
NUM_COMMUNITY_MAPPINGS = NUM_HOSTS * COMMUNITIES_PER_NETWORK

# Crude per-table attribution of the captured SQL (first FROM/JOIN table).
_TABLE_RE = re.compile(r"\b(?:FROM|JOIN)\s+[\"']?([a-zA-Z_][a-zA-Z_0-9]*)")

# Number of distinct SQL statements kept per table as samples.
_SAMPLE_LIMIT = 3


class TableStats(NamedTuple):
    """Query statistics for one database table.

    Attributes:
        count: Number of captured queries attributed to the table.
        time_seconds: Cumulative database time of those queries.
        samples: The first distinct SQL statements (at most _SAMPLE_LIMIT),
            e.g. an unfetched relation shows up as many identical queries
            with a single sample, which identifies the offending code path.
    """

    count: int
    time_seconds: float
    samples: list[str]


class Measurement(NamedTuple):
    """Measurements for one GET request against an endpoint.

    Attributes:
        query_count: Number of SQL queries the request executed.
        median_seconds: Median wall time of the request over BENCH_RUNS runs.
        tables: Per-table attribution of the executed queries.
    """

    query_count: int
    median_seconds: float
    tables: dict[str, TableStats]


def _table_attribution(captured_queries: list[dict[str, str]]) -> dict[str, TableStats]:
    """Return the per-table attribution of the captured queries."""
    stats: dict[str, TableStats] = {}
    for query in captured_queries:
        match = _TABLE_RE.search(query["sql"])
        if match:
            table = match.group(1)
            prev = stats.get(table, TableStats(count=0, time_seconds=0.0, samples=[]))
            samples = prev.samples
            if len(samples) < _SAMPLE_LIMIT and query["sql"] not in samples:
                samples = [*samples, query["sql"]]
            stats[table] = TableStats(
                count=prev.count + 1,
                time_seconds=prev.time_seconds + float(query["time"]),
                samples=samples,
            )
    return dict(sorted(stats.items(), key=lambda item: (-item[1].count, -item[1].time_seconds)))


def _format_attribution(tables: dict[str, TableStats]) -> str:
    """Format the attribution as one line per table: count, table, db time, sample."""
    lines = []
    for table, stats in tables.items():
        sample = stats.samples[0] if stats.samples else ""
        sample = (sample[:100] + " ...") if len(sample) > 100 else sample
        lines.append(f"  {stats.count:>4}x {table:<22} ({stats.time_seconds * 1000:>7.1f}ms) {sample}")
    return "\n".join(lines)


# Pinned query counts for the dataset above.  The list count covers auth,
# pagination count, the host list, one prefetch query per related
# collection, and one query per community mapping from
# CommunitySerializer.get_hosts.  The detail count is for a single host with
# the full set of related objects and two community mappings.  If a change
# here is intentional, update the number in the same commit and say why in
# the test output message.
PINNED_HOST_LIST_QUERIES = 221
PINNED_HOST_DETAIL_QUERIES = 22


class HostQueryProfileTestCase(MregAPITestCase):
    first_host_name: str = "HOST_NOT_CONFIGURED"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._bench_measurements: list[dict[str, Any]] = []
        if BENCH_OUT:
            cls.addClassCleanup(cls._write_bench, BENCH_OUT)

    @classmethod
    def _write_bench(cls, file: str):
        payload = {
            "dataset": {
                "networks": NUM_NETWORKS,
                "communities_per_network": COMMUNITIES_PER_NETWORK,
                "hosts": NUM_HOSTS,
                "community_mappings": NUM_COMMUNITY_MAPPINGS,
                "bench_runs": BENCH_RUNS,
            },
            "measurements": cls._bench_measurements,
        }
        with open(file, "w") as fp:
            json.dump(payload, fp, indent=2)

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

    def _measure_get(self, path: str) -> Measurement:
        """Return the Measurement for GET on path."""
        # Warm-up and timing runs (timings are only recorded in bench mode).
        durations: list[float] = []
        for _ in range(BENCH_RUNS):
            start = time.perf_counter()
            response = self.client.get(self._create_path(path), format=self.format.value)
            durations.append(time.perf_counter() - start)
        self.assertEqual(response.status_code, 200, f"GET {path} did not return 200")
        durations.sort()
        median_seconds = durations[len(durations) // 2]

        # Query counting on a separate run, so the capture itself cannot
        # affect the timings.
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self._create_path(path), format=self.format.value)
        self.assertEqual(response.status_code, 200, f"GET {path} did not return 200")
        return Measurement(
            query_count=len(ctx.captured_queries),
            median_seconds=median_seconds,
            tables=_table_attribution(ctx.captured_queries),
        )

    def _record(self, endpoint: str, measurement: Measurement, pinned_count: int) -> None:
        if BENCH_OUT:
            self._bench_measurements.append(
                {
                    "endpoint": endpoint,
                    "query_count": measurement.query_count,
                    "median_seconds": round(measurement.median_seconds, 6),
                    "query_tables": {
                        # Serialize explicitly; a NamedTuple would be dumped
                        # as a JSON array.
                        table: {
                            "count": stats.count,
                            "time_seconds": stats.time_seconds,
                            "samples": stats.samples,
                        }
                        for table, stats in measurement.tables.items()
                    },
                }
            )
        else:
            self.assertEqual(
                measurement.query_count,
                pinned_count,
                f"{endpoint}: expected {pinned_count} queries, got {measurement.query_count}. "
                "The query profile of the host endpoints changed; if this is "
                "intentional, update the pinned count in this test.\n"
                "Query attribution (count, table, db time, sample SQL):\n"
                f"{_format_attribution(measurement.tables)}\n"
                "Hint: a per-object count (>1) on a table means an unfetched "
                "relation; re-run with MREG_BENCH_OUT=<path> for the full "
                "attribution and sample SQL of every table.",
            )

    def test_host_list_query_count(self):
        measurement = self._measure_get("hosts/")
        self._record(
            f"GET /hosts/ ({NUM_HOSTS} hosts, {NUM_COMMUNITY_MAPPINGS} community mappings)",
            measurement,
            PINNED_HOST_LIST_QUERIES,
        )

    def test_host_detail_query_count(self):
        measurement = self._measure_get(f"hosts/{self.first_host_name}")
        self._record(
            f"GET /hosts/{self.first_host_name} (host with full related data)",
            measurement,
            PINNED_HOST_DETAIL_QUERIES,
        )
