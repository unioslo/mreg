from typing import List, Tuple, Union
from itertools import chain

from unittest_parametrize import ParametrizedTestCase, param, parametrize

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.models.base import Label
from mreg.models.host import Host, Ipaddress
from mreg.models.network import NetGroupRegexPermission
from mreg.models.resource_records import Cname

from .tests import MregAPITestCase


def create_hosts(name: str, count: int) -> List[Host]:
    """Create hosts."""

    hosts: List[Host] = []
    for i in range(count):
        hosts.append(
            Host.objects.create(
                name=f"{name}{i}.example.com".replace("_", ""),
                contact="admin@example.com",
                ttl=3600,
                comment="Test host",
            )
        )

    return hosts


def create_cnames(hosts: List[Host]) -> List[Cname]:
    """Create cnames."""

    cnames: List[Cname] = []
    for host in hosts:
        cnames.append(
            Cname.objects.create(
                host=host,
                name=f"cname.{host.name}",
                ttl=3600,
            )
        )

    return cnames


def create_ipaddresses(hosts: List[Host]) -> List[Ipaddress]:
    """Create ipaddresses."""

    ipaddresses: List[Ipaddress] = []
    for i, host in enumerate(hosts):
        ipaddresses.append(
            Ipaddress.objects.create(
                host=host,
                ipaddress=f"10.0.0.{i}",
            )
        )

    return ipaddresses


def create_labels(name: str, count: int) -> List[Label]:
    """Create labels."""

    labels: List[Label] = []
    for i in range(count):
        labels.append(
            Label.objects.create(
                name=f"{name}{i}".replace("_", ""),
                description="Test label",
            )
        )

    return labels


def create_atoms(name: str, count: int) -> List[HostPolicyAtom]:
    """Create atoms."""

    atoms: List[HostPolicyAtom] = []
    for i in range(count):
        atoms.append(
            HostPolicyAtom.objects.create(
                name=f"{name}{i}".replace("_", ""),
                description=f"Test atom {i}",
            )
        )

    return atoms


def create_roles(
    name: str, hosts: List[Host], atoms: List[HostPolicyAtom], labels: List[Label]
) -> Tuple[List[HostPolicyRole], List[HostPolicyAtom], List[Label]]:
    """Create roles."""

    if not atoms: # pragma: no cover
        atoms = create_atoms(f"{name}atom", len(hosts))

    if not labels: # pragma: no cover
        labels = create_labels(f"{name}label", len(hosts))

    if len(hosts) != len(atoms) or len(hosts) != len(labels): # pragma: no cover
        raise ValueError("Hosts, Atoms, and Labels must be the same length.")

    roles: List[HostPolicyRole] = []

    for i, h in enumerate(hosts):
        policy = HostPolicyRole.objects.create(name=f"{name}host{i}".replace("_", ""), description="Test role")
        policy.hosts.add(h)
        policy.labels.add(labels[i])
        policy.atoms.add(atoms[i])
        roles.append(policy)
    return (roles, atoms, labels)

def resolve_target(target: Union[str, List[str]]) -> List[int]:
    if isinstance(target, str):
        return [int(target)]
    else:
        return [int(t) for t in target]
    
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
            param("hosts", "id", "1", 1, id="hosts_id"),
            param("hosts", "id__in", "2", 1, id="hosts_id__in_2"),
            param("hosts", "id__in", "1,2", 2, id="hosts_id__in_12"),
            param("hosts", "id__in", "0,1,2", 3, id="hosts_id__in_012"),
            param("hosts", "name", "hostsname0.example.com", 1, id="hosts_name"),
            param("hosts", "name__contains", "namecontains1", 1, id="hosts_name__contains"),
            param("hosts", "name__icontains", "nameicontains2", 1, id="hosts_name__icontains"),
            param("hosts", "name__iexact", "hostsnameiexact2.example.com", 1, id="hosts_name__iexact"),
            param("hosts", "name__startswith", "hostsnamestartswith1", 1, id="hosts_name__startswith"),
            param("hosts", "name__endswith", "endswith0.example.com", 1, id="hosts_name__endswith"),
            param("hosts", "name__regex", "nameregex[1-2].example.com", 2, id="hosts_name__regex"),
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
            param("cnames", "host__name__regex", "cnameshostnameregex[0-1]", 2, id="cnames_host__regex"),
        ],
    )
    def test_filtering_for_host(self, endpoint: str, query_key: str, target: str, expected_hits: str) -> None:
        """Test filtering on host."""

        generate_count = 3     
        hosts = create_hosts(f"{endpoint}{query_key}", generate_count)
        cnames = create_cnames(hosts)
        ipadresses = create_ipaddresses(hosts)

        if query_key.startswith("id"):
            targets = target.split(",") if query_key.endswith("__in") else [target]
            resolved_targets = resolve_target(targets)
            target = ",".join(str(hosts[t].id) for t in resolved_targets) # type: ignore

        msg_prefix = f"{endpoint} : {query_key} -> {target} => "

        response = self.client.get(f"/api/v1/{endpoint}/?{query_key}={target}")
        self.assertEqual(response.status_code, 200, msg=f"{msg_prefix} {response.content}")
        data = response.json()
        self.assertEqual(data["count"], expected_hits, msg=f"{msg_prefix} {data}")

        for obj in chain(ipadresses, cnames, hosts):
            obj.delete()

    @parametrize(
        ("endpoint", "query_key", "target", "expected_hits"),
        [
            param("roles", "name", "roleshost0", 1, id="roles_name"),
            param("roles", "name__contains", "roleshost1", 1, id="roles_name__contains"),
            param("roles", "name__icontains", "roleshost2", 1, id="roles_name__icontains"),
            param("roles", "name__iexact", "roleshost2", 1, id="roles_name__iexact"),
            param("roles", "name__startswith", "roleshost1", 1, id="roles_name__startswith"),
            param("roles", "name__endswith", "host1", 1, id="roles_name__endswith"),
            param("roles", "name__regex", "roleshost[0-1]", 2, id="roles_name__regex"),
            param("roles", "atoms__name__exact", "rolesatomsnameexact1", 1, id="roles_atoms__name__exact"),
            param("roles", "atoms__name__contains", "namecontains1", 1, id="roles_atoms__name__contains"),
            param("roles", "atoms__name__regex", "nameregex[0-1]", 2, id="roles_atoms__name__regex"),
            param("roles", "hosts__name__exact", "roleshostsnameexact1.example.com", 1, id="roles_hosts__name__exact"),
            param("roles", "hosts__name__contains", "namecontains1", 1, id="roles_hosts__name__contains"),
            param("roles", "hosts__name__regex", "nameregex[0-1].example.com", 2, id="roles_hosts__name__regex"),
            param("roles", "labels__name__exact", "roleslabelsnameexact1", 1, id="roles_labels__name__exact"),
            param("roles", "labels__name__contains", "namecontains1", 1, id="roles_labels__name__contains"),
            param("roles", "labels__name__regex", "nameregex[0-1]", 2, id="roles_labels__name__regex"),
            param("atoms", "name", "atomsname0", 1, id="atoms_name"),
            param("atoms", "name__contains", "namecontains1", 1, id="atoms_name__contains"),
            param("atoms", "name__icontains", "nameicontains2", 1, id="atoms_name__icontains"),
            param("atoms", "name__iexact", "atomsnameiexact2", 1, id="atoms_name__iexact"),
            param("atoms", "name__startswith", "atomsnamestartswith1", 1, id="atoms_name__startswith"),
            param("atoms", "name__endswith", "endswith0", 1, id="atoms_name__endswith"),
            param("atoms", "name__regex", "nameregex[0-1]", 2, id="atoms_name__regex"),
            param("atoms", "description", "Test atom 1", 1, id="atoms_description"),
            param("atoms", "description__contains", "Test atom", 3, id="atoms_description__contains"),
            param("atoms", "description__regex", "Test atom [0-1]", 2, id="atoms_description__regex"),
        ],
    )
    def test_filtering_for_hostpolicy(self, endpoint: str, query_key: str, target: str, expected_hits: str) -> None:
        """Test filtering on hostpolicy."""

        generate_count = 3
        msg_prefix = f"{endpoint} : {query_key} -> {target} => "

        hosts = create_hosts(f"{endpoint}{query_key}", generate_count)
        atoms = create_atoms(f"{endpoint}{query_key}", generate_count)
        labels = create_labels(f"{endpoint}{query_key}", generate_count)

        roles, atoms, labels = create_roles(endpoint, hosts, atoms, labels)

        response = self.client.get(f"/api/v1/hostpolicy/{endpoint}/?{query_key}={target}")
        self.assertEqual(response.status_code, 200, msg=f"{msg_prefix} {response.content}")
        data = response.json()
        self.assertEqual(data["count"], expected_hits, msg=f"{msg_prefix} {data}")

        for obj in chain(roles, atoms, labels, hosts):
            obj.delete()

    @parametrize(("cidr", "exists"), [                 
                param("10.0.0.0/24", True, id="cidr_0_true"),
                param("10.0.1.0/24", True, id="cidr_1_true"),
                param("10.0.2.0/24", True, id="cidr_2_true"),
                param("10.0.3.0/24", False, id="cidr_3_false"),

                param("10.0.0.1", True, id="ip_0_1_true"),
                param("10.0.0.2", True, id="ip_0_2_true"),
                param("10.0.1.1", True, id="ip_1_1_true"),
                param("10.0.2.1", True, id="ip_2_1_true"),

                param("10.0.3.1", False, id="ip_3_1_false"),
        ],
    )
    def test_filter_netgroup_regex_permission(self, cidr: str, exists: bool) -> None:
        """Test filtering on netgroup regex permission."""

        generate_count = 3

        for i in range(generate_count):
            NetGroupRegexPermission.objects.create(
                regex=".*",
                range=f"10.0.{i}.0/24"
            )

        response = self.client.get(f"/api/v1/permissions/netgroupregex/?range={cidr}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 1 if exists else 0)