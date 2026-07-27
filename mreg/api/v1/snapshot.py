"""Synchronous, versioned portable snapshots."""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from django.conf import settings
from django.db import DatabaseError, connection, transaction
from django.db.models import Count
from django.http import FileResponse
from rest_framework.response import Response
from rest_framework.views import APIView

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg import __version__
from mreg.api.permissions import IsAuthenticated
from mreg.models.base import Label, NameServer
from mreg.models.host import BACnetID, Host, HostContact, HostGroup, Ipaddress, PtrOverride
from mreg.models.auth import User
from mreg.models.network import NetGroupRegexPermission, Network, NetworkExcludedRange
from mreg.models.network_policy import (
    Community,
    HostCommunityMapping,
    NetworkPolicy,
    NetworkPolicyAttribute,
    NetworkPolicyAttributeValue,
)
from mreg.models.resource_records import Cname, Hinfo, Loc, Mx, Naptr, Srv, Sshfp, Txt
from mreg.models.zone import (
    ForwardZone,
    ForwardZoneDelegation,
    ReverseZone,
    ReverseZoneDelegation,
)


ARCHIVE_FORMAT = "mreg-snapshot-v1"
JSON_FORMAT = "mreg-import-json-v1"
ARCHIVE_MEDIA_TYPE = "application/vnd.uio.mreg-snapshot+tar"
JSON_MEDIA_TYPE = "application/json"
SUPPORTED_OPTIONS = {
    "include_audit": "false",
    "validate": "true",
    "redact": "false",
}


class SnapshotError(Exception):
    """An error safe to report to a snapshot client."""

    def __init__(self, message: str, *, model: str | None = None, object_id: Any = None):
        super().__init__(message)
        self.model = model
        self.object_id = object_id


class SnapshotRequestError(SnapshotError):
    pass


class SnapshotUnavailable(SnapshotError):
    pass


class SnapshotNotAcceptable(SnapshotRequestError):
    pass


def _ref(kind: str, pk: Any) -> str:
    return f"{kind}:{pk}"


def _item(reference: str, kind: str, attributes: dict[str, Any]) -> dict[str, Any]:
    return {"ref": reference, "kind": kind, "operation": "create", "attributes": attributes}


def _without_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def _normalized_mac(value: str) -> str | None:
    if not value:
        return None
    compact = "".join(character for character in value.lower() if character.isalnum())
    if len(compact) != 12:
        raise SnapshotError(f"Invalid MAC address {value!r}")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


class NetworkIndex:
    """Small longest-prefix-match index for legacy IP rows."""

    def __init__(self) -> None:
        self.by_family: dict[int, dict[int, dict[str, tuple[int, str]]]] = {4: {}, 6: {}}
        for pk, value in Network.objects.order_by("pk").values_list("pk", "network"):
            network = ipaddress.ip_network(str(value))
            self.by_family[network.version].setdefault(network.prefixlen, {})[str(network)] = (pk, str(network))

    def match(self, value: str) -> tuple[int, str] | None:
        address = ipaddress.ip_address(value)
        by_prefix = self.by_family[address.version]
        for prefix in sorted(by_prefix, reverse=True):
            candidate = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
            if candidate in by_prefix[prefix]:
                return by_prefix[prefix][candidate]
        return None


def _attachment_ref(host_id: int, network_id: int, mac: str | None) -> str:
    suffix = mac.replace(":", "") if mac else "none"
    return f"host_attachment:{host_id}:{network_id}:{suffix}"


def _base_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    for obj in Label.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(_ref("label", obj.pk), "label", {"name": obj.name, "description": obj.description})
    for obj in NameServer.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(_ref("nameserver", obj.pk), "nameserver", _without_none({"name": obj.name, "ttl": obj.ttl}))
    for obj in NetworkPolicyAttribute.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(
            _ref("network_policy_attribute", obj.pk),
            "network_policy_attribute",
            {"name": obj.name, "description": obj.description},
        )
    for obj in NetworkPolicy.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(
            _ref("network_policy", obj.pk),
            "network_policy",
            _without_none(
                {
                    "name": obj.name,
                    "description": obj.description,
                    "community_template_pattern": obj.community_template_pattern,
                }
            ),
        )
    values = NetworkPolicyAttributeValue.objects.select_related("policy", "attribute").order_by("pk")
    for obj in values.iterator(chunk_size=chunk_size):
        yield _item(
            _ref("network_policy_attribute_value", obj.pk),
            "network_policy_attribute_value",
            {
                "policy_name_ref": _ref("network_policy", obj.policy_id),
                "attribute_name_ref": _ref("network_policy_attribute", obj.attribute_id),
                "value": obj.value,
            },
        )


def _network_zone_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    for obj in Network.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(
            _ref("network", obj.pk),
            "network",
            _without_none(
                {
                    "cidr": str(obj.network),
                    "description": obj.description,
                    "vlan": obj.vlan,
                    "dns_delegated": obj.dns_delegated,
                    "category": obj.category,
                    "location": obj.location,
                    "frozen": obj.frozen,
                    "reserved": obj.reserved,
                    "max_communities": obj.max_communities,
                    "policy_ref": _ref("network_policy", obj.policy_id) if obj.policy_id else None,
                }
            ),
        )
    ranges = NetworkExcludedRange.objects.select_related("network").order_by("pk")
    for obj in ranges.iterator(chunk_size=chunk_size):
        yield _item(
            _ref("excluded_range", obj.pk),
            "excluded_range",
            {
                "network_ref": _ref("network", obj.network_id),
                "start_ip": obj.start_ip,
                "end_ip": obj.end_ip,
                "description": "",
            },
        )
    communities = Community.objects.select_related("network__policy").order_by("pk")
    for obj in communities.iterator(chunk_size=chunk_size):
        if obj.network.policy_id is None:
            raise SnapshotError(
                "Community references a network without a policy", model="Community", object_id=obj.pk
            )
        yield _item(
            _ref("community", obj.pk),
            "community",
            {
                "policy_name_ref": _ref("network_policy", obj.network.policy_id),
                "network_cidr_ref": _ref("network", obj.network_id),
                "name": obj.name,
                "description": obj.description,
            },
        )
    yield from _zone_items(ForwardZone, "forward_zone", chunk_size)
    yield from _zone_items(ReverseZone, "reverse_zone", chunk_size)
    yield from _delegation_items(ForwardZoneDelegation, "forward_zone_delegation", "forward_zone", chunk_size)
    yield from _delegation_items(ReverseZoneDelegation, "reverse_zone_delegation", "reverse_zone", chunk_size)


def _zone_items(model, kind: str, chunk_size: int) -> Iterator[dict[str, Any]]:
    queryset = model.objects.prefetch_related("nameservers").order_by("pk")
    for obj in queryset.iterator(chunk_size=chunk_size):
        attributes = {
            "name": obj.name,
            "primary_ns": obj.primary_ns,
            "nameservers": [_ref("nameserver", ns.pk) for ns in obj.nameservers.all()],
            "email": obj.email,
            "serial_no": obj.serialno,
            "refresh": obj.refresh,
            "retry": obj.retry,
            "expire": obj.expire,
            "soa_ttl": obj.soa_ttl,
            "default_ttl": obj.default_ttl,
        }
        if kind == "reverse_zone":
            attributes["network"] = str(obj.network)
        yield _item(_ref(kind, obj.pk), kind, attributes)


def _delegation_items(model, kind: str, zone_kind: str, chunk_size: int) -> Iterator[dict[str, Any]]:
    queryset = model.objects.prefetch_related("nameservers").order_by("pk")
    for obj in queryset.iterator(chunk_size=chunk_size):
        yield _item(
            _ref(kind, obj.pk),
            kind,
            {
                "zone_ref": _ref(zone_kind, obj.zone_id),
                "name": obj.name,
                "comment": obj.comment,
                "nameservers": [_ref("nameserver", ns.pk) for ns in obj.nameservers.all()],
            },
        )


def _wildcard_ids() -> set[int]:
    return set(Host.objects.filter(name__contains="*").values_list("pk", flat=True))


def _host_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    queryset = Host.objects.exclude(pk__in=wildcards).order_by("pk")
    for obj in queryset.iterator(chunk_size=chunk_size):
        yield _item(
            _ref("host", obj.pk),
            "host",
            _without_none(
                {
                    "name": obj.name,
                    "zone_ref": _ref("forward_zone", obj.zone_id) if obj.zone_id else None,
                    "ttl": obj.ttl,
                    "comment": obj.comment,
                }
            ),
        )


def _ip_rows(chunk_size: int):
    return Ipaddress.objects.select_related("host").order_by("host_id", "pk").iterator(chunk_size=chunk_size)


def _attachment_items(index: NetworkIndex, wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    seen_for_host: set[str] = set()
    current_host = None
    for obj in _ip_rows(chunk_size):
        if obj.host_id in wildcards:
            if obj.macaddress:
                raise SnapshotError(
                    "Wildcard IP assignment has a MAC address that cannot be represented",
                    model="Ipaddress",
                    object_id=obj.pk,
                )
            continue
        if current_host != obj.host_id:
            current_host = obj.host_id
            seen_for_host.clear()
        match = index.match(obj.ipaddress)
        if match is None:
            raise SnapshotError("IP address is not contained in a network", model="Ipaddress", object_id=obj.pk)
        network_id, network = match
        mac = _normalized_mac(obj.macaddress)
        reference = _attachment_ref(obj.host_id, network_id, mac)
        if reference in seen_for_host:
            continue
        seen_for_host.add(reference)
        yield _item(
            reference,
            "host_attachment",
            _without_none(
                {
                    "host_name_ref": _ref("host", obj.host_id),
                    "network_ref": _ref("network", network_id),
                    "mac_address": mac,
                }
            ),
        )


def _ip_items(index: NetworkIndex, wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    duplicate = (
        Ipaddress.objects.values("ipaddress").annotate(count=Count("pk")).filter(count__gt=1).order_by("ipaddress").first()
    )
    if duplicate:
        raise SnapshotError(f"IP address {duplicate['ipaddress']} is assigned more than once", model="Ipaddress")
    for obj in _ip_rows(chunk_size):
        if obj.host_id in wildcards:
            continue
        match = index.match(obj.ipaddress)
        if match is None:
            raise SnapshotError("IP address is not contained in a network", model="Ipaddress", object_id=obj.pk)
        network_id, _ = match
        mac = _normalized_mac(obj.macaddress)
        yield _item(
            _ref("ip_address", obj.pk),
            "ip_address",
            {"attachment_id_ref": _attachment_ref(obj.host_id, network_id, mac), "address": obj.ipaddress},
        )


def _record_attributes(
    type_name: str,
    owner_name: str,
    data: dict[str, Any],
    *,
    ttl: int | None = None,
    owner_kind: str | None = None,
    anchor_ref: str | None = None,
) -> dict[str, Any]:
    return _without_none(
        {
            "type_name": type_name,
            "owner_kind": owner_kind,
            "owner_name": owner_name,
            "anchor_name_ref": anchor_ref,
            "ttl": ttl,
            "data": data,
        }
    )


def _parse_loc(value: str, *, pk: Any) -> dict[str, float]:
    tokens = value.split()
    try:
        lat_end = tokens.index("N") if "N" in tokens else tokens.index("S")
        lon_start = lat_end + 1
        lon_end = tokens.index("E") if "E" in tokens else tokens.index("W")

        def coordinate(parts: list[str], direction: str) -> float:
            numbers = [float(part) for part in parts]
            result = numbers[0]
            if len(numbers) > 1:
                result += numbers[1] / 60
            if len(numbers) > 2:
                result += numbers[2] / 3600
            return -result if direction in {"S", "W"} else result

        remaining = [float(token.removesuffix("m")) for token in tokens[lon_end + 1:]]
        if not remaining:
            raise ValueError("missing altitude")
        result = {
            "latitude": coordinate(tokens[:lat_end], tokens[lat_end]),
            "longitude": coordinate(tokens[lon_start:lon_end], tokens[lon_end]),
            "altitude_m": remaining[0],
        }
        for key, number in zip(
            ("size_m", "horizontal_precision_m", "vertical_precision_m"), remaining[1:], strict=False
        ):
            result[key] = number
        return result
    except (ValueError, IndexError) as error:
        raise SnapshotError("LOC value cannot be translated", model="Loc", object_id=pk) from error


def _dns_record_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    wildcard_hosts = {pk: (name, ttl) for pk, name, ttl in Host.objects.filter(pk__in=wildcards).values_list("pk", "name", "ttl")}
    for obj in Ipaddress.objects.filter(host_id__in=wildcards).select_related("host").order_by("pk").iterator(chunk_size=chunk_size):
        address = ipaddress.ip_address(obj.ipaddress)
        yield _item(
            _ref("record_ip_address", obj.pk),
            "record",
            _record_attributes("A" if address.version == 4 else "AAAA", obj.host.name, {"address": obj.ipaddress}, ttl=obj.host.ttl),
        )

    specifications = (
        (Hinfo, "HINFO", lambda o: {"cpu": o.cpu, "os": o.os}, lambda o: o.host.ttl),
        (Loc, "LOC", lambda o: _parse_loc(o.loc, pk=o.pk), lambda o: o.host.ttl),
        (Mx, "MX", lambda o: {"preference": o.priority, "exchange": o.mx}, lambda o: o.host.ttl),
        (Txt, "TXT", lambda o: {"value": o.txt}, lambda o: o.host.ttl),
        (
            Naptr,
            "NAPTR",
            lambda o: {
                "order": o.order,
                "preference": o.preference,
                "flags": o.flag,
                "services": o.service,
                "regexp": o.regex,
                "replacement": o.replacement,
            },
            lambda o: o.host.ttl,
        ),
        (
            Sshfp,
            "SSHFP",
            lambda o: {"algorithm": o.algorithm, "fp_type": o.hash_type, "fingerprint": o.fingerprint},
            lambda o: o.ttl if o.ttl is not None else o.host.ttl,
        ),
    )
    for model, type_name, data_factory, ttl_factory in specifications:
        queryset = model.objects.select_related("host").order_by("pk")
        for obj in queryset.iterator(chunk_size=chunk_size):
            wildcard = obj.host_id in wildcards
            if type_name == "MX" and not wildcard:
                owner_kind = "forward_zone"
                anchor_ref = _ref("forward_zone", obj.host.zone_id) if obj.host.zone_id else None
                if anchor_ref is None:
                    raise SnapshotError("MX owner has no forward zone", model="Mx", object_id=obj.pk)
            else:
                owner_kind = None if wildcard else "host"
                anchor_ref = None if wildcard else _ref("host", obj.host_id)
            yield _item(
                _ref(f"record_{model._meta.model_name}", obj.pk),
                "record",
                _record_attributes(
                    type_name,
                    obj.host.name,
                    data_factory(obj),
                    ttl=ttl_factory(obj),
                    owner_kind=owner_kind,
                    anchor_ref=anchor_ref,
                ),
            )
    for model, type_name, data_factory in (
        (Cname, "CNAME", lambda o: {"target": o.host.name}),
        (Srv, "SRV", lambda o: {"priority": o.priority, "weight": o.weight, "port": o.port, "target": o.host.name}),
    ):
        queryset = model.objects.select_related("host").order_by("pk")
        for obj in queryset.iterator(chunk_size=chunk_size):
            yield _item(
                _ref(f"record_{model._meta.model_name}", obj.pk),
                "record",
                _record_attributes(type_name, obj.name, data_factory(obj), ttl=obj.ttl),
            )

    for host_id, (name, _ttl) in wildcard_hosts.items():
        has_dns = Ipaddress.objects.filter(host_id=host_id).exists() or any(
            model.objects.filter(host_id=host_id).exists() for model, *_ in specifications
        )
        if not has_dns:
            raise SnapshotError("Wildcard host has no translatable DNS data", model="Host", object_id=host_id)
        host = Host.objects.get(pk=host_id)
        if host.comment or host.contacts.exists() or host.hostgroups.exists() or host.hostpolicyroles.exists():
            raise SnapshotError("Wildcard host has non-DNS relationships", model="Host", object_id=host_id)
        if BACnetID.objects.filter(host_id=host_id).exists() or HostCommunityMapping.objects.filter(host_id=host_id).exists():
            raise SnapshotError("Wildcard host has non-DNS relationships", model="Host", object_id=host_id)


def _relationship_items(index: NetworkIndex, wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    ptrs = PtrOverride.objects.select_related("host").order_by("pk")
    for obj in ptrs.iterator(chunk_size=chunk_size):
        if obj.host_id in wildcards:
            raise SnapshotError("Wildcard PTR override cannot be translated", model="PtrOverride", object_id=obj.pk)
        yield _item(
            _ref("ptr_override", obj.pk),
            "ptr_override",
            {"host_name_ref": _ref("host", obj.host_id), "address": obj.ipaddress},
        )
    for obj in BACnetID.objects.order_by("pk").iterator(chunk_size=chunk_size):
        if obj.host_id in wildcards:
            continue
        yield _item(
            _ref("bacnet_id", obj.pk),
            "bacnet_id",
            {"bacnet_id": obj.pk, "host_name_ref": _ref("host", obj.host_id)},
        )
    contacts = HostContact.objects.prefetch_related("hosts").order_by("pk")
    for obj in contacts.iterator(chunk_size=chunk_size):
        hosts = [_ref("host", host.pk) for host in obj.hosts.all() if host.pk not in wildcards]
        if hosts:
            yield _item(_ref("host_contact", obj.pk), "host_contact", {"email": obj.email, "hosts": hosts})
    yield from _host_group_items(wildcards)

    mappings = HostCommunityMapping.objects.select_related("ipaddress", "community__network").order_by("pk")
    seen: dict[str, int] = {}
    for obj in mappings.iterator(chunk_size=chunk_size):
        if obj.host_id in wildcards:
            continue
        match = index.match(obj.ipaddress.ipaddress)
        if match is None:
            raise SnapshotError("Community IP is not contained in a network", model="HostCommunityMapping", object_id=obj.pk)
        network_id, _ = match
        mac = _normalized_mac(obj.ipaddress.macaddress)
        attachment = _attachment_ref(obj.host_id, network_id, mac)
        if obj.community.network_id != network_id:
            raise SnapshotError("Community does not match the IP network", model="HostCommunityMapping", object_id=obj.pk)
        previous = seen.get(attachment)
        if previous is not None and previous != obj.community_id:
            raise SnapshotError(
                "One attachment maps to conflicting legacy communities", model="HostCommunityMapping", object_id=obj.pk
            )
        if previous is not None:
            continue
        seen[attachment] = obj.community_id
        policy_id = obj.community.network.policy_id
        if policy_id is None:
            raise SnapshotError("Community network has no policy", model="HostCommunityMapping", object_id=obj.pk)
        yield _item(
            _ref("attachment_community_assignment", obj.pk),
            "attachment_community_assignment",
            {
                "attachment_id_ref": attachment,
                "policy_name_ref": _ref("network_policy", policy_id),
                "community_name_ref": _ref("community", obj.community_id),
            },
        )


def _host_group_items(wildcards: set[int]) -> Iterator[dict[str, Any]]:
    groups = list(HostGroup.objects.prefetch_related("parent", "hosts", "owners").order_by("pk"))
    pending = {group.pk: group for group in groups}
    emitted: set[int] = set()
    while pending:
        ready = [group for group in pending.values() if {parent.pk for parent in group.parent.all()} <= emitted]
        if not ready:
            group = min(pending.values(), key=lambda value: value.pk)
            raise SnapshotError("Host group parent relationships contain a cycle", model="HostGroup", object_id=group.pk)
        for group in sorted(ready, key=lambda value: value.pk):
            yield _item(
                _ref("host_group", group.pk),
                "host_group",
                {
                    "name": group.name,
                    "description": group.description,
                    "hosts": [_ref("host", host.pk) for host in group.hosts.all() if host.pk not in wildcards],
                    "parent_groups": [_ref("host_group", parent.pk) for parent in group.parent.all()],
                    "owner_groups": [owner.name for owner in group.owners.all()],
                },
            )
            emitted.add(group.pk)
            del pending[group.pk]


def _host_policy_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    for obj in HostPolicyAtom.objects.order_by("pk").iterator(chunk_size=chunk_size):
        yield _item(_ref("host_policy_atom", obj.pk), "host_policy_atom", {"name": obj.name, "description": obj.description})
    roles = HostPolicyRole.objects.prefetch_related("atoms", "hosts", "labels").order_by("pk")
    for obj in roles.iterator(chunk_size=chunk_size):
        yield _item(_ref("host_policy_role", obj.pk), "host_policy_role", {"name": obj.name, "description": obj.description})
    for role in roles.iterator(chunk_size=chunk_size):
        for atom in role.atoms.all():
            yield _item(
                f"host_policy_role_atom:{role.pk}:{atom.pk}",
                "host_policy_role_atom",
                {"role_name_ref": _ref("host_policy_role", role.pk), "atom_name_ref": _ref("host_policy_atom", atom.pk)},
            )
        for host in role.hosts.all():
            if host.pk not in wildcards:
                yield _item(
                    f"host_policy_role_host:{role.pk}:{host.pk}",
                    "host_policy_role_host",
                    {"role_name_ref": _ref("host_policy_role", role.pk), "host_name_ref": _ref("host", host.pk)},
                )
        for label in role.labels.all():
            yield _item(
                f"host_policy_role_label:{role.pk}:{label.pk}",
                "host_policy_role_label",
                {"role_name_ref": _ref("host_policy_role", role.pk), "label_name_ref": _ref("label", label.pk)},
            )


def iter_import_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    wildcards = _wildcard_ids()
    index = NetworkIndex()
    yield from _base_items(chunk_size)
    yield from _network_zone_items(chunk_size)
    yield from _host_items(wildcards, chunk_size)
    yield from _attachment_items(index, wildcards, chunk_size)
    yield from _ip_items(index, wildcards, chunk_size)
    yield from _dns_record_items(wildcards, chunk_size)
    yield from _relationship_items(index, wildcards, chunk_size)
    yield from _host_policy_items(wildcards, chunk_size)


@dataclass
class SnapshotArtifact:
    path: Path
    temporary_directory: tempfile.TemporaryDirectory
    digest_hex: str
    digest_base64: str
    filename: str
    content_type: str


@dataclass(frozen=True)
class SnapshotOptions:
    snapshot_format: str
    include_permissions: bool


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def iter_permission_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    """Yield legacy authorization rules separately from portable domain items."""
    queryset = NetGroupRegexPermission.objects.prefetch_related("labels").order_by("pk")
    for permission in queryset.iterator(chunk_size=chunk_size):
        yield _item(
            _ref("netgroup_regex_permission", permission.pk),
            "netgroup_regex_permission",
            {
                "group": permission.group,
                "range": str(permission.range),
                "regex": permission.regex,
                "labels": [label.name for label in permission.labels.all()],
            },
        )


def _write_ndjson(path: Path, values: Iterable[dict[str, Any]]) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    with path.open("wb") as output:
        for value in values:
            encoded = _json_bytes(value) + b"\n"
            output.write(encoded)
            digest.update(encoded)
            count += 1
    return count, digest.hexdigest()


def _write_snapshot_data(
    items_path: Path,
    permissions_path: Path | None,
    chunk_size: int,
) -> tuple[int, str, int | None, str | None, datetime]:
    try:
        with transaction.atomic(), connection.cursor() as cursor:
            if connection.vendor != "postgresql":
                raise SnapshotUnavailable("A consistent PostgreSQL snapshot cannot be obtained")
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            cursor.execute("SELECT transaction_timestamp()")
            database_timestamp = cursor.fetchone()[0]
            item_count, item_sha256 = _write_ndjson(items_path, iter_import_items(chunk_size))
            if permissions_path is None:
                permission_count = None
                permission_sha256 = None
            else:
                permission_count, permission_sha256 = _write_ndjson(
                    permissions_path, iter_permission_items(chunk_size)
                )
    except SnapshotError:
        raise
    except DatabaseError as error:
        raise SnapshotUnavailable("A consistent database snapshot could not be read") from error
    return item_count, item_sha256, permission_count, permission_sha256, database_timestamp


def _build_json_artifact(items_path: Path, artifact_path: Path, requested_by: str, created_at: datetime) -> None:
    with artifact_path.open("wb") as raw, gzip.GzipFile(
        filename="", fileobj=raw, mode="wb", mtime=int(created_at.timestamp())
    ) as output:
        output.write(b'{"requested_by":')
        output.write(_json_bytes(requested_by))
        output.write(b',"items":[')
        first = True
        with items_path.open("rb") as items:
            for line in items:
                if not first:
                    output.write(b",")
                output.write(line.rstrip(b"\n"))
                first = False
        output.write(b"]}\n")


def _build_archive(
    items_path: Path,
    permissions_path: Path | None,
    artifact_path: Path,
    manifest: dict[str, Any],
    created_at: datetime,
) -> None:
    manifest_bytes = _json_bytes(manifest) + b"\n"
    with artifact_path.open("wb") as raw, gzip.GzipFile(
        filename="", fileobj=raw, mode="wb", mtime=int(created_at.timestamp())
    ) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = int(created_at.timestamp())
            info.mode = 0o644
            import io

            archive.addfile(info, io.BytesIO(manifest_bytes))
            info = tarfile.TarInfo("items.ndjson")
            info.size = items_path.stat().st_size
            info.mtime = int(created_at.timestamp())
            info.mode = 0o644
            with items_path.open("rb") as items:
                archive.addfile(info, items)
            if permissions_path is not None:
                info = tarfile.TarInfo("permissions.ndjson")
                info.size = permissions_path.stat().st_size
                info.mtime = int(created_at.timestamp())
                info.mode = 0o644
                with permissions_path.open("rb") as permissions:
                    archive.addfile(info, permissions)


def create_snapshot_artifact(
    snapshot_format: str,
    requested_by: str,
    instance: str,
    *,
    include_permissions: bool = False,
) -> SnapshotArtifact:
    temporary_directory = tempfile.TemporaryDirectory(dir=settings.MREG_SNAPSHOT_TMPDIR)
    directory = Path(temporary_directory.name)
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    items_path = directory / "items.ndjson"
    permissions_path = directory / "permissions.ndjson" if include_permissions else None
    try:
        count, items_sha256, permission_count, permission_sha256, database_timestamp = _write_snapshot_data(
            items_path,
            permissions_path,
            settings.MREG_SNAPSHOT_CHUNK_SIZE,
        )
        if count == 0:
            raise SnapshotError("The source contains no snapshot items")
        timestamp = created_at.strftime("%Y%m%dT%H%M%SZ")
        if snapshot_format == ARCHIVE_FORMAT:
            artifact_path = directory / f"mreg-snapshot-{timestamp}-v1.tar.gz"
            manifest = {
                "format": "no.uio.mreg.snapshot",
                "format_version": 1,
                "created_at": created_at.isoformat().replace("+00:00", "Z"),
                "source": {"product": "django-mreg", "version": __version__, "instance": instance},
                "snapshot": {
                    "consistent": True,
                    "database_timestamp": database_timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
                "items": {"path": "items.ndjson", "count": count, "sha256": items_sha256},
                "permissions": (
                    {
                        "path": "permissions.ndjson",
                        "count": permission_count,
                        "sha256": permission_sha256,
                    }
                    if include_permissions
                    else None
                ),
                "semantics": {
                    "dependency_ordered": True,
                    "generated_records_omitted": [
                        "A_from_ip_assignment",
                        "AAAA_from_ip_assignment",
                        "PTR_from_ip_assignment",
                        "NS_from_zone",
                    ],
                    "audit_included": False,
                    "permissions_included": include_permissions,
                    "redacted": False,
                },
            }
            _build_archive(items_path, permissions_path, artifact_path, manifest, created_at)
            content_type = ARCHIVE_MEDIA_TYPE
        else:
            artifact_path = directory / f"mreg-import-{timestamp}-v1.json.gz"
            _build_json_artifact(items_path, artifact_path, requested_by, created_at)
            content_type = JSON_MEDIA_TYPE
        digest = hashlib.sha256()
        with artifact_path.open("rb") as artifact:
            while chunk := artifact.read(1024 * 1024):
                digest.update(chunk)
        digest_bytes = digest.digest()
        return SnapshotArtifact(
            path=artifact_path,
            temporary_directory=temporary_directory,
            digest_hex=digest.hexdigest(),
            digest_base64=base64.b64encode(digest_bytes).decode("ascii"),
            filename=artifact_path.name,
            content_type=content_type,
        )
    except Exception:
        temporary_directory.cleanup()
        raise


class SnapshotFileResponse(FileResponse):
    def __init__(self, artifact: SnapshotArtifact):
        self.artifact = artifact
        super().__init__(artifact.path.open("rb"), as_attachment=True, filename=artifact.filename, content_type=artifact.content_type)

    def close(self):
        try:
            super().close()
        finally:
            self.artifact.temporary_directory.cleanup()


def _error_response(code: str, message: str, status_code: int, error: SnapshotError | None = None) -> Response:
    body: dict[str, Any] = {"error": code, "message": message}
    if error and error.model is not None:
        body["source"] = {"model": error.model, "id": error.object_id}
    return Response(body, status=status_code)


def _header_allows(header: str, value: str) -> bool:
    """Return whether a simple weighted HTTP capability header permits value."""
    value_type = value.split("/", 1)[0] if "/" in value else None
    for entry in header.lower().split(","):
        parts = [part.strip() for part in entry.split(";")]
        candidate = parts[0]
        quality = 1.0
        for parameter in parts[1:]:
            if parameter.startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0
        if quality <= 0:
            continue
        if candidate in {"*", "*/*", value.lower()}:
            return True
        if value_type and candidate == f"{value_type}/*":
            return True
    return False


def _parse_request(request) -> SnapshotOptions:
    allowed = {"format", "include_permissions", *SUPPORTED_OPTIONS}
    unknown = set(request.query_params) - allowed
    if unknown:
        raise SnapshotRequestError(f"Unsupported query parameter: {sorted(unknown)[0]}")
    for key in allowed:
        if len(request.query_params.getlist(key)) > 1:
            raise SnapshotRequestError(f"Query parameter {key!r} may only be supplied once")
    snapshot_format = request.query_params.get("format", ARCHIVE_FORMAT)
    if snapshot_format not in {ARCHIVE_FORMAT, JSON_FORMAT}:
        raise SnapshotRequestError(f"Unsupported snapshot format: {snapshot_format}")
    include_permissions_value = request.query_params.get("include_permissions", "false")
    if include_permissions_value not in {"false", "true"}:
        raise SnapshotRequestError("Option 'include_permissions' must be 'true' or 'false'")
    include_permissions = include_permissions_value == "true"
    if include_permissions and snapshot_format != ARCHIVE_FORMAT:
        raise SnapshotRequestError(
            "Option 'include_permissions=true' is only supported by mreg-snapshot-v1"
        )
    for key, expected in SUPPORTED_OPTIONS.items():
        actual = request.query_params.get(key, expected)
        if actual != expected:
            raise SnapshotRequestError(f"Option {key!r} only supports {expected!r} in version 1")
    media_type = ARCHIVE_MEDIA_TYPE if snapshot_format == ARCHIVE_FORMAT else JSON_MEDIA_TYPE
    accept = request.headers.get("Accept", "*/*")
    if not _header_allows(accept, media_type):
        raise SnapshotNotAcceptable(f"The requested format requires Accept: {media_type}")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    if accept_encoding and not _header_allows(accept_encoding, "gzip"):
        raise SnapshotNotAcceptable("The snapshot requires gzip content encoding")
    return SnapshotOptions(snapshot_format=snapshot_format, include_permissions=include_permissions)


class SnapshotView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        if not User.from_request(request).is_mreg_snapshotter:
            return _error_response(
                "snapshot_forbidden",
                "The principal does not have snapshot permission",
                403,
            )
        try:
            options = _parse_request(request)
            artifact = create_snapshot_artifact(
                options.snapshot_format,
                request.user.username,
                request.get_host(),
                include_permissions=options.include_permissions,
            )
        except SnapshotNotAcceptable as error:
            return _error_response("snapshot_not_acceptable", str(error), 406, error)
        except SnapshotRequestError as error:
            return _error_response("invalid_snapshot_request", str(error), 400, error)
        except SnapshotUnavailable as error:
            return _error_response("snapshot_unavailable", str(error), 503, error)
        except SnapshotError as error:
            return _error_response("snapshot_failed", str(error), 409, error)
        except OSError:
            return _error_response("snapshot_unavailable", "The snapshot artifact could not be created", 503)

        response = SnapshotFileResponse(artifact)
        response["Content-Encoding"] = "gzip"
        response["Digest"] = f"sha-256=:{artifact.digest_base64}:"
        response["ETag"] = f'"snapshot-{artifact.digest_hex}"'
        response["Cache-Control"] = "private, no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
