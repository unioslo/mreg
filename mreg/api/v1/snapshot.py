"""Synchronous, versioned portable snapshots."""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import io
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
from rest_framework.exceptions import PermissionDenied
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg import __version__
from mreg.api.permissions import IsSnapshotGroupMember
from mreg.models.base import Label, NameServer
from mreg.models.host import BACnetID, Host, HostContact, HostGroup, Ipaddress, PtrOverride
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
DEFERRED_WILDCARD_RECORD_TYPES = frozenset({"HINFO", "LOC", "SSHFP"})


class SnapshotArchiveRenderer(JSONRenderer):
    """Register the archive representation for DRF content negotiation."""

    media_type = ARCHIVE_MEDIA_TYPE
    format = ARCHIVE_FORMAT


class SnapshotJSONRenderer(JSONRenderer):
    """Register the JSON import representation's query format."""

    format = JSON_FORMAT


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


def _validate_snapshot_options(snapshot_format: str, include_permissions: bool) -> None:
    if snapshot_format not in {ARCHIVE_FORMAT, JSON_FORMAT}:
        raise SnapshotRequestError(f"Unsupported snapshot format: {snapshot_format}")
    if include_permissions and snapshot_format != ARCHIVE_FORMAT:
        raise SnapshotRequestError("Option 'include_permissions=true' is only supported by mreg-snapshot-v1")


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
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


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
            raise SnapshotError("Community references a network without a policy", model="Community", object_id=obj.pk)
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
    duplicate = Ipaddress.objects.values("ipaddress").annotate(count=Count("pk")).filter(count__gt=1).order_by("ipaddress").first()
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

        remaining = [float(token.removesuffix("m")) for token in tokens[lon_end + 1 :]]
        if not remaining:
            raise ValueError("missing altitude")
        result = {
            "latitude": coordinate(tokens[:lat_end], tokens[lat_end]),
            "longitude": coordinate(tokens[lon_start:lon_end], tokens[lon_end]),
            "altitude_m": remaining[0],
        }
        for key, number in zip(("size_m", "horizontal_precision_m", "vertical_precision_m"), remaining[1:], strict=False):
            result[key] = number
        return result
    except (ValueError, IndexError) as error:
        raise SnapshotError("LOC value cannot be translated", model="Loc", object_id=pk) from error


def _split_dns_character_strings(value: str) -> list[str]:
    """Split text into RFC 1035 character-strings of at most 255 octets."""
    chunks: list[str] = []
    current: list[str] = []
    current_size = 0
    for character in value:
        character_size = len(character.encode("utf-8"))
        if current and current_size + character_size > 255:
            chunks.append("".join(current))
            current = []
            current_size = 0
        current.append(character)
        current_size += character_size
    chunks.append("".join(current))
    return chunks


_HOST_RECORD_SPECIFICATIONS = (
    (Hinfo, "HINFO", lambda obj: {"cpu": obj.cpu, "os": obj.os}, lambda obj: obj.host.ttl),
    (Loc, "LOC", lambda obj: _parse_loc(obj.loc, pk=obj.pk), lambda obj: obj.host.ttl),
    (Mx, "MX", lambda obj: {"preference": obj.priority, "exchange": obj.mx}, lambda obj: obj.host.ttl),
    (Txt, "TXT", lambda obj: {"value": _split_dns_character_strings(obj.txt)}, lambda obj: obj.host.ttl),
    (
        Naptr,
        "NAPTR",
        lambda obj: {
            "order": obj.order,
            "preference": obj.preference,
            "flags": obj.flag,
            "services": obj.service,
            "regexp": obj.regex,
            "replacement": obj.replacement,
        },
        lambda obj: obj.host.ttl,
    ),
    (
        Sshfp,
        "SSHFP",
        lambda obj: {
            "algorithm": obj.algorithm,
            "fp_type": obj.hash_type,
            "fingerprint": obj.fingerprint,
        },
        lambda obj: obj.ttl if obj.ttl is not None else obj.host.ttl,
    ),
)


def _wildcard_address_record_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    queryset = Ipaddress.objects.filter(host_id__in=wildcards).select_related("host").order_by("pk")
    for obj in queryset.iterator(chunk_size=chunk_size):
        address = ipaddress.ip_address(obj.ipaddress)
        yield _item(
            _ref("record_ip_address", obj.pk),
            "record",
            _record_attributes(
                "A" if address.version == 4 else "AAAA",
                obj.host.name,
                {"address": obj.ipaddress},
                ttl=obj.host.ttl,
            ),
        )


def _host_dns_record_items(
    wildcards: set[int],
    chunk_size: int,
    *,
    deferred: bool,
) -> Iterator[dict[str, Any]]:
    for model, type_name, data_factory, ttl_factory in _HOST_RECORD_SPECIFICATIONS:
        queryset = model.objects.select_related("host").order_by("pk")
        for obj in queryset.iterator(chunk_size=chunk_size):
            wildcard = obj.host_id in wildcards
            is_deferred = wildcard and type_name in DEFERRED_WILDCARD_RECORD_TYPES
            if is_deferred != deferred:
                continue
            if type_name == "MX" and not wildcard:
                owner_kind = "forward_zone"
                anchor_ref = _ref("forward_zone", obj.host.zone_id) if obj.host.zone_id else None
                if anchor_ref is None:
                    raise SnapshotError("MX owner has no forward zone", model="Mx", object_id=obj.pk)
            else:
                owner_kind = None if wildcard else "host"
                anchor_ref = None if wildcard else _ref("host", obj.host_id)
            item = _item(
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
            if is_deferred:
                item["deferred"] = {
                    "reason": "wildcard_owner_not_supported_by_import_contract",
                    "requires_manual_handling": True,
                }
            yield item


def _standalone_dns_record_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    for model, type_name, data_factory in (
        (Cname, "CNAME", lambda obj: {"target": obj.host.name}),
        (
            Srv,
            "SRV",
            lambda obj: {
                "priority": obj.priority,
                "weight": obj.weight,
                "port": obj.port,
                "target": obj.host.name,
            },
        ),
    ):
        queryset = model.objects.select_related("host").order_by("pk")
        for obj in queryset.iterator(chunk_size=chunk_size):
            yield _item(
                _ref(f"record_{model._meta.model_name}", obj.pk),
                "record",
                _record_attributes(type_name, obj.name, data_factory(obj), ttl=obj.ttl),
            )


def _validate_wildcard_hosts(wildcards: set[int], chunk_size: int) -> None:
    for host in Host.objects.filter(pk__in=wildcards).order_by("pk").iterator(chunk_size=chunk_size):
        has_dns = Ipaddress.objects.filter(host_id=host.pk).exists() or any(
            model.objects.filter(host_id=host.pk).exists() for model, *_ in _HOST_RECORD_SPECIFICATIONS
        )
        if not has_dns:
            raise SnapshotError("Wildcard host has no translatable DNS data", model="Host", object_id=host.pk)
        if host.comment or host.contacts.exists() or host.hostgroups.exists() or host.hostpolicyroles.exists():
            raise SnapshotError("Wildcard host has non-DNS relationships", model="Host", object_id=host.pk)
        if BACnetID.objects.filter(host_id=host.pk).exists() or HostCommunityMapping.objects.filter(host_id=host.pk).exists():
            raise SnapshotError("Wildcard host has non-DNS relationships", model="Host", object_id=host.pk)


def _dns_record_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    yield from _wildcard_address_record_items(wildcards, chunk_size)
    yield from _host_dns_record_items(wildcards, chunk_size, deferred=False)
    yield from _standalone_dns_record_items(chunk_size)
    _validate_wildcard_hosts(wildcards, chunk_size)


def _deferred_dns_record_items(wildcards: set[int], chunk_size: int) -> Iterator[dict[str, Any]]:
    yield from _host_dns_record_items(wildcards, chunk_size, deferred=True)


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
            raise SnapshotError("One attachment maps to conflicting legacy communities", model="HostCommunityMapping", object_id=obj.pk)
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


def iter_deferred_record_items(chunk_size: int) -> Iterator[dict[str, Any]]:
    """Yield valid source records whose automatic import must be deferred."""
    yield from _deferred_dns_record_items(_wildcard_ids(), chunk_size)


@dataclass(frozen=True)
class SnapshotArtifact:
    path: Path
    temporary_directory: tempfile.TemporaryDirectory[str]
    digest_hex: str
    digest_base64: str
    filename: str
    content_type: str

    def cleanup(self) -> None:
        self.temporary_directory.cleanup()


@dataclass(frozen=True)
class SnapshotOptions:
    snapshot_format: str
    include_permissions: bool


@dataclass(frozen=True)
class SnapshotDataFile:
    path: Path
    count: int
    sha256: str

    def manifest_entry(self) -> dict[str, str | int]:
        return {
            "path": self.path.name,
            "count": self.count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SnapshotData:
    items: SnapshotDataFile
    deferred_records: SnapshotDataFile
    permissions: SnapshotDataFile | None
    database_timestamp: datetime


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


def _write_ndjson(path: Path, values: Iterable[dict[str, Any]]) -> SnapshotDataFile:
    digest = hashlib.sha256()
    count = 0
    with path.open("wb") as output:
        for value in values:
            encoded = _json_bytes(value) + b"\n"
            output.write(encoded)
            digest.update(encoded)
            count += 1
    return SnapshotDataFile(path=path, count=count, sha256=digest.hexdigest())


def _write_snapshot_data(
    directory: Path,
    chunk_size: int,
    *,
    include_permissions: bool,
) -> SnapshotData:
    try:
        with transaction.atomic(), connection.cursor() as cursor:
            if connection.vendor != "postgresql":
                raise SnapshotUnavailable("A consistent PostgreSQL snapshot cannot be obtained")
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            cursor.execute("SELECT transaction_timestamp()")
            database_timestamp = cursor.fetchone()[0]
            items = _write_ndjson(directory / "items.ndjson", iter_import_items(chunk_size))
            deferred_records = _write_ndjson(
                directory / "deferred-records.ndjson",
                iter_deferred_record_items(chunk_size),
            )
            permissions = (
                _write_ndjson(directory / "permissions.ndjson", iter_permission_items(chunk_size)) if include_permissions else None
            )
    except SnapshotError:
        raise
    except DatabaseError as error:
        raise SnapshotUnavailable("A consistent database snapshot could not be read") from error
    return SnapshotData(
        items=items,
        deferred_records=deferred_records,
        permissions=permissions,
        database_timestamp=database_timestamp,
    )


def _write_json_array(output, path: Path) -> None:
    first = True
    with path.open("rb") as values:
        for line in values:
            if not first:
                output.write(b",")
            output.write(line.rstrip(b"\n"))
            first = False


def _build_json_artifact(
    data: SnapshotData,
    artifact_path: Path,
    requested_by: str,
    created_at: datetime,
) -> None:
    with artifact_path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=int(created_at.timestamp())) as output:
        output.write(b'{"requested_by":')
        output.write(_json_bytes(requested_by))
        output.write(b',"items":[')
        _write_json_array(output, data.items.path)
        output.write(b'],"deferred_records":[')
        _write_json_array(output, data.deferred_records.path)
        output.write(b"]}\n")


def _tar_info(name: str, size: int, created_at: datetime) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = int(created_at.timestamp())
    info.mode = 0o644
    return info


def _add_bytes_to_archive(archive: tarfile.TarFile, name: str, content: bytes, created_at: datetime) -> None:
    archive.addfile(_tar_info(name, len(content), created_at), io.BytesIO(content))


def _add_data_file_to_archive(archive: tarfile.TarFile, data_file: SnapshotDataFile, created_at: datetime) -> None:
    with data_file.path.open("rb") as source:
        archive.addfile(_tar_info(data_file.path.name, data_file.path.stat().st_size, created_at), source)


def _build_archive(
    data: SnapshotData,
    artifact_path: Path,
    manifest: dict[str, Any],
    created_at: datetime,
) -> None:
    manifest_bytes = _json_bytes(manifest) + b"\n"
    with (
        artifact_path.open("wb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=int(created_at.timestamp())) as compressed,
    ):
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            _add_bytes_to_archive(archive, "manifest.json", manifest_bytes, created_at)
            _add_data_file_to_archive(archive, data.items, created_at)
            _add_data_file_to_archive(archive, data.deferred_records, created_at)
            if data.permissions is not None:
                _add_data_file_to_archive(archive, data.permissions, created_at)


def _build_manifest(data: SnapshotData, created_at: datetime, instance: str) -> dict[str, Any]:
    permissions_included = data.permissions is not None
    return {
        "format": "no.uio.mreg.snapshot",
        "format_version": 1,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "source": {"product": "django-mreg", "version": __version__, "instance": instance},
        "snapshot": {
            "consistent": True,
            "database_timestamp": data.database_timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "items": data.items.manifest_entry(),
        "deferred_records": data.deferred_records.manifest_entry(),
        "permissions": data.permissions.manifest_entry() if data.permissions is not None else None,
        "semantics": {
            "dependency_ordered": True,
            "generated_records_omitted": [
                "A_from_ip_assignment",
                "AAAA_from_ip_assignment",
                "PTR_from_ip_assignment",
                "NS_from_zone",
            ],
            "audit_included": False,
            "permissions_included": permissions_included,
            "redacted": False,
            "fully_importable": data.deferred_records.count == 0,
        },
    }


def _artifact_digest(path: Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest(), base64.b64encode(digest.digest()).decode("ascii")


def create_snapshot_artifact(
    snapshot_format: str,
    requested_by: str,
    instance: str,
    *,
    include_permissions: bool = False,
) -> SnapshotArtifact:
    _validate_snapshot_options(snapshot_format, include_permissions)
    temporary_directory = tempfile.TemporaryDirectory(dir=settings.MREG_SNAPSHOT_TMPDIR)
    directory = Path(temporary_directory.name)
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        data = _write_snapshot_data(
            directory,
            settings.MREG_SNAPSHOT_CHUNK_SIZE,
            include_permissions=include_permissions,
        )
        if data.items.count == 0:
            raise SnapshotError("The source contains no snapshot items")
        timestamp = created_at.strftime("%Y%m%dT%H%M%SZ")
        if snapshot_format == ARCHIVE_FORMAT:
            artifact_path = directory / f"mreg-snapshot-{timestamp}-v1.tar.gz"
            manifest = _build_manifest(data, created_at, instance)
            _build_archive(data, artifact_path, manifest, created_at)
            content_type = ARCHIVE_MEDIA_TYPE
        else:
            artifact_path = directory / f"mreg-import-{timestamp}-v1.json.gz"
            _build_json_artifact(data, artifact_path, requested_by, created_at)
            content_type = JSON_MEDIA_TYPE
        digest_hex, digest_base64 = _artifact_digest(artifact_path)
        return SnapshotArtifact(
            path=artifact_path,
            temporary_directory=temporary_directory,
            digest_hex=digest_hex,
            digest_base64=digest_base64,
            filename=artifact_path.name,
            content_type=content_type,
        )
    except Exception:
        temporary_directory.cleanup()
        raise


class SnapshotFileResponse(FileResponse):
    def __init__(self, artifact: SnapshotArtifact):
        self.artifact = artifact
        source = None
        try:
            source = artifact.path.open("rb")
            super().__init__(source, as_attachment=True, filename=artifact.filename, content_type=artifact.content_type)
        except Exception:
            if source is not None:
                source.close()
            artifact.cleanup()
            raise

    def close(self) -> None:
        try:
            super().close()
        finally:
            self.artifact.cleanup()


def _error_response(code: str, message: str, status_code: int, error: SnapshotError | None = None) -> Response:
    body: dict[str, Any] = {"error": code, "message": message}
    if error and error.model is not None:
        body["source"] = {"model": error.model, "id": error.object_id}
    return Response(body, status=status_code, content_type=JSON_MEDIA_TYPE)


def _header_allows(header: str, value: str) -> bool:
    """Return whether the most specific HTTP capability range permits value."""
    value_type = value.split("/", 1)[0] if "/" in value else None
    matches: list[tuple[int, float]] = []
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
        if not 0 <= quality <= 1:
            quality = 0
        if candidate == value.lower():
            matches.append((2, quality))
        elif value_type and candidate == f"{value_type}/*":
            matches.append((1, quality))
        elif candidate in {"*", "*/*"}:
            matches.append((0, quality))
    if not matches:
        return False
    specificity = max(match[0] for match in matches)
    return max(quality for match_specificity, quality in matches if match_specificity == specificity) > 0


def _parse_request(request) -> SnapshotOptions:
    allowed = {"format", "include_permissions", *SUPPORTED_OPTIONS}
    unknown = set(request.query_params) - allowed
    if unknown:
        raise SnapshotRequestError(f"Unsupported query parameter: {sorted(unknown)[0]}")
    for key in allowed:
        if len(request.query_params.getlist(key)) > 1:
            raise SnapshotRequestError(f"Query parameter {key!r} may only be supplied once")
    snapshot_format = request.query_params.get("format", ARCHIVE_FORMAT)
    include_permissions_value = request.query_params.get("include_permissions", "false")
    if include_permissions_value not in {"false", "true"}:
        raise SnapshotRequestError("Option 'include_permissions' must be 'true' or 'false'")
    include_permissions = include_permissions_value == "true"
    _validate_snapshot_options(snapshot_format, include_permissions)
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
    permission_classes = (IsSnapshotGroupMember,)
    renderer_classes = (SnapshotArchiveRenderer, SnapshotJSONRenderer)

    def handle_exception(self, exc: Exception) -> Response:
        if isinstance(exc, PermissionDenied):
            return _error_response(
                "snapshot_forbidden",
                "The principal does not have snapshot permission",
                403,
            )
        return super().handle_exception(exc)

    def get(self, request):
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
        response["Content-Digest"] = f"sha-256=:{artifact.digest_base64}:"
        response["ETag"] = f'"snapshot-{artifact.digest_hex}"'
        response["Cache-Control"] = "private, no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
