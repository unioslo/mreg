#!/usr/bin/env python3
"""Generate TreeTop policy data from existing MREG API endpoints."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SNAPSHOT = ROOT / "treetop/fixtures/policy-source.json"
DEFAULT_OUTPUT_DIR = ROOT / "treetop/data"
SNAPSHOT_SCHEMA_VERSION = 1
API_PAGE_SIZE = 1000

LABEL_RESOURCE_KINDS = (
    "MREG::Host",
    "MREG::Ipaddress",
    "MREG::Cname",
    "MREG::Hinfo",
    "MREG::Loc",
    "MREG::Mx",
    "MREG::Naptr",
    "MREG::NameServer",
    "MREG::PtrOverride",
    "MREG::Sshfp",
    "MREG::Srv",
    "MREG::Txt",
    "MREG::BACnetID",
    "MREG::HostPolicyRole",
)

STATIC_NAME_PATTERNS = (
    {"name": "dns_wildcard", "regex": r"\*"},
    {"name": "dns_wildcard_valid_depth", "regex": r"^(?:[^.]+\.){3,}[^.]+$"},
    {"name": "dns_underscore", "regex": "_"},
)

IP_SCOPED_ACTIONS = (
    "host_create",
    "host_update",
    "host_delete",
    "host_contacts_create",
    "host_contacts_delete",
    "ipaddress_create",
    "ipaddress_update",
    "ipaddress_delete",
    "hinfo_create",
    "hinfo_update",
    "hinfo_delete",
    "loc_create",
    "loc_update",
    "loc_delete",
    "mx_create",
    "mx_update",
    "mx_delete",
    "naptr_create",
    "naptr_update",
    "naptr_delete",
    "name_server_create",
    "name_server_update",
    "name_server_delete",
    "ptr_override_create",
    "ptr_override_update",
    "ptr_override_delete",
    "sshfp_create",
    "sshfp_update",
    "sshfp_delete",
    "srv_create",
    "srv_update",
    "srv_delete",
    "txt_create",
    "txt_update",
    "txt_delete",
    "bacnet_id_create",
    "bacnet_id_update",
    "bacnet_id_delete",
)

HOSTNAME_SCOPED_ACTIONS = (
    "cname_create",
    "cname_update",
    "cname_delete",
)

NETWORK_SCOPED_ACTIONS = (
    "community_create",
    "community_update",
    "community_delete",
    "host_create",
    "host_delete",
)

class ConversionError(ValueError):
    """Raised when MREG API data cannot be converted safely."""


@dataclass(frozen=True, order=True)
class NetworkPermission:
    network: str
    group: str
    regex: str
    labels: tuple[str, ...]


@dataclass(frozen=True, order=True)
class HostPolicyRole:
    name: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class GeneratedPolicy:
    labels: str
    cedar: str
    report: str


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConversionError(f"{context} must be a JSON object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConversionError(f"{context} must be a JSON array")
    return value


def _string(row: Mapping[str, Any], field: str, context: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ConversionError(f"{context}.{field} must be a non-empty string")
    return value


def _label_names(value: Any, context: str) -> tuple[str, ...]:
    labels = _array(value, context)
    if any(not isinstance(label, str) or not label for label in labels):
        raise ConversionError(f"{context} must contain only non-empty strings")
    return tuple(sorted(set(labels)))


def _permission(row: Mapping[str, Any], context: str) -> NetworkPermission:
    network_value = _string(row, "range", context)
    group = _string(row, "group", context)
    regex = _string(row, "regex", context)
    try:
        network = str(ipaddress.ip_network(network_value, strict=True))
    except ValueError as exc:
        raise ConversionError(f"Invalid permission range {network_value!r}: {exc}") from exc
    try:
        re.compile(regex)
    except re.error as exc:
        raise ConversionError(f"Invalid permission regex {regex!r}: {exc}") from exc
    return NetworkPermission(
        network=network,
        group=group,
        regex=regex,
        labels=_label_names(row.get("labels"), f"{context}.labels"),
    )


def _role(row: Mapping[str, Any], context: str) -> HostPolicyRole:
    return HostPolicyRole(
        name=_string(row, "name", context),
        labels=_label_names(row.get("labels"), f"{context}.labels"),
    )


def parse_snapshot(text: str) -> tuple[tuple[NetworkPermission, ...], tuple[HostPolicyRole, ...]]:
    """Parse the deterministic, normalized snapshot produced from MREG endpoints."""
    try:
        payload = _object(json.loads(text), "snapshot")
    except json.JSONDecodeError as exc:
        raise ConversionError(f"Snapshot is not valid JSON: {exc}") from exc
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise ConversionError(f"snapshot.schema_version must be {SNAPSHOT_SCHEMA_VERSION}")

    permission_rows = _array(payload.get("permissions"), "snapshot.permissions")
    permissions = {
        _permission(_object(row, f"snapshot.permissions[{index}]"), f"snapshot.permissions[{index}]")
        for index, row in enumerate(permission_rows)
    }
    if not permissions:
        raise ConversionError("snapshot.permissions contains no data rows")

    role_rows = _array(payload.get("roles"), "snapshot.roles")
    roles_by_name: dict[str, HostPolicyRole] = {}
    for index, value in enumerate(role_rows):
        context = f"snapshot.roles[{index}]"
        role = _role(_object(value, context), context)
        if role.name in roles_by_name:
            raise ConversionError(f"Duplicate host-policy role {role.name!r}")
        roles_by_name[role.name] = role
    if not roles_by_name:
        raise ConversionError("snapshot.roles contains no data rows")
    return tuple(sorted(permissions)), tuple(sorted(roles_by_name.values()))


def serialize_snapshot(
    permissions: Iterable[NetworkPermission],
    roles: Iterable[HostPolicyRole],
) -> str:
    """Serialize only the endpoint fields needed to reproduce generated policy."""
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "permissions": [
            {
                "group": permission.group,
                "labels": list(permission.labels),
                "range": permission.network,
                "regex": permission.regex,
            }
            for permission in sorted(set(permissions))
        ],
        "roles": [
            {"labels": list(role.labels), "name": role.name}
            for role in sorted(set(roles))
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def snapshot_from_endpoint_rows(
    permission_rows: Sequence[Mapping[str, Any]],
    role_rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
) -> str:
    """Normalize the three existing endpoint responses into one stable snapshot."""
    label_names: dict[int, str] = {}
    names_seen: set[str] = set()
    for index, row in enumerate(label_rows):
        context = f"labels[{index}]"
        label_id = row.get("id")
        if isinstance(label_id, bool) or not isinstance(label_id, int):
            raise ConversionError(f"{context}.id must be an integer")
        name = _string(row, "name", context)
        if label_id in label_names:
            raise ConversionError(f"Duplicate label id {label_id}")
        if name in names_seen:
            raise ConversionError(f"Duplicate label name {name!r}")
        label_names[label_id] = name
        names_seen.add(name)

    def resolve_labels(row: Mapping[str, Any], context: str) -> tuple[str, ...]:
        label_ids = _array(row.get("labels"), f"{context}.labels")
        resolved: set[str] = set()
        for label_id in label_ids:
            if isinstance(label_id, bool) or not isinstance(label_id, int):
                raise ConversionError(f"{context}.labels must contain only integer label ids")
            try:
                resolved.add(label_names[label_id])
            except KeyError as exc:
                raise ConversionError(f"{context} references unknown label id {label_id}") from exc
        return tuple(sorted(resolved))

    permissions: list[NetworkPermission] = []
    for index, row in enumerate(permission_rows):
        context = f"permissions[{index}]"
        normalized = dict(row)
        normalized["labels"] = list(resolve_labels(row, context))
        permissions.append(_permission(normalized, context))

    roles: list[HostPolicyRole] = []
    for index, row in enumerate(role_rows):
        context = f"roles[{index}]"
        normalized = dict(row)
        normalized["labels"] = list(resolve_labels(row, context))
        roles.append(_role(normalized, context))
    return serialize_snapshot(permissions, roles)


def _validated_api_base_url(value: str) -> str:
    url = value.rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ConversionError("MREG API base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConversionError("MREG API base URL must not contain credentials, a query, or a fragment")
    return url


def _same_origin(url: str, base_url: str) -> bool:
    parsed = urlparse(url)
    base = urlparse(base_url)
    return (parsed.scheme.lower(), parsed.netloc.lower()) == (base.scheme.lower(), base.netloc.lower())


def _fetch_paginated_rows(
    *,
    base_url: str,
    path: str,
    token: str,
    timeout: float,
    ordering: str,
) -> list[Mapping[str, Any]]:
    query = urlencode({"ordering": ordering, "page_size": API_PAGE_SIZE})
    next_url: str | None = f"{urljoin(base_url + '/', path.lstrip('/'))}?{query}"
    seen_urls: set[str] = set()
    rows: list[Mapping[str, Any]] = []

    while next_url is not None:
        if next_url in seen_urls:
            raise ConversionError(f"MREG API pagination loop detected at {next_url}")
        if not _same_origin(next_url, base_url):
            raise ConversionError(f"MREG API pagination URL changed origin: {next_url}")
        seen_urls.add(next_url)
        request = Request(next_url, headers={"Accept": "application/json"})
        # Do not allow urllib to copy the API token to a redirected request.
        # The endpoint URLs already include their canonical trailing slash.
        request.add_unredirected_header("Authorization", f"Token {token}")
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL scheme and origin are validated.
                response_url = response.geturl()
                if not _same_origin(response_url, base_url):
                    raise ConversionError(f"MREG API response changed origin: {response_url}")
                payload = _object(json.loads(response.read()), f"response from {next_url}")
        except HTTPError as exc:
            raise ConversionError(f"MREG API returned HTTP {exc.code} for {next_url}") from exc
        except URLError as exc:
            raise ConversionError(f"Unable to reach MREG API at {next_url}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise ConversionError(f"MREG API returned invalid JSON for {next_url}: {exc}") from exc

        page_rows = _array(payload.get("results"), f"response from {next_url}.results")
        rows.extend(
            _object(row, f"response from {next_url}.results[{index}]")
            for index, row in enumerate(page_rows)
        )
        following = payload.get("next")
        if following is None:
            next_url = None
        elif isinstance(following, str) and following:
            next_url = urljoin(next_url, following)
        else:
            raise ConversionError(f"response from {next_url}.next must be a URL or null")
    return rows


def fetch_policy_snapshot(base_url: str, token: str, timeout: float = 20.0) -> str:
    """Fetch current policy inputs from existing MREG endpoints."""
    base_url = _validated_api_base_url(base_url)
    token = token.strip()
    if not token or "\r" in token or "\n" in token:
        raise ConversionError("MREG_API_TOKEN must be a non-empty HTTP header value")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConversionError("MREG API timeout must be a finite number greater than zero")

    labels = _fetch_paginated_rows(
        base_url=base_url,
        path="/api/v1/labels/",
        token=token,
        timeout=timeout,
        ordering="name",
    )
    permissions = _fetch_paginated_rows(
        base_url=base_url,
        path="/api/v1/permissions/netgroupregex/",
        token=token,
        timeout=timeout,
        ordering="range,group",
    )
    roles = _fetch_paginated_rows(
        base_url=base_url,
        path="/api/v1/hostpolicy/roles/",
        token=token,
        timeout=timeout,
        ordering="name",
    )
    return snapshot_from_endpoint_rows(permissions, roles, labels)


def _stable_name(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _actions(actions: Sequence[str], indent: str = "        ") -> str:
    values = [f'MREG::Action::{_quote(action)}' for action in actions]
    return "[" + (",\n" + indent).join(values) + "]"


def _ranges(networks: Sequence[str], *, attribute: str = "ip") -> str:
    checks = [f'resource.{attribute}.isInRange(ip({_quote(network)}))' for network in networks]
    return "(" + (" ||\n     ").join(checks) + ")"


def _network_values(networks: Sequence[str]) -> str:
    checks = [f'resource.network == {_quote(network)}' for network in networks]
    return "(" + (" ||\n     ").join(checks) + ")"


def _permit_ip_rule(group: str, regex: str, networks: Sequence[str]) -> str:
    label = _stable_name("netgroup", regex)
    policy_id = _stable_name("netgroup_ip", group, regex)
    return f'''@id("MREG.generated.{policy_id}")
permit (
    principal in MREG::Group::{_quote(group)},
    action in
        {_actions(IP_SCOPED_ACTIONS)},
    resource
)
when {{
    resource has nameLabels &&
    resource.nameLabels.contains({_quote(label)}) &&
    resource has ip &&
    {_ranges(networks)}
}};
'''


def _permit_hostname_rule(group: str, regex: str) -> str:
    label = _stable_name("netgroup", regex)
    policy_id = _stable_name("netgroup_hostname", group, regex)
    return f'''@id("MREG.generated.{policy_id}")
permit (
    principal in MREG::Group::{_quote(group)},
    action in
        {_actions(HOSTNAME_SCOPED_ACTIONS)},
    resource is MREG::Cname
)
when {{
    resource has nameLabels &&
    resource.nameLabels.contains({_quote(label)})
}};
'''


def _permit_network_rule(group: str, networks: Sequence[str]) -> str:
    policy_id = _stable_name("netgroup_network", group)
    return f'''@id("MREG.generated.{policy_id}")
permit (
    principal in MREG::Group::{_quote(group)},
    action in
        {_actions(NETWORK_SCOPED_ACTIONS)},
    resource
)
when {{
    resource has network &&
    {_network_values(networks)}
}};
'''


def _permit_role_rule(group: str, regex: str, role_name: str, networks: Sequence[str]) -> str:
    label = _stable_name("netgroup", regex)
    policy_id = _stable_name("hostpolicy_role", group, regex, role_name)
    return f'''@id("MREG.generated.{policy_id}")
permit (
    principal in MREG::Group::{_quote(group)},
    action == MREG::Action::"hostpolicy_role_host_membership_update",
    resource == MREG::HostPolicyRole::{_quote(role_name)}
)
when {{
    resource has nameLabels &&
    resource.nameLabels.contains({_quote(label)}) &&
    resource has ip &&
    {_ranges(networks)}
}};
'''


def _group_values(permissions: Iterable[NetworkPermission], *fields: str) -> dict[tuple[str, ...], set[str]]:
    grouped: dict[tuple[str, ...], set[str]] = {}
    for permission in permissions:
        key = tuple(str(getattr(permission, field)) for field in fields)
        grouped.setdefault(key, set()).add(permission.network)
    return grouped


def _normalized_networks(networks: Iterable[str]) -> tuple[str, ...]:
    """Sort and collapse redundant ranges without mixing address families."""
    parsed = [ipaddress.ip_network(network) for network in networks]
    collapsed = [
        network
        for version in (4, 6)
        for network in ipaddress.collapse_addresses(
            network for network in parsed if network.version == version
        )
    ]
    return tuple(str(network) for network in collapsed)


def generate_policy(permissions: Sequence[NetworkPermission], roles: Sequence[HostPolicyRole]) -> GeneratedPolicy:
    permissions = tuple(sorted(set(permissions)))
    roles = tuple(sorted(set(roles)))
    regexes = sorted({permission.regex for permission in permissions})
    patterns = [
        {"name": _stable_name("netgroup", regex), "regex": regex}
        for regex in regexes
    ]
    labels = [
        {
            "kind": kind,
            "field": "hostname",
            "output": "nameLabels",
            "patterns": [
                *(STATIC_NAME_PATTERNS if kind != "MREG::HostPolicyRole" else ()),
                *patterns,
            ],
        }
        for kind in LABEL_RESOURCE_KINDS
    ]

    rules: list[str] = [
        "// Generated from the normalized MREG API policy snapshot. Do not edit by hand.\n",
    ]
    rule_ids: list[str] = []

    by_group_regex = _group_values(permissions, "group", "regex")
    for (group, regex), networks_set in sorted(by_group_regex.items()):
        networks = _normalized_networks(networks_set)
        rules.append(_permit_ip_rule(group, regex, networks))
        rules.append(_permit_hostname_rule(group, regex))
        rule_ids.extend(
            (
                _stable_name("netgroup_ip", group, regex),
                _stable_name("netgroup_hostname", group, regex),
            )
        )

    by_group = _group_values(permissions, "group")
    for (group,), networks_set in sorted(by_group.items()):
        networks = _normalized_networks(networks_set)
        rules.append(_permit_network_rule(group, networks))
        rule_ids.append(_stable_name("netgroup_network", group))

    role_networks: dict[tuple[str, str, str], set[str]] = {}
    used_legacy_labels: set[str] = set()
    for permission in permissions:
        permission_labels = set(permission.labels)
        if not permission_labels:
            continue
        for role in roles:
            shared = permission_labels.intersection(role.labels)
            if not shared:
                continue
            used_legacy_labels.update(shared)
            key = (permission.group, permission.regex, role.name)
            role_networks.setdefault(key, set()).add(permission.network)

    for (group, regex, role_name), networks_set in sorted(role_networks.items()):
        rules.append(_permit_role_rule(group, regex, role_name, _normalized_networks(networks_set)))
        rule_ids.append(_stable_name("hostpolicy_role", group, regex, role_name))

    permission_labels = {label for permission in permissions for label in permission.labels}
    role_labels = {label for role in roles for label in role.labels}
    report_data = {
        "permission_rows": len(permissions),
        "role_rows": len(roles),
        "unique_regexes": len(regexes),
        "generated_rules": len(rule_ids),
        "generated_role_rules": len(role_networks),
        "unused_permission_labels": sorted(permission_labels - used_legacy_labels),
        "unmatched_role_labels": sorted(role_labels - permission_labels),
        "derived_labels": {regex: _stable_name("netgroup", regex) for regex in regexes},
        "policy_ids": sorted(rule_ids),
    }
    return GeneratedPolicy(
        labels=json.dumps(labels, indent=2, ensure_ascii=False) + "\n",
        cedar="\n".join(rules).rstrip() + "\n",
        report=json.dumps(report_data, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    )


def _outputs(output_dir: Path, policy: GeneratedPolicy) -> dict[Path, str]:
    return {
        output_dir / "labels.json": policy.labels,
        output_dir / "netgroup.cedar": policy.cedar,
        output_dir / "netgroup-conversion-report.json": policy.report,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("MREG_API_BASE_URL"),
        help="fetch current inputs from MREG instead of using the checked-in snapshot",
    )
    parser.add_argument(
        "--api-timeout",
        default=os.environ.get("MREG_API_TIMEOUT", "20"),
        type=float,
        help="per-request MREG API timeout in seconds (default: 20)",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--check", action="store_true", help="fail if generated output differs")
    args = parser.parse_args(argv)

    try:
        fetched_snapshot = None
        if args.api_base_url:
            token = os.environ.get("MREG_API_TOKEN", "")
            if not token:
                raise ConversionError("MREG_API_TOKEN is required when MREG_API_BASE_URL is configured")
            fetched_snapshot = fetch_policy_snapshot(args.api_base_url, token, args.api_timeout)
            snapshot = fetched_snapshot
        else:
            snapshot = args.snapshot.read_text()
        permissions, roles = parse_snapshot(snapshot)
        generated = generate_policy(permissions, roles)
    except (ConversionError, OSError) as exc:
        print(f"Unable to generate TreeTop policy: {exc}", file=sys.stderr)
        return 2

    outputs = _outputs(args.output_dir, generated)
    if args.check:
        stale = [path for path, content in outputs.items() if not path.exists() or path.read_text() != content]
        if fetched_snapshot is not None and (
            not args.snapshot.exists() or args.snapshot.read_text() != fetched_snapshot
        ):
            stale.append(args.snapshot)
        if stale:
            print("Generated TreeTop policy is stale: " + ", ".join(str(path) for path in stale), file=sys.stderr)
            return 1
        print("Generated TreeTop permission policy matches the MREG API snapshot")
        return 0

    if fetched_snapshot is not None:
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(fetched_snapshot)
        print(f"wrote {args.snapshot}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_text(content)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
