#!/usr/bin/env python3
"""Generate TreeTop policy data from deterministic mreg-cli table output."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PERMISSIONS = ROOT / "treetop/fixtures/network-permissions.txt"
DEFAULT_ROLES = ROOT / "treetop/fixtures/hostpolicy-roles.txt"
DEFAULT_OUTPUT_DIR = ROOT / "treetop/data"

PERMISSION_HEADERS = ("Range", "Group", "Regex", "Labels")
ROLE_HEADERS = ("Name", "Description", "Labels")

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

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class ConversionError(ValueError):
    """Raised when mreg-cli output cannot be converted safely."""


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


def _column_starts(header_line: str, headers: Sequence[str]) -> tuple[int, ...]:
    starts: list[int] = []
    cursor = 0
    for header in headers:
        index = header_line.find(header, cursor)
        if index < 0:
            raise ConversionError(f"Expected table header {header!r}: {header_line!r}")
        if starts and index - cursor < 3:
            raise ConversionError(f"Table columns are not separated by at least three spaces: {header_line!r}")
        starts.append(index)
        cursor = index + len(header)
    if header_line[: starts[0]].strip() or header_line[cursor:].strip():
        raise ConversionError(f"Unexpected content in table header: {header_line!r}")
    return tuple(starts)


def parse_fixed_width_table(text: str, headers: Sequence[str]) -> list[tuple[str, ...]]:
    """Parse an OutputManager fixed-width table without splitting field content."""
    lines = [ANSI_ESCAPE.sub("", line.rstrip()) for line in text.splitlines() if line.strip()]
    if not lines:
        raise ConversionError("mreg-cli output is empty")
    starts = _column_starts(lines[0], headers)
    rows: list[tuple[str, ...]] = []
    for line_number, line in enumerate(lines[1:], start=2):
        if len(line) <= starts[-2]:
            raise ConversionError(f"Row {line_number} is shorter than the required columns: {line!r}")
        # OutputManager pads an empty final column with spaces. Be tolerant of
        # users or editors stripping that trailing whitespace from a capture.
        line = line.ljust(starts[-1])
        values = tuple(
            line[start : starts[index + 1] if index + 1 < len(starts) else None].strip()
            for index, start in enumerate(starts)
        )
        if not any(values):
            continue
        if any(not value for value in values[:-1]):
            raise ConversionError(f"Row {line_number} has an empty required column: {line!r}")
        rows.append(values)
    if not rows:
        raise ConversionError("mreg-cli output contains no data rows")
    return rows


def _parse_labels(value: str) -> tuple[str, ...]:
    return tuple(sorted({label.strip() for label in value.split(",") if label.strip()}))


def parse_permissions(text: str) -> tuple[NetworkPermission, ...]:
    permissions: set[NetworkPermission] = set()
    for network_value, group, regex, labels_value in parse_fixed_width_table(text, PERMISSION_HEADERS):
        try:
            network = str(ipaddress.ip_network(network_value, strict=True))
        except ValueError as exc:
            raise ConversionError(f"Invalid permission range {network_value!r}: {exc}") from exc
        try:
            re.compile(regex)
        except re.error as exc:
            raise ConversionError(f"Invalid permission regex {regex!r}: {exc}") from exc
        permissions.add(
            NetworkPermission(
                network=network,
                group=group,
                regex=regex,
                labels=_parse_labels(labels_value),
            )
        )
    return tuple(sorted(permissions))


def parse_roles(text: str) -> tuple[HostPolicyRole, ...]:
    roles_by_name: dict[str, HostPolicyRole] = {}
    for name, _description, labels_value in parse_fixed_width_table(text, ROLE_HEADERS):
        role = HostPolicyRole(name=name, labels=_parse_labels(labels_value))
        if name in roles_by_name:
            raise ConversionError(f"Duplicate host-policy role {name!r}")
        roles_by_name[name] = role
    return tuple(sorted(roles_by_name.values()))


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
        "// Generated from mreg-cli permission data. Do not edit by hand.\n",
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
    parser.add_argument("--permissions", type=Path, default=DEFAULT_PERMISSIONS)
    parser.add_argument("--roles", type=Path, default=DEFAULT_ROLES)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--check", action="store_true", help="fail if generated output differs")
    args = parser.parse_args(argv)

    try:
        permissions = parse_permissions(args.permissions.read_text())
        roles = parse_roles(args.roles.read_text())
        generated = generate_policy(permissions, roles)
    except (ConversionError, OSError) as exc:
        print(f"Unable to generate TreeTop policy: {exc}", file=sys.stderr)
        return 2

    outputs = _outputs(args.output_dir, generated)
    if args.check:
        stale = [path for path, content in outputs.items() if not path.exists() or path.read_text() != content]
        if stale:
            print("Generated TreeTop policy is stale: " + ", ".join(str(path) for path in stale), file=sys.stderr)
            return 1
        print("Generated TreeTop permission policy matches the mreg-cli fixtures")
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_text(content)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
