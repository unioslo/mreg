"""Authoritative MREG policy resource and action contracts.

This module deliberately has no Django dependencies.  Runtime resource adapters
and the Cedar schema generator both consume these declarations so their view of
resource kinds, identifiers, attributes, and actions cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass


CRUD_OPERATIONS = ("create", "delete", "read", "update")


@dataclass(frozen=True)
class ResourceAttributeContract:
    """One optional Cedar resource attribute."""

    name: str
    cedar_type: str = "String"


@dataclass(frozen=True)
class ResourceContract:
    """Policy-facing resource metadata shared by Python and Cedar."""

    kind: str
    operations: tuple[str, ...] = ()
    attributes: tuple[ResourceAttributeContract, ...] = ()
    identifier_fields: tuple[str, ...] = ("pk", "id", "name", "cpk", "hostpk", "network")

    @property
    def actions(self) -> tuple[str, ...]:
        token = snake_case(self.kind)
        return tuple(f"{token}_{operation}" for operation in self.operations)


def snake_case(value: str) -> str:
    """Return the stable action token for a Python/Cedar resource name."""
    import re

    if value.startswith("BACnet"):
        value = f"Bacnet{value[len('BACnet') :]}"
    value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = value.replace("-", "_")
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower() or "generic"


HOST_ATTRIBUTES = tuple(
    ResourceAttributeContract(name, cedar_type)
    for name, cedar_type in (
        ("kind", "String"),
        ("id", "String"),
        ("name", "String"),
        ("path", "String"),
        ("hostname", "String"),
        ("ip", "ipaddr"),
        ("nameLabels", "Set<String>"),
    )
)


RESOURCE_CONTRACTS = (
    ResourceContract("Generic"),
    ResourceContract("Host", CRUD_OPERATIONS, HOST_ATTRIBUTES),
    ResourceContract("HostContact", identifier_fields=("pk", "id", "email")),
    ResourceContract(
        "Ipaddress",
        CRUD_OPERATIONS,
        (
            ResourceAttributeContract("kind"),
            ResourceAttributeContract("id"),
            ResourceAttributeContract("ip", "ipaddr"),
        ),
        identifier_fields=("pk", "id", "ipaddress"),
    ),
    *(ResourceContract(kind, CRUD_OPERATIONS) for kind in (
        "Cname",
        "Hinfo",
        "Loc",
        "Mx",
        "Naptr",
        "NameServer",
        "PtrOverride",
        "Sshfp",
        "Srv",
        "Txt",
        "BACnetID",
        "Community",
        "HostCommunityMapping",
        "Label",
        "Network",
        "NetworkPolicy",
        "NetworkPolicyAttribute",
        "NetworkPolicyAttributeValue",
    )),
)


RESOURCE_CONTRACT_BY_KIND = {contract.kind: contract for contract in RESOURCE_CONTRACTS}

MEMBERSHIP_ACTIONS = {
    "superuser": "superuser_access",
    "admin": "admin_access",
    "group_admin": "hostgroup_admin_access",
    "network_admin": "network_admin_access",
    "dns_wildcard": "dns_wildcard_admin_access",
    "dns_underscore": "dns_underscore_admin_access",
    "hostpolicy_admin": "hostpolicy_admin_access",
}

CUSTOM_ACTIONS = frozenset(
    {
        *MEMBERSHIP_ACTIONS.values(),
        "create_label",
        "delete_label",
        "edit_label",
        "host_contacts_read",
        "ip_broadcast_management",
        "ip_gw_management",
        "ip_network_management",
        "ip_reserved_management",
        "ip_restricted_management",
        "is_superuser",
        "view_label",
    }
)

POLICY_ACTIONS = tuple(
    sorted(
        {
            *CUSTOM_ACTIONS,
            *(action for contract in RESOURCE_CONTRACTS for action in contract.actions),
        }
    )
)


def render_cedar_schema() -> str:
    """Render the deterministic human-readable Cedar schema."""
    lines = [
        "namespace MREG {",
        "    entity Group;",
        "    entity User in [Group];",
        "",
    ]
    for contract in RESOURCE_CONTRACTS:
        if contract.attributes:
            lines.append(f"    entity {contract.kind} = {{")
            lines.extend(
                f"        {attribute.name}?: {attribute.cedar_type},"
                for attribute in contract.attributes
            )
            lines.append("    };")
        else:
            lines.append(f"    entity {contract.kind};")
    lines.extend(("", "    action"))
    for index, action in enumerate(POLICY_ACTIONS):
        suffix = "," if index < len(POLICY_ACTIONS) - 1 else ""
        lines.append(f'        "{action}"{suffix}')
    lines.extend(
        (
            "    appliesTo {",
            "        principal: User,",
            "        resource: [",
        )
    )
    for index, contract in enumerate(RESOURCE_CONTRACTS):
        suffix = "," if index < len(RESOURCE_CONTRACTS) - 1 else ""
        lines.append(f"            {contract.kind}{suffix}")
    lines.extend(("        ]", "    };", "}", ""))
    return "\n".join(lines)
