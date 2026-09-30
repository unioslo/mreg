"""Pytest snapshot tests for model display/verbose names, and their interaction
with their `display_name()` representations.
"""

from django.apps import apps
from django.db.models import Model

from mreg.utils import display_name

from inline_snapshot import snapshot

MODELS: list[Model] = sorted(
    (m for m in apps.get_models() if m._meta.app_label in {"mreg", "hostpolicy"}),
    key=lambda m: (m._meta.app_label, m.__name__),
)
"""All models in both the mreg and hostpolicy apps."""


def test_display_name_snapshot():
    """Snapshot test for model display names."""
    result = {f"{m._meta.app_label}.{m.__name__}": display_name(m) for m in MODELS}
    assert result == snapshot(
        {
            "hostpolicy.HostPolicyAtom": "atom",
            "hostpolicy.HostPolicyRole": "role",
            "mreg.BACnetID": "BACnet ID",
            "mreg.Cname": "CNAME record",
            "mreg.Community": "community",
            "mreg.ExpiringToken": "token",
            "mreg.ForwardZone": "forward zone",
            "mreg.ForwardZoneDelegation": "forward zone delegation",
            "mreg.Hinfo": "HINFO record",
            "mreg.History": "history entry",
            "mreg.Host": "host",
            "mreg.HostCommunityMapping": "host community mapping",
            "mreg.HostContact": "host contact",
            "mreg.HostGroup": "host group",
            "mreg.Ipaddress": "IP address",
            "mreg.Label": "label",
            "mreg.Loc": "LOC record",
            "mreg.Mx": "MX record",
            "mreg.NameServer": "nameserver",
            "mreg.Naptr": "NAPTR record",
            "mreg.NetGroupRegexPermission": "netgroup regex permission",
            "mreg.Network": "network",
            "mreg.NetworkExcludedRange": "network excluded range",
            "mreg.NetworkPolicy": "network policy",
            "mreg.NetworkPolicyAttribute": "network policy attribute",
            "mreg.NetworkPolicyAttributeValue": "network policy attribute value",
            "mreg.PtrOverride": "PTR override",
            "mreg.ReverseZone": "reverse zone",
            "mreg.ReverseZoneDelegation": "reverse zone delegation",
            "mreg.Srv": "SRV record",
            "mreg.Sshfp": "SSHFP record",
            "mreg.Txt": "TXT record",
            "mreg.User": "user",
        }
    )


def test_display_name_capitalize_snapshot():
    """Snapshot test for model display names."""
    result = {f"{m._meta.app_label}.{m.__name__}": display_name(m, capitalize=True) for m in MODELS}
    assert result == snapshot(
        {
            "hostpolicy.HostPolicyAtom": "Atom",
            "hostpolicy.HostPolicyRole": "Role",
            "mreg.BACnetID": "BACnet ID",
            "mreg.Cname": "CNAME record",
            "mreg.Community": "Community",
            "mreg.ExpiringToken": "Token",
            "mreg.ForwardZone": "Forward zone",
            "mreg.ForwardZoneDelegation": "Forward zone delegation",
            "mreg.Hinfo": "HINFO record",
            "mreg.History": "History entry",
            "mreg.Host": "Host",
            "mreg.HostCommunityMapping": "Host community mapping",
            "mreg.HostContact": "Host contact",
            "mreg.HostGroup": "Host group",
            "mreg.Ipaddress": "IP address",
            "mreg.Label": "Label",
            "mreg.Loc": "LOC record",
            "mreg.Mx": "MX record",
            "mreg.NameServer": "Nameserver",
            "mreg.Naptr": "NAPTR record",
            "mreg.NetGroupRegexPermission": "Netgroup regex permission",
            "mreg.Network": "Network",
            "mreg.NetworkExcludedRange": "Network excluded range",
            "mreg.NetworkPolicy": "Network policy",
            "mreg.NetworkPolicyAttribute": "Network policy attribute",
            "mreg.NetworkPolicyAttributeValue": "Network policy attribute value",
            "mreg.PtrOverride": "PTR override",
            "mreg.ReverseZone": "Reverse zone",
            "mreg.ReverseZoneDelegation": "Reverse zone delegation",
            "mreg.Srv": "SRV record",
            "mreg.Sshfp": "SSHFP record",
            "mreg.Txt": "TXT record",
            "mreg.User": "User",
        }
    )


def test_verbose_name_snapshot():
    """Snapshot test for the verbose names of models."""
    result = {
        f"{m._meta.app_label}.{m.__name__}": {
            "verbose_name": str(m._meta.verbose_name),
            "verbose_name_plural": str(m._meta.verbose_name_plural),
        }
        for m in MODELS
    }
    assert result == snapshot(
        {
            "hostpolicy.HostPolicyAtom": {"verbose_name": "atom", "verbose_name_plural": "atoms"},
            "hostpolicy.HostPolicyRole": {"verbose_name": "role", "verbose_name_plural": "roles"},
            "mreg.BACnetID": {"verbose_name": "BACnet ID", "verbose_name_plural": "BACnet IDs"},
            "mreg.Cname": {"verbose_name": "CNAME record", "verbose_name_plural": "CNAME records"},
            "mreg.Community": {"verbose_name": "community", "verbose_name_plural": "communities"},
            "mreg.ExpiringToken": {"verbose_name": "token", "verbose_name_plural": "tokens"},
            "mreg.ForwardZone": {"verbose_name": "forward zone", "verbose_name_plural": "forward zones"},
            "mreg.ForwardZoneDelegation": {"verbose_name": "forward zone delegation", "verbose_name_plural": "forward zone delegations"},
            "mreg.Hinfo": {"verbose_name": "HINFO record", "verbose_name_plural": "HINFO records"},
            "mreg.History": {"verbose_name": "history entry", "verbose_name_plural": "history entries"},
            "mreg.Host": {"verbose_name": "host", "verbose_name_plural": "hosts"},
            "mreg.HostCommunityMapping": {"verbose_name": "host community mapping", "verbose_name_plural": "host community mappings"},
            "mreg.HostContact": {"verbose_name": "host contact", "verbose_name_plural": "host contacts"},
            "mreg.HostGroup": {"verbose_name": "host group", "verbose_name_plural": "host groups"},
            "mreg.Ipaddress": {"verbose_name": "IP address", "verbose_name_plural": "IP addresses"},
            "mreg.Label": {"verbose_name": "label", "verbose_name_plural": "labels"},
            "mreg.Loc": {"verbose_name": "LOC record", "verbose_name_plural": "LOC records"},
            "mreg.Mx": {"verbose_name": "MX record", "verbose_name_plural": "MX records"},
            "mreg.NameServer": {"verbose_name": "nameserver", "verbose_name_plural": "nameservers"},
            "mreg.Naptr": {"verbose_name": "NAPTR record", "verbose_name_plural": "NAPTR records"},
            "mreg.NetGroupRegexPermission": {
                "verbose_name": "netgroup regex permission",
                "verbose_name_plural": "netgroup regex permissions",
            },
            "mreg.Network": {"verbose_name": "network", "verbose_name_plural": "networks"},
            "mreg.NetworkExcludedRange": {"verbose_name": "network excluded range", "verbose_name_plural": "network excluded ranges"},
            "mreg.NetworkPolicy": {"verbose_name": "network policy", "verbose_name_plural": "network policies"},
            "mreg.NetworkPolicyAttribute": {"verbose_name": "network policy attribute", "verbose_name_plural": "network policy attributes"},
            "mreg.NetworkPolicyAttributeValue": {
                "verbose_name": "network policy attribute value",
                "verbose_name_plural": "network policy attribute values",
            },
            "mreg.PtrOverride": {"verbose_name": "PTR override", "verbose_name_plural": "PTR overrides"},
            "mreg.ReverseZone": {"verbose_name": "reverse zone", "verbose_name_plural": "reverse zones"},
            "mreg.ReverseZoneDelegation": {"verbose_name": "reverse zone delegation", "verbose_name_plural": "reverse zone delegations"},
            "mreg.Srv": {"verbose_name": "SRV record", "verbose_name_plural": "SRV records"},
            "mreg.Sshfp": {"verbose_name": "SSHFP record", "verbose_name_plural": "SSHFP records"},
            "mreg.Txt": {"verbose_name": "TXT record", "verbose_name_plural": "TXT records"},
            "mreg.User": {"verbose_name": "user", "verbose_name_plural": "users"},
        }
    )
