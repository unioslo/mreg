from rest_framework.permissions import SAFE_METHODS

from mreg.api.permissions import IsAuthenticated
from mreg.api.treetop import authorize_policy_stack, policy_any, policy_leaf
from mreg.models.auth import User
from mreg.models.host import Host
from mreg.models.network import NetGroupRegexPermission
from hostpolicy.models import HostPolicyRole


class IsSuperOrHostPolicyAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, or has been granted access through a
    NetGroupRegexPermission, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        user = User.from_request(request)
        if request.method in SAFE_METHODS:
            legacy = True
        elif user.is_mreg_superuser_or_hostpolicy_admin:
            legacy = True
        else:
            legacy = self._legacy_role_host_permission(request, view)

        if request.method not in SAFE_METHODS and view.__class__.__name__ in {
            "HostPolicyRoleHostsDetail",
            "HostPolicyRoleHostsList",
        }:
            return self._authorize_role_host_membership(
                request=request,
                view=view,
                legacy=legacy,
            )
        if request.method not in SAFE_METHODS and view.__class__.__name__ in {
            "HostPolicyRoleAtomsDetail",
            "HostPolicyRoleAtomsList",
        }:
            role_name = str(view.kwargs.get("name") or "any")
            return authorize_policy_stack(
                legacy,
                request=request,
                root=policy_leaf(
                    action="hostpolicy_role_atom_membership_update",
                    resource_kind="HostPolicyRole",
                    resource_id=role_name,
                    resource_attrs={"kind": "host_policy_role", "name": role_name},
                ),
                view=view,
                permission_class=self.__class__.__name__,
            )
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, dict) else None,
            fallback_action="hostpolicy_admin_access",
        )

    def _authorize_role_host_membership(self, *, request, view, legacy: bool) -> bool:
        role_name = str(view.kwargs.get("name") or "")
        hostname = str(view.kwargs.get("host") or request.data.get("name") or "")
        role_labels = tuple(
            HostPolicyRole.objects.filter(name=role_name).values_list(
                "labels__name", flat=True
            )
        )
        ips = tuple(
            str(ip)
            for ip in Host.objects.filter(name=hostname)
            .exclude(ipaddresses__ipaddress=None)
            .values_list("ipaddresses__ipaddress", flat=True)
        )
        leaves = tuple(
            policy_leaf(
                action="hostpolicy_role_host_membership_update",
                resource_kind="Host",
                resource_id=hostname or "any",
                resource_attrs={
                    "kind": "host",
                    "name": hostname,
                    "hostname": hostname,
                    "ip": ip,
                    "roleLabel": str(label),
                },
            )
            for label in role_labels
            for ip in ips
        )
        root = (
            policy_any(*leaves)
            if leaves
            else policy_leaf(
                action="hostpolicy_role_host_membership_update",
                resource_kind="Host",
                resource_id=hostname or "any",
                resource_attrs={
                    "kind": "host",
                    "name": hostname,
                    "hostname": hostname,
                },
            )
        )
        return authorize_policy_stack(
            legacy,
            request=request,
            root=root,
            view=view,
            permission_class=self.__class__.__name__,
        )

    @staticmethod
    def _legacy_role_host_permission(request, view) -> bool:
        name = view.kwargs.get("name")
        if name is None:  # pragma: no cover
            return False
        if view.__class__.__name__ not in {
            "HostPolicyRoleHostsDetail",
            "HostPolicyRoleHostsList",
        }:
            return False
        role_labels = HostPolicyRole.objects.filter(name=name).values_list("labels__name", flat=True)
        if not any(role_labels):
            return False
        hostname = view.kwargs.get("host", request.data.get("name"))
        if not hostname:  # pragma: no cover
            return False
        ips = list(
            Host.objects.filter(name=hostname)
            .exclude(ipaddresses__ipaddress=None)
            .values_list("ipaddresses__ipaddress", flat=True)
        )
        permissions = NetGroupRegexPermission.find_perm(request.user.group_list, hostname, ips)
        if not permissions.exists():
            return False
        permission_labels = permissions.values_list("labels__name", flat=True)
        return any(label in permission_labels for label in role_labels)

    def has_m2m_change_permission(self, request, view):
        return True
