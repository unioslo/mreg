from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated as DRFIsAuthenticated, SAFE_METHODS
from rest_framework.request import Request

from structlog import get_logger

from mreg.api.responses import error_body
from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import Host, HostGroup
from mreg.models.network import NetGroupRegexPermission, Network

from mreg.models.auth import User, MregAdminGroup
from mreg.api.treetop import (
    PolicyCheck,
    PolicyResource,
    authorize_policy_stack,
    policy_all,
    policy_any,
    policy_enforcement_enabled,
    policy_leaf,
    policy_parity,
    policy_shadow_enabled,
)
from mreg.policy.contracts import MEMBERSHIP_ACTIONS, snake_case
from mreg.policy.resources import (
    adapter_for_kind,
    crud_operation_from_method,
    policy_action_from_view,
    resource_id_from_view,
    resource_kind_from_view,
    stringify_attribute,
)

# NOTE: We _must_ import `rest_framework.generics` in an `if TYPE_CHECKING:`
# block because DRF does some dynamic import shenanigans on runtime using
# the `DEFAULT_PERMISSION_CLASSES` we defined in `settings.py`, causing
# an import cycle if we _actually_ import the generics module on runtime.
if TYPE_CHECKING:
    from rest_framework.generics import GenericAPIView
    from rest_framework.serializers import Serializer
    from mreg.models.base import BaseModel

logger = get_logger()

DEFAULT_RESOURCE_ATTRS = {"kind": "generic", "id": "any"}


class ParityMixin:
    """Translate legacy permission results into explicit policy contracts."""

    _MEMBERSHIP_ACTIONS = {
        MregAdminGroup.SUPERUSER: MEMBERSHIP_ACTIONS["superuser"],
        MregAdminGroup.ADMINUSER: MEMBERSHIP_ACTIONS["admin"],
        MregAdminGroup.GROUP_ADMIN: MEMBERSHIP_ACTIONS["group_admin"],
        MregAdminGroup.NETWORK_ADMIN: MEMBERSHIP_ACTIONS["network_admin"],
        MregAdminGroup.DNS_WILDCARD: MEMBERSHIP_ACTIONS["dns_wildcard"],
        MregAdminGroup.DNS_UNDERSCORE: MEMBERSHIP_ACTIONS["dns_underscore"],
        MregAdminGroup.HOSTPOLICY_ADMIN: MEMBERSHIP_ACTIONS["hostpolicy_admin"],
    }

    @staticmethod
    def _stringify_attr_value(value: Any) -> str:
        """Convert attribute values to strings for TreeTop resource attributes."""
        return stringify_attribute(value)

    @staticmethod
    def _snake_case(value: str) -> str:
        """Normalize model/resource names to snake_case action/resource tokens."""
        return snake_case(value)

    def _resource_kind_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: "Serializer | None" = None,
        obj: Any = None,
    ) -> str:
        return resource_kind_from_view(view=view, validated_serializer=validated_serializer, obj=obj)

    def _resource_id_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: "Serializer | None" = None,
        obj: Any = None,
        data: Mapping[str, Any] | None = None,
        default: str = "any",
    ) -> str:
        """Resolve a stable resource identifier through its registered adapter."""
        kind = self._resource_kind_from_view(view=view, validated_serializer=validated_serializer, obj=obj)
        return resource_id_from_view(
            view=view,
            kind=kind,
            validated_serializer=validated_serializer,
            obj=obj,
            data=data,
            default=default,
        )

    def _crud_operation_from_method(self, method: str) -> str:
        """Map an HTTP method to a CRUD operation token."""
        return crud_operation_from_method(method)

    def _crud_action(self, resource_kind: str, operation: str) -> str:
        """Build a policy action name like `<resource>_<operation>`."""
        contract = adapter_for_kind(resource_kind).contract
        if operation not in contract.operations:
            raise ValueError(f"{resource_kind} does not declare the {operation} policy operation")
        return f"{self._snake_case(resource_kind)}_{operation}"

    def _policy_action_from_view(
        self,
        *,
        view: "GenericAPIView",
        resource_kind: str,
        operation: str,
    ) -> str:
        """Resolve an explicit custom action or the model-backed CRUD action."""
        return policy_action_from_view(view=view, resource_kind=resource_kind, operation=operation)

    def _normalize_resource_attrs(
        self,
        *,
        resource_kind: str,
        attrs: Mapping[str, Any] | None,
    ) -> dict[str, str]:
        """Normalize resource attributes to string values with a canonical kind."""
        return adapter_for_kind(resource_kind).attributes(attrs)

    def pp(
        self,
        *,
        decision: bool,
        action: str,
        request: Request,
        view: "GenericAPIView",
        resource_kind: str = "Generic",
        resource_id: str = "any",
        resource_attrs: Mapping[str, str] | None = None,
    ) -> bool:
        """Queue one parity check without changing the legacy decision."""
        return policy_parity(
            decision,
            request=request,
            view=view,
            permission_class=self.__class__.__name__,
            check=PolicyCheck(
                action=action,
                resource=PolicyResource(
                    kind=resource_kind,
                    id=resource_id,
                    attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
                ),
            ),
        )

    def pp_generic_action(
        self,
        attrs: Mapping[str, Any],
        decision: bool,
        action: str,
        request: Request,
        view: GenericAPIView,
        kind: str = "Generic",
        resource_id: str = "any",
    ) -> bool:
        """Convenience wrapper that normalizes attrs and forwards to pp()."""
        return self.pp(
            decision=decision,
            action=action,
            request=request,
            view=view,
            resource_kind=kind,
            resource_id=str(resource_id),
            resource_attrs=self._normalize_resource_attrs(resource_kind=kind, attrs=attrs),
        )

    def user_has_permission(
        self, membership: MregAdminGroup, request: Request, view: GenericAPIView, exclude_superuser: bool = False
    ) -> bool:
        """
        Check if the user has a given generic permission level.
        """
        user = User.from_request(request)
        memberlist = membership.settings_groups_or_raise()

        if not exclude_superuser and membership != MregAdminGroup.SUPERUSER:
            memberlist.extend(MregAdminGroup.SUPERUSER.settings_groups_or_raise())

        is_member = user.is_member_of_any(memberlist)

        return is_member

    def user_is_superuser(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a superuser.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.SUPERUSER,
            request=request,
            view=view,
        )

    def user_is_admin(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is an admin.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.ADMINUSER,
            request=request,
            view=view,
        )

    def user_is_network_admin(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a network admin.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.NETWORK_ADMIN,
            request=request,
            view=view,
        )

    def user_is_dns_wildcard_admin(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a DNS wildcard admin.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.DNS_WILDCARD,
            request=request,
            view=view,
        )

    def user_is_dns_underscore_admin(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a DNS underscore admin.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.DNS_UNDERSCORE,
            request=request,
            view=view,
        )

    def user_is_hostgroup_admin(self, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a hostgroup admin.
        """
        return self.user_has_permission(
            membership=MregAdminGroup.GROUP_ADMIN,
            request=request,
            view=view,
        )

    def user_is_any(self, *memberships: MregAdminGroup, request: Request, view: GenericAPIView) -> bool:
        """
        Check if the user is a member of any of the given groups.
        """
        for membership in memberships:
            if self.user_has_permission(membership, request, view):
                return True
        return False

    def authorize_memberships(
        self,
        *memberships: MregAdminGroup,
        legacy_decision: bool,
        request: Request,
        view: GenericAPIView,
    ) -> bool:
        """Authorize an OR of membership actions in one TreeTop call."""
        leaves = tuple(
            policy_leaf(
                action=self._MEMBERSHIP_ACTIONS[membership],
                resource_kind="Generic",
                resource_id="any",
                resource_attrs=DEFAULT_RESOURCE_ATTRS,
            )
            for membership in memberships
        )
        root = leaves[0] if len(leaves) == 1 else policy_any(*leaves)
        return authorize_policy_stack(
            legacy_decision,
            request=request,
            root=root,
            view=view,
            permission_class=self.__class__.__name__,
        )

    def authorize_endpoint(
        self,
        *,
        legacy_decision: bool,
        request: Request,
        view: GenericAPIView,
        validated_serializer: Serializer | None = None,
        obj: Any = None,
        data: Mapping[str, Any] | None = None,
        fallback_action: str = "authenticated_access",
    ) -> bool:
        """Authorize one ordinary endpoint operation as a single-leaf stack."""
        try:
            resource_kind = self._resource_kind_from_view(
                view=view,
                validated_serializer=validated_serializer,
                obj=obj,
            )
            operation = self._crud_operation_from_method(request.method)
            action = self._policy_action_from_view(
                view=view,
                resource_kind=resource_kind,
                operation=operation,
            )
            resource_id = self._resource_id_from_view(
                view=view,
                validated_serializer=validated_serializer,
                obj=obj,
                data=data,
            )
            attrs = self._normalize_resource_attrs(
                resource_kind=resource_kind,
                attrs=data,
            )
        except ValueError:
            resource_kind = "Generic"
            action = fallback_action
            resource_id = str(next(iter(getattr(view, "kwargs", {}).values()), "any"))
            attrs = DEFAULT_RESOURCE_ATTRS
        return authorize_policy_stack(
            legacy_decision,
            request=request,
            root=policy_leaf(
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
                resource_attrs=attrs,
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )


class CRUDPermissionsMixin:
    """
    Mixin to provide `has_{create, update, destroy}_permission` methods
    for all permission classes. By default, these methods return `False`,
    and should be overridden in subclasses to provide this functionality (if used).
    """

    # Can be overridden in subclasses to provide custom permission logic
    # for different operations.
    def has_create_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer) -> bool:
        return False

    def has_update_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer) -> bool:
        return False

    def has_destroy_permission(self, request: Request, view: GenericAPIView, validated_serializer: BaseModel) -> bool:
        return False


class IsAuthenticated(DRFIsAuthenticated, CRUDPermissionsMixin, ParityMixin):
    """
    Allows access only to authenticated users.
    """

    def deny_superuser_only_names(self, data=None, name=None, view=None, request=None):
        """Check for superuser only names. If match, return True."""
        import mreg.api.v1.views as v1_views

        if data is not None:
            name = data.get("name", "")
            if not name:
                if "host" in data:
                    name = data["host"].name

        name = (name or "").strip()  # Guarantee coercion to string

        if not request:  # pragma: no cover
            return False

        if not view:  # pragma: no cover
            return False

        # Underscore is allowed for non-superuser in SRV records,
        # and for members of <DNS_UNDERSCORE_GROUP> in all records.
        if (
            "_" in name
            and not isinstance(view, (v1_views.SrvDetail, v1_views.SrvList))
            and not self.user_is_dns_underscore_admin(request, view)
        ):
            return True

        # Except for super-users, only members of the DNS wildcard group can create wildcard records.
        # And then only below subdomains, like *.sub.example.com
        if "*" in name and (not self.user_is_dns_wildcard_admin(request, view) or name.count(".") < 3):
            return True

        return False

    def deny_reserved_ipaddress(self, ip: str, request: Request, view: GenericAPIView) -> bool:
        """Check if an ip address is reserved, and if so, only permit
        NETWORK_ADMIN_GROUP members."""

        if self.user_is_network_admin(request, view):
            return False

        network = Network.objects.filter(network__net_contains=ip).first()
        if not network:
            return False

        return network.is_reserved_ipaddress(ip)

    def deny_restricted_ipaddress(self, ip: str, request: Request, view: GenericAPIView) -> bool:
        """Check all IP restrictions applied while assigning an address."""
        if self.deny_reserved_ipaddress(ip, request, view):
            return True
        if self.user_is_network_admin(request, view):
            return False
        network = Network.objects.filter(network__net_contains=ip).first()
        if not network:
            return False
        address = ipaddress.ip_address(ip)
        return address in {
            network.network.network_address,
            network.network.broadcast_address,
        }

    pass


class IsAuthenticatedWithPolicy(IsAuthenticated):
    """Authenticate locally, then authorize the endpoint once in TreeTop."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.authorize_endpoint(
            legacy_decision=True,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
        )


class UserInfoPermission(IsAuthenticated):
    """Authorize access to the requesting user's or another user's details."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = User.from_request(request)
        target_username = request.query_params.get("username") or user.username
        self_access = target_username == user.username
        legacy = self_access or user.is_mreg_superuser_or_admin or user.is_mreg_hostgroup_admin
        return authorize_policy_stack(
            legacy,
            request=request,
            root=policy_leaf(
                action="user_info_read",
                resource_kind="Generic",
                resource_id=str(target_username),
                resource_attrs={
                    "kind": "generic",
                    "name": str(target_username),
                    "selfAccess": str(self_access).lower(),
                },
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )


class IsAuthenticatedAndReadOnly(IsAuthenticated):
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method not in SAFE_METHODS:
            return False
        return self.authorize_endpoint(
            legacy_decision=True,
            request=request,
            view=view,
        )


class IsSuperGroupMember(IsAuthenticated):
    """
    Permit user if in super user group.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        return self.pp(
            decision=User.from_request(request).is_mreg_superuser,
            action="is_superuser",
            request=request,
            view=view,
        )


class IsSuperOrAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return self.authorize_endpoint(legacy_decision=True, request=request, view=view)
        legacy = self.user_is_admin(request=request, view=view)
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
            fallback_action=self._MEMBERSHIP_ACTIONS[MregAdminGroup.ADMINUSER],
        )


class IsSuperOrNetworkAdminMember(IsAuthenticated):
    """
    Permit user if in super user group or network admin group.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        legacy = self.user_is_any(
            MregAdminGroup.SUPERUSER,
            MregAdminGroup.NETWORK_ADMIN,
            request=request,
            view=view,
        )
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
            fallback_action=self._MEMBERSHIP_ACTIONS[MregAdminGroup.NETWORK_ADMIN],
        )


class IsSuperOrReadOnly(IsAuthenticated):
    """Authorize safe reads or superuser-only mutations with one stack."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        legacy = request.method in SAFE_METHODS or self.user_is_superuser(request, view)
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
            fallback_action=self._MEMBERSHIP_ACTIONS[MregAdminGroup.SUPERUSER],
        )


class IsNetworkAdminOrReadOnly(IsAuthenticated):
    """Authorize safe reads or network-admin mutations with one stack."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        legacy = request.method in SAFE_METHODS or self.user_is_any(
            MregAdminGroup.SUPERUSER,
            MregAdminGroup.NETWORK_ADMIN,
            request=request,
            view=view,
        )
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
            fallback_action=self._MEMBERSHIP_ACTIONS[MregAdminGroup.NETWORK_ADMIN],
        )


class IsSuperOrGroupAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return self.authorize_endpoint(legacy_decision=True, request=request, view=view)

        legacy = self.user_is_any(
            MregAdminGroup.SUPERUSER,
            MregAdminGroup.GROUP_ADMIN,
            request=request,
            view=view,
        )
        return self.authorize_endpoint(
            legacy_decision=legacy,
            request=request,
            view=view,
            data=request.data if isinstance(request.data, Mapping) else None,
            fallback_action=self._MEMBERSHIP_ACTIONS[MregAdminGroup.GROUP_ADMIN],
        )


class IsGrantedNetGroupRegexPermission(IsAuthenticated):
    """
    Permit user if the user has been granted access through a
    NetGroupRegexPermission.

    Note that if there is a network element in the URL, this class checks for access to the
    network element itself and then short-circuits. This is URL only, so the user cannot manipulate
    this input in the request body.
    """

    def has_permission(self, request, view):
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not super().has_permission(request, view):
            return False

        user = User.from_request(request)
        if request.method in SAFE_METHODS:
            resource_kind = self._resource_kind_from_view(view=view)
            return self.pp_generic_action(
                decision=True,
                action=self._policy_action_from_view(
                    view=view,
                    resource_kind=resource_kind,
                    operation="read",
                ),
                kind=resource_kind,
                resource_id=self._resource_id_from_view(view=view),
                attrs={"path": request.path},
                request=request,
                view=view,
            )

        if user.is_mreg_superuser_or_admin:
            return True

        if policy_enforcement_enabled() or policy_shadow_enabled():
            return True

        # Will do do more object checks later, but initially refuse any
        # unwarranted requests.
        qs = NetGroupRegexPermission.objects.filter(group__in=user.group_list)
        # If the view has a network in the URL, use the network itself as part
        # of the permission check. This is URL only, so the user cannot manipulate
        # this input in the request body.
        network_in_url = view.kwargs.get("network")
        if network_in_url:
            qs = qs.filter(range=network_in_url)
        if qs.exists():
            return True
        return False

    def _target_policy_node(
        self,
        *,
        hostname: str,
        ips: Sequence[str],
        action: str,
        resource_kind: str,
        resource_id: str,
        policy_name: str | None = None,
        extra_attrs: Mapping[str, str] | None = None,
    ):
        """Build an OR of target-IP leaves with raw authorization facts."""
        checked_name = str(policy_name or hostname)
        values = tuple(ips) or (None,)
        leaves = []
        for ip in values:
            attrs = {
                "kind": self._snake_case(resource_kind),
                "name": checked_name,
                "hostname": str(hostname),
                "dnsWildcard": str("*" in checked_name).lower(),
                "dnsWildcardValidDepth": str(checked_name.count(".") >= 3).lower(),
                "dnsUnderscore": str("_" in checked_name).lower(),
            }
            if ip is not None:
                attrs["ip"] = str(ip)
                network = Network.objects.filter(network__net_contains=str(ip)).first()
                attrs["ipReserved"] = str(bool(network and network.is_reserved_ipaddress(str(ip)))).lower()
                attrs["ipRestricted"] = str(
                    bool(
                        network
                        and (
                            network.is_reserved_ipaddress(str(ip))
                            or ipaddress.ip_address(ip)
                            in {
                                network.network.network_address,
                                network.network.broadcast_address,
                            }
                        )
                    )
                ).lower()
            if extra_attrs:
                attrs.update(extra_attrs)
            leaves.append(
                policy_leaf(
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    resource_attrs=attrs,
                )
            )
        return leaves[0] if len(leaves) == 1 else policy_any(*leaves)

    def _required_resource_kind(
        self,
        *,
        view: GenericAPIView,
        validated_serializer: Serializer | None = None,
        obj: Any = None,
    ) -> str:
        """Translate an unregistered target into the legacy permission error."""
        try:
            return self._resource_kind_from_view(
                view=view,
                validated_serializer=validated_serializer,
                obj=obj,
            )
        except ValueError as exc:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}") from exc

    def has_perm(
        self,
        user,
        hostname,
        ips,
        request: Request,
        view: GenericAPIView,
        require_ip=True,
        action: str | None = None,
        resource_kind: str = "Host",
        resource_id: str | None = None,
        legacy_decision: bool | None = None,
    ):
        """Evaluate all hostname/IP candidates in one synchronous policy stack."""
        legacy = (
            bool(NetGroupRegexPermission.find_perm(user.group_list, hostname, ips, require_ip))
            if legacy_decision is None
            else bool(legacy_decision)
        )
        operation = self._crud_operation_from_method(request.method)
        resolved_action = action or self._crud_action(resource_kind, operation)
        resolved_resource_id = str(resource_id or hostname or "any")
        root = self._target_policy_node(
            hostname=str(hostname),
            ips=tuple(str(ip) for ip in ips),
            action=resolved_action,
            resource_kind=resource_kind,
            resource_id=resolved_resource_id,
        )
        return authorize_policy_stack(
            legacy,
            request=request,
            root=root,
            view=view,
            permission_class=self.__class__.__name__,
        )

    def has_obj_perm(
        self,
        user: User,
        obj: str,
        request: Request,
        view: GenericAPIView,
        action: str | None = None,
        resource_kind: str = "Host",
        resource_id: str | None = None,
    ) -> bool:
        """Resolve hostname/IPs from an object and delegate to has_perm()."""
        return self.has_perm(
            user,
            *self._get_hostname_and_ips(obj),
            request=request,
            view=view,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
        )

    def _flatten_policy_attrs(self, data: Mapping[str, Any], *, resource_kind: str) -> dict[str, str]:
        """Adapt serializer data through the resource's registered adapter."""
        return adapter_for_kind(resource_kind).attributes(data)

    @staticmethod
    def _legacy_target_permission(user: User, hostname: str, ips: Sequence[str], *, require_ip: bool = True) -> bool:
        return bool(NetGroupRegexPermission.find_perm(user.group_list, hostname, ips, require_ip))

    def _has_create_target_permission(
        self,
        *,
        user: User,
        request: Request,
        view: GenericAPIView,
        data: Mapping[str, Any],
        action: str,
        resource_kind: str,
        resource_id: str,
        restriction_denied: bool,
    ) -> bool:
        """Build and authorize the complete create stack in one call."""
        import mreg.api.v1.views as v1_views

        ip_value = data.get("ipaddress")
        host = data.get("host")
        standalone_name = str(data.get("name") or "")
        standalone_target = not host and not isinstance(
            view,
            (
                v1_views.CnameList,
                v1_views.HostList,
                v1_views.IpaddressList,
                v1_views.PtrOverrideList,
            ),
        )
        if isinstance(view, v1_views.CnameList):
            name = self._stringify_attr_value(data["name"])
            node = self._target_policy_node(
                hostname=name,
                ips=(),
                action=action,
                resource_kind=resource_kind,
                resource_id=name,
            )
            target_legacy = self._legacy_target_permission(user, name, (), require_ip=False)
            nodes = [node]
        else:
            if isinstance(view, v1_views.HostList):
                hostname = str(getattr(host, "name", None) or data.get("name") or "")
                if not hostname:
                    return False
                ips = [ip_value] if ip_value else []
            elif isinstance(view, (v1_views.IpaddressList, v1_views.PtrOverrideList)):
                if not (ip_value and host):
                    return False
                hostname = host.name
                ips = [ip_value]
            elif host:
                hostname, ips = self._get_hostname_and_ips(host)
            elif standalone_name:
                hostname, ips = standalone_name, []
            else:
                raise exceptions.PermissionDenied(f"Unhandled view: {view}")

            if not hostname:
                return False
            nodes = [
                self._target_policy_node(
                    hostname=str(hostname),
                    ips=tuple(str(ip) for ip in ips),
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=self._stringify_attr_value(hostname),
                    policy_name=self._stringify_attr_value(data.get("name") or hostname),
                )
            ]
            target_legacy = self._legacy_target_permission(user, hostname, ips)
            if isinstance(view, (v1_views.IpaddressList, v1_views.PtrOverrideList)):
                old_hostname, old_ips = self._get_hostname_and_ips(host)
                nodes.insert(
                    0,
                    self._target_policy_node(
                        hostname=str(old_hostname),
                        ips=tuple(str(ip) for ip in old_ips),
                        action=action,
                        resource_kind=resource_kind,
                        resource_id=resource_id,
                    ),
                )
                target_legacy = target_legacy and self._legacy_target_permission(
                    user,
                    old_hostname,
                    old_ips,
                )

        role_legacy = user.is_mreg_superuser or (user.is_mreg_admin and not standalone_target)
        legacy = user.is_mreg_superuser or (not restriction_denied and (role_legacy or target_legacy))
        root = nodes[0] if len(nodes) == 1 else policy_all(*nodes)
        return authorize_policy_stack(
            legacy,
            request=request,
            root=root,
            view=view,
            permission_class=self.__class__.__name__,
        )

    def has_create_permission(self, request, view, validated_serializer):
        """Authorize create operations using CRUD parity actions and legacy rules."""
        user = User.from_request(request)
        data: dict[str, Any] = validated_serializer.validated_data  # type: ignore
        logger.debug(
            "create_permission_check",
            user=user.username,
            view=view.__class__.__name__,
            fields=sorted(data),
        )

        resource_kind = self._required_resource_kind(
            view=view,
            validated_serializer=validated_serializer,
        )
        action = self._policy_action_from_view(
            view=view,
            resource_kind=resource_kind,
            operation="create",
        )
        resource_id = self._resource_id_from_view(
            view=view,
            validated_serializer=validated_serializer,
            data=data,
        )
        ip_value = data.get("ipaddress")

        restriction_denied = self.deny_superuser_only_names(
            data=data,
            view=view,
            request=request,
        ) or bool(
            ip_value
            and self.deny_restricted_ipaddress(
                ip=ip_value,
                view=view,
                request=request,
            )
        )
        return self._has_create_target_permission(
            user=user,
            request=request,
            view=view,
            data=data,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
            restriction_denied=restriction_denied,
        )

    def has_destroy_permission(self, request, view, validated_serializer):
        """Authorize delete operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views

        user = User.from_request(request)

        target_obj = view.get_object()
        host_obj = target_obj
        standalone_target = False
        if not isinstance(view, v1_views.HostDetail) and hasattr(target_obj, "host"):
            host_obj = target_obj.host
        elif not isinstance(view, v1_views.HostDetail):
            standalone_target = True

        resource_kind = self._required_resource_kind(view=view, obj=target_obj)
        action = self._policy_action_from_view(
            view=view,
            resource_kind=resource_kind,
            operation="delete",
        )
        resource_id = self._resource_id_from_view(view=view, obj=target_obj)
        if standalone_target:
            hostname = str(getattr(target_obj, "name", resource_id))
            ips = []
        else:
            hostname, ips = self._get_hostname_and_ips(host_obj)
        restriction_denied = self.deny_superuser_only_names(
            name=host_obj.name,
            view=view,
            request=request,
        ) or bool(
            hasattr(host_obj, "ipaddress")
            and self.deny_reserved_ipaddress(
                ip=host_obj.ipaddress,
                view=view,
                request=request,
            )
        )
        target_legacy = self._legacy_target_permission(user, hostname, ips)
        legacy = user.is_mreg_superuser or (not restriction_denied and ((user.is_mreg_admin and not standalone_target) or target_legacy))
        return authorize_policy_stack(
            legacy,
            request=request,
            root=self._target_policy_node(
                hostname=hostname,
                ips=tuple(str(ip) for ip in ips),
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
                policy_name=self._stringify_attr_value(getattr(target_obj, "name", None) or hostname),
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )

    def _host_detail_update_stack(
        self,
        *,
        user: User,
        target_obj: Any,
        data: Mapping[str, Any],
        action: str,
        resource_kind: str,
    ):
        hostname, ips = self._get_hostname_and_ips(target_obj)
        nodes = [
            self._target_policy_node(
                hostname=hostname,
                ips=tuple(str(ip) for ip in ips),
                action=action,
                resource_kind=resource_kind,
                resource_id=self._stringify_attr_value(hostname),
                policy_name=self._stringify_attr_value(getattr(target_obj, "name", None) or hostname),
            )
        ]
        legacy = self._legacy_target_permission(user, hostname, ips)
        if "name" in data:
            new_name = self._stringify_attr_value(data["name"])
            nodes.insert(
                0,
                self._target_policy_node(
                    hostname=new_name,
                    ips=tuple(str(ip) for ip in ips),
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=new_name,
                    policy_name=new_name,
                ),
            )
            legacy = legacy and self._legacy_target_permission(user, new_name, ips)
        return (nodes[0] if len(nodes) == 1 else policy_all(*nodes), legacy)

    def _related_host_update_stack(
        self,
        *,
        user: User,
        target_obj: Any,
        data: Mapping[str, Any],
        action: str,
        resource_kind: str,
        resource_id: str,
    ):
        hosts = [target_obj.host]
        if "host" in data and data["host"] != target_obj.host:
            hosts.insert(0, data["host"])
        nodes = []
        legacy_values = []
        for host in hosts:
            hostname, ips = self._get_hostname_and_ips(host)
            nodes.append(
                self._target_policy_node(
                    hostname=hostname,
                    ips=tuple(str(ip) for ip in ips),
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    policy_name=self._stringify_attr_value(data.get("name") or getattr(target_obj, "name", None) or hostname),
                )
            )
            legacy_values.append(self._legacy_target_permission(user, hostname, ips))
        return (nodes[0] if len(nodes) == 1 else policy_all(*nodes), all(legacy_values))

    def has_update_permission(self, request, view, validated_serializer):
        """Authorize update operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views

        user = User.from_request(request)

        data: dict[str, Any] = validated_serializer.validated_data  # type: ignore
        target_obj = view.get_object()
        standalone_target = not isinstance(view, v1_views.HostDetail) and not hasattr(target_obj, "host")

        resource_kind = self._required_resource_kind(
            view=view,
            validated_serializer=validated_serializer,
            obj=target_obj,
        )
        action = self._policy_action_from_view(
            view=view,
            resource_kind=resource_kind,
            operation="update",
        )
        resource_id = self._resource_id_from_view(
            view=view,
            validated_serializer=validated_serializer,
            obj=target_obj,
            data=data,
        )

        restriction_denied = self.deny_superuser_only_names(
            data=data,
            view=view,
            request=request,
        ) or bool(
            "ipaddress" in data
            and self.deny_restricted_ipaddress(
                ip=data["ipaddress"],
                view=view,
                request=request,
            )
        )

        if isinstance(view, v1_views.HostDetail):
            root, target_legacy = self._host_detail_update_stack(
                user=user,
                target_obj=target_obj,
                data=data,
                action=action,
                resource_kind=resource_kind,
            )
        elif hasattr(target_obj, "host"):
            root, target_legacy = self._related_host_update_stack(
                user=user,
                target_obj=target_obj,
                data=data,
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
            )
        else:
            current_name = str(getattr(target_obj, "name", resource_id))
            nodes = [
                self._target_policy_node(
                    hostname=current_name,
                    ips=(),
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    policy_name=str(data.get("name") or current_name),
                )
            ]
            if data.get("name") and data["name"] != current_name:
                new_name = str(data["name"])
                nodes.insert(
                    0,
                    self._target_policy_node(
                        hostname=new_name,
                        ips=(),
                        action=action,
                        resource_kind=resource_kind,
                        resource_id=new_name,
                        policy_name=new_name,
                    ),
                )
            root = nodes[0] if len(nodes) == 1 else policy_all(*nodes)
            target_legacy = False

        legacy = user.is_mreg_superuser or (not restriction_denied and ((user.is_mreg_admin and not standalone_target) or target_legacy))
        return authorize_policy_stack(
            legacy,
            request=request,
            root=root,
            view=view,
            permission_class=self.__class__.__name__,
        )

    def _get_hostname_and_ips(self, hostobject):
        """Extract a host's canonical name and all attached IP addresses."""
        ips = []
        host = HostSerializer(hostobject)
        for i in host.data["ipaddresses"]:
            ips.append(i["ipaddress"])
        return host.data["name"], ips


class IsGrantedNetGroupRegexOrNetworkAdmin(IsGrantedNetGroupRegexPermission):
    """Combine the former DRF OR expression into one endpoint decision."""

    def has_permission(self, request, view):
        if not DRFIsAuthenticated.has_permission(self, request, view):
            return False
        user = User.from_request(request)
        legacy = request.method in SAFE_METHODS or user.is_mreg_superuser_or_admin
        if not legacy:
            qs = NetGroupRegexPermission.objects.filter(group__in=user.group_list)
            if network_in_url := view.kwargs.get("network"):
                qs = qs.filter(range=network_in_url)
            legacy = qs.exists() or user.is_mreg_network_admin
        resource_kind = self._resource_kind_from_view(view=view)
        operation = self._crud_operation_from_method(request.method)
        action = self._policy_action_from_view(
            view=view,
            resource_kind=resource_kind,
            operation=operation,
        )
        network = str(view.kwargs.get("network") or "")
        attrs = self._normalize_resource_attrs(
            resource_kind=resource_kind,
            attrs=request.data if isinstance(request.data, Mapping) else None,
        )
        if network:
            attrs["network"] = network
        return authorize_policy_stack(
            legacy,
            request=request,
            root=policy_leaf(
                action=action,
                resource_kind=resource_kind,
                resource_id=self._resource_id_from_view(
                    view=view,
                    data=request.data if isinstance(request.data, Mapping) else None,
                ),
                resource_attrs=attrs,
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )


class HostContactsPermission(IsGrantedNetGroupRegexPermission):
    """Authorize a host-contact endpoint against its complete host target."""

    def has_permission(self, request, view):
        if not DRFIsAuthenticated.has_permission(self, request, view):
            return False
        user = User.from_request(request)
        hostname = str(view.kwargs.get("name") or "")
        host = Host.objects.filter(name=hostname).first()
        ips = self._get_hostname_and_ips(host)[1] if host is not None else []
        action = {
            "GET": "host_contacts_read",
            "HEAD": "host_contacts_read",
            "OPTIONS": "host_contacts_read",
            "POST": "host_contacts_create",
            "DELETE": "host_contacts_delete",
        }.get(request.method, "host_contacts_read")
        restriction_denied = request.method not in SAFE_METHODS and self.deny_superuser_only_names(
            name=hostname,
            view=view,
            request=request,
        )
        target_legacy = self._legacy_target_permission(user, hostname, ips)
        legacy = (
            request.method in SAFE_METHODS or user.is_mreg_superuser or (not restriction_denied and (user.is_mreg_admin or target_legacy))
        )
        return authorize_policy_stack(
            legacy,
            request=request,
            root=self._target_policy_node(
                hostname=hostname,
                ips=tuple(str(ip) for ip in ips),
                action=action,
                resource_kind="Host",
                resource_id=hostname or "any",
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )


class BACnetPermission(IsGrantedNetGroupRegexPermission):
    """Authorize BACnet reads and mutations against the attached host."""

    def has_permission(self, request, view):
        if not DRFIsAuthenticated.has_permission(self, request, view):
            return False
        user = User.from_request(request)
        host = None
        if request.method == "POST":
            host_id = request.data.get("host")
            hostname = request.data.get("hostname")
            if host_id is not None:
                host = Host.objects.filter(pk=host_id).first()
            elif hostname:
                host = Host.objects.filter(name=hostname).first()
        elif view.kwargs.get("id") is not None:
            try:
                obj = view.get_queryset().filter(pk=view.kwargs["id"]).first()
            except (TypeError, ValueError):
                obj = None
            host = getattr(obj, "host", None)

        hostname = str(getattr(host, "name", "any"))
        ips = self._get_hostname_and_ips(host)[1] if host is not None else []
        operation = self._crud_operation_from_method(request.method)
        action = self._crud_action("BACnetID", operation)
        target_legacy = bool(host is not None and self._legacy_target_permission(user, hostname, ips))
        legacy = request.method in SAFE_METHODS or user.is_mreg_superuser_or_admin or target_legacy
        return authorize_policy_stack(
            legacy,
            request=request,
            root=self._target_policy_node(
                hostname=hostname,
                ips=tuple(str(ip) for ip in ips),
                action=action,
                resource_kind="BACnetID",
                resource_id=str(request.data.get("id") or view.kwargs.get("id") or "any"),
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )


class HostGroupPermission(IsAuthenticated):
    def has_permission(self, request, view):
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not super().has_permission(request, view):
            return False
        user = User.from_request(request)
        if request.method in SAFE_METHODS:
            return self.authorize_endpoint(legacy_decision=True, request=request, view=view)
        if policy_enforcement_enabled() or policy_shadow_enabled():
            return True
        if user.is_mreg_superuser or user.is_mreg_hostgroup_admin:
            return True
        # Will do do more object checks later, but initially refuse any
        # unwarranted requests.
        if HostGroup.objects.filter(owners__name__in=user.group_list).exists():
            return True
        return False

    @staticmethod
    def _request_user_is_owner(hostgroup, request):
        owners = list(set(hostgroup.owners.values_list("name", flat=True)))
        return User.from_request(request).is_member_of_any(owners)

    def _authorize_hostgroup(
        self,
        *,
        legacy: bool,
        request: Request,
        view: GenericAPIView,
        hostgroup: HostGroup,
        action: str,
        requester_is_owner: bool,
        owner_mutation: bool = False,
        description_update: bool = False,
    ) -> bool:
        return authorize_policy_stack(
            legacy,
            request=request,
            root=policy_leaf(
                action=action,
                resource_kind="HostGroup",
                resource_id=str(hostgroup.name),
                resource_attrs={
                    "kind": "host_group",
                    "name": str(hostgroup.name),
                    "requesterIsOwner": str(requester_is_owner).lower(),
                    "ownerMutation": str(owner_mutation).lower(),
                    "descriptionUpdate": str(description_update).lower(),
                },
            ),
            view=view,
            permission_class=self.__class__.__name__,
        )

    def has_m2m_change_permission(self, request, view):
        user = User.from_request(request)
        requester_is_owner = self._request_user_is_owner(view.object, request)
        owner_mutation = getattr(view, "m2m_field", None) == "owners"
        legacy = user.is_mreg_superuser or user.is_mreg_hostgroup_admin
        if not owner_mutation:
            legacy = legacy or requester_is_owner
        return self._authorize_hostgroup(
            legacy=legacy,
            request=request,
            view=view,
            hostgroup=view.object,
            action="hostgroup_membership_update",
            requester_is_owner=requester_is_owner,
            owner_mutation=owner_mutation,
        )

    # patch will only happen on HostGroupDetail
    def has_update_permission(self, request, view, validated_serializer):
        user = User.from_request(request)
        obj = view.get_object()
        requester_is_owner = self._request_user_is_owner(obj, request)
        legacy = user.is_mreg_superuser or user.is_mreg_hostgroup_admin
        if not legacy and "description" in validated_serializer.validated_data:
            legacy = requester_is_owner
        return self._authorize_hostgroup(
            legacy=legacy,
            request=request,
            view=view,
            hostgroup=obj,
            action="host_group_update",
            requester_is_owner=requester_is_owner,
            description_update="description" in validated_serializer.validated_data,
        )

    def has_destroy_permission(self, request, view, validated_serializer):
        user = User.from_request(request)
        legacy = user.is_mreg_superuser or user.is_mreg_hostgroup_admin
        hostgroup = view.get_object()
        return self._authorize_hostgroup(
            legacy=legacy,
            request=request,
            view=view,
            hostgroup=hostgroup,
            action="host_group_delete",
            requester_is_owner=self._request_user_is_owner(hostgroup, request),
        )


class IsGrantedReservedAddressPermission(IsAuthenticated):
    def has_ipaddress_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer):
        if policy_enforcement_enabled():
            return True
        user = User.from_request(request)
        if user.is_mreg_superuser_or_admin or user.is_mreg_network_admin:
            return True

        data = validated_serializer.validated_data
        if not data or not (ip := data.get("ipaddress")):
            return True

        try:
            ipaddr = ipaddress.ip_address(ip)
        except ValueError:
            # invalid IP, let serializer handle it
            return True

        try:
            network: Network = Network.objects.get(network__net_contains=ip)
        except Network.DoesNotExist:
            pass  # network not in mreg
        else:
            if ipaddr in (network.network.broadcast_address, network.network.network_address):
                raise exceptions.PermissionDenied(
                    error_body("Setting a network or broadcast address on a host requires network admin privileges.")
                )
        return True

    def has_create_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer) -> bool:
        return self.has_ipaddress_permission(request, view, validated_serializer)

    def has_update_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer) -> bool:
        return self.has_ipaddress_permission(request, view, validated_serializer)

    def has_destroy_permission(self, request: Request, view: GenericAPIView, validated_serializer: BaseModel) -> bool:
        # Deleting will never assign IPs.
        # Furthermore, the permissions check in `perform_destroy` passes
        # in a `BaseModel` instance instead of a serializer when checking
        # destroy permissions, so we cannot access any sort of validated data.
        return self.has_permission(request, view)
