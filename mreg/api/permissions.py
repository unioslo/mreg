from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from django.db import models
from typing import TYPE_CHECKING, Any
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated as DRFIsAuthenticated, SAFE_METHODS
from rest_framework.request import Request

from structlog import get_logger

from mreg.api.responses import error_body
from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import HostGroup
from mreg.models.network import NetGroupRegexPermission, Network

from mreg.models.auth import User, MregAdminGroup
from mreg.api.treetop import PolicyCheck, PolicyResource, policy_parity

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

    _CRUD_METHOD_TO_OPERATION = {
        "GET": "read",
        "HEAD": "read",
        "OPTIONS": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }
    _IDENTIFIER_FIELDS = ("pk", "id", "name")
    _VIEW_IDENTIFIER_FIELDS = ("pk", "id", "name", "cpk", "hostpk", "network")
    _MEMBERSHIP_ACTIONS = {
        MregAdminGroup.SUPERUSER: "superuser_access",
        MregAdminGroup.ADMINUSER: "admin_access",
        MregAdminGroup.GROUP_ADMIN: "hostgroup_admin_access",
        MregAdminGroup.NETWORK_ADMIN: "network_admin_access",
        MregAdminGroup.DNS_WILDCARD: "dns_wildcard_admin_access",
        MregAdminGroup.DNS_UNDERSCORE: "dns_underscore_admin_access",
        MregAdminGroup.HOSTPOLICY_ADMIN: "hostpolicy_admin_access",
    }

    @staticmethod
    def _stringify_attr_value(value: Any) -> str:
        """Convert attribute values to strings for TreeTop resource attributes."""
        return "" if value is None else str(value)

    @staticmethod
    def _snake_case(value: str) -> str:
        """Normalize model/resource names to snake_case action/resource tokens."""
        if value.startswith("BACnet"):
            value = f"Bacnet{value[len('BACnet') :]}"
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
        value = value.replace("-", "_")
        value = re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower()
        return value or "generic"

    @staticmethod
    def _resource_name_from_model(model: Any) -> str | None:
        """Return a model class name if available, otherwise None."""
        name = getattr(model, "__name__", None)
        return str(name) if name else None

    def _resource_kind_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: "Serializer | None" = None,
        obj: Any = None,
    ) -> str:
        """Resolve a resource kind from a concrete object or serializer model.

        View-name guessing is deliberately rejected: renaming a view must not
        silently alter authorization action names.
        """
        if obj is not None:
            return obj.__class__.__name__

        if validated_serializer is not None:
            serializer_model = self._resource_name_from_model(getattr(getattr(validated_serializer, "Meta", None), "model", None))
            if serializer_model:
                return serializer_model

        if validated_serializer is not None:
            instance = getattr(validated_serializer, "instance", None)
            if instance is not None:
                return instance.__class__.__name__

        explicit_kind = getattr(view, "policy_resource_kind", None)
        if isinstance(explicit_kind, str) and explicit_kind.strip():
            return explicit_kind

        try:
            serializer_class = view.get_serializer_class()
        except (AttributeError, TypeError) as exc:
            raise ValueError(f"{view.__class__.__name__} must declare an explicit policy resource kind") from exc
        view_model = self._resource_name_from_model(getattr(getattr(serializer_class, "Meta", None), "model", None))
        if view_model:
            return view_model
        raise ValueError(f"{view.__class__.__name__} serializer must declare Meta.model for policy parity")

    @classmethod
    def _identifier_from(cls, source: Any, fields: tuple[str, ...]) -> str | None:
        if source is None:
            return None
        for field_name in fields:
            value = source.get(field_name) if isinstance(source, Mapping) else getattr(source, field_name, None)
            if value is not None:
                return str(value)
        return None

    def _resource_id_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: "Serializer | None" = None,
        obj: Any = None,
        data: Mapping[str, Any] | None = None,
        default: str = "any",
    ) -> str:
        """Resolve a stable resource identifier for parity logging/evaluation."""
        serializer_instance = getattr(validated_serializer, "instance", None)
        candidates = (
            self._identifier_from(obj, self._IDENTIFIER_FIELDS),
            self._identifier_from(data, self._IDENTIFIER_FIELDS),
            self._identifier_from(serializer_instance, self._IDENTIFIER_FIELDS),
            self._identifier_from(getattr(view, "kwargs", None), self._VIEW_IDENTIFIER_FIELDS),
        )
        return next((value for value in candidates if value is not None), default)

    def _crud_operation_from_method(self, method: str) -> str:
        """Map an HTTP method to a CRUD operation token."""
        try:
            return self._CRUD_METHOD_TO_OPERATION[method.upper()]
        except KeyError as exc:
            raise ValueError(f"Unsupported HTTP method for policy parity: {method}") from exc

    def _crud_action(self, resource_kind: str, operation: str) -> str:
        """Build a policy action name like `<resource>_<operation>`."""
        return f"{self._snake_case(resource_kind)}_{operation}"

    def _policy_action_from_view(
        self,
        *,
        view: "GenericAPIView",
        resource_kind: str,
        operation: str,
    ) -> str:
        """Resolve an explicit custom action or the model-backed CRUD action."""
        explicit_actions = getattr(view, "policy_actions", None)
        if isinstance(explicit_actions, Mapping):
            explicit_action = explicit_actions.get(operation)
            if isinstance(explicit_action, str) and explicit_action.strip():
                return explicit_action
        return self._crud_action(resource_kind, operation)

    def _normalize_resource_attrs(
        self,
        *,
        resource_kind: str,
        attrs: Mapping[str, Any] | None,
    ) -> dict[str, str]:
        """Normalize resource attributes to string values with a canonical kind."""
        normalized = {str(key): self._stringify_attr_value(value) for key, value in (attrs or {}).items()}
        # Callers cannot override the resource kind through request data.
        normalized["kind"] = self._snake_case(resource_kind)
        return normalized

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

        return self.pp(
            decision=is_member,
            action=self._MEMBERSHIP_ACTIONS[membership],
            request=request,
            view=view,
        )

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

    pass


class IsAuthenticatedAndReadOnly(IsAuthenticated):
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return request.method in SAFE_METHODS


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
            return True
        return self.user_is_admin(request=request, view=view)


class IsSuperOrNetworkAdminMember(IsAuthenticated):
    """
    Permit user if in super user group or network admin group.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        return self.user_is_any(MregAdminGroup.SUPERUSER, MregAdminGroup.NETWORK_ADMIN, request=request, view=view)


class IsSuperOrGroupAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True

        return self.user_is_any(MregAdminGroup.SUPERUSER, MregAdminGroup.GROUP_ADMIN, request=request, view=view)


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
    ):
        """Evaluate NetGroupRegexPermission and parity for hostname/IP tuples."""
        legacy = bool(NetGroupRegexPermission.find_perm(user.group_list, hostname, ips, require_ip))
        operation = self._crud_operation_from_method(request.method)
        resolved_action = action or self._crud_action(resource_kind, operation)
        resolved_resource_id = str(resource_id or hostname or "any")
        policy: list[bool] = []
        if ips:
            # This will perform one policy lookup per IP for the host. This should probably be optimized server side.
            for ip in ips:
                policy.append(
                    self.pp(
                        decision=legacy,
                        action=resolved_action,
                        request=request,
                        view=view,
                        resource_kind=resource_kind,
                        resource_id=resolved_resource_id,
                        resource_attrs={"hostname": str(hostname), "ip": str(ip)},
                    )
                )
        else:
            policy.append(
                self.pp(
                    decision=legacy,
                    action=resolved_action,
                    request=request,
                    view=view,
                    resource_kind=resource_kind,
                    resource_id=resolved_resource_id,
                    resource_attrs={"hostname": str(hostname)},
                )
            )

        return any(policy)

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

    def _flatten_policy_attrs(self, data: Mapping[str, Any]) -> dict[str, str]:
        """Flatten one model level into scalar attributes for policy parity."""
        attrs: dict[str, str] = {}
        for key, value in data.items():
            if isinstance(value, models.Model):
                for field in value._meta.fields:
                    attrs[f"{key}_{field.name}"] = self._stringify_attr_value(getattr(value, field.name, ""))
            else:
                attrs[key] = self._stringify_attr_value(value)
        return attrs

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
    ) -> bool:
        """Apply the view-specific legacy create rules after common checks."""
        import mreg.api.v1.views as v1_views

        ip_value = data.get("ipaddress")
        host = data.get("host")
        host_ip_views = (
            v1_views.HostList,
            v1_views.IpaddressList,
            v1_views.PtrOverrideList,
        )

        if isinstance(view, (v1_views.IpaddressList, v1_views.PtrOverrideList)):
            if host and not self.has_obj_perm(
                user,
                host,
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
            ):
                return False

        if isinstance(view, v1_views.CnameList):
            name = self._stringify_attr_value(data["name"])
            return self.has_perm(
                user,
                name,
                (),
                require_ip=False,
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
                resource_id=name,
            )

        if isinstance(view, host_ip_views):
            if not (ip_value and host):
                return False
            hostname = host.name
            ips = [ip_value]
        elif host:
            hostname, ips = self._get_hostname_and_ips(host)
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        if not (ips and hostname):
            return False
        return self.has_perm(
            user,
            hostname,
            ips,
            request=request,
            view=view,
            action=action,
            resource_kind=resource_kind,
            resource_id=self._stringify_attr_value(hostname),
        )

    def has_create_permission(self, request, view, validated_serializer):
        """Authorize create operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views

        user = User.from_request(request)
        data: dict[str, Any] = validated_serializer.validated_data  # type: ignore
        logger.debug(
            "create_permission_check",
            user=user.username,
            view=view.__class__.__name__,
            fields=sorted(data),
        )

        if self.user_is_superuser(request=request, view=view):
            return True

        handled_by_view = isinstance(
            view,
            (
                v1_views.CnameList,
                v1_views.HostList,
                v1_views.IpaddressList,
                v1_views.PtrOverrideList,
            ),
        )
        if not handled_by_view and "host" not in data:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        resource_kind = self._resource_kind_from_view(
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
        attrs = self._flatten_policy_attrs(data)
        ip_value = data.get("ipaddress")

        # First check if we are asking for a restricted name.
        if self.deny_superuser_only_names(data=data, view=view, request=request):
            return False
        # Then check if we are asking for an IP address *and* it is reserved.
        if ip_value and self.deny_reserved_ipaddress(
            ip=ip_value,
            view=view,
            request=request,
        ):
            return False

        # If the user is an admin, they are now free to create (minus the above checks).
        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            resource_id=resource_id,
            attrs=attrs,
            request=request,
            view=view,
        ):
            return True
        return self._has_create_target_permission(
            user=user,
            request=request,
            view=view,
            data=data,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
        )

    def has_destroy_permission(self, request, view, validated_serializer):
        """Authorize delete operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views

        user = User.from_request(request)

        if self.user_is_superuser(request=request, view=view):
            return True

        target_obj = view.get_object()
        host_obj = target_obj
        if not isinstance(view, v1_views.HostDetail) and hasattr(target_obj, "host"):
            host_obj = target_obj.host
        elif not isinstance(view, v1_views.HostDetail):
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        resource_kind = self._resource_kind_from_view(view=view, obj=target_obj)
        action = self._policy_action_from_view(
            view=view,
            resource_kind=resource_kind,
            operation="delete",
        )
        resource_id = self._resource_id_from_view(view=view, obj=target_obj)
        if self.deny_superuser_only_names(name=host_obj.name, view=view, request=request):
            return False
        if hasattr(host_obj, "ipaddress"):
            if self.deny_reserved_ipaddress(ip=host_obj.ipaddress, view=view, request=request):
                return False

        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            resource_id=resource_id,
            attrs={"id": resource_id},
            request=request,
            view=view,
        ):
            return True
        return self.has_obj_perm(
            user,
            host_obj,
            request=request,
            view=view,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
        )

    def _has_host_detail_update_permission(
        self,
        *,
        user: User,
        request: Request,
        view: GenericAPIView,
        target_obj: Any,
        data: Mapping[str, Any],
        action: str,
        resource_kind: str,
    ) -> bool:
        hostname, ips = self._get_hostname_and_ips(target_obj)
        if "name" in data:
            new_name = self._stringify_attr_value(data["name"])
            if not self.has_perm(
                user,
                new_name,
                ips,
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
                resource_id=new_name,
            ):
                return False
        return self.has_perm(
            user,
            hostname,
            ips,
            request=request,
            view=view,
            action=action,
            resource_kind=resource_kind,
            resource_id=self._stringify_attr_value(hostname),
        )

    def _has_related_host_update_permission(
        self,
        *,
        user: User,
        request: Request,
        view: GenericAPIView,
        target_obj: Any,
        data: Mapping[str, Any],
        action: str,
        resource_kind: str,
        resource_id: str,
    ) -> bool:
        if "host" in data and data["host"] != target_obj.host:
            if not self.has_obj_perm(
                user,
                data["host"],
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
            ):
                return False
        return self.has_obj_perm(
            user,
            target_obj.host,
            request=request,
            view=view,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
        )

    def has_update_permission(self, request, view, validated_serializer):
        """Authorize update operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views

        user = User.from_request(request)

        if self.user_is_superuser(request=request, view=view):
            return True

        data: dict[str, Any] = validated_serializer.validated_data  # type: ignore
        target_obj = view.get_object()
        if not isinstance(view, v1_views.HostDetail) and not hasattr(target_obj, "host"):
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        resource_kind = self._resource_kind_from_view(
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

        if self.deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if "ipaddress" in data:
            if self.deny_reserved_ipaddress(ip=data["ipaddress"], view=view, request=request):
                return False

        admin_attrs = {str(key): self._stringify_attr_value(value) for key, value in data.items()}
        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            resource_id=resource_id,
            attrs=admin_attrs,
            request=request,
            view=view,
        ):
            return True

        if isinstance(view, v1_views.HostDetail):
            return self._has_host_detail_update_permission(
                user=user,
                target_obj=target_obj,
                data=data,
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
            )
        if hasattr(target_obj, "host"):
            return self._has_related_host_update_permission(
                user=user,
                request=request,
                view=view,
                target_obj=target_obj,
                data=data,
                action=action,
                resource_kind=resource_kind,
                resource_id=resource_id,
            )
        # Testing these kinds of should-never-happen codepaths is hard.
        # We have to basically mock a complete API call and then break it.
        raise exceptions.PermissionDenied(f"Unhandled view: {view}")  # pragma: no cover

    def _get_hostname_and_ips(self, hostobject):
        """Extract a host's canonical name and all attached IP addresses."""
        ips = []
        host = HostSerializer(hostobject)
        for i in host.data["ipaddresses"]:
            ips.append(i["ipaddress"])
        return host.data["name"], ips


class HostGroupPermission(IsAuthenticated):
    def has_permission(self, request, view):
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not super().has_permission(request, view):
            return False
        user = User.from_request(request)
        if request.method in SAFE_METHODS:
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

    def has_m2m_change_permission(self, request, view):
        user = User.from_request(request)
        if user.is_mreg_superuser or user.is_mreg_hostgroup_admin:
            return True
        return self._request_user_is_owner(view.object, request)

    # patch will only happen on HostGroupDetail
    def has_update_permission(self, request, view, validated_serializer):
        user = User.from_request(request)
        if user.is_mreg_superuser or user.is_mreg_hostgroup_admin:
            return True
        if "description" in validated_serializer.validated_data:
            return self._request_user_is_owner(view.get_object(), request)
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        user = User.from_request(request)
        if user.is_mreg_superuser or user.is_mreg_hostgroup_admin:
            return True
        return False


class IsGrantedReservedAddressPermission(IsAuthenticated):
    def has_ipaddress_permission(self, request: Request, view: GenericAPIView, validated_serializer: Serializer):
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
