from __future__ import annotations

import ipaddress
import re
from django.db import models
from typing import TYPE_CHECKING, Iterable, Mapping, Optional, Tuple, Any
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated as DRFIsAuthenticated, SAFE_METHODS
from rest_framework.request import Request

from structlog import get_logger


from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import HostGroup
from mreg.models.network import NetGroupRegexPermission, Network

from mreg.models.auth import User, MregAdminGroup
from mreg.api.treetop import policy_parity

# NOTE: We _must_ import `rest_framework.generics` in an `if TYPE_CHECKING:`
# block because DRF does some dynamic import shenanigans on runtime using
# the `DEFAULT_PERMISSION_CLASSES` we defined in `settings.py`, causing
# an import cycle if we _actually_ import the generics module on runtime.
if TYPE_CHECKING:
    from rest_framework.generics import GenericAPIView
    from rest_framework.serializers import Serializer
    from mreg.models.base import BaseModel

logger = get_logger()

DEFAULT_RESOURCE_ATTRS = {"kind": "Any", "id": "any"}


class ParityMixin:
    """Small helpers to reduce repetition around policy_parity.

    The public pp() method logs every call. For cases where multiple checks
    feed into a single decision (pp_any, pp_all), use _pp() internally to avoid
    nested logging and only log the final result.
    """

    _CRUD_METHOD_TO_OPERATION = {
        "GET": "read",
        "HEAD": "read",
        "OPTIONS": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }

    @staticmethod
    def _stringify_attr_value(value: Any) -> str:
        """Convert attribute values to strings for TreeTop resource attributes."""
        return "" if value is None else str(value)

    @staticmethod
    def _snake_case(value: str) -> str:
        """Normalize model/resource names to snake_case action/resource tokens."""
        if value.startswith("BACnet"):
            value = f"Bacnet{value[len('BACnet'):]}"
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
        value = value.replace("-", "_")
        value = re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower()
        return value or "generic"

    @staticmethod
    def _resource_name_from_model(model: Any) -> Optional[str]:
        """Return a model class name if available, otherwise None."""
        name = getattr(model, "__name__", None)
        return str(name) if name else None

    def _resource_kind_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: Optional["Serializer"] = None,
        obj: Any = None,
    ) -> str:
        """Resolve a resource kind for parity from object/serializer/view metadata.

        Resolution order:
        1. concrete object class
        2. serializer Meta.model (validated serializer)
        3. view serializer Meta.model
        4. validated serializer instance class
        5. view class name with common DRF suffixes stripped
        """
        if obj is not None:
            return obj.__class__.__name__

        if validated_serializer is not None:
            serializer_model = self._resource_name_from_model(
                getattr(getattr(validated_serializer, "Meta", None), "model", None)
            )
            if serializer_model:
                return serializer_model

        try:
            serializer_class = view.get_serializer_class()
            view_model = self._resource_name_from_model(
                getattr(getattr(serializer_class, "Meta", None), "model", None)
            )
            if view_model:
                return view_model
        except Exception:
            pass

        if validated_serializer is not None:
            instance = getattr(validated_serializer, "instance", None)
            if instance is not None:
                return instance.__class__.__name__

        view_name = view.__class__.__name__
        for suffix in ("List", "Detail", "View"):
            if view_name.endswith(suffix):
                view_name = view_name[: -len(suffix)]
                break
        return view_name or "Generic"

    def _resource_id_from_view(
        self,
        *,
        view: "GenericAPIView",
        validated_serializer: Optional["Serializer"] = None,
        obj: Any = None,
        data: Optional[Mapping[str, Any]] = None,
        default: str = "any",
    ) -> str:
        """Resolve a stable resource identifier for parity logging/evaluation."""
        if obj is not None:
            for key in ("pk", "id", "name"):
                val = getattr(obj, key, None)
                if val is not None:
                    return str(val)

        if data:
            for key in ("pk", "id", "name"):
                val = data.get(key)
                if val is not None:
                    return str(val)

        if validated_serializer is not None:
            instance = getattr(validated_serializer, "instance", None)
            if instance is not None:
                for key in ("pk", "id", "name"):
                    val = getattr(instance, key, None)
                    if val is not None:
                        return str(val)

        view_kwargs = getattr(view, "kwargs", {})
        if isinstance(view_kwargs, Mapping):
            for key in ("pk", "id", "name", "cpk", "hostpk", "network"):
                if key in view_kwargs and view_kwargs[key] is not None:
                    return str(view_kwargs[key])

        return default

    def _crud_operation_from_method(self, method: str) -> str:
        """Map an HTTP method to a CRUD operation token."""
        return self._CRUD_METHOD_TO_OPERATION.get(method.upper(), "read")

    def _crud_action(self, resource_kind: str, operation: str) -> str:
        """Build a policy action name like `<resource>_<operation>`."""
        return f"{self._snake_case(resource_kind)}_{operation}"

    def _normalize_resource_attrs(
        self,
        *,
        resource_kind: str,
        attrs: Optional[Mapping[str, Any]],
    ) -> dict[str, str]:
        """Normalize resource attributes to string values with a canonical kind."""
        normalized = {"kind": self._snake_case(resource_kind)}
        if attrs:
            normalized.update(
                {str(k): self._stringify_attr_value(v) for k, v in attrs.items()}
            )
        return normalized

    def _pp(
        self,
        *,
        decision: bool,
        action: str,
        request: Request,
        view: "GenericAPIView",
        resource_kind: str = "Generic",
        resource_id: str = "any",
        resource_attrs: Optional[Mapping[str, str]] = None,
        log: bool = True,
    ) -> bool:
        """Internal policy parity check. Set log=False to skip logging."""
        if not log:
            # For internal use: return decision without calling policy_parity
            return decision
        return policy_parity(
            decision,
            request=request,
            view=view,
            permission_class=self.__class__.__name__,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource_attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
        )

    def pp(
        self,
        *,
        decision: bool,
        action: str,
        request: Request,
        view: "GenericAPIView",
        resource_kind: str = "Generic",
        resource_id: str = "any",
        resource_attrs: Optional[Mapping[str, str]] = None,
    ) -> bool:
        """Run one parity check and emit a single parity log record."""
        return self._pp(
            decision=decision,
            action=action,
            request=request,
            view=view,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource_attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
            log=True,
        )

    def pp_host(
        self,
        *,
        decision: bool,
        request: Request,
        view: "GenericAPIView",
        resource_id: str = "",
        action: str = "host_read",
        resource_attrs: Optional[Mapping[str, str]] = None,
    ) -> bool:
        """Helper for host-related actions.

        Assumes `resource_kind="Host"` and tries to extract the resource ID from
        `resource_attrs["hostname"]` if not explicitly given.
        """

        if not resource_id and resource_attrs and "hostname" in resource_attrs:
            resource_id = resource_attrs["hostname"]

        return self.pp(
            decision=decision,
            action=action,
            request=request,
            view=view,
            resource_kind="Host",
            resource_id=resource_id or "any",
            resource_attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
        )

    def pp_any(
        self,
        *,
        checks: Iterable[Tuple[bool, str]],  # (decision, action)
        request: Request,
        view: "GenericAPIView",
        resource_kind: str = "Generic",
        resource_attrs: Optional[Mapping[str, str]] = None,
    ) -> bool:
        """Return True if any candidate check succeeds, without nested logging."""
        # Use internal _pp with log=False to avoid nested logging for each check
        for decision, action in checks:
            if self._pp(
                decision=decision,
                action=action,
                request=request,
                view=view,
                resource_kind=resource_kind,
                resource_attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
                log=False,
            ):
                return True
        return False

    def pp_all(
        self,
        *,
        checks: Iterable[Tuple[bool, str]],
        request: Request,
        view: "GenericAPIView",
        resource_kind: str = "Generic",
        resource_attrs: Optional[Mapping[str, str]] = None,
    ) -> bool:
        """Return True if all candidate checks succeed, without nested logging."""
        # Use internal _pp with log=False to avoid nested logging for each check
        for decision, action in checks:
            if not self._pp(
                decision=decision,
                action=action,
                request=request,
                view=view,
                resource_kind=resource_kind,
                resource_attrs=resource_attrs or DEFAULT_RESOURCE_ATTRS,
                log=False,
            ):
                return False
        return True

    def pp_generic_action(
        self,
        attrs: Mapping[str, Any],
        decision: bool,
        action: str,
        request: Request,
        view: GenericAPIView,
        kind: str = "Generic",
        id: str = "any"
    ) -> bool:
        """Convenience wrapper that normalizes attrs and forwards to pp()."""
        return self.pp(
            decision=decision,
            action=action,
            request=request,
            view=view,
            resource_kind=kind,
            resource_id=str(id),
            resource_attrs=self._normalize_resource_attrs(resource_kind=kind, attrs=attrs),
        )

    def user_has_permission(
        self,
        membership: MregAdminGroup,
        request: Request,
        view: GenericAPIView,
        exclude_superuser: bool = False
    ) -> bool:
        """
        Check if the user has a given generic permission level.
        """
        user = User.from_request(request)
        memberlist = membership.settings_groups_or_raise()
        
        if not exclude_superuser and membership != MregAdminGroup.SUPERUSER:
            memberlist.extend(MregAdminGroup.SUPERUSER.settings_groups_or_raise())

        is_member = user.is_member_of_any(memberlist)

        match membership:
            case MregAdminGroup.SUPERUSER:
                action = "superuser_access"
            case MregAdminGroup.ADMINUSER:
                action = "admin_access"
            case MregAdminGroup.GROUP_ADMIN:
                action = "hostgroup_admin_access"
            case MregAdminGroup.NETWORK_ADMIN:
                action = "network_admin_access"
            case MregAdminGroup.DNS_WILDCARD:
                action = "dns_wildcard_admin_access"
            case MregAdminGroup.DNS_UNDERSCORE:
                action = "dns_underscore_admin_access"
            case MregAdminGroup.HOSTPOLICY_ADMIN:
                action = "hostpolicy_admin_access"

        return self.pp(
            decision=is_member,
            action=action,
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

    def user_is_any(
        self,
        *memberships: MregAdminGroup,
        request: Request,
        view: GenericAPIView
    ) -> bool:
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
            name = data.get('name', '')
            if not name:
                if 'host' in data:
                    name = data['host'].name

        name = (name or '').strip() # Guarantee coercion to string

        if not request: # pragma: no cover
            return False

        if not view: # pragma: no cover
            return False

        # Underscore is allowed for non-superuser in SRV records,
        # and for members of <DNS_UNDERSCORE_GROUP> in all records.
        if '_' in name and not isinstance(view, (v1_views.SrvDetail, v1_views.SrvList)) \
                    and not self.user_is_dns_underscore_admin(request, view):
            return True

        # Except for super-users, only members of the DNS wildcard group can create wildcard records.
        # And then only below subdomains, like *.sub.example.com
        if '*' in name and (not self.user_is_dns_wildcard_admin(request, view) or name.count('.') < 3):
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


        return policy_parity(
                User.from_request(request).is_mreg_superuser,
                request=request,
                view=view,
                permission_class=self.__class__.__name__,
                action="is_superuser",
                resource_kind="Generic",
                resource_id="any",
                resource_attrs={"kind": "Any", "id": "any"},
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
                action=self._crud_action(resource_kind, "read"),
                kind=resource_kind,
                id=self._resource_id_from_view(view=view),
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
        network_in_url = view.kwargs.get('network')
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
        action: Optional[str] = None,
        resource_kind: str = "Host",
        resource_id: Optional[str] = None,
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
        action: Optional[str] = None,
        resource_kind: str = "Host",
        resource_id: Optional[str] = None,
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

    def has_create_permission(self, request, view, validated_serializer):
        """Authorize create operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views
        user = User.from_request(request)

        logger.debug("create_permission_check", user=user.username, view=view.__class__.__name__, data=validated_serializer.validated_data)

        if self.user_is_superuser(request=request, view=view):
            return True

        hostname = None
        ips = []
        
        attrs: dict[str, str] = {}
        data: dict[str, Any] = validated_serializer.validated_data # type: ignore
        resource_kind = self._resource_kind_from_view(
            view=view,
            validated_serializer=validated_serializer,
        )
        action = self._crud_action(resource_kind, "create")
        resource_id = self._resource_id_from_view(
            view=view,
            validated_serializer=validated_serializer,
            data=data,
        )

        # Convert all data from the serializer to strings to feed as attributes to the policy engine.
        # We also introspect BaseModel instances to flatten them out (one level deep).
        # For example:
        # key: Host value: hostobj -> attrs["host.id"] = "1", attrs["host.name"] = "hostname.example.com"
        if data:
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    attrs[key] = self._stringify_attr_value(value)
                elif isinstance(value, models.Model):
                    for field in value._meta.fields:
                        attrs[f"{key}_{field.name}"] = self._stringify_attr_value(
                            getattr(value, field.name, "")
                        )
                else:
                    attrs[key] = self._stringify_attr_value(value)


        ipaddress = data.get('ipaddress', None)
        host = data.get('host', None)

        # First check if we are asking for a restricted name.
        if self.deny_superuser_only_names(data=data, view=view, request=request):
            return False
        # Then check if we are asking for an IP address *and* it is reserved.
        if ipaddress and self.deny_reserved_ipaddress(ip=ipaddress, view=view, request=request):
            return False

        handled_by_view = isinstance(
            view,
            (v1_views.CnameList, v1_views.HostList, v1_views.IpaddressList, v1_views.PtrOverrideList),
        )
        if not handled_by_view and 'host' not in data:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        # If the user is an admin, they are now free to create (minus the above checks).
        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            id=resource_id,
            attrs=attrs,
            request=request,
            view=view,
        ):
            return True
        # Now check if the user has permission to the host object (if any).
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
        # CNAMEs are special, we check only the cname, not the ip addresses.
        if isinstance(view, v1_views.CnameList):
            return self.has_perm(
                user,
                data['name'],
                (),
                require_ip=False,
                request=request,
                view=view,
                action=action,
                resource_kind=resource_kind,
                resource_id=self._stringify_attr_value(data['name']),
            )
        # For hosts and other objects, we need to check the host and its IPs.
        if isinstance(view, (v1_views.HostList, v1_views.IpaddressList, v1_views.PtrOverrideList)):
            # HostList does not require ipaddress, but if none, the permissions will not match, so just refuse it.
            # If the Host object is missing or invalid, refuse it (this should be caught by the serializer anyway).
            if not (ipaddress and host):
                return False
                            
            ips.append(ipaddress)
            hostname = host.name
        elif 'host' in data:
            hostname, ips = self._get_hostname_and_ips(data['host'])
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        if ips and hostname:
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
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        """Authorize delete operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views
        user = User.from_request(request)

        if user.is_mreg_superuser:
            return True

        target_obj = view.get_object()
        resource_kind = self._resource_kind_from_view(view=view, obj=target_obj)
        action = self._crud_action(resource_kind, "delete")
        resource_id = self._resource_id_from_view(view=view, obj=target_obj)

        host_obj = target_obj
        if isinstance(view, v1_views.HostDetail):
            pass
        elif hasattr(target_obj, 'host'):
            host_obj = target_obj.host
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")
        if self.deny_superuser_only_names(name=host_obj.name, view=view, request=request):
            return False
        if hasattr(host_obj, 'ipaddress'):
            if self.deny_reserved_ipaddress(ip=host_obj.ipaddress, view=view, request=request):
                return False

        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            id=resource_id,
            attrs={"id": resource_id},
            request=request,
            view=view
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

    def has_update_permission(self, request, view, validated_serializer):
        """Authorize update operations using CRUD parity actions and legacy rules."""
        import mreg.api.v1.views as v1_views
        user = User.from_request(request)

        if user.is_mreg_superuser:
            return True

        data: dict[str, Any] = validated_serializer.validated_data  # type: ignore
        target_obj = view.get_object()
        resource_kind = self._resource_kind_from_view(
            view=view,
            validated_serializer=validated_serializer,
            obj=target_obj,
        )
        action = self._crud_action(resource_kind, "update")
        resource_id = self._resource_id_from_view(
            view=view,
            validated_serializer=validated_serializer,
            obj=target_obj,
            data=data,
        )

        if self.deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if 'ipaddress' in data:
            if self.deny_reserved_ipaddress(ip=data['ipaddress'], view=view, request=request):
                return False

        if not isinstance(view, v1_views.HostDetail) and not hasattr(target_obj, 'host'):
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        admin_attrs = {
            str(key): self._stringify_attr_value(value)
            for key, value in data.items()
        }
        if self.pp_generic_action(
            decision=user.is_mreg_admin,
            action=action,
            kind=resource_kind,
            id=resource_id,
            attrs=admin_attrs,
            request=request,
            view=view,
        ):
            return True

        obj = target_obj
        if isinstance(view, v1_views.HostDetail):
            hostname, ips = self._get_hostname_and_ips(obj)
            # If renaming a host, make sure the user has permission to both the
            # new and and old hostname.
            if 'name' in data:
                if not self.has_perm(
                    user,
                    data['name'],
                    ips,
                    request=request,
                    view=view,
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=self._stringify_attr_value(data['name']),
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
        elif hasattr(obj, 'host'):
            # If changing host object, make sure the user has permission the
            # new one.
            if 'host' in data and data['host'] != obj.host:
                if not self.has_obj_perm(
                    user,
                    data['host'],
                    request=request,
                    view=view,
                    action=action,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                ):
                    return False
            return self.has_obj_perm(
                user,
                obj.host,
                request=request,
                view=view,
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
        for i in host.data['ipaddresses']:
            ips.append(i['ipaddress'])
        return host.data['name'], ips


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
        owners = list(set(hostgroup.owners.values_list('name', flat=True)))
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
        if 'description' in validated_serializer.validated_data:
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
        if (user.is_mreg_superuser_or_admin or user.is_mreg_network_admin):
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
            pass # network not in mreg
        else:
            if ipaddr in (network.network.broadcast_address, network.network.network_address):
                raise exceptions.PermissionDenied(
                    {"ERROR": "Setting a network or broadcast address on a host requires network admin privileges."}
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
