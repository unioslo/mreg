from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated as DRFIsAuthenticated, SAFE_METHODS
from rest_framework.request import Request

from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import HostGroup
from mreg.models.network import NetGroupRegexPermission, Network

from mreg.models.auth import User

# NOTE: We _must_ import `rest_framework.generics` in an `if TYPE_CHECKING:`
# block because DRF does some dynamic import shenanigans on runtime using
# the `DEFAULT_PERMISSION_CLASSES` we defined in `settings.py`, causing
# an import cycle if we _actually_ import the generics module on runtime.
if TYPE_CHECKING:
    from rest_framework.generics import GenericAPIView
    from rest_framework.serializers import Serializer
    from mreg.models.base import BaseModel



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


class IsAuthenticated(DRFIsAuthenticated, CRUDPermissionsMixin):
    """
    Allows access only to authenticated users.
    """
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
        return User.from_request(request).is_mreg_superuser


class IsSuperOrAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        return User.from_request(request).is_mreg_superuser_or_admin


class IsSuperOrNetworkAdminMember(IsAuthenticated):
    """
    Permit user if in super user group and also the network admin
    can change some views and some fields.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        user = User.from_request(request)
        if user.is_mreg_superuser:
            return True
        if user.is_mreg_network_admin:
            return True
        return False


class IsSuperOrGroupAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = User.from_request(request)
        if request.method in SAFE_METHODS:
            return True
        return user.is_mreg_superuser or user.is_mreg_hostgroup_admin


def _deny_superuser_only_names(data=None, name=None, view=None, request=None):
    """Check for superuser only names. If match, return True."""
    import mreg.api.v1.views

    if data is not None:
        name = data.get('name', '')
        if not name:
            if 'host' in data:
                name = data['host'].name

    if not request: # pragma: no cover
        return False

    user = User.from_request(request)

    # Underscore is allowed for non-superuser in SRV records,
    # and for members of <DNS_UNDERSCORE_GROUP> in all records.
    if '_' in name and not isinstance(view, (mreg.api.v1.views.SrvDetail,
                                             mreg.api.v1.views.SrvList)) \
                   and not user.is_mreg_dns_underscore_admin:
        return True

    # Except for super-users, only members of the DNS wildcard group can create wildcard records.
    # And then only below subdomains, like *.sub.example.com
    if '*' in name and (not user.is_mreg_dns_wildcard_admin or name.count('.') < 3):
        return True

    return False


def is_reserved_ip(ip):
    network = Network.objects.filter(network__net_contains=ip).first()
    if network:
        return any(ip == str(i) for i in network.get_reserved_ipaddresses())
    return False


def _deny_reserved_ipaddress(ip, request):
    """Check if an ip address is reserved, and if so, only permit
    NETWORK_ADMIN_GROUP members."""
    if is_reserved_ip(ip):
        if User.from_request(request).is_mreg_network_admin:
            return False
        return True
    return False
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
            return True
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

    @staticmethod
    def has_perm(user, hostname, ips, require_ip=True):
        return bool(NetGroupRegexPermission.find_perm(user.group_list,
                                                      hostname, ips, require_ip))

    def has_obj_perm(self, user, obj):
        return self.has_perm(user, *self._get_hostname_and_ips(obj))

    def has_create_permission(self, request, view, validated_serializer):
        import mreg.api.v1.views
        user = User.from_request(request)
        if user.is_mreg_superuser:
            return True

        hostname = None
        ips = []
        data = validated_serializer.validated_data
        if _deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if 'ipaddress' in data:
            if _deny_reserved_ipaddress(data['ipaddress'], request):
                return False
        if user.is_mreg_admin:
            return True
        if isinstance(view, (mreg.api.v1.views.IpaddressList,
                             mreg.api.v1.views.PtrOverrideList)):
            if 'host' in data:
                if not self.has_obj_perm(user, data['host']):
                    return False
        if isinstance(view, mreg.api.v1.views.CnameList):
            # only check the cname, don't care about ip addresses
            return self.has_perm(user, data['name'], (), require_ip=False)
        if isinstance(view, (mreg.api.v1.views.HostList,
                             mreg.api.v1.views.IpaddressList,
                             mreg.api.v1.views.PtrOverrideList)):
            # HostList does not require ipaddress, but if none, the permissions
            # will not match, so just refuse it.
            ip = data.get('ipaddress', None)
            if ip is None:
                return False
            ips.append(ip)
            hostname = data['host'].name
        elif 'host' in data:
            hostname, ips = self._get_hostname_and_ips(data['host'])
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        if ips and hostname:
            return self.has_perm(user, hostname, ips)
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        import mreg.api.v1.views
        user = User.from_request(request)

        if user.is_mreg_superuser:
            return True
        obj = view.get_object()
        if isinstance(view, mreg.api.v1.views.HostDetail):
            pass
        elif hasattr(obj, 'host'):
            obj = obj.host
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")
        if _deny_superuser_only_names(name=obj.name, view=view, request=request):
            return False
        if hasattr(obj, 'ipaddress'):
            if _deny_reserved_ipaddress(obj.ipaddress, request):
                return False
        if user.is_mreg_admin:
            return True
        return self.has_obj_perm(user, obj)

    def has_update_permission(self, request, view, validated_serializer):
        import mreg.api.v1.views
        user = User.from_request(request)

        if user.is_mreg_superuser:
            return True
        data = validated_serializer.validated_data
        if _deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if 'ipaddress' in data:
            if _deny_reserved_ipaddress(data['ipaddress'], request):
                return False
        if user.is_mreg_admin:
            return True
        obj = view.get_object()
        if isinstance(view, mreg.api.v1.views.HostDetail):
            hostname, ips = self._get_hostname_and_ips(obj)
            # If renaming a host, make sure the user has permission to both the
            # new and and old hostname.
            if 'name' in data:
                if not self.has_perm(user, data['name'], ips):
                    return False
            return self.has_perm(user, hostname, ips)
        elif hasattr(obj, 'host'):
            # If changing host object, make sure the user has permission the
            # new one.
            if 'host' in data and data['host'] != obj.host:
                if not self.has_obj_perm(user, data['host']):
                    return False
            return self.has_obj_perm(user, obj.host)
        # Testing these kinds of should-never-happen codepaths is hard.
        # We have to basically mock a complete API call and then break it.
        raise exceptions.PermissionDenied(f"Unhandled view: {view}")  # pragma: no cover

    def _get_hostname_and_ips(self, hostobject):
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

