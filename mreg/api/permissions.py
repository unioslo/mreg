from django.conf import settings
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated, SAFE_METHODS

from typing import cast, TYPE_CHECKING

from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import HostGroup
from mreg.models.network import NetGroupRegexPermission, Network

if TYPE_CHECKING:
    from mreg.models.auth import User

NETWORK_ADMIN_GROUP = 'NETWORK_ADMIN_GROUP'
SUPERUSER_GROUP = 'SUPERUSER_GROUP'
ADMINUSER_GROUP = 'ADMINUSER_GROUP'
DNS_WILDCARD_GROUP = 'DNS_WILDCARD_GROUP'
DNS_UNDERSCORE_GROUP = 'DNS_UNDERSCORE_GROUP'


def get_settings_groups(group_setting_name):
    groupnames = getattr(settings, group_setting_name, None)
    if groupnames is None:
        raise exceptions.APIException(detail=f'{group_setting_name} is unset in config')
    if isinstance(groupnames, str):
        groupnames = (groupnames, )
    return groupnames


def request_in_settings_group(request, group_setting_name):
    return user_in_settings_group(request.user, group_setting_name)


def user_in_settings_group(user, group_setting_name):
    groupnames = get_settings_groups(group_setting_name)
    return _list_in_list(groupnames, user.group_list)


def _list_in_list(list_a, list_b):
    # Returns true if any of element in list_a is in list_b
    return any(i in list_b for i in list_a)


def user_object_is_superuser(user: "User") -> bool:
    return user_in_settings_group(user, 'SUPERUSER_GROUP')

def user_object_is_adminuser(user: "User") -> bool:
    return user_in_settings_group(user, 'ADMINUSER_GROUP')

def user_object_is_group_adminuser(user: "User") -> bool:
    return user_in_settings_group(user, 'GROUPADMINUSER_GROUP')

def user_object_is_network_adminuser(user: "User") -> bool:
    return user_in_settings_group(user, 'NETWORK_ADMIN_GROUP')

def is_super_or_admin(user: "User") -> bool:
    return user_object_is_superuser(user) or user_object_is_adminuser(user)

def is_super_or_group_admin(user: "User") -> bool:
    return user_object_is_superuser(user) or user_object_is_group_adminuser(user)


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
        return request_in_settings_group(request, SUPERUSER_GROUP)


class IsSuperOrAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        return is_super_or_admin(cast("User", request.user))


class IsSuperOrNetworkAdminMember(IsAuthenticated):
    """
    Permit user if in super user group and also the network admin
    can change some views and some fields.
    """

    def has_permission(self, request, view):
        import mreg.api.v1.views
        if not super().has_permission(request, view):
            return False
        if user_object_is_superuser(cast("User", request.user)):
            return True
        if request_in_settings_group(request, NETWORK_ADMIN_GROUP):
            if isinstance(view, mreg.api.v1.views.NetworkDetail):
                if request.method == 'PATCH':
                    # Only allow update of the reserved/frozen fields
                    allowed_fields = {'frozen', 'reserved'}
                    if allowed_fields.issuperset(request.data):
                        return True
            elif isinstance(view, (mreg.api.v1.views.NetworkExcludedRangeList,
                                   mreg.api.v1.views.NetworkExcludedRangeDetail)):
                return True
        return False


class IsSuperOrGroupAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        return is_super_or_group_admin(cast("User", request.user))


def _deny_superuser_only_names(data=None, name=None, view=None, request=None):
    """Check for superuser only names. If match, return True."""
    import mreg.api.v1.views

    if data is not None:
        name = data.get('name', '')
        if not name:
            if 'host' in data:
                name = data['host'].name

    if name is None:
        return False

    # Underscore is allowed for non-superuser in SRV records,
    # and for members of <DNS_UNDERSCORE_GROUP> in all records.
    if '_' in name and not isinstance(view, (mreg.api.v1.views.SrvDetail,
                                             mreg.api.v1.views.SrvList)) \
                   and not request_in_settings_group(request, DNS_UNDERSCORE_GROUP):
        return True

    # Except for super-users, only members of the DNS wildcard group can create wildcard records.
    # And then only below subdomains, like *.sub.example.com
    if '*' in name and (not request_in_settings_group(request, DNS_WILDCARD_GROUP) or name.count('.') < 3):
        return True

    return False


def is_reserved_ip(ip, network=None):
    if network is None:
        network = Network.objects.filter(network__net_contains=ip).first()

    if network:
        return any(ip == str(i) for i in network.get_reserved_ipaddresses())
    return False


def _deny_reserved_ipaddress(ip, request):
    """Check if an ip address is reserved, and if so, only permit
    NETWORK_ADMIN_GROUP members."""
    if is_reserved_ip(ip):
        if request_in_settings_group(request, NETWORK_ADMIN_GROUP):
            return False
        return True
    return False


class IsGrantedNetGroupRegexPermission(IsAuthenticated):
    """
    Permit user if the user has been granted access through a
    NetGroupRegexPermission.
    """

    def has_permission(self, request, view):
        user = cast("User", request.user)
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        if is_super_or_admin(user):
            return True
        # Will do do more object checks later, but initially refuse any
        # unwarranted requests.
        if NetGroupRegexPermission.objects.filter(group__in=user.group_list
                                                  ).exists():
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

        if user_object_is_superuser(request.user):
            return True

        hostname = None
        ips = []
        data = validated_serializer.validated_data
        if _deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if 'ipaddress' in data:
            if _deny_reserved_ipaddress(data['ipaddress'], request):
                return False
        if user_object_is_adminuser(request.user):
            return True
        if isinstance(view, (mreg.api.v1.views.IpaddressList,
                             mreg.api.v1.views.PtrOverrideList)):
            if 'host' in data:
                if not self.has_obj_perm(request.user, data['host']):
                    return False
        if isinstance(view, mreg.api.v1.views.CnameList):
            # only check the cname, don't care about ip addresses
            return self.has_perm(request.user, data['name'], (), require_ip=False)
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
        else:  # pragma: no cover
            # Testing these kinds of should-never-happen codepaths is hard.
            # We have to basically mock a complete API call and then break it.
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        if ips and hostname:
            return self.has_perm(request.user, hostname, ips)
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        import mreg.api.v1.views

        if user_object_is_superuser(request.user):
            return True
        obj = view.get_object()
        if isinstance(view, mreg.api.v1.views.HostDetail):
            pass
        elif hasattr(obj, 'host'):
            obj = obj.host
        else:  # pragma: no cover
            # Testing these kinds of should-never-happen codepaths is hard.
            # We have to basically mock a complete API call and then break it.
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")
        if _deny_superuser_only_names(name=obj.name, view=view, request=request):
            return False
        if hasattr(obj, 'ipaddress'):
            if _deny_reserved_ipaddress(obj.ipaddress, request):
                return False
        if user_object_is_adminuser(request.user):
            return True
        return self.has_obj_perm(request.user, obj)

    def has_update_permission(self, request, view, validated_serializer):
        import mreg.api.v1.views
        if user_object_is_superuser(request.user):
            return True
        data = validated_serializer.validated_data
        if _deny_superuser_only_names(data=data, view=view, request=request):
            return False
        if 'ipaddress' in data:
            if _deny_reserved_ipaddress(data['ipaddress'], request):
                return False
        if user_object_is_adminuser(request.user):
            return True
        obj = view.get_object()
        if isinstance(view, mreg.api.v1.views.HostDetail):
            hostname, ips = self._get_hostname_and_ips(obj)
            # If renaming a host, make sure the user has permission to both the
            # new and and old hostname.
            if 'name' in data:
                if not self.has_perm(request.user, data['name'], ips):
                    return False
            return self.has_perm(request.user, hostname, ips)
        elif hasattr(obj, 'host'):
            # If changing host object, make sure the user has permission the
            # new one.
            if 'host' in data and data['host'] != obj.host:
                if not self.has_obj_perm(request.user, data['host']):
                    return False
            return self.has_obj_perm(request.user, obj.host)
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
        user = cast("User", request.user)
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        if is_super_or_group_admin(user):
            return True
        # Will do do more object checks later, but initially refuse any
        # unwarranted requests.
        if HostGroup.objects.filter(owners__name__in=user.group_list).exists():
            return True
        return False

    @staticmethod
    def is_super_or_group_admin(request):
        return is_super_or_group_admin(request.user)

    @staticmethod
    def _request_user_is_owner(hostgroup, request):
        owners = set(hostgroup.owners.values_list('name', flat=True))
        return _list_in_list(request.user.group_list, owners)

    def has_m2m_change_permission(self, request, view):
        if is_super_or_group_admin(request.user):
            return True
        return self._request_user_is_owner(view.object, request)

    # patch will only happen on HostGroupDetail
    def has_update_permission(self, request, view, validated_serializer):
        if is_super_or_group_admin(request.user):
            return True
        if 'description' in validated_serializer.validated_data:
            return self._request_user_is_owner(view.get_object(), request)
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        if is_super_or_group_admin(request.user):
            return True
        return False
