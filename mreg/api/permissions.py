from django.conf import settings
from rest_framework import exceptions
from rest_framework.permissions import BasePermission, SAFE_METHODS

import mreg.api.v1.views

from mreg.api.v1.serializers import HostSerializer
from mreg.models import NetGroupRegexPermission


def get_settings_groups(group_setting_name):
    groupnames = getattr(settings, group_setting_name, None)
    if groupnames is None:
        raise exceptions.APIException(detail=f'{group_setting_name} is unset in config')
    if isinstance(groupnames, str):
        groupnames = (groupnames, )
    return groupnames


def user_in_settings_group(request, group_setting_name):
    groupnames = get_settings_groups(group_setting_name)
    return request.user.groups.filter(name__in=groupnames).exists()


def _list_in_list(a, b):
    # Returns true if any of element in a is in b
    return any(i in b for i in a)


def user_in_required_group(user):
    return _list_in_list(get_settings_groups('REQUIRED_USER_GROUPS'),
                         user.group_list)


def user_is_superuser(user):
    groups = get_settings_groups('SUPERUSER_GROUP')
    return _list_in_list(groups, user.group_list)


def user_is_adminuser(user):
    groups = get_settings_groups('ADMINUSER_GROUP')
    return _list_in_list(groups, user.group_list)


def is_super_or_admin(user):
    return user_is_superuser(user) or user_is_adminuser(user)


class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return False
        return request.method in SAFE_METHODS


class IsInRequiredGroup(BasePermission):
    """
    Allows only access to users in the required group.
    """

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return False
        return user_in_settings_group(request, 'REQUIRED_USER_GROUPS')


class ReadOnlyForRequiredGroup(IsInRequiredGroup):
    """
    Allows read only access to users in the required group.
    """

    def has_permission(self, request, view):
        if super().has_permission(request, view):
            return request.method in SAFE_METHODS
        return False


class IsSuperGroupMember(BasePermission):
    """
    Permit user if in super user group.
    """

    group = 'SUPERUSER_GROUP'

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return False
        return user_in_settings_group(request, 'SUPERUSER_GROUP')


class IsSuperOrAdminOrReadOnly(BasePermission):
    """
    Permit user if in super or admin group, else read only.
    """

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        if not user_in_required_group(request.user):
            return False
        return is_super_or_admin(request.user)


class IsGrantedNetGroupRegexPermission(BasePermission):
    """
    Permit user if the user has been granted access through a
    NetGroupRegexPermission.
    """

    def has_permission(self, request, view):
        # This method is called before the view is executed, so
        # just do some preliminary checks.
        if not bool(request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        if is_super_or_admin(request.user):
            return True
        if not user_in_required_group(request.user):
            return False
        # Will do do more object checks later, but initially refuse any
        # unwarranted requests.
        if NetGroupRegexPermission.objects.filter(group__in=request.user.group_list
                                                  ).exists():
            return True
        return False

    def has_perm(self, user, hostname, ips):
        return bool(NetGroupRegexPermission.find_perm(user.group_list,
                                                      hostname, ips))

    def has_obj_perm(self, user, obj):
        return self.has_perm(user, self._get_hostname_and_ips(obj))

    def has_create_permission(self, request, view, validated_serializer):
        if is_super_or_admin(request.user):
            return True
        hostname = None
        ips = []
        data = validated_serializer.validated_data
        # If the ip
        if isinstance(view, (mreg.api.v1.views.HostList,
                             mreg.api.v1.views.IpaddressList)):
            # HostList does not require ipaddress, but if none, the permissions
            # will not match, so just refuse it.
            if 'ipaddress' not in data:
                return False
            ips.append(data['ipaddress'])
            hostname = data['host'].name
        elif 'host' in data:
            hostname, ips = self._get_hostname_and_ips(data['host'])
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        if ips and hostname:
            return self.has_perm(request.user, hostname, ips)
        return False

    def has_destroy_permission(self, request, view, validated_serializer):
        if is_super_or_admin(request.user):
            return True
        obj = view.get_object()
        if isinstance(view, mreg.api.v1.views.HostDetail):
            pass
        elif hasattr(obj, 'host'):
            obj = obj.host
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

        return self.has_obj_perm(request.user, obj)

    def has_update_permission(self, request, view, validated_serializer):
        if is_super_or_admin(request.user):
            return True
        data = validated_serializer.validated_data
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
            return self.has_obj_perm(request.user, obj.host)
        else:
            raise exceptions.PermissionDenied(f"Unhandled view: {view}")

    def _get_hostname_and_ips(self, hostobject):
        ips = []
        host = HostSerializer(hostobject)
        for i in host.data['ipaddresses']:
            ips.append(i['ipaddress'])
        return host.data['name'], ips
