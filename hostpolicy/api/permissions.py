from rest_framework.permissions import IsAuthenticated, SAFE_METHODS

from mreg.api.permissions import user_is_superuser, user_in_settings_group

from mreg.models import Host, NetGroupRegexPermission
from hostpolicy.models import HostPolicyRole


def user_is_hostpolicy_adminuser(user):
    return user_in_settings_group(user, 'HOSTPOLICYADMIN_GROUP')


def is_super_or_hostpolicy_admin(user):
    return user_is_superuser(user) or user_is_hostpolicy_adminuser(user)


class IsSuperOrHostPolicyAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, or has been granted access through a
    NetGroupRegexPermission, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            # Not even reading is allowed if you're not authenticated
            return False
        if request.method in SAFE_METHODS:
            return True
        if is_super_or_hostpolicy_admin(request.user):
            return True

        # Is this request about atoms or something else that isn't a role?
        # In that case, non-admin-users shouldn't have access anyway, and we can deny the request.
        if not (view.__class__.__name__ == 'HostPolicyRoleHostsDetail' or
                view.__class__.__name__ == 'HostPolicyRoleHostsList'):
            return False

        # Find out which labels are attached to this role
        role_labels = HostPolicyRole.objects.filter(name=view.kwargs['name']).values_list('labels__name', flat=True)
        if not any(role_labels):
            # if the role doesn't have any labels, there's no possibility of access at this point
            return False

        # Find all the NetGroupRegexPermission objects that correspond with
        # the ipaddress, hostname, and the groups that the user is a member of
        if 'host' in view.kwargs:
            hostname = view.kwargs['host']
        else:
            hostname = request.data.get("name")
        ips = list(Host.objects.filter(
                        name=hostname
                    ).exclude(
                        ipaddresses__ipaddress=None
                    ).values_list('ipaddresses__ipaddress', flat=True))
        qs = NetGroupRegexPermission.find_perm(request.user.group_list, hostname, ips)

        # If no permissions matched the host/ip, we deny access
        if not qs.exists():
            return False

        # Do any of those permissions have labels that match the labels attached to this role?
        # If so, access is granted
        perm_labels = qs.values_list('labels__name', flat=True)
        if any(label in perm_labels for label in role_labels):
            return True

        # If the code got to this point, it means none of the labels matched.
        return False

    def has_m2m_change_permission(self, request, view):
        return True
