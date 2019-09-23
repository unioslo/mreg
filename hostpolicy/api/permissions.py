from rest_framework.permissions import IsAuthenticated, SAFE_METHODS

from mreg.api.permissions import user_is_superuser, user_in_settings_group


def user_is_hostpolicy_adminuser(user):
    return user_in_settings_group(user, 'HOSTPOLICYADMIN_GROUP')


def is_super_or_hostpolicy_admin(user):
    return user_is_superuser(user) or user_is_hostpolicy_adminuser(user)


class IsSuperOrHostPolicyAdminOrReadOnly(IsAuthenticated):
    """
    Permit user if in super or group admin group, else read only.
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in SAFE_METHODS:
            return True
        return is_super_or_hostpolicy_admin(request.user)

    def has_m2m_change_permission(self, request, view):
        return is_super_or_hostpolicy_admin(request.user)
