from typing import cast

# Notes about using functools.cached_property:
# 1) Prior to Python 3.12 there is a performance penalty for using
# functools.cached_property over django.utils.functional.cached_property.
# See https://stackoverflow.com/questions/68593165/what-is-the-difference-between-cached-property-in-django-vs-pythons-functools
# for more information.
# 2) Cached properties have a life cycle that is tied to the instance itself.
# This means that the next connection creating a new user object will recache the
# properties in question. This ensures both performance and that during the lifetime
# of a given request users permissions will be persistent.
from functools import cached_property

import enum

from django.contrib.auth.models import AbstractUser
from django.conf import settings

from rest_framework import exceptions
from rest_framework.request import Request

from structlog import get_logger


logger = get_logger(__name__)


class MregAdminGroup(enum.Enum):
    """Enumeration of mreg admin groups."""

    SUPERUSER = "SUPERUSER_GROUP"
    ADMINUSER = "ADMINUSER_GROUP"
    GROUP_ADMIN = "GROUPADMINUSER_GROUP"
    NETWORK_ADMIN = "NETWORK_ADMIN_GROUP"
    DNS_WILDCARD = "DNS_WILDCARD_GROUP"
    DNS_UNDERSCORE = "DNS_UNDERSCORE_GROUP"
    HOSTPOLICY_ADMIN = "HOSTPOLICYADMIN_GROUP"

    def settings_groups_or_raise(self) -> list[str]:
        """Get the group names from the settings, or raise an exception if unset.
        
        Note that system adminstrators can override the default values of these groups
        by setting the corresponding values in the Django settings file.                

        :return: A list of group names (str) from the settings.
        """
        groupnames = getattr(settings, self.value, None)
        if groupnames is None:
            raise exceptions.APIException(detail=f"{self.value} is unset in config")

        # This bit of semantics is retained from the original implementation
        if isinstance(groupnames, str):
            groupnames = [groupnames]

        return groupnames


class User(AbstractUser):
    """Custom user model for mreg.

    This class extends the default Django user model with custom properties and methods
    to manage user permissions within mreg.
    """

    @cached_property
    def group_list(self) -> list[str]:
        """Provide a list of group names that the user is a member of.
        
        Note: This is a cached property, so it will only be calculated once per instance.
        """
        return list(self.groups.values_list("name", flat=True))

    # The following properties are used to check if a user is a member of a specific group
    # or a set of groups. This is used to determine if a user has the necessary permissions
    # to perform certain actions within mreg.
    # Note that all users in a Django system have core attributes like is_superuser, is_staff,
    # and is_active, but these are not used in mreg. Instead, mreg uses custom groups to manage
    # permissions, and to make this explicit the properties involved include the string "mreg".

    @cached_property
    def is_mreg_superuser(self) -> bool:
        """Check if the user is a member of the superuser group.
        
        This is the highest level of access in mreg, and grants the user full control over
        pretty much everything.
        """
        return self.is_member_of_any(MregAdminGroup.SUPERUSER.settings_groups_or_raise())

    @cached_property
    def is_mreg_admin(self) -> bool:
        """Check if the user is a member of the admin group.
        
        This is a slightly lower level of access than the superuser group, but still grants
        the user a high level of overall control over mreg.
        """
        return self.is_member_of_any(MregAdminGroup.ADMINUSER.settings_groups_or_raise())

    @cached_property
    def is_mreg_hostgroup_admin(self) -> bool:
        """Check if the user is allowed to administer hostgroups.

        Normal users can access hostgroups that they own. Group admins can access all hostgroups, 
        and can also create and delete hostgroups.
        """
        return self.is_member_of_any(MregAdminGroup.GROUP_ADMIN.settings_groups_or_raise())

    @cached_property
    def is_mreg_network_admin(self) -> bool:
        """Check if the user is allowed to administer networks.
        
        This grants the user the ability to create, delete, and modify network objects.
        """
        return self.is_member_of_any(MregAdminGroup.NETWORK_ADMIN.settings_groups_or_raise())

    @cached_property
    def is_mreg_dns_wildcard_admin(self) -> bool:
        """Check if the user is allowed to administer DNS wildcard records."""
        return self.is_member_of_any(MregAdminGroup.DNS_WILDCARD.settings_groups_or_raise())

    @cached_property
    def is_mreg_dns_underscore_admin(self) -> bool:
        """Check if the user is allowed to administer DNS underscore records."""
        return self.is_member_of_any(MregAdminGroup.DNS_UNDERSCORE.settings_groups_or_raise())

    @property
    def is_mreg_hostpolicy_admin(self) -> bool:
        """Check if the user is allowed to administer hostpolicy.
        
        A user with this permission can create, delete, and modify hostpolicy roles / atoms.
        """
        return self.is_member_of_any(MregAdminGroup.HOSTPOLICY_ADMIN.settings_groups_or_raise())

    @cached_property
    def is_mreg_superuser_or_admin(self) -> bool:
        """Check if the user is a superuser or an admin."""
        return self.is_mreg_admin or self.is_mreg_superuser

    @cached_property
    def is_mreg_superuser_or_hostpolicy_admin(self) -> bool:
        """Check if the user is a superuser or a hostpolicy admin."""
        return self.is_mreg_hostpolicy_admin or self.is_mreg_superuser

    @classmethod
    def from_request(cls, request: Request) -> "User":
        """Get the authenticated user from a request, or raise if not authenticated.

        :param request: The incoming request.

        :return: The authenticated user as an mreg.models.auth.User object.
        """
        if not request.user.is_authenticated:
            logger.error(
                "user",
                message="Attempted to coerce an authenticated user from unauthenticated request",
                user=request.user,
                url=request.path_info,
                method=request.method,
            )
            raise exceptions.NotAuthenticated("Not authenticated")

        return cast(cls, request.user)

    def is_member_of(self, groupname: str) -> bool:
        """Check if the user is a member of a specific group.
        
        :param groupname: The name of the group to check.

        :return: True if the user is a member of the group, False otherwise.
        """
        return groupname in self.group_list

    def is_member_of_any(self, groupnames: list[str]) -> bool:
        """Check if the user is a member of any of a list of groups.
        
        :param groupnames: A list of group names (str) to check.

        :return: True if the user is a member of any of the groups, False otherwise.
        """
        return any(self.is_member_of(groupname) for groupname in groupnames)
