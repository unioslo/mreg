from typing import cast

import enum

from django.contrib.auth.models import AbstractUser
from django.http.request import HttpRequest
from django.conf import settings

from rest_framework import exceptions

class MregAdminGroup(enum.Enum):

    SUPERUSER = 'SUPERUSER_GROUP'
    ADMINUSER = 'ADMINUSER_GROUP'
    GROUP_ADMIN = 'GROUPADMINUSER_GROUP'
    NETWORK_ADMIN = 'NETWORK_ADMIN_GROUP'
    DNS_WILDCARD = 'DNS_WILDCARD_GROUP'
    DNS_UNDERSCORE = 'DNS_UNDERSCORE_GROUP'
    HOSTPOLICY_ADMIN = 'HOSTPOLICYADMIN_GROUP'

    def settings_groups_or_raise(self) -> list[str]:
        groupnames = getattr(settings, self.value, None)
        if groupnames is None:
            raise exceptions.APIException(detail=f'{self.value} is unset in config')
        
        # This bit of semantics is retained from the original implementation
        if isinstance(groupnames, str):
            groupnames = [groupnames]

        return groupnames

class User(AbstractUser):

    _group_list = None

    @property
    def group_list(self):
        if self._group_list is None:
            self._group_list = list(self.groups.values_list("name", flat=True))
        return self._group_list

    @property
    def is_mreg_superuser(self):
        return self.is_member_of_any(MregAdminGroup.SUPERUSER.settings_groups_or_raise())

    @property
    def is_mreg_admin(self):
        return self.is_member_of_any(MregAdminGroup.ADMINUSER.settings_groups_or_raise())

    @property
    def is_mreg_group_admin(self):
        return self.is_member_of_any(MregAdminGroup.GROUP_ADMIN.settings_groups_or_raise())

    @property
    def is_mreg_network_admin(self):
        return self.is_member_of_any(MregAdminGroup.NETWORK_ADMIN.settings_groups_or_raise())
    
    @property
    def is_mreg_dns_wildcard_admin(self):
        return self.is_member_of_any(MregAdminGroup.DNS_WILDCARD.settings_groups_or_raise())
    
    @property
    def is_mreg_dns_underscore_admin(self):
        return self.is_member_of_any(MregAdminGroup.DNS_UNDERSCORE.settings_groups_or_raise())

    @property
    def is_mreg_hostpolicy_admin(self):
        return self.is_member_of_any(MregAdminGroup.HOSTPOLICY_ADMIN.settings_groups_or_raise())

    @property
    def is_mreg_superuser_or_admin(self):
        return self.is_mreg_admin or self.is_mreg_superuser

    @property
    def is_mreg_superuser_or_hostpolicy_admin(self):
        return self.is_mreg_hostpolicy_admin or self.is_mreg_superuser

    @classmethod
    def from_request(cls, request: HttpRequest) -> 'User':
        if not request.user.is_authenticated:
            raise exceptions.NotAuthenticated("Attempted to coerce an authenticated user from unauthenticated request")

        return cast(cls, request.user)

    def is_member_of(self, groupname: str) -> bool:
        return groupname in self.group_list
    
    def is_member_of_any(self, groupnames: list[str]) -> bool:
        return any(self.is_member_of(groupname) for groupname in groupnames)

