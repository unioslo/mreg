from django.contrib.auth.models import AbstractUser
from mreg.api.exceptions import ValidationError403, ValidationError400
from mreg.models.network import Network, NetworkExcludedRange, NetGroupRegexPermission

from mreg.api.permissions import (
    user_object_is_adminuser,
    user_object_is_group_adminuser,
    user_object_is_superuser,
    user_object_is_network_adminuser,
    user_in_settings_group,
    is_reserved_ip,
    DNS_UNDERSCORE_GROUP,
    DNS_WILDCARD_GROUP,
)

class User(AbstractUser):

    _group_list = None

    @property
    def group_list(self):
        if self._group_list is None:
            self._group_list = list(self.groups.values_list("name", flat=True))
        return self._group_list

    @property
    def is_mreg_admin(self):
        return user_object_is_adminuser(self)

    @property
    def is_mreg_group_admin(self):
        return user_object_is_group_adminuser(self)
    
    @property
    def is_mreg_superuser(self):
        return user_object_is_superuser(self)
    
    @property
    def is_mreg_network_admin(self):
        return user_object_is_network_adminuser(self)
    
    @property
    def is_mreg_network_admin_or_admin(self):
        return self.is_mreg_network_admin or self.is_mreg_admin
    
    @property
    def is_mreg_admin_or_superuser(self):
        return self.is_mreg_admin or self.is_mreg_superuser
    
    def is_permitted_to_create_host_without_ipaddress_or_raise(self):
        """Check if a user is permitted to create a host without an IP address.

        A user is permitted to create a host without an IP address if:
        - The user is an admin user.
        - The user is a network admin user.
        - The user is a superuser.

        :raises: ValidationError403 if the user is not permitted to create a host without an IP address.

        :return: Nothing    
        """
        if not (self.is_mreg_admin_or_superuser or self.is_mreg_network_admin):
            raise ValidationError403("Only admins, superusers, and network admins can create a host without an IP address.")
        
        return

    def is_permitted_to_use_dnsname_or_raise(self, dnsname: str):
        """Check if a user is permitted to use a DNS name.
        
        A user is permitted to use a DNS name if:
        - The name does not contain underscores or asterisks.
        - The name contains an underscore and the user is in the DNS_UNDERSCORE_GROUP or is a superuser.
        - The name contains an asterisk and the user is in the DNS_WILDCARD_GROUP and the name
          has more than than 3 dots, *or* the user is a superuser.

        :param dnsname: The DNS name to check, as a string.

        :raises: ValidationError403 if the user is not permitted to use the DNS name, with a message explaining why.
        
        :return: Nothing
        """
        if '_' not in dnsname and '*' not in dnsname:
            return

        if '_' in dnsname and not (user_in_settings_group(self, DNS_UNDERSCORE_GROUP) or self.is_mreg_superuser):
                raise ValidationError403("The DNS name contains an underscore, only allowed for DNS_UNDERSCORE_GROUP or superusers.")
        
        if '*' in dnsname:
            if not (user_in_settings_group(self, DNS_WILDCARD_GROUP) or self.is_mreg_superuser):
                raise ValidationError403("The DNS name contains an asterisk, only allowd for DNS_WILDCARD_GROUP or superusers.")
            
            if dnsname.count('.') < 3 and not self.is_mreg_superuser:
                raise ValidationError403("The DNS name contains an asterisk, but it must have more than 3 dots.")
        
        return
    
    def is_permitted_to_use_ipaddress_or_raise(self, ipaddress: str):
        """Check if a user is permitted to use a given IP address.

        A user is permitted to use an IP if:
        - The IP is not reserved.
        - The IP is not in a frozen network.
        - The IP is not in an excluded range.

        For other cases the following rules apply:
        - If the network is frozen, noone is permitted to use the IP address.
        - If the IP address is reserved, only superusers and network admins are permitted to use it.
        - If the IP address is in an excluded range, noone is permitted to use it.
        - If the IP address is not in a network, admins, superusers, and network admins are permitted to use it, and
          users may use the IP address if they have a permission entry for range containing the IP address.

        :param ip: The IP address to check, as a string.

        :raises: ValidationError403 if the user is not permitted to use the IP address, with a message explaining why.

        :return: Nothing
        """
        network = Network.objects.filter(network__net_contains=ipaddress).first()
        if network:
            if network.frozen:
                raise ValidationError403("The network is frozen.")

            if is_reserved_ip(ipaddress, network) and not (self.is_mreg_superuser or self.is_mreg_network_admin):
                raise ValidationError403("The IP address is reserved, only superusers and network admins can use it.")

            if NetworkExcludedRange.objects.filter(start_ip__lte=ipaddress, end_ip__gte=ipaddress).exists():
                raise ValidationError400("The IP address is in an excluded range, no-one can use it.")

            return

        # The IP address is not contained in a network known to mreg, but the user may still have a permission
        # entry for the range containing the IP address. This is a very weird use case, but it is used in
        # test_can_create_change_and_delete_host in test_host_permissions.py # 57.
        # This test maintains feature parity with the original code.
        if NetGroupRegexPermission.objects.filter(group__in=self.group_list).filter(range__net_contains=ipaddress).exists():
            return

        # We now know that the IP address is not in a network, and that the user does not have a permission mask
        # that would allow them to use the IP address. In this case, only admins, superusers, and network admins
        # are permitted to use the IP address.
        if self.is_mreg_admin_or_superuser or self.is_mreg_network_admin:
            return
        else:
            raise ValidationError403("The IP address is not in a network, only admins, superusers, and network admins can use it.")
        
    def display(self):
        permissions_list = []
        if self.is_mreg_admin:
            permissions_list.append("Admin")
        if self.is_mreg_superuser:
            permissions_list.append("Superuser")
        if self.is_mreg_group_admin:
            permissions_list.append("Group Admin")
        if self.is_mreg_network_admin:
            permissions_list.append("Network Admin")

        return f"{self.username} ({', '.join(permissions_list)} from groups: {', '.join(self.group_list)})"
