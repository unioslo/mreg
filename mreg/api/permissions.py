from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated, SAFE_METHODS

from structlog import get_logger

from mreg.api.v1.serializers import HostSerializer
from mreg.models.host import HostGroup, Host
from mreg.models.network import NetGroupRegexPermission, Network
from mreg.models.policy import PolicyRole

from mreg.models.auth import User

logger = get_logger()

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
        import mreg.api.v1.views
        if not super().has_permission(request, view):
            return False

        user = User.from_request(request)

        if user.is_mreg_superuser:
            return True
        if user.is_mreg_network_admin:
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
        if NetGroupRegexPermission.objects.filter(group__in=user.group_list).exists():
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

class IsSuperOrPolicyAdminOrReadOnly(IsAuthenticated):
    """Permit user if in super or host policy admin group, else read only."""

    def has_permission(self, request, view):
        user = User.from_request(request)
        logpoint = "IsSuperOrPolicyAdminOrReadOnly.has_permission"

        logger.debug(logpoint, user=user)

        if not super().has_permission(request, view):
            logger.debug(logpoint, authenticated=False, result="Denied")
            return False
        if request.method in SAFE_METHODS:
            logger.debug(logpoint, method=request.method, safe_methods=True, result="Allowed")
            return True
        if user.is_mreg_superuser_or_hostpolicy_admin:
            logger.debug(logpoint, is_admin_or_hostpolicy_admin=True, result="Allowed")
            return True

        # We now turn to testing for user write access. This requires there to be a Label attached to the PolicyRole
        # in question. If there is no Label, we deny access, if there is a Label, we check if the user has been granted
        # access through a NetGroupRegexPermission.
        role_name = view.kwargs.get('name')
        if role_name is None:
            logger.debug(logpoint, role_name=None, result="Denied")
            return False
        
        # Find out which labels are attached to this role
        role_labels = PolicyRole.objects.filter(name=role_name).values_list('labels__name', flat=True)
        if not any(role_labels):
            # if the role doesn't have any labels, there's no possibility of access at this point
            logger.debug(logpoint, role_labels=None, result="Denied")
            return False
        
        # Find all the NetGroupRegexPermission objects that correspond with
        # the ipaddress, hostname, and the groups that the user is a member of
        # Also, ensure that the hostname is not empty.
        hostname = view.kwargs.get('host', request.data.get("name"))
        if not hostname:
            logger.debug(logpoint, hostname=None, result="Denied")
            return False
        
        ips = list(Host.objects.filter(name=hostname).exclude(
                        ipaddresses__ipaddress=None
                    ).values_list('ipaddresses__ipaddress', flat=True))
        logger.debug(logpoint, hostname=hostname, ips=ips)
        qs = NetGroupRegexPermission.find_perm(user.group_list, hostname, ips)

        # If no permissions matched the host/ip, we deny access
        if not qs.exists():
            logger.debug(logpoint, netgroupregexpermission="Empty set", result="Denied")
            return False

        # Do any of those permissions have labels that match the labels attached to this role?
        # If so, access is granted
        perm_labels = qs.values_list('labels__name', flat=True)
        if any(label in perm_labels for label in role_labels):
            logger.debug(logpoint, perm_labels=perm_labels, role_labels=role_labels, result="Allowed")
            return True

        logger.debug(logpoint, perm_labels=perm_labels, role_labels=role_labels, result="Denied")
        return False

    def has_m2m_change_permission(self, request, view):
        return True
