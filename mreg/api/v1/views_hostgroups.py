
from django.contrib.auth.models import Group
from django.db.models import Prefetch

from rest_framework import status
from rest_framework.response import Response

from mreg.api.permissions import (HostGroupPermission,
                                  IsSuperOrGroupAdminOrReadOnly)
from mreg.models.host import Host, HostGroup
from mreg.models.auth import User

from mreg.mixins import LowerCaseLookupMixin

from . import serializers
from .history import HistoryLog
from .views import (MregListCreateAPIView,
                    MregPermissionsListCreateAPIView,
                    MregPermissionsUpdateDestroy,
                    MregRetrieveUpdateDestroyAPIView,
                    )
from .views_m2m import M2MDetail, M2MList, M2MPermissions

from .filters import HostGroupFilterSet


class HostGroupM2MPermissions(M2MPermissions):

    def check_m2m_update_permission(self, request):
        for permission in self.get_permissions():
            if isinstance(self, (HostGroupOwnersList, HostGroupOwnersDetail)):
                user = User.from_request(request)
                if not (user.is_mreg_superuser or user.is_mreg_group_admin):
                    self.permission_denied(request)
            else:
                if not permission.has_m2m_change_permission(request, self):
                    self.permission_denied(request)


class HostGroupLogMixin(HistoryLog):

    log_resource = 'group'
    model = HostGroup
    foreign_key_name = 'group'


class HostGroupPermissionsListCreateAPIView(HostGroupLogMixin,
                                            HostGroupM2MPermissions,
                                            MregPermissionsListCreateAPIView):

    permission_classes = (HostGroupPermission, )


class HostGroupPermissionsUpdateDestroy(HostGroupLogMixin,
                                        HostGroupM2MPermissions,
                                        MregPermissionsUpdateDestroy,
                                        MregRetrieveUpdateDestroyAPIView):

    permission_classes = (HostGroupPermission, )


def _hostgroup_prefetcher(qs):
    return qs.prefetch_related(Prefetch(
                 'hosts', queryset=Host.objects.order_by('name'))
                ).prefetch_related(Prefetch(
                 'owners', queryset=Group.objects.order_by('name')))


class HostGroupList(HostGroupLogMixin, LowerCaseLookupMixin, MregListCreateAPIView):
    """
    get:
    Lists all hostgroups in use.

    post:
    Creates a new hostgroup object.
    """

    queryset = HostGroup.objects.all()
    serializer_class = serializers.HostGroupSerializer
    permission_classes = (IsSuperOrGroupAdminOrReadOnly, )
    filterset_class = HostGroupFilterSet
    lookup_field = 'name'

    def post(self, request, *args, **kwargs):
        if self.get_object_from_request(request):
            content = {'ERROR': 'hostgroup name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)
        return super().post(request, *args, **kwargs)


class HostGroupDetail(LowerCaseLookupMixin, HostGroupPermissionsUpdateDestroy):
    """
    get:
    Returns details for the specified hostgroup. Includes hostgroups that are members.

    patch:
    Updates part of hostgroup.

    delete:
    Delete the specified hostgroup.
    """

    queryset = _hostgroup_prefetcher(HostGroup.objects.all())
    serializer_class = serializers.HostGroupSerializer
    lookup_field = 'name'


class HostGroupM2MList(M2MList, HostGroupPermissionsListCreateAPIView):

    lookup_field = 'name'
    cls = HostGroup


class HostGroupM2MDetail(M2MDetail, HostGroupPermissionsUpdateDestroy):

    cls = HostGroup


class HostGroupGroupsList(HostGroupM2MList):
    """
    get:
    Lists all hostgroup members for a hostgroup.

    post:
    Adds a new hostgroup member to a hostgroup.
    """

    serializer_class = serializers.HostGroupSerializer
    m2m_field = 'groups'
    m2m_object = HostGroup


class HostGroupGroupsDetail(HostGroupM2MDetail):
    """
    get:
    Returns details for the specified hostgroup member.

    patch:
    Not allowed.

    delete:
    Delete the specified hostgroup member.
    """

    serializer_class = serializers.HostGroupSerializer
    m2m_field = 'groups'
    lookup_field = 'group'


class HostGroupHostsList(HostGroupM2MList):
    """
    get:
    Lists all host members for a hostgroup.

    post:
    Adds a new host member to a hostgroup.
    """

    serializer_class = serializers.HostNameSerializer
    m2m_field = 'hosts'
    m2m_object = Host


class HostGroupHostsDetail(HostGroupM2MDetail):
    """
    get:
    Returns details for the specified host member.

    patch:
    Not allowed.

    delete:
    Delete the specified host member.
    """

    serializer_class = serializers.GroupSerializer
    m2m_field = 'hosts'
    lookup_field = 'host'


class HostGroupOwnersList(HostGroupM2MList):
    """
    get:
    Lists all owners for a hostgroup.

    post:
    Adds a new owner to a hostgroup.
    """

    serializer_class = serializers.GroupSerializer
    m2m_field = 'owners'
    m2m_object = Group
    m2m_create_if_missing = True


class HostGroupOwnersDetail(HostGroupM2MDetail):
    """
    get:
    Returns details for the specified host owner.

    patch:
    Not allowed.

    delete:
    Delete the specified host owner.
    """

    serializer_class = serializers.GroupSerializer
    m2m_field = 'owners'
    lookup_field = 'owner'
