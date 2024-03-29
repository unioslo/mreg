from django.db.models import Prefetch
from rest_framework import status
from rest_framework.response import Response

from url_filter.filtersets import ModelFilterSet

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from hostpolicy.api.permissions import IsSuperOrHostPolicyAdminOrReadOnly
from mreg.api.v1.serializers import HostNameSerializer
from mreg.api.v1.views import (MregListCreateAPIView,
                               MregPermissionsListCreateAPIView,
                               MregPermissionsUpdateDestroy,
                               MregRetrieveUpdateDestroyAPIView,
                               )

from mreg.api.v1.history import HistoryLog
from mreg.api.v1.views_m2m import M2MDetail, M2MList, M2MPermissions
from mreg.models.host import Host

from . import serializers


class HostPolicyAtomFilterSet(ModelFilterSet):
    class Meta:
        model = HostPolicyAtom


class HostPolicyRoleFilterSet(ModelFilterSet):
    class Meta:
        model = HostPolicyRole


class HostPolicyAtomLogMixin(HistoryLog):

    log_resource = 'hostpolicy_atom'
    model = HostPolicyAtom


class HostPolicyRoleLogMixin(HistoryLog):

    log_resource = 'hostpolicy_role'
    model = HostPolicyRole


class HostPolicyPermissionsListCreateAPIView(M2MPermissions,
                                             MregPermissionsListCreateAPIView):

    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )


class HostPolicyPermissionsUpdateDestroy(M2MPermissions,
                                         MregPermissionsUpdateDestroy,
                                         MregRetrieveUpdateDestroyAPIView):

    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )


class HostPolicyAtomList(HostPolicyAtomLogMixin, MregListCreateAPIView):

    queryset = HostPolicyAtom.objects.all()
    serializer_class = serializers.HostPolicyAtomSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'

    def get_queryset(self):
        qs = super().get_queryset()
        return HostPolicyRoleFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data['name']).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        return super().post(request, *args, **kwargs)


class HostPolicyAtomDetail(HostPolicyAtomLogMixin, MregRetrieveUpdateDestroyAPIView):

    queryset = HostPolicyAtom.objects.all()
    serializer_class = serializers.HostPolicyAtomSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'


def _role_prefetcher(qs):
    return qs.prefetch_related(Prefetch(
               'hosts', queryset=Host.objects.order_by('name'))
               ).prefetch_related(Prefetch(
                'atoms', queryset=HostPolicyAtom.objects.order_by('name')))


class HostPolicyRoleList(HostPolicyRoleLogMixin, MregListCreateAPIView):

    queryset = HostPolicyRole.objects.all()
    serializer_class = serializers.HostPolicyRoleSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'

    def get_queryset(self):
        qs = _role_prefetcher(super().get_queryset())
        return HostPolicyRoleFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data['name']).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        return super().post(request, *args, **kwargs)


class HostPolicyRoleDetail(HostPolicyRoleLogMixin, MregRetrieveUpdateDestroyAPIView):

    queryset = HostPolicyRole.objects.all()
    serializer_class = serializers.HostPolicyRoleSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'

    def get_queryset(self):
        return _role_prefetcher(super().get_queryset())


class HostPolicyM2MList(HostPolicyRoleLogMixin, M2MList,
                        HostPolicyPermissionsListCreateAPIView):

    lookup_field = 'name'
    cls = HostPolicyRole


class HostPolicyM2MDetail(HostPolicyRoleLogMixin, M2MDetail,
                          HostPolicyPermissionsUpdateDestroy):

    cls = HostPolicyRole


class HostPolicyRoleAtomsList(HostPolicyM2MList):
    """
    get:
    Lists all atom members for a hostpolicy role.

    post:
    Adds a new atom member to a hostpolicy role.
    """

    serializer_class = serializers.HostPolicyAtomSerializer
    m2m_field = 'atoms'
    m2m_object = HostPolicyAtom


class HostPolicyRoleAtomsDetail(HostPolicyM2MDetail):
    """
    get:
    Returns details for the specified atom member.

    patch:
    Not allowed.

    delete:
    Remove the specified atom membership.
    """

    serializer_class = serializers.HostPolicyAtomSerializer
    m2m_field = 'atoms'
    lookup_field = 'atom'


class HostPolicyRoleHostsList(HostPolicyM2MList):
    """
    get:
    Lists all host members for a hostpolicy role.

    post:
    Adds a new host member to a hostpolicy role.
    """

    serializer_class = HostNameSerializer
    m2m_field = 'hosts'
    m2m_object = Host


class HostPolicyRoleHostsDetail(HostPolicyM2MDetail):
    """
    get:
    Returns details for the specified host member.

    patch:
    Not allowed.

    delete:
    Remove the specified host membership.
    """

    serializer_class = HostNameSerializer
    m2m_field = 'hosts'
    lookup_field = 'host'
