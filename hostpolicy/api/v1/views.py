from django.db.models import Prefetch
from rest_framework import status
from rest_framework.response import Response

from django_filters import rest_framework as filters
from rest_framework import filters as rest_filters

from hostpolicy.api.permissions import IsSuperOrHostPolicyAdminOrReadOnly
from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.api.v1.history import HistoryLog
from mreg.api.v1.serializers import HostNameSerializer
from mreg.api.v1.views import (
    MregListCreateAPIView,
    MregPermissionsListCreateAPIView,
    MregPermissionsUpdateDestroy,
    MregRetrieveUpdateDestroyAPIView,
)
from mreg.api.v1.views_m2m import M2MDetail, M2MList, M2MPermissions
from mreg.mixins import LowerCaseLookupMixin
from mreg.models.host import Host

from mreg.api.v1.filters import STRING_OPERATORS, INT_OPERATORS

from . import serializers

# Note that related lookups don't work at the moment, so we need to do them explicitly.
class HostPolicyAtomFilterSet(filters.FilterSet):
    class Meta:
        model = HostPolicyAtom
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "create_date": INT_OPERATORS,
            "updated_at": INT_OPERATORS,
            "description": STRING_OPERATORS,
            "roles": INT_OPERATORS,
        }


class HostPolicyRoleFilterSet(filters.FilterSet):
    # This seems to be required due to the many-to-many relationships?
    atoms__name__exact = filters.CharFilter(field_name='atoms__name', lookup_expr='exact')
    atoms__name__contains = filters.CharFilter(field_name='atoms__name', lookup_expr='contains')
    atoms__name__regex = filters.CharFilter(field_name='atoms__name', lookup_expr='regex')

    hosts__name__exact = filters.CharFilter(field_name='hosts__name', lookup_expr='exact')
    hosts__name__contains = filters.CharFilter(field_name='hosts__name', lookup_expr='contains')
    hosts__name__regex = filters.CharFilter(field_name='hosts__name', lookup_expr='regex')

    labels__name__exact = filters.CharFilter(field_name='labels__name', lookup_expr='exact')
    labels__name__contains = filters.CharFilter(field_name='labels__name', lookup_expr='contains')
    labels__name__regex = filters.CharFilter(field_name='labels__name', lookup_expr='regex')

    class Meta:
        model = HostPolicyRole
        fields = {
            "id": INT_OPERATORS,
            "name": STRING_OPERATORS,
            "create_date": INT_OPERATORS,
            "updated_at": INT_OPERATORS,
            "hosts": INT_OPERATORS,
            "atoms": INT_OPERATORS,
            "labels": INT_OPERATORS,
        }

class HostPolicyAtomLogMixin(HistoryLog):

    log_resource = 'hostpolicy_atom'
    model = HostPolicyAtom
    filter_backends = (
        rest_filters.SearchFilter,
        filters.DjangoFilterBackend,
        rest_filters.OrderingFilter,
    )
    ordering_fields = "__all__"



class HostPolicyRoleLogMixin(HistoryLog):

    log_resource = 'hostpolicy_role'
    model = HostPolicyRole
    filter_backends = (
        rest_filters.SearchFilter,
        filters.DjangoFilterBackend,
        rest_filters.OrderingFilter,
    )
    ordering_fields = "__all__"


class HostPolicyPermissionsListCreateAPIView(M2MPermissions,
                                             MregPermissionsListCreateAPIView):

    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )


class HostPolicyPermissionsUpdateDestroy(M2MPermissions,
                                         MregPermissionsUpdateDestroy,
                                         MregRetrieveUpdateDestroyAPIView):

    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )


class HostPolicyAtomList(HostPolicyAtomLogMixin, LowerCaseLookupMixin, MregListCreateAPIView):

    queryset = HostPolicyAtom.objects.all()
    serializer_class = serializers.HostPolicyAtomSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'
    filterset_class = HostPolicyAtomFilterSet

    def post(self, request, *args, **kwargs):
        if self.get_object_from_request(request):
            content = {"ERROR": "name already in use"}
            return Response(content, status=status.HTTP_409_CONFLICT)

        return super().post(request, *args, **kwargs)


class HostPolicyAtomDetail(HostPolicyAtomLogMixin, LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):

    queryset = HostPolicyAtom.objects.all()
    serializer_class = serializers.HostPolicyAtomSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'


def _role_prefetcher(qs):
    return qs.prefetch_related(Prefetch(
               'hosts', queryset=Host.objects.order_by('name'))
               ).prefetch_related(Prefetch(
                'atoms', queryset=HostPolicyAtom.objects.order_by('name')))


class HostPolicyRoleList(HostPolicyRoleLogMixin, LowerCaseLookupMixin, MregListCreateAPIView):

    queryset = HostPolicyRole.objects.all()
    serializer_class = serializers.HostPolicyRoleSerializer
    permission_classes = (IsSuperOrHostPolicyAdminOrReadOnly, )
    lookup_field = 'name'
    filterset_class = HostPolicyRoleFilterSet

    def post(self, request, *args, **kwargs):
        if self.get_object_from_request(request):
            content = {"ERROR": "name already in use"}
            return Response(content, status=status.HTTP_409_CONFLICT)
        return super().post(request, *args, **kwargs)


class HostPolicyRoleDetail(HostPolicyRoleLogMixin, LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):

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
