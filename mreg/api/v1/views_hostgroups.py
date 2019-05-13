from django.contrib.auth.models import Group
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.response import Response
from url_filter.filtersets import ModelFilterSet

from mreg.models import Host, HostGroup
from mreg.api.permissions import (HostGroupPermission,
                                  IsSuperOrGroupAdminOrReadOnly)

from . import serializers
from .views import (MregMixin,
                    MregPermissionsListCreateAPIView,
                    MregPermissionsUpdateDestroy,
                    MregRetrieveUpdateDestroyAPIView,
                    )


class HostGroupFilterSet(ModelFilterSet):
    class Meta:
        model = HostGroup

class M2MPermissions:

    def perform_m2m_alteration(self, method, instance):
        self.check_m2m_update_permission(self.request)
        method(instance)

    def check_m2m_update_permission(self, request):
        for permission in self.get_permissions():
            if isinstance(self, (HostGroupOwnersList, HostGroupOwnersDetail)):
                if not permission.is_super_or_group_admin(request):
                    self.permission_denied(request)
            else:
                if not permission.has_m2m_change_permission(request, self):
                    self.permission_denied(request)


class HostGroupPermissionsListCreateAPIView(M2MPermissions,
                                            MregPermissionsListCreateAPIView):

    permission_classes = (HostGroupPermission, )


class HostGroupPermissionsUpdateDestroy(M2MPermissions,
                                        MregPermissionsUpdateDestroy,
                                        MregRetrieveUpdateDestroyAPIView):

    permission_classes = (HostGroupPermission, )



class HostGroupList(MregMixin, generics.ListCreateAPIView):
    """
    get:
    Lists all hostgroups in use.

    post:
    Creates a new hostgroup object.
    """
    queryset = HostGroup.objects.get_queryset()
    serializer_class = serializers.HostGroupSerializer
    permission_classes = (IsSuperOrGroupAdminOrReadOnly, )

    def get_queryset(self):
        qs = super().get_queryset()
        qs = qs.prefetch_related(Prefetch(
               'hosts', queryset=Host.objects.order_by('name'))
               ).prefetch_related(Prefetch(
                'owners', queryset=Group.objects.order_by('name')))
        return HostGroupFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data['name']).exists():
                content = {'ERROR': 'hostgroup name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        location = '/hostgroups/%s' % serializer.validated_data['name']
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostGroupDetail(HostGroupPermissionsUpdateDestroy):
    """
    get:
    Returns details for the specified hostgroup. Includes hostgroups that are members.

    patch:
    Updates part of hostgroup.

    delete:
    Delete the specified hostgroup.
    """

    queryset = HostGroup.objects.get_queryset(
                 ).prefetch_related(Prefetch(
                   'hosts', queryset=Host.objects.order_by('name'))
                 ).prefetch_related(Prefetch(
                    'owners', queryset=Group.objects.order_by('name')))
    serializer_class = serializers.HostGroupSerializer
    lookup_field = 'name'


class HostGroupM2MList(HostGroupPermissionsListCreateAPIView):

    lookup_field = 'name'

    def get_queryset(self):
        self.hostgroup = get_object_or_404(HostGroup,
                                           name=self.kwargs[self.lookup_field])
        self.m2mrelation = getattr(self.hostgroup, self.m2m_field)
        return self.m2mrelation.all().order_by('name')

    def post(self, request, *args, **kwargs):
        qs = self.get_queryset()
        if "name" in request.data:
            name = request.data['name']
            if qs.filter(name=name).exists():
                content = {'ERROR': f'{name} already in {self.m2m_field}'}
                return Response(content, status=status.HTTP_409_CONFLICT)
            try:
                instance = self.m2m_object.objects.get(name=name)
            except self.m2m_object.DoesNotExist:
                content = {'ERROR': f'"{name}" does not exist'}
                return Response(content, status=status.HTTP_404_NOT_FOUND)
            self.perform_m2m_alteration(self.m2mrelation.add, instance)
            location = f'/hostgroups/{self.hostgroup.name}/{self.m2m_field}/{instance.name}'
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})
        else:
            content = {'ERROR': 'No name provided'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)



class HostGroupM2MDetail(HostGroupPermissionsUpdateDestroy):
    """
    get:
    Returns details for the specified m2mrelation member.

    patch:
    Not allowed.

    delete:
    Delete the specified m2mrelation member.
    """

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, name=self.kwargs[self.lookup_field])
        return obj

    def get_queryset(self):
        self.hostgroup = get_object_or_404(HostGroup, name=self.kwargs['name'])
        self.m2mrelation = getattr(self.hostgroup, self.m2m_field)
        return self.m2mrelation.all()

    def patch(self, request, *args, **kwargs):
        raise MethodNotAllowed()

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_m2m_alteration(self.m2mrelation.remove, instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


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

    serializer_class = serializers.HostNameSerializer
    m2m_field = 'owners'
    m2m_object = Group


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
