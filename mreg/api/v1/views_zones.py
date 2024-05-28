import django.core.exceptions

from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404

from rest_framework import (generics, renderers, status)
from rest_framework.decorators import (api_view, renderer_classes)
from rest_framework.exceptions import ParseError
from rest_framework.request import Request
from rest_framework.response import Response

from mreg.models.base import NameServer
from mreg.models.host import Host
from mreg.models.zone import ForwardZone, ForwardZoneDelegation, ReverseZone, ReverseZoneDelegation

from mreg.mixins import LowerCaseLookupMixin

from mreg.api.permissions import (IsSuperGroupMember, IsAuthenticatedAndReadOnly)

from .serializers import (ForwardZoneDelegationSerializer, ForwardZoneSerializer,
                          ReverseZoneDelegationSerializer, ReverseZoneSerializer)
from .views import (MregRetrieveUpdateDestroyAPIView, )
from .zonefile import ZoneFile

from .filters import (ForwardZoneFilterSet, ReverseZoneFilterSet)


def _update_parent_zone(qs, zonename):
    """Try to figure if the zone name is a sub zone, and if so, set
       the parent zone's updated attribute to True to make sure it
       will be in the next zonefile export."""
    splitted = zonename.split(".")[1:]
    names = set(qs.values_list('name', flat=True))
    for i in range(len(splitted)):
        name = ".".join(splitted[i:])
        if name in names:
            zone = qs.get(name=name)
            zone.updated = True
            zone.save()
            break


def _validate_nameservers(names):
    if not names:
        raise ParseError(detail="No nameservers submitted")

    done = set()
    for name in names:
        if name in done:
            raise ParseError(detail=f"Nameserver {name} is used multiple times")
        try:
            NameServer.validate_name(name)
        except django.core.exceptions.ValidationError as error:
            raise ParseError(detail=str(error))
        done.add(name)


def _get_request_nameservers(request: Request, field: str = "primary_ns") -> list[str]:
    """Extract nameservers from the request data."""
    if request.content_type == "application/json":
        return request.data.get(field, [])
    return request.data.getlist(field, [])


class ZoneList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all zones.

    post:
    Create a zone. The primary_ns field is a list where the first element will be the primary nameserver.

    """

    lookup_field = 'name'
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        qs = super().get_queryset()
        return self.filterset(data=self.request.GET, queryset=qs).qs

    def post(self, request: Request, *args, **kwargs):
        qs = self.get_queryset()
        if qs.filter(name=request.data["name"]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)
        # A copy is required since the original is immutable
        nameservers = _get_request_nameservers(request)
        _validate_nameservers(nameservers)
        data = request.data.copy()
        data['primary_ns'] = nameservers[0]
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        zone = serializer.create()
        self.perform_create(zone)
        zone.update_nameservers(nameservers)
        _update_parent_zone(qs, zone.name)
        location = request.path + zone.name
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class ForwardZoneList(ZoneList):
    filterset = ForwardZoneFilterSet
    serializer_class = ForwardZoneSerializer
    queryset = ForwardZone.objects.all().order_by('name')


class ReverseZoneList(ZoneList):
    filterset = ReverseZoneFilterSet
    serializer_class = ReverseZoneSerializer
    queryset = ReverseZone.objects.all().order_by('network')


class ZoneDelegationList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all the zone's delegations.

    post:
    Create a delegation for the zone.
    """

    lookup_field = 'name'
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        self.parentzone = get_object_or_404(self.model, name=self.kwargs[self.lookup_field])
        self.queryset = self.parentzone.delegations.all().order_by('id')
        return self.filterset(data=self.request.GET, queryset=self.queryset).qs

    def post(self, request: Request, *args, **kwargs):
        qs = self.get_queryset()
        if qs.filter(name=request.data[self.lookup_field]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)
        nameservers = _get_request_nameservers(request, "nameservers")
        _validate_nameservers(nameservers)
        data = request.data.copy()
        data['zone'] = self.parentzone.pk
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        delegation = serializer.create()
        self.perform_create(delegation)
        delegation.update_nameservers(nameservers)
        self.parentzone.updated = True
        self.parentzone.save()
        location = request.path + delegation.name
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class ForwardZoneDelegationList(ZoneDelegationList):
    filterset = ForwardZoneFilterSet
    serializer_class = ForwardZoneDelegationSerializer
    model = ForwardZone


class ReverseZoneDelegationList(ZoneDelegationList):
    filterset = ReverseZoneFilterSet
    serializer_class = ReverseZoneDelegationSerializer
    model = ReverseZone


class ZoneDetail(LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):
    """
    get:
    List details for a zone.

    patch:
    Update parts of a zone.
    Nameservers need to be patched through /zones/<type>/<name>/nameservers.
    primary_ns needs to be a nameserver of the zone

    delete:
    Delete a zone.
    """

    lookup_field = 'name'
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]

        if "name" in request.data:
            content = {'ERROR': 'Not allowed to change name'}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        if "nameservers" in request.data:
            content = {'ERROR': 'Not allowed to patch nameservers, use /zones/{}/nameservers'.format(query)}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        zone = self.get_object()
        # Check if primary_ns is in the zone's list of nameservers
        if "primary_ns" in request.data:
            if request.data['primary_ns'] not in [nameserver.name for nameserver in zone.nameservers.all()]:
                content = {'ERROR': "%s is not one of %s's nameservers" % (request.data['primary_ns'], query)}
                return Response(content, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(zone, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer, updated=True)
        location = request.path + zone.name
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def delete(self, request, *args, **kwargs):
        zone = self.get_object()
        if isinstance(zone, ForwardZone):
            qs = Host.objects.filter(zone=zone)
            if qs.exists():
                content = {'ERROR': f'{zone.name} still in use by {qs.count()} hosts'}
                return Response(content, status=status.HTTP_403_FORBIDDEN)
        with transaction.atomic():
            zone.remove_nameservers()
            zone.delete()
        _update_parent_zone(self.get_queryset(), zone.name)
        location = request.path + zone.name
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


class ForwardZoneDetail(ZoneDetail):

    serializer_class = ForwardZoneSerializer
    queryset = ForwardZone.objects.all()


class ReverseZoneDetail(ZoneDetail):

    serializer_class = ReverseZoneSerializer
    queryset = ReverseZone.objects.all()


class ZoneDelegationDetail(LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):

    lookup_field = 'delegation'
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        parentname = self.kwargs['name']
        self.parentzone = get_object_or_404(self.model, name=parentname)
        return super().get_queryset()

    def get_object(self):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(self.get_queryset(), name=query)
        self.check_object_permissions(self.request, zone)
        return zone

    def get(self, request, *args, **kwargs):
        zone = self.get_object()
        serializer = self.get_serializer(zone)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        if "comment" in request.data and len(request.data) == 1:
            # Also update the parent zone's updated attribute
            self.get_queryset()
            self.parentzone.updated = True
            self.parentzone.save()
            return super().patch(request, *args, **kwargs)
        else:
            content = {'ERROR': 'Only allowed to change comment'}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        zone = self.get_object()
        zone.remove_nameservers()
        zone.delete()
        # Also update the parent zone's updated attribute
        self.parentzone.updated = True
        self.parentzone.save()
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': request.path})


class ForwardZoneDelegationDetail(ZoneDelegationDetail):
    model = ForwardZone
    queryset = ForwardZoneDelegation.objects.all()
    serializer_class = ForwardZoneDelegationSerializer


class ReverseZoneDelegationDetail(ZoneDelegationDetail):
    model = ReverseZone
    queryset = ReverseZoneDelegation.objects.all()
    serializer_class = ReverseZoneDelegationSerializer


class ZoneNameServerDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns a list of nameservers for a given zone.

    patch:
    Set the nameserver list of a zone. Requires all the nameservers of the zone
    and removes the ones not mentioned.
    """

    lookup_field = 'name'
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get(self, request, *args, **kwargs):
        zone = self.get_object()
        return Response([ns.name for ns in zone.nameservers.all()], status=status.HTTP_200_OK)

    def patch(self, request: Request, *args, **kwargs):
        if 'primary_ns' not in request.data:
            return Response({'ERROR': 'No nameserver found in body'}, status=status.HTTP_400_BAD_REQUEST)
        zone = self.get_object()
        nameservers = _get_request_nameservers(request)
        _validate_nameservers(nameservers)
        zone.update_nameservers(nameservers)
        zone.primary_ns = nameservers[0]
        zone.updated = True
        self.perform_update(zone)
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': request.path})


class ForwardZoneNameServerDetail(ZoneNameServerDetail):
    queryset = ForwardZone.objects.all()
    serializer_class = ForwardZoneSerializer


class ReverseZoneNameServerDetail(ZoneNameServerDetail):
    queryset = ReverseZone.objects.all()
    serializer_class = ReverseZoneSerializer


@api_view()
def forward_zone_by_hostname(request, *args, **kwargs):
    """
    Get which zone would match a hostname.

    Note the hostname does not need to exist as a Host.
    """
    hostname = kwargs['hostname'].lower()
    zone = ForwardZone.get_zone_by_hostname(hostname)
    if zone is None:
        raise Http404
    if zone.name != hostname and zone.delegations.exists():
        for delegation in zone.delegations.all():
            if hostname == delegation.name or hostname.endswith(f".{delegation.name}"):
                serializer = ForwardZoneDelegationSerializer(delegation)
                ret = {"delegation": serializer.data}
                return Response(ret, status=status.HTTP_200_OK)
    serializer = ForwardZoneSerializer(zone)
    ret = {"zone": serializer.data}
    return Response(ret, status=status.HTTP_200_OK)


class PlainTextRenderer(renderers.TemplateHTMLRenderer):
    """
    Custom renderer used for outputting plaintext.
    """
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        # Utilize TemplateHTMLRenderer's exception handling
        if isinstance(data, dict):
            return super().render(data, accepted_media_type=None,
                                  renderer_context=renderer_context)
        return data.encode(self.charset)


@api_view()
@renderer_classes([PlainTextRenderer])
def zone_file_detail(request, *args, **kwargs):
    """
    Handles a DNS zone file in plaintext.

    get:
    Generate zonefile for a given zone.
    """

    zonename = kwargs['name']

    if zonename.endswith(".arpa"):
        qs = ReverseZone.objects.all()
    else:
        qs = ForwardZone.objects.all()

    try:
        zone = qs.get(name=zonename)
    except (ForwardZone.DoesNotExist, ReverseZone.DoesNotExist):
        raise Http404

    excludePrivateAddresses: bool = False
    if 'excludePrivate' in request.GET and request.GET['excludePrivate'].lower() in ['true', 'yes', 't', 'y', '1']:
        excludePrivateAddresses = True

    # XXX: a force argument to force serialno update?
    zone.update_serialno()
    zonefile = ZoneFile(zone, excludePrivateAddresses)
    return Response(zonefile.generate())
