import django.core.exceptions

from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404

from rest_framework import (generics, renderers, status)
from rest_framework.decorators import api_view
from rest_framework.exceptions import MethodNotAllowed, ParseError
from rest_framework.response import Response

from url_filter.filtersets import ModelFilterSet

from mreg.models import (ForwardZone, ForwardZoneDelegation,
                         Host, NameServer,
                         ReverseZone, ReverseZoneDelegation)
from mreg.api.permissions import (IsSuperGroupMember, IsAuthenticatedAndReadOnly)

from .serializers import (ForwardZoneDelegationSerializer, ForwardZoneSerializer,
                          ReverseZoneDelegationSerializer, ReverseZoneSerializer)
from .views import (MregRetrieveUpdateDestroyAPIView, )
from .zonefile import ZoneFile


class ForwardZoneFilterSet(ModelFilterSet):
    class Meta:
        model = ForwardZone


class ForwardZoneDelegationFilterSet(ModelFilterSet):
    class Meta:
        model = ForwardZoneDelegation


class ReverseZoneFilterSet(ModelFilterSet):
    class Meta:
        model = ReverseZone


class ReverseZoneDelegationFilterSet(ModelFilterSet):
    class Meta:
        model = ReverseZoneDelegation


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


class ZoneList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all zones.

    post:
    Create a zone. The primary_ns field is a list where the first element will be the primary nameserver.

    """

    lookup_field = 'name'
    serializer_class = ForwardZoneSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def _get_forward(self):
        self.queryset = ForwardZone.objects.all().order_by('id')
        qs = super(ZoneList, self).get_queryset()
        return ForwardZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    def _get_reverse(self):
        self.queryset = ReverseZone.objects.all().order_by('id')
        qs = super(ZoneList, self).get_queryset()
        self.serializer_class = ReverseZoneSerializer
        return ReverseZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    def get_queryset(self, name=None):
        """
        #Applies filtering to the queryset
        #:return: filtered list of zones
        """

        if name:
            if name.endswith(".arpa"):
                return self._get_reverse()
            else:
                return self._get_forward()

    def list(self, request):
        # TODO: non paginated response.
        ret = []
        for qs in (self._get_forward(), self._get_reverse()):
            serializer = self.serializer_class(qs, many=True)
            ret.extend(serializer.data)
        return Response(ret)

    def post(self, request, *args, **kwargs):
        qs = self.get_queryset(name=request.data[self.lookup_field])
        if qs.filter(name=request.data["name"]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)
        # A copy is required since the original is immutable
        nameservers = request.data.getlist('primary_ns')
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


class ZoneDelegationList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all the zone's delegations.

    post:
    Create a delegation for the zone.
    """

    lookup_field = 'name'
    serializer_class = ForwardZoneDelegationSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        """
        #Applies filtering to the queryset
        #:return: filtered list of zones delegation for the parent zone
        """

        zonename = self.kwargs[self.lookup_field]
        if zonename.endswith(".arpa"):
            self.parentzone = get_object_or_404(ReverseZone, name=zonename)
            self.queryset = self.parentzone.delegations.all().order_by('id')
            self.serializer_class = ReverseZoneDelegationSerializer
            qs = super().get_queryset()
            return ReverseZoneFilterSet(data=self.request.query_params, queryset=qs).filter()
        else:
            self.parentzone = get_object_or_404(ForwardZone, name=zonename)
            self.queryset = self.parentzone.delegations.all().order_by('id')
            qs = super().get_queryset()
            return ForwardZoneFilterSet(data=self.request.query_params, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        qs = self.get_queryset()
        if qs.filter(name=request.data[self.lookup_field]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)

        nameservers = request.data.getlist('nameservers')
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


@api_view()
def zone_by_hostname(request, *args, **kwargs):
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


class ZoneDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    List details for a zone.

    patch:
    Update parts of a zone.
    Nameservers need to be patched through /zones/<name>/nameservers. primary_ns needs to be a nameserver of the zone

    delete:
    Delete a zone.
    """

    lookup_field = 'name'
    serializer_class = ForwardZoneSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        zonename = self.kwargs[self.lookup_field]

        if zonename.endswith(".arpa"):
            self.queryset = ReverseZone.objects.all()
            self.serializer_class = ReverseZoneSerializer
        else:
            self.queryset = ForwardZone.objects.all()
        return super().get_queryset()

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


class ZoneDelegationDetail(MregRetrieveUpdateDestroyAPIView):

    lookup_field = 'delegation'
    serializer_class = ForwardZoneDelegationSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        zonename = self.kwargs[self.lookup_field]
        parentname = self.kwargs['name']

        if zonename.endswith(".arpa"):
            self.parentzone = get_object_or_404(ReverseZone, name=parentname)
            self.queryset = ReverseZoneDelegation.objects.all()
            self.serializer_class = ReverseZoneDelegationSerializer
        else:
            self.parentzone = get_object_or_404(ForwardZone, name=parentname)
            self.queryset = ForwardZoneDelegation.objects.all()
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
        raise MethodNotAllowed(request.method)

    def delete(self, request, *args, **kwargs):
        zone = self.get_object()
        zone.remove_nameservers()
        zone.delete()
        # Also update the parent zone's updated attribute
        self.parentzone.updated = True
        self.parentzone.save()
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': request.path})


class ZoneNameServerDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns a list of nameservers for a given zone.

    patch:
    Set the nameserver list of a zone. Requires all the nameservers of the zone
    and removes the ones not mentioned.
    """

    lookup_field = 'name'
    serializer_class = ForwardZoneSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )

    def get_queryset(self):
        zonename = self.kwargs[self.lookup_field]

        if zonename.endswith(".arpa"):
            self.queryset = ReverseZone.objects.all()
            self.serializer_class = ReverseZoneSerializer
        else:
            self.queryset = ForwardZone.objects.all()
        return super().get_queryset()

    def get(self, request, *args, **kwargs):
        zone = self.get_object()
        return Response([ns.name for ns in zone.nameservers.all()], status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        if 'primary_ns' not in request.data:
            return Response({'ERROR': 'No nameserver found in body'}, status=status.HTTP_400_BAD_REQUEST)
        zone = self.get_object()
        nameservers = request.data.getlist('primary_ns')
        _validate_nameservers(nameservers)
        zone.update_nameservers(nameservers)
        zone.primary_ns = request.data.getlist('primary_ns')[0]
        zone.updated = True
        self.perform_update(zone)
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': request.path})


class PlainTextRenderer(renderers.TemplateHTMLRenderer):
    """
    Custom renderer used for outputting plaintext.
    """
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        # Utilize TemplateHTMLRenderer's exception handling
        if type(data) is dict:
            return super().render(data, accepted_media_type=None,
                                  renderer_context=renderer_context)
        return data.encode(self.charset)


class ZoneFileDetail(generics.GenericAPIView):
    """
    Handles a DNS zone file in plaintext.

    get:
    Generate zonefile for a given zone.
    """

    renderer_classes = (PlainTextRenderer, )
    lookup_field = 'name'

    def get_queryset(self):
        zonename = self.kwargs[self.lookup_field]

        if zonename.endswith(".arpa"):
            self.queryset = ReverseZone.objects.all()
        else:
            self.queryset = ForwardZone.objects.all()
        return super().get_queryset()

    def get(self, request, *args, **kwargs):
        zone = self.get_object()
        # XXX: a force argument to force serialno update?
        zone.update_serialno()
        zonefile = ZoneFile(zone)
        return Response(zonefile.generate())
