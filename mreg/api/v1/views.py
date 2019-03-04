import bisect
import ipaddress


from collections import defaultdict

import django.core.exceptions

from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import (filters, generics, renderers, status)
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view
from rest_framework.exceptions import ParseError, MethodNotAllowed
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_extensions.etag.mixins import ETAGMixin
from url_filter.filtersets import ModelFilterSet

from mreg.api.v1.serializers import (CnameSerializer, HinfoPresetSerializer,
        HostNameSerializer, HostSerializer, HostSaveSerializer,
        IpaddressSerializer, MxSerializer, NameServerSerializer,
        NaptrSerializer, PtrOverrideSerializer, SrvSerializer,
        NetworkSerializer, TxtSerializer, ForwardZoneSerializer,
        ForwardZoneDelegationSerializer, ReverseZoneSerializer,
        ReverseZoneDelegationSerializer, ModelChangeLogSerializer)
from mreg.models import (Cname, ForwardZone, ForwardZoneDelegation, HinfoPreset, Host, Ipaddress,
                         Mx, NameServer, Naptr, Network, PtrOverride, ReverseZone,
                         ReverseZoneDelegation, Srv, Txt, ModelChangeLog)
from mreg.utils import create_serialno

from .zonefile import ZoneFile


# These filtersets are used for applying generic filtering to all objects.
class CnameFilterSet(ModelFilterSet):
    class Meta:
        model = Cname


class HinfoFilterSet(ModelFilterSet):
    class Meta:
        model = HinfoPreset


class HostFilterSet(ModelFilterSet):
    class Meta:
        model = Host


class IpaddressFilterSet(ModelFilterSet):
    class Meta:
        model = Ipaddress


class NaptrFilterSet(ModelFilterSet):
    class Meta:
        model = Naptr


class NameServerFilterSet(ModelFilterSet):
    class Meta:
        model = NameServer


class PtrOverrideFilterSet(ModelFilterSet):
    class Meta:
        model = PtrOverride


class SrvFilterSet(ModelFilterSet):
    class Meta:
        model = Srv


class MxFilterSet(ModelFilterSet):
    class Meta:
        model = Mx


class NetworkFilterSet(ModelFilterSet):
    class Meta:
        model = Network


class TxtFilterSet(ModelFilterSet):
    class Meta:
        model = Txt


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


class MregRetrieveUpdateDestroyAPIView(ETAGMixin,
        generics.RetrieveUpdateDestroyAPIView):
    """
    Applies stricter handling of HTTP requests and responses.
    Apply this mixin to generic classes that don't implement their own CRUD-operations.
    Makes sure patch returns sempty body, 204 - No Content, and location of object.
    """

    def patch(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer_class = self.get_serializer_class()
        obj = get_object_or_404(queryset)
        serializer = serializer_class(obj, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            # Currently all APIs on root path. Must adjust if we move to /api/resource
            # or /api/v1/resource etc.
            resource = request.path.split("/")[1]
            location = '/%s/%s' % (resource, getattr(obj, self.lookup_field))
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


class CnameList(generics.ListCreateAPIView):
    """
    get:
    Lists all cnames / aliases.

    post:
    Creates a new cname.
    """
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer
    lookup_field = 'name'

    def get_queryset(self):
        qs = super().get_queryset()
        return CnameFilterSet(data=self.request.GET, queryset=qs).filter()


class CnameDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified cname.

    patch:
    Update parts of the cname.

    delete:
    Delete the specified cname.
    """
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer
    lookup_field = 'name'


class HinfoPresetList(generics.ListCreateAPIView):
    """
    get:
    Lists all hinfo presets.

    post:
    Creates a new hinfo preset.
    """
    queryset = HinfoPreset.objects.all()
    serializer_class = HinfoPresetSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return HinfoFilterSet(data=self.request.GET, queryset=qs).filter()


class HinfoPresetDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for a hinfo preset.

    patch:
    Update parts of a hinfo preset.

    delete:
    Delete a hinfo preset.
    """
    queryset = HinfoPreset.objects.all()
    serializer_class = HinfoPresetSerializer


class HostList(generics.ListCreateAPIView):
    """
    get:
    Lists all hostnames.

    post:
    Create a new host object. Allows posting with IP address in data.
    """
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return HostFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.queryset.filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        hostdata = request.data.copy()

        if 'ipaddress' in hostdata:
            ipkey = hostdata['ipaddress']
            del hostdata['ipaddress']
            host = Host()
            hostserializer = HostSerializer(host, data=hostdata)

            if hostserializer.is_valid(raise_exception=True):
                with transaction.atomic():
                    hostserializer.save()
                    ipdata = {'host': host.pk, 'ipaddress': ipkey}
                    ip = Ipaddress()
                    ipserializer = IpaddressSerializer(ip, data=ipdata)
                    if ipserializer.is_valid(raise_exception=True):
                        ipserializer.save()
                        location = '/hosts/%s' % host.name
                        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})
        else:
            host = Host()
            hostserializer = HostSerializer(host, data=hostdata)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified host. Includes relations like IP address/a-records, ptr-records, cnames.

    patch:
    Update parts of the host.

    delete:
    Delete the specified host.
    """
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def get_object(self, queryset=queryset):
        return get_object_or_404(Host, name=self.kwargs['pk'])

    def patch(self, request, *args, **kwargs):
        query = self.kwargs['pk']

        if "name" in request.data:
            if self.queryset.filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        host = get_object_or_404(Host, name=query)
        serializer = HostSaveSerializer(host, data=request.data, partial=True)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            location = '/hosts/%s' % host.name
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


@api_view(['GET'])
def host_newest(request, *args, **kwargs):
    newest = Host.objects.order_by('-updated_at').first()
    return Response(HostSerializer(newest).data)


class IpaddressList(generics.ListCreateAPIView):
    """
    get:
    Lists all ipaddresses in use.

    post:
    Creates a new ipaddress object. Requires an existing host.
    """
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ('host', 'ipaddress', 'macaddress')

    def get_queryset(self):
        qs = super().get_queryset()
        return IpaddressFilterSet(data=self.request.GET, queryset=qs).filter()


class IpaddressDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified Ipaddress object by {id}.

    patch:
    Update parts of the ipaddress.

    delete:
    Delete the specified ipaddress.
    """
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer


@api_view(['GET'])
def ipaddress_newest(request, *args, **kwargs):
    newest = Ipaddress.objects.order_by('-updated_at').first()
    return Response(IpaddressSerializer(newest).data)


class MxList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all MX-records.

    post:
    Create a new MX-record.
    """

    queryset = Mx.objects.all()
    serializer_class = MxSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return MxFilterSet(data=self.request.GET, queryset=qs).filter()


class MxDetail(MregRetrieveUpdateDestroyAPIView):
    """
     get:
     List details for a MX-record.

     patch:
     Update parts of a MX-record.

     delete:
     Deletes a MX-record.
     """
    queryset = Mx.objects.all()
    serializer_class = MxSerializer


class NaptrList(generics.ListCreateAPIView):
    """
    get:
    List all Naptr-records.

    post:
    Create a new Naptr-record.
    """
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return NaptrFilterSet(data=self.request.GET, queryset=qs).filter()


class NaptrDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified Naptr-record.

    patch:
    Update parts of the specified Naptr-record.

    delete:
    Delete the specified Naptr-record.
    """
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer


class NameServerList(generics.ListCreateAPIView):
    """
    get:
    List all nameserver-records.

    post:
    Create a new nameserver-record.
    """
    queryset = NameServer.objects.all()
    serializer_class = NameServerSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return NameServerFilterSet(data=self.request.GET, queryset=qs).filter()


class NameServerDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified nameserver-record.

    patch:
    Update parts of the specified nameserver-record.

    delete:
    Delete the specified nameserver-record.
    """
    queryset = NameServer.objects.all()
    serializer_class = NameServerSerializer


class PtrOverrideList(generics.ListCreateAPIView):
    """
    get:
    List all ptr-overrides.

    post:
    Create a new ptr-override.
    """
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return PtrOverrideFilterSet(data=self.request.GET, queryset=qs).filter()


class PtrOverrideDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified ptr-override.

    patch:
    Update parts of the specified ptr-override.

    delete:
    Delete the specified ptr-override.
    """
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer


class SrvList(generics.ListCreateAPIView):
    """
    get:
    List all service records.

    post:
    Create a new service record.
    """
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return SrvFilterSet(data=self.request.GET, queryset=qs).filter()


class SrvDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified srvice record.

    patch:
    Update parts of the specified service record.

    delete:
    Delete the specified service record.
    """
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer


def _get_iprange(kwargs):
    """
    Helper function to get the range from the params dict.
    :param kwargs: kwargs
    :return: The iprange as a string, or raises an error
    """
    try:
        ip = kwargs['ip']
        mask = kwargs['range']
        iprange = '%s/%s' % (ip, mask)
        ipaddress.ip_network(iprange)
        return iprange
    except ValueError as error:
        raise ParseError(detail=str(error))

def _overlap_check(range, exclude=None):
    try:
        network = ipaddress.ip_network(range)
    except ValueError as error:
        raise ParseError(detail=str(error))

    overlap = Network.overlap_check(network)
    if exclude:
        overlap = overlap.exclude(id=exclude.id)
    if overlap:
        info = ", ".join(map(str,overlap))
        return Response({'ERROR': 'Network overlaps with: {}'.format(info)},
                        status=status.HTTP_409_CONFLICT)

class NetworkList(generics.ListAPIView):
    """
    list:
    Returns a list of networks

    post:
    Create a new network. The new network can't overlap with any existing networks.
    """
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer

    def post(self, request, *args, **kwargs):
        error = _overlap_check(request.data['range'])
        if error:
            return error
        ip_network = ipaddress.ip_network(request.data['range'])
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        network = serializer.create()
        # Changed the default value of reserved if the size of the network is too low
        if ip_network.num_addresses <= 4:
            network.reserved = min(2, ip_network.num_addresses)
        network.save()
        location = '/networks/%s' % request.data
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


    def get_queryset(self):
        """
        Applies filtering to the queryset
        :return: filtered list of networks
        """
        qs = super().get_queryset()
        return NetworkFilterSet(data=self.request.GET, queryset=qs).filter()

def _get_network(kwargs):
    iprange = _get_iprange(kwargs)
    return get_object_or_404(Network, range=iprange)


class NetworkDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    List details for a network.

    patch:
    Partially update a network. Updating a zone's range is not allowed

    delete:
    Deletes a network unless it has IP addresses that are still in use
    """
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer

    lookup_field = 'range'

    def get(self, request, queryset=queryset, *args, **kwargs):
        network = _get_network(kwargs)
        serializer = self.get_serializer(network)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        network = _get_network(kwargs)
        if 'range' in request.data:
            error = _overlap_check(request.data['range'], exclude=network)
            if error:
                return error
        serializer = self.get_serializer(network, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        location = '/networks/%s' % network.range
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def delete(self, request, *args, **kwargs):
        network = _get_network(kwargs)
        used_ipaddresses = network.get_used_ipaddresses()
        if used_ipaddresses:
            return Response({'ERROR': 'Network contains IP addresses that are in use'}, status=status.HTTP_409_CONFLICT)

        network.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view()
def network_by_ip(request, *args, **kwargs):
    try:
        ip = ipaddress.ip_address(kwargs['ip'])
    except ValueError as error:
        raise ParseError(detail=str(error))
    network = Network.get_network_by_ip(str(ip))
    if network:
        serializer = NetworkSerializer(network)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        raise Http404


@api_view()
def network_first_unused(request, *args, **kwargs):
    network = _get_network(kwargs)
    ip = network.get_first_unused()
    if ip:
        return Response(ip, status=status.HTTP_200_OK)
    else:
        content = {'ERROR': 'No available IPs'}
        return Response(content, status=status.HTTP_404_NOT_FOUND)

def _network_ptroverride_list(kwargs):
    network = _get_network(kwargs)
    from_ip = str(network.network.network_address)
    to_ip = str(network.network.broadcast_address)
    return PtrOverride.objects.filter(ipaddress__range=(from_ip, to_ip))


@api_view()
def network_ptroverride_list(request, *args, **kwargs):
    ptrs = _network_ptroverride_list(kwargs)
    ptr_list = [ i.ipaddress for i in ptrs ]
    return Response(ptr_list, status=status.HTTP_200_OK)


@api_view()
def network_ptroverride_host_list(request, *args, **kwargs):
    ptrs = _network_ptroverride_list(kwargs)
    ret = dict()
    info =  ptrs.values_list('host__name', 'ipaddress')
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        ret[ip] = host
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_reserved_list(request, *args, **kwargs):
    network = _get_network(kwargs)
    reserved = list(map(str, sorted(network.get_reserved_ipaddresses())))
    return Response(reserved, status=status.HTTP_200_OK)


@api_view()
def network_used_count(request, *args, **kwargs):
    network = _get_network(kwargs)
    return Response(network.get_used_ipaddress_count(), status=status.HTTP_200_OK)


@api_view()
def network_used_list(request, *args, **kwargs):
    network = _get_network(kwargs)
    used_ipaddresses = list(map(str, sorted(network.get_used_ipaddresses())))
    return Response(used_ipaddresses, status=status.HTTP_200_OK)


@api_view()
def network_used_host_list(request, *args, **kwargs):
    network = _get_network(kwargs)
    ret = defaultdict(list)
    info =  network._get_used_ipaddresses().values_list('host__name', 'ipaddress')
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        bisect.insort(ret[ip], host)
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_unused_count(request, *args, **kwargs):
    network = _get_network(kwargs)
    unused_ipaddresses = network.get_unused_ipaddresses()
    return Response(len(unused_ipaddresses), status=status.HTTP_200_OK)


@api_view()
def network_unused_list(request, *args, **kwargs):
    network = _get_network(kwargs)
    unused_ipaddresses = list(map(str, sorted(network.get_unused_ipaddresses())))
    return Response(unused_ipaddresses, status=status.HTTP_200_OK)


class TxtList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all txt-records.

    post:
    Create a new txt-record.
    """

    queryset = Txt.objects.all()
    serializer_class = TxtSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return TxtFilterSet(data=self.request.GET, queryset=qs).filter()


class TxtDetail(MregRetrieveUpdateDestroyAPIView):
    """
     get:
     List details for a txt-record.

     patch:
     Update parts of a txt-record.

     delete:
     Deletes a txt-record.
     """
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


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


class ZoneList(generics.ListCreateAPIView):
    """
    get:
    Returns a list of all zones.

    post:
    Create a zone. The primary_ns field is a list where the first element will be the primary nameserver.

    """

    lookup_field = 'name'
    serializer_class = ForwardZoneSerializer

    def _get_forward(self):
        self.queryset = ForwardZone.objects.all()
        qs = super(ZoneList, self).get_queryset()
        return ForwardZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    def _get_reverse(self):
        self.queryset = ReverseZone.objects.all()
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
        zone.save()
        zone.update_nameservers(nameservers)
        _update_parent_zone(qs, zone.name)
        location = f"/zones/{zone.name}"
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

    def get_queryset(self):
        """
        #Applies filtering to the queryset
        #:return: filtered list of zones delegation for the parent zone
        """

        zonename = self.kwargs[self.lookup_field]
        if zonename.endswith(".arpa"):
            self.parentzone = get_object_or_404(ReverseZone, name=zonename)
            self.queryset = self.parentzone.delegations.all()
            self.serializer_class = ReverseZoneDelegationSerializer
            qs = super().get_queryset()
            return ReverseZoneFilterSet(data=self.request.query_params, queryset=qs).filter()
        else:
            self.parentzone = get_object_or_404(ForwardZone, name=zonename)
            self.queryset = self.parentzone.delegations.all()
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
        delegation.save()
        delegation.update_nameservers(nameservers)
        self.parentzone.updated = True
        self.parentzone.save()
        location = f"/zones/{self.parentzone.name}/delegations/{delegation.name}"
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


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

        zone = get_object_or_404(self.get_queryset(), name=query)
        # Check if primary_ns is in the zone's list of nameservers
        if "primary_ns" in request.data:
            if request.data['primary_ns'] not in [nameserver.name for nameserver in zone.nameservers.all()]:
                content = {'ERROR': "%s is not one of %s's nameservers" % (request.data['primary_ns'], query)}
                return Response(content, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(zone, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(updated=True)
        location = f"/zones/{zone.name}"
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def delete(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        qs = self.get_queryset()
        zone = get_object_or_404(qs, name=query)
        zone.remove_nameservers()
        zone.delete()
        _update_parent_zone(qs, zone.name)
        location = f"/zones/{zone.name}"
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


class ZoneDelegationDetail(MregRetrieveUpdateDestroyAPIView):

    lookup_field = 'delegation'
    serializer_class = ForwardZoneDelegationSerializer

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

    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(self.get_queryset(), name=query)
        serializer = self.get_serializer(zone)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        raise MethodNotAllowed()

    def delete(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(self.get_queryset(), name=query)
        zone.remove_nameservers()
        zone.delete()
        # Also update the parent zone's updated attribute
        self.parentzone.updated = True
        self.parentzone.save()
        location = f"/zones/{zone.zone.name}/delegations/{zone.name}"
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


class ZoneNameServerDetail(ETAGMixin, generics.GenericAPIView):
    """
    get:
    Returns a list of nameservers for a given zone.

    patch:
    Set the nameserver list of a zone. Requires all the nameservers of the zone
    and removes the ones not mentioned.
    """

    lookup_field = 'name'
    serializer_class = ForwardZoneSerializer

    def get_queryset(self):
        zonename = self.kwargs[self.lookup_field]

        if zonename.endswith(".arpa"):
            self.queryset = ReverseZone.objects.all()
            self.serializer_class = ReverseZoneSerializer
        else:
            self.queryset = ForwardZone.objects.all()
        return super().get_queryset()

    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(self.get_queryset(), name=query)
        return Response([ns.name for ns in zone.nameservers.all()], status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(self.get_queryset(), name=query)
        if 'primary_ns' not in request.data:
            return Response({'ERROR': 'No nameserver found in body'}, status=status.HTTP_400_BAD_REQUEST)

        nameservers = request.data.getlist('primary_ns')
        _validate_nameservers(nameservers)
        zone.update_nameservers(nameservers)
        zone.primary_ns = request.data.getlist('primary_ns')[0]
        zone.updated = True
        zone.save()
        location = f"/zones/{query}/nameservers"
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


class ModelChangeLogList(generics.ListAPIView):
    """
    get:
    Lists the models/tables with registered entries. To access the history of an object, GET /{tablename}/{object-id}

    post:
    Not used. Saving objects to history is handled by signals internally.
    """
    queryset = ModelChangeLog.objects.all()
    serializer_class = ModelChangeLogSerializer

    def get(self, request, *args, **kwargs):
        # Return a list of available tables there are logged histories for.
        tables = list(set([value['table_name'] for value in self.queryset.values('table_name')]))
        return Response(data=tables, status=status.HTTP_200_OK)


class ModelChangeLogDetail(generics.RetrieveAPIView):
    """
    get:
    Retrieve all log entries for an object in a table.

    patch:
    Not implemented. Changing a log entry doesn't really make sense, and log entries are handles internally.
    """
    queryset = ModelChangeLog.objects.all()
    serializer_class = ModelChangeLogSerializer

    def get(self, request, *args, **kwargs):
        query_table = self.kwargs['table']
        query_row = self.kwargs['pk']
        try:
            logs_by_date = [vals for vals in self.queryset.filter(table_name=query_table,
                                                                  table_row=query_row).order_by('timestamp').values()]

            return Response(logs_by_date, status=status.HTTP_200_OK)
        except ModelChangeLog.DoesNotExist:
            raise Http404


def _get_ips_by_range(iprange):
    network = ipaddress.ip_network(iprange)
    from_ip = str(network.network_address)
    to_ip = str(network.broadcast_address)
    return Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip))


def _dhcphosts_by_range(iprange):
    ips = _get_ips_by_range(iprange)
    ips = ips.exclude(macaddress='').order_by('ipaddress')
    ips = ips.values('host__name', 'ipaddress', 'macaddress')
    return Response(ips)

class DhcpHostsAllV4(generics.GenericAPIView):

    def get(self, request, *args, **kwargs):
        return _dhcphosts_by_range('0.0.0.0/0')


class DhcpHostsAllV6(generics.GenericAPIView):

    def get(self, request, *args, **kwargs):
        return _dhcphosts_by_range('::/0')


class DhcpHostsByRange(generics.GenericAPIView):

    def get(self, request, *args, **kwargs):
        return _dhcphosts_by_range(_get_iprange(kwargs))


def _dhcpv6_hosts_by_ipv4(iprange):
    """
    Find all hosts which have both an ipv4 and ipv6 address,
    and where the ipv4 address has a mac assosicated.
    Future fun: limit to hosts which have only one ipv4 and ipv6 address?
    """
    ipv4 = _get_ips_by_range(iprange)
    ipv4 = ipv4.exclude(macaddress='')
    ipv4 = ipv4.select_related('host')
    ipv4_host_ids = [ip.host.id for ip in ipv4]
    ipv4_host2mac = dict([(hostname, mac) for hostname, mac in
                          ipv4.values_list('host__name', 'macaddress')])
    ipv6 = _get_ips_by_range('::/0')
    ipv6 = ipv6.filter(macaddress='')
    ipv6 = ipv6.filter(host__in=ipv4_host_ids).order_by('ipaddress')
    ret = []
    for hostname, ip in ipv6.values_list('host__name', 'ipaddress'):
        ret.append({'host__name': hostname, 'ipaddress': ip,
                    'macaddress': ipv4_host2mac[hostname]})
    return Response(ret)


class DhcpHostsV4ByV6(APIView):

    renderer_classes = (JSONRenderer, )

    def get(self, request, *args, **kwargs):
        if 'ip' in kwargs:
            iprange = _get_iprange(kwargs)
        else:
            iprange = '0.0.0.0/0'
        return _dhcpv6_hosts_by_ipv4(iprange)


class PlainTextRenderer(renderers.BaseRenderer):
    """
    Custom renderer used for outputting plaintext.
    """
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        return data.encode(self.charset)


class ZoneFileDetail(generics.GenericAPIView):
    """
    Handles a DNS zone file in plaintext.
    All models should have a zf_string method that outputs its relevant data.

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
        zone = get_object_or_404(self.get_queryset(), name=self.kwargs[self.lookup_field])
        # XXX: a force argument to force serialno update?
        zone.update_serialno()
        zonefile = ZoneFile(zone)
        return Response(zonefile.generate())
