import bisect
import ipaddress
from collections import defaultdict

from django.db import transaction
from django.shortcuts import get_object_or_404

from rest_framework import (filters, generics, status)
from rest_framework.decorators import api_view
from rest_framework.exceptions import MethodNotAllowed, ParseError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_extensions.etag.mixins import ETAGMixin

from url_filter.filtersets import ModelFilterSet


import mreg.models
from mreg.api.permissions import (IsAuthenticatedAndReadOnly,
                                  IsGrantedNetGroupRegexPermission,
                                  IsSuperGroupMember,
                                  IsSuperOrAdminOrReadOnly,
                                  IsSuperOrGroupAdminOrReadOnly,
                                  IsSuperOrNetworkAdminMember,)
from mreg.models import (Cname, Hinfo, Host, HostGroup, Ipaddress, Loc,
                         ModelChangeLog, Mx, NameServer, Naptr, Network,
                         PtrOverride, Srv, Sshfp, Txt)

from .serializers import (CnameSerializer, HinfoSerializer,
                          HostSerializer, IpaddressSerializer,
                          LocSerializer,
                          ModelChangeLogSerializer, MxSerializer,
                          NameServerSerializer, NaptrSerializer,
                          NetGroupRegexPermissionSerializer, NetworkSerializer,
                          PtrOverrideSerializer, SrvSerializer,
                          SshfpSerializer, TxtSerializer)


# These filtersets are used for applying generic filtering to all objects.
class CnameFilterSet(ModelFilterSet):
    class Meta:
        model = Cname


class HinfoFilterSet(ModelFilterSet):
    class Meta:
        model = Hinfo


class HostFilterSet(ModelFilterSet):
    class Meta:
        model = Host


class HostGroupFilterSet(ModelFilterSet):
    class Meta:
        model = HostGroup


class IpaddressFilterSet(ModelFilterSet):
    class Meta:
        model = Ipaddress

class LocFilterSet(ModelFilterSet):
    class Meta:
        model = Loc

class NaptrFilterSet(ModelFilterSet):
    class Meta:
        model = Naptr


class NameServerFilterSet(ModelFilterSet):
    class Meta:
        model = NameServer


class PtrOverrideFilterSet(ModelFilterSet):
    class Meta:
        model = PtrOverride


class SshfpFilterSet(ModelFilterSet):
    class Meta:
        model = Sshfp


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


class NetGroupRegexPermissionFilterSet(ModelFilterSet):
    class Meta:
        model = mreg.models.NetGroupRegexPermission


class MregMixin:

    filter_backends = (filters.SearchFilter, filters.OrderingFilter,)
    ordering_fields = '__all__'


class MregRetrieveUpdateDestroyAPIView(ETAGMixin,
                                       generics.RetrieveUpdateDestroyAPIView):
    """
    Makes sure patch returns sempty body, 204 - No Content, and location of object.
    """

    def perform_update(self, serializer, **kwargs):
        serializer.save(**kwargs)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        if self.lookup_field in serializer.validated_data:
            # Remove the value of self.lookup_field from end of path
            location = request.path[:-len(kwargs[self.lookup_field])]
            # and replace with updated one
            location += str(serializer.validated_data[self.lookup_field])
        else:
            location = request.path
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def put(self, request, *args, **kwargs):
        raise MethodNotAllowed()


class MregListCreateAPIView(MregMixin, generics.ListCreateAPIView):

    def post(self, request, *args, **kwargs):
        # Add a location header for all POSTs
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        location = request.path + str(serializer.validated_data[self.lookup_field])
        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class MregPermissionsUpdateDestroy:

    def perform_destroy(self, instance):
        # Custom check destroy permissions
        self.check_destroy_permissions(self.request, instance)
        instance.delete()

    def perform_update(self, serializer, **kwargs):
        # Custom check update permissions
        self.check_update_permissions(self.request, serializer)
        serializer.save(**kwargs)

    def check_destroy_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_destroy_permission(request,
                                                     self,
                                                     validated_serializer):
                self.permission_denied(request)

    def check_update_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_update_permission(request,
                                                    self,
                                                    validated_serializer):
                self.permission_denied(request)


class MregPermissionsListCreateAPIView(MregMixin, generics.ListCreateAPIView):

    def perform_create(self, serializer):
        # Custom check create permissions
        self.check_create_permissions(self.request, serializer)
        serializer.save()

    def check_create_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_create_permission(request,
                                                    self,
                                                    validated_serializer):
                self.permission_denied(request)


class HostPermissionsUpdateDestroy(MregPermissionsUpdateDestroy):

    # permission_classes = settings.MREG_PERMISSION_CLASSES
    permission_classes = (IsGrantedNetGroupRegexPermission, )


class HostPermissionsListCreateAPIView(MregPermissionsListCreateAPIView):

    # permission_classes = settings.MREG_PERMISSION_CLASSES
    permission_classes = (IsGrantedNetGroupRegexPermission, )


class CnameList(HostPermissionsListCreateAPIView):
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


class CnameDetail(HostPermissionsUpdateDestroy,
                  MregRetrieveUpdateDestroyAPIView):
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


class HinfoList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all hinfos.

    post:
    Creates a new hinfo.
    """
    queryset = Hinfo.objects.all().order_by('host')
    serializer_class = HinfoSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return HinfoFilterSet(data=self.request.GET, queryset=qs).filter()


class HinfoDetail(HostPermissionsUpdateDestroy,
                  MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for a hinfo.

    patch:
    Update parts of a hinfo.

    delete:
    Delete a hinfo.
    """
    queryset = Hinfo.objects.all()
    serializer_class = HinfoSerializer


class HostList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all hostnames.

    post:
    Create a new host object. Allows posting with IP address in data.
    """
    queryset = Host.objects.get_queryset().order_by('id')
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
                        self.perform_create(ipserializer)
                        location = request.path + host.name
                        return Response(status=status.HTTP_201_CREATED, headers={'Location': location})
        else:
            host = Host()
            hostserializer = HostSerializer(host, data=hostdata)
            if hostserializer.is_valid(raise_exception=True):
                self.perform_create(hostserializer)
                location = request.path + host.name
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostDetail(HostPermissionsUpdateDestroy,
                 MregRetrieveUpdateDestroyAPIView):
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
    lookup_field = 'name'

    def patch(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        return super().patch(request, *args, **kwargs)


class IpaddressList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all ipaddresses in use.

    post:
    Creates a new ipaddress object. Requires an existing host.
    """
    queryset = Ipaddress.objects.get_queryset().order_by('id')
    serializer_class = IpaddressSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return IpaddressFilterSet(data=self.request.GET, queryset=qs).filter()


class IpaddressDetail(HostPermissionsUpdateDestroy,
                      MregRetrieveUpdateDestroyAPIView):
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


class LocList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all LOCs.

    post:
    Creates a new LOC.
    """
    queryset = Loc.objects.all().order_by('host')
    serializer_class = LocSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return LocFilterSet(data=self.request.GET, queryset=qs).filter()


class LocDetail(HostPermissionsUpdateDestroy,
                MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for a LOC.

    patch:
    Update parts of a LOC.

    delete:
    Delete a LOC.
    """
    queryset = Loc.objects.all()
    serializer_class = LocSerializer


class MxList(HostPermissionsListCreateAPIView):
    """
    get:
    Returns a list of all MX-records.

    post:
    Create a new MX-record.
    """

    queryset = Mx.objects.get_queryset().order_by('id')
    serializer_class = MxSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return MxFilterSet(data=self.request.GET, queryset=qs).filter()


class MxDetail(HostPermissionsUpdateDestroy,
               MregRetrieveUpdateDestroyAPIView):
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


class NaptrList(HostPermissionsListCreateAPIView):
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


class NaptrDetail(HostPermissionsUpdateDestroy,
                  MregRetrieveUpdateDestroyAPIView):
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


class NameServerList(HostPermissionsListCreateAPIView):
    """
    get:
    List all nameserver-records.

    post:
    Create a new nameserver-record.
    """

    queryset = NameServer.objects.all()
    serializer_class = NameServerSerializer
    lookup_field = 'name'

    def get_queryset(self):
        qs = super().get_queryset()
        return NameServerFilterSet(data=self.request.GET, queryset=qs).filter()


class NameServerDetail(HostPermissionsUpdateDestroy,
                       MregRetrieveUpdateDestroyAPIView):
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
    lookup_field = 'name'


class PtrOverrideList(HostPermissionsListCreateAPIView):
    """
    get:
    List all ptr-overrides.

    post:
    Create a new ptr-override.
    """
    queryset = PtrOverride.objects.get_queryset().order_by('id')
    serializer_class = PtrOverrideSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return PtrOverrideFilterSet(data=self.request.GET, queryset=qs).filter()


class PtrOverrideDetail(HostPermissionsUpdateDestroy,
                        MregRetrieveUpdateDestroyAPIView):
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


class SshfpList(HostPermissionsListCreateAPIView):
    """
    get:
    List all sshfp records.

    post:
    Create a new sshfp record.
    """
    queryset = Sshfp.objects.get_queryset().order_by('id')
    serializer_class = SshfpSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return SshfpFilterSet(data=self.request.GET, queryset=qs).filter()


class SshfpDetail(HostPermissionsUpdateDestroy,
                  MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified sshfp.

    patch:
    Update parts of the specified sshfp.

    delete:
    Delete the specified sshfp.
    """
    queryset = Sshfp.objects.all()
    serializer_class = SshfpSerializer


class SrvList(HostPermissionsListCreateAPIView):
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


class SrvDetail(HostPermissionsUpdateDestroy,
                MregRetrieveUpdateDestroyAPIView):
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


def _overlap_check(range, exclude=None):
    try:
        network = ipaddress.ip_network(range)
    except ValueError as error:
        raise ParseError(detail=str(error))

    overlap = Network.objects.filter(network__net_overlaps=network)
    if exclude:
        overlap = overlap.exclude(id=exclude.id)
    if overlap:
        info = ", ".join(map(str, overlap))
        return Response({'ERROR': 'Network overlaps with: {}'.format(info)},
                        status=status.HTTP_409_CONFLICT)


class NetworkList(MregListCreateAPIView):
    """
    list:
    Returns a list of networks

    post:
    Create a new network. The new network can't overlap with any existing networks.
    """
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly, )
    lookup_field = 'network'

    def get_queryset(self):
        """
        Applies filtering to the queryset
        :return: filtered list of networks
        """
        qs = super().get_queryset()
        return NetworkFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        error = _overlap_check(request.data['network'])
        if error:
            return error
        return super().post(request, *args, **kwargs)


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
    permission_classes = (IsSuperOrNetworkAdminMember | IsAuthenticatedAndReadOnly, )

    lookup_field = 'network'

    def patch(self, request, *args, **kwargs):
        network = self.get_object()
        if 'network' in request.data:
            error = _overlap_check(request.data['network'], exclude=network)
            if error:
                return error
        return super().patch(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        network = self.get_object()
        used_ipaddresses = network.get_used_ipaddresses()
        if used_ipaddresses:
            return Response({'ERROR': 'Network contains IP addresses that are in use'},
                            status=status.HTTP_409_CONFLICT)

        self.perform_destroy(network)
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view()
def network_by_ip(request, *args, **kwargs):
    try:
        ip = ipaddress.ip_address(kwargs['ip'])
    except ValueError as error:
        raise ParseError(detail=str(error))
    network = get_object_or_404(Network, network__net_contains_or_equals=ip)
    serializer = NetworkSerializer(network)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view()
def network_first_unused(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    ip = network.get_first_unused()
    if ip:
        return Response(ip, status=status.HTTP_200_OK)
    else:
        content = {'ERROR': 'No available IPs'}
        return Response(content, status=status.HTTP_404_NOT_FOUND)


def _network_ptroverride_list(kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    from_ip = str(network.network.network_address)
    to_ip = str(network.network.broadcast_address)
    return PtrOverride.objects.filter(ipaddress__range=(from_ip, to_ip))


@api_view()
def network_ptroverride_list(request, *args, **kwargs):
    ptrs = _network_ptroverride_list(kwargs)
    ptr_list = [i.ipaddress for i in ptrs]
    return Response(ptr_list, status=status.HTTP_200_OK)


@api_view()
def network_ptroverride_host_list(request, *args, **kwargs):
    ptrs = _network_ptroverride_list(kwargs)
    ret = dict()
    info = ptrs.values_list('host__name', 'ipaddress')
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        ret[ip] = host
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_reserved_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    reserved = list(map(str, sorted(network.get_reserved_ipaddresses())))
    return Response(reserved, status=status.HTTP_200_OK)


@api_view()
def network_used_count(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    return Response(network.get_used_ipaddress_count(), status=status.HTTP_200_OK)


@api_view()
def network_used_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    used_ipaddresses = list(map(str, sorted(network.get_used_ipaddresses())))
    return Response(used_ipaddresses, status=status.HTTP_200_OK)


@api_view()
def network_used_host_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    ret = defaultdict(list)
    info = network._get_used_ipaddresses().values_list('host__name', 'ipaddress')
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        bisect.insort(ret[ip], host)
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_unused_count(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    return Response(network.get_unused_ipaddress_count(), status=status.HTTP_200_OK)


@api_view()
def network_unused_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs['network'])
    unused_ipaddresses = list(map(str, sorted(network.get_unused_ipaddresses())))
    return Response(unused_ipaddresses, status=status.HTTP_200_OK)


class TxtList(HostPermissionsListCreateAPIView):
    """
    get:
    Returns a list of all txt-records.

    post:
    Create a new txt-record.
    """

    queryset = Txt.objects.get_queryset().order_by('id')
    serializer_class = TxtSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        return TxtFilterSet(data=self.request.GET, queryset=qs).filter()


class TxtDetail(HostPermissionsUpdateDestroy,
                MregRetrieveUpdateDestroyAPIView):
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


class NetGroupRegexPermissionList(MregMixin, generics.ListCreateAPIView):
    """
    """

    queryset = mreg.models.NetGroupRegexPermission.objects.all().order_by('id')
    serializer_class = NetGroupRegexPermissionSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly, )

    def get_queryset(self):
        qs = super().get_queryset()
        return NetGroupRegexPermissionFilterSet(data=self.request.GET, queryset=qs).filter()


class NetGroupRegexPermissionDetail(MregRetrieveUpdateDestroyAPIView):
    """
    """

    queryset = mreg.models.NetGroupRegexPermission.objects.all().order_by('id')
    serializer_class = NetGroupRegexPermissionSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly, )


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
        tables = list({value['table_name'] for value in self.queryset.values('table_name')})
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
        logs_by_date = [vals for vals in self.queryset.filter(table_name=query_table,
                                                              table_row=query_row).order_by('timestamp').values()]

        return Response(logs_by_date, status=status.HTTP_200_OK)


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


def _get_ips_by_range(iprange):
    network = ipaddress.ip_network(iprange)
    from_ip = str(network.network_address)
    to_ip = str(network.broadcast_address)
    return Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip))


def _dhcphosts_by_range(iprange):
    ips = _get_ips_by_range(iprange)
    ips = ips.exclude(macaddress='').order_by('ipaddress')
    ips = ips.values('host__name', 'ipaddress', 'macaddress', 'host__zone__name')
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
    ipv4_host2mac = {hostname: mac for hostname, mac in
                     ipv4.values_list('host__name', 'macaddress')}
    ipv6 = _get_ips_by_range('::/0')
    ipv6 = ipv6.filter(macaddress='')
    ipv6 = ipv6.filter(host__in=ipv4_host_ids).order_by('ipaddress')
    ret = []
    for values in ipv6.values('host__name', 'host__zone__name', 'ipaddress'):
        values['macaddress'] = ipv4_host2mac[values['host__name']]
        ret.append(values)
    return Response(ret)


class DhcpHostsV4ByV6(APIView):

    renderer_classes = (JSONRenderer, )

    def get(self, request, *args, **kwargs):
        if 'ip' in kwargs:
            iprange = _get_iprange(kwargs)
        else:
            iprange = '0.0.0.0/0'
        return _dhcpv6_hosts_by_ipv4(iprange)
