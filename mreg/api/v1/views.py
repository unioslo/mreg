import bisect
import ipaddress
from collections import Counter, defaultdict
from typing import cast

from django.db import transaction
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404

from django_filters import rest_framework as rest_filters

from rest_framework import filters, generics, status
from rest_framework.decorators import api_view
from rest_framework.exceptions import MethodNotAllowed, ParseError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from mreg.models.base import NameServer, History
from mreg.models.host import Host, Ipaddress, PtrOverride
from mreg.models.network import Network, NetGroupRegexPermission
from mreg.types import IPAllocationMethod
from mreg.models.resource_records import Cname, Loc, Naptr, Srv, Sshfp, Txt, Hinfo, Mx
from mreg.models.auth import User
from mreg.api.exceptions import NoIpAddressesError404, ValidationError400, ValidationError404

from mreg.api.permissions import (
    IsAuthenticatedAndReadOnly,
    IsGrantedNetGroupRegexPermission,
    IsSuperGroupMember,
    IsSuperOrAdminOrReadOnly,
    IsSuperOrNetworkAdminMember,
)

from .filters import (
    CnameFilterSet,
    HinfoFilterSet,
    HistoryFilterSet,
    HostFilterSet,
    IpaddressFilterSet,
    LocFilterSet,
    MxFilterSet,
    NameServerFilterSet,
    NaptrFilterSet,
    NetGroupRegexPermissionFilterSet,
    NetworkExcludedRangeFilterSet,
    NetworkFilterSet,
    PtrOverrideFilterSet,
    SrvFilterSet,
    SshfpFilterSet,
    TxtFilterSet,
)
from .history import HistoryLog
from .serializers import (
    CnameSerializer,
    HinfoSerializer,
    HistorySerializer,
    HostSerializer,
    IpaddressSerializer,
    LocSerializer,
    MxSerializer,
    NameServerSerializer,
    NaptrSerializer,
    NetGroupRegexPermissionSerializer,
    NetworkSerializer,
    NetworkExcludedRangeSerializer,
    PtrOverrideSerializer,
    SrvSerializer,
    SshfpSerializer,
    TxtSerializer,
    HostCreateSerializer,
)

from mreg.mixins import LowerCaseLookupMixin

class MregMixin:
    filter_backends = (
        filters.SearchFilter,
        rest_filters.DjangoFilterBackend,
        filters.OrderingFilter,
    )
    ordering_fields = "__all__"


class HostLogMixin(HistoryLog):
    log_resource = "host"
    model = Host
    foreign_key_name = "host"

    @staticmethod
    def manipulate_data(action, serializer, data, orig_data):
        # No need to store zone, as it is automatically set by name
        data.pop("zone", None)
        # No need to store host, as changes to a host will also log, unless the
        # host itself has changed
        if (
            action == "update"
            and "host" in data
            and data["host"].id == orig_data["host"]
        ):
            pass
        else:
            data.pop("host", None)


class MregRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    """
    Makes sure patch returns empty body, 204 - No Content, and location of object.
    """

    def perform_update(self, serializer, **kwargs):
        super().perform_update(serializer)
        serializer.save(**kwargs)

    def patch(self, request, *args, **kwargs):
        self.instance = instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        if self.lookup_field in serializer.validated_data:
            # Remove the value of self.lookup_field from end of path
            location = request.path[: -len(kwargs[self.lookup_field])]
            # and replace with updated one
            location += str(serializer.validated_data[self.lookup_field])
        else:
            location = request.path
        return Response(
            status=status.HTTP_204_NO_CONTENT, headers={"Location": location}
        )

    def put(self, request, *args, **kwargs):
        raise MethodNotAllowed()


class MregListCreateAPIView(MregMixin, generics.ListCreateAPIView):
    def _get_location(self, request, serializer):
        return request.path + str(serializer.validated_data[self.lookup_field])

    def post(self, request, *args, **kwargs):
        # Add a location header for all POSTs
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        location = self._get_location(request, serializer)
        return Response(status=status.HTTP_201_CREATED, headers={"Location": location})


class MregPermissionsUpdateDestroy:
    def perform_destroy(self, instance):
        # Custom check destroy permissions
        self.check_destroy_permissions(self.request, instance)
        super().perform_destroy(instance)

    def perform_update(self, serializer, **kwargs):
        # Custom check update permissions
        self.check_update_permissions(self.request, serializer)
        self.orig_data = self.get_serializer(self.get_object()).data
        serializer.save(**kwargs)
        super().perform_update(serializer)

    def check_destroy_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_destroy_permission(
                request, self, validated_serializer
            ):
                self.permission_denied(request)

    def check_update_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_update_permission(
                request, self, validated_serializer
            ):
                self.permission_denied(request)


class MregPermissionsListCreateAPIView(MregMixin, generics.ListCreateAPIView):
    def perform_create(self, serializer):
        # Custom check create permissions
        self.check_create_permissions(self.request, serializer)
        super().perform_create(serializer)

    def check_create_permissions(self, request, validated_serializer):
        for permission in self.get_permissions():
            if not permission.has_create_permission(
                request, self, validated_serializer
            ):
                self.permission_denied(request)


class HostPermissionsUpdateDestroy(HostLogMixin, MregPermissionsUpdateDestroy):
    # permission_classes = settings.MREG_PERMISSION_CLASSES
    permission_classes = (IsGrantedNetGroupRegexPermission,)


class HostPermissionsListCreateAPIView(HostLogMixin, MregPermissionsListCreateAPIView):
    # permission_classes = settings.MREG_PERMISSION_CLASSES
    permission_classes = (IsGrantedNetGroupRegexPermission,)


class CnameList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all cnames / aliases.

    post:
    Creates a new cname.
    """

    queryset = Cname.objects.all()
    serializer_class = CnameSerializer
    lookup_field = "name"
    filterset_class = CnameFilterSet



class CnameDetail(HostPermissionsUpdateDestroy,
                  LowerCaseLookupMixin,
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
    lookup_field = "name"


class HinfoList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all hinfos.

    post:
    Creates a new hinfo.
    """

    queryset = Hinfo.objects.all().order_by("host")
    serializer_class = HinfoSerializer
    filterset_class = HinfoFilterSet



class HinfoDetail(HostPermissionsUpdateDestroy,
                  LowerCaseLookupMixin,
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


def _host_prefetcher(qs):
    return qs.prefetch_related(
        "bacnetid", "cnames", "hinfo", "loc", "mxs", "ptr_overrides", "txts"
    ).prefetch_related(
        Prefetch("ipaddresses", queryset=Ipaddress.objects.order_by("ipaddress"))
    )


class HostList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all hostnames.

    post:
    Create a new host object. Allows posting with IP address in data.
    """

    queryset = Host.objects.get_queryset().order_by("id")
    serializer_class = HostSerializer
    # We manipulate the query set with _host_prefetcher in get_queryset,
    # so HostFilterSet would need to implement these changes.
    # However, we also reuse _host_prefetcher in the HostDetail view below
    # so this would all require a bit of careful refactoring...
    # filterset_class = HostFilterSet

    def get_queryset(self):
        qs = _host_prefetcher(super().get_queryset())
        return HostFilterSet(data=self.request.GET, queryset=qs).qs

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return HostCreateSerializer
        return HostSerializer

    def post(self, request, *args, **kwargs):        
        ip_address = request.data.get('ipaddress')
        network = request.data.get('network')
        allocation_method = request.data.get('allocation_method')
        name = request.data.get('name')
        user = cast(User, request.user)

        print(f"ip_address: {ip_address} name: {name} network: {network} allocation_method: {allocation_method}")

        if not name:
            raise ValidationError400("You must specify a name for the new host.")

        user.is_permitted_to_use_dnsname_or_raise(name)

        if ip_address and network:
            raise ValidationError400("You can't specify both 'ipaddress' and 'network'")
        
        if allocation_method and not network:
            raise ValidationError400("You must specify a network if you want to use 'allocation_method'")

        if network:
            # Check that we have a valid network
            try:
                ipaddress.ip_network(network)
            except ValueError as error:
                raise ValidationError400(str(error))

            try:
                net = Network.objects.get(network=network)
            except Network.DoesNotExist:
                raise ValidationError404(f"Network {network} not found.")
            
            if allocation_method:
                try:
                    allocation_method_enum = IPAllocationMethod(allocation_method.lower())
                except ValueError:
                    options = [method.value for method in IPAllocationMethod]
                    raise ValidationError400(f"allocation_method must be one of {', '.join(options)}")
            else:
                allocation_method_enum = IPAllocationMethod.FIRST

            if allocation_method_enum == IPAllocationMethod.RANDOM:
                ip_address = net.get_random_unused()
            else:
                ip_address = net.get_first_unused()

            if not ip_address:
                raise NoIpAddressesError404("No free ip addresses found in {net}.")

        if not ip_address:
            user.is_permitted_to_create_host_without_ipaddress_or_raise()
            serializer = self.get_serializer(data={"name": name})
        else:
            serializer = self.get_serializer(data={"ipaddress": ip_address, "name": name})
            user.is_permitted_to_use_ipaddress_or_raise(ip_address)
        
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            host = serializer.save()
            self.save_log_create(serializer)

        location = f"{request.path}{host.name}"
        return Response(
            status=status.HTTP_201_CREATED,
            headers={"Location": location},
        )

class HostDetail(HostPermissionsUpdateDestroy,
                 LowerCaseLookupMixin,
                 MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified host. Includes relations like IP address/a-records, ptr-records, cnames.

    patch:
    Update parts of the host.

    delete:
    Delete the specified host.
    """

    queryset = _host_prefetcher(Host.objects.all())
    serializer_class = HostSerializer
    lookup_field = "name"

    def patch(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data["name"]).exists():
                content = {"ERROR": "name already in use"}
                return Response(content, status=status.HTTP_409_CONFLICT)

        return super().patch(request, *args, **kwargs)


class HistoryList(MregMixin, generics.ListAPIView):
    queryset = History.objects.all().order_by('id')
    serializer_class = HistorySerializer
    filterset_class = HistoryFilterSet


class HistoryDetail(MregMixin, generics.RetrieveAPIView):

    queryset = History.objects.all()
    serializer_class = HistorySerializer


class IpaddressList(HostPermissionsListCreateAPIView):
    """
    get:
    Lists all ipaddresses in use.

    post:
    Creates a new ipaddress object. Requires an existing host.
    """

    queryset = Ipaddress.objects.get_queryset().order_by("id")
    serializer_class = IpaddressSerializer
    filterset_class = IpaddressFilterSet


class IpaddressDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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

    queryset = Loc.objects.all().order_by("host")
    serializer_class = LocSerializer
    filterset_class = LocFilterSet


class LocDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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

    queryset = Mx.objects.get_queryset().order_by("id")
    serializer_class = MxSerializer
    filterset_class = MxFilterSet


class MxDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
    filterset_class = NaptrFilterSet


class NaptrDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
    lookup_field = "name"
    filterset_class = NameServerFilterSet


class NameServerDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
    lookup_field = "name"


class PtrOverrideList(HostPermissionsListCreateAPIView):
    """
    get:
    List all ptr-overrides.

    post:
    Create a new ptr-override.
    """

    queryset = PtrOverride.objects.get_queryset().order_by("id")
    serializer_class = PtrOverrideSerializer
    filterset_class = PtrOverrideFilterSet


class PtrOverrideDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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

    queryset = Sshfp.objects.get_queryset().order_by("id")
    serializer_class = SshfpSerializer
    filterset_class = SshfpFilterSet


class SshfpDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
    filterset_class = SrvFilterSet


class SrvDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
        return Response(
            {"ERROR": "Network overlaps with: {}".format(info)},
            status=status.HTTP_409_CONFLICT,
        )


class NetworkList(MregListCreateAPIView):
    """
    list:
    Returns a list of networks

    post:
    Create a new network. The new network can't overlap with any existing networks.
    """

    queryset = Network.objects.all().prefetch_related("excluded_ranges")
    serializer_class = NetworkSerializer
    permission_classes = (IsSuperGroupMember | IsAuthenticatedAndReadOnly,)
    lookup_field = "network"
    filterset_class = NetworkFilterSet

    def post(self, request, *args, **kwargs):
        error = _overlap_check(request.data["network"])
        if error:
            return error
        return super().post(request, *args, **kwargs)


class NetworkDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    List details for a network.

    patch:
    Partially update a network.

    delete:
    Deletes a network unless it has IP addresses that are still in use
    """

    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsSuperOrNetworkAdminMember | IsAuthenticatedAndReadOnly,)

    lookup_field = "network"

    def patch(self, request, *args, **kwargs):
        network = self.get_object()
        if "network" in request.data:
            error = _overlap_check(request.data["network"], exclude=network)
            if error:
                return error
        return super().patch(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        network = self.get_object()
        if network.used_addresses:
            return Response(
                {"ERROR": "Network contains IP addresses that are in use"},
                status=status.HTTP_409_CONFLICT,
            )

        self.perform_destroy(network)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NetworkExcludedRangeList(MregListCreateAPIView):
    """
    list:
    Returns a list of excluded ipaddress ranges

    post:
    Create a new excluded range for a network.
    """

    serializer_class = NetworkExcludedRangeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember | IsAuthenticatedAndReadOnly,)

    def _get_location(self, request, serializer):
        # Can not get Location if the attribute is not set in the serializer
        obj = self.get_queryset().get(**serializer.validated_data)
        return request.path + str(obj.pk)

    def get_queryset(self):
        """
        Applies filtering to the queryset
        :return: filtered list of network excludes
        """
        qs = get_object_or_404(
            Network, network=self.kwargs["network"]
        ).excluded_ranges.all()
        return NetworkExcludedRangeFilterSet(data=self.request.GET, queryset=qs).qs


class NetworkExcludedRangeDetail(MregRetrieveUpdateDestroyAPIView):
    """
    get:
    List details for an excluded range.

    patch:
    Partially update an excluded range.

    delete:
    Deletes an excluded range.
    """

    serializer_class = NetworkExcludedRangeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember | IsAuthenticatedAndReadOnly,)
    lookup_field = "pk"

    def get_queryset(self):
        network = get_object_or_404(Network, network=self.kwargs["network"])
        return network.excluded_ranges.all()


@api_view()
def network_by_ip(request, *args, **kwargs):
    try:
        ip = ipaddress.ip_address(kwargs["ip"])
    except ValueError as error:
        raise ParseError(detail=str(error))
    network = get_object_or_404(Network, network__net_contains_or_equals=ip)
    serializer = NetworkSerializer(network)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view()
def network_first_unused(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    ip = network.get_first_unused()
    if ip:
        return Response(ip, status=status.HTTP_200_OK)
    else:
        content = {"ERROR": "No available IPs"}
        return Response(content, status=status.HTTP_404_NOT_FOUND)


@api_view()
def network_random_unused(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    ip = network.get_random_unused()
    if ip:
        return Response(ip, status=status.HTTP_200_OK)
    else:
        content = {"ERROR": "No available IPs"}
        return Response(content, status=status.HTTP_404_NOT_FOUND)


@api_view()
def network_ptroverride_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    ptrs = network._used_ptroverrides()
    ptr_list = ptrs.values_list("ipaddress", flat=True).order_by("ipaddress")
    return Response(ptr_list, status=status.HTTP_200_OK)


@api_view()
def network_ptroverride_host_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    ptrs = network._used_ptroverrides()
    ret = dict()
    info = ptrs.values_list("host__name", "ipaddress")
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        ret[ip] = host
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_reserved_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    reserved = list(map(str, sorted(network.get_reserved_ipaddresses())))
    return Response(reserved, status=status.HTTP_200_OK)


@api_view()
def network_used_count(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    return Response(len(network.used_addresses), status=status.HTTP_200_OK)


@api_view()
def network_used_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    used_ipaddresses = list(map(str, sorted(network.used_addresses)))
    return Response(used_ipaddresses, status=status.HTTP_200_OK)


@api_view()
def network_used_host_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    ret = defaultdict(list)
    info = network._used_ipaddresses().values_list("host__name", "ipaddress")
    for host, ip in sorted(info, key=lambda i: ipaddress.ip_address(i[1])):
        bisect.insort(ret[ip], host)
    return Response(ret, status=status.HTTP_200_OK)


@api_view()
def network_unused_count(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    return Response(network.unused_count, status=status.HTTP_200_OK)


@api_view()
def network_unused_list(request, *args, **kwargs):
    network = get_object_or_404(Network, network=kwargs["network"])
    unused_ipaddresses = list(map(str, sorted(network.unused_addresses)))
    return Response(unused_ipaddresses, status=status.HTTP_200_OK)


class TxtList(HostPermissionsListCreateAPIView):
    """
    get:
    Returns a list of all txt-records.

    post:
    Create a new txt-record.
    """

    queryset = Txt.objects.get_queryset().order_by("id")
    serializer_class = TxtSerializer
    filterset_class = TxtFilterSet


class TxtDetail(HostPermissionsUpdateDestroy, MregRetrieveUpdateDestroyAPIView):
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
    """ """

    queryset = NetGroupRegexPermission.objects.all().order_by('id')
    serializer_class = NetGroupRegexPermissionSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)
    filterset_class = NetGroupRegexPermissionFilterSet


class NetGroupRegexPermissionDetail(MregRetrieveUpdateDestroyAPIView):
    """ """

    queryset = NetGroupRegexPermission.objects.all().order_by('id')
    serializer_class = NetGroupRegexPermissionSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)


def _get_iprange(kwargs):
    """
    Helper function to get the range from the params dict.
    :param kwargs: kwargs
    :return: The iprange as a string, or raises an error
    """
    try:
        ip = kwargs["ip"]
        mask = kwargs["range"]
        iprange = "%s/%s" % (ip, mask)
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
    ips = ips.exclude(macaddress="").order_by("ipaddress")
    ips = ips.values("host__name", "ipaddress", "macaddress", "host__zone__name")
    return Response(ips)


@api_view()
def dhcp_hosts_all_v4(request, *args, **kwargs):
    return _dhcphosts_by_range("0.0.0.0/0")


@api_view()
def dhcp_hosts_all_v6(request, *args, **kwargs):
    return _dhcphosts_by_range("::/0")


@api_view()
def dhcp_hosts_by_range(request, *args, **kwargs):
    return _dhcphosts_by_range(_get_iprange(kwargs))


def _dhcpv6_hosts_by_ipv4(iprange):
    """
    Find all hosts which have only one ipv4 and one ipv6 address,
    and where the ipv4 address has a mac associated and the
    ipv6 address has not.
    """

    def _unique_host_ids(qs):
        counter = Counter(qs.values_list("host__id", flat=True))
        return [host_id for host_id, count in counter.items() if count == 1]

    ipv6 = _get_ips_by_range("::/0")
    qs = ipv6.filter(macaddress="").filter(host__in=_unique_host_ids(ipv6))
    ipv6_hosts = _unique_host_ids(qs)

    ipv4 = _get_ips_by_range(iprange)
    qs = ipv4.filter(host__in=ipv6_hosts)
    qs = qs.exclude(macaddress="").filter(host__in=_unique_host_ids(qs))
    ipv4_hosts = _unique_host_ids(qs)
    ipv4 = ipv4.filter(host__in=ipv4_hosts)
    ipv4_host2mac = {
        hostname: mac for hostname, mac in ipv4.values_list("host__name", "macaddress")
    }
    ipv6 = ipv6.filter(host__in=ipv4_hosts).order_by("ipaddress")
    ret = []
    for values in ipv6.values("host__name", "host__zone__name", "ipaddress"):
        values["macaddress"] = ipv4_host2mac[values["host__name"]]
        ret.append(values)
    return Response(ret)


class DhcpHostsV4ByV6(APIView):
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        if "ip" in kwargs:
            iprange = _get_iprange(kwargs)
        else:
            iprange = "0.0.0.0/0"
        return _dhcpv6_hosts_by_ipv4(iprange)
