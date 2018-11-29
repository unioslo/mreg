from rest_framework import generics
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import Http404, QueryDict
from django.shortcuts import get_object_or_404
from rest_framework_extensions.etag.mixins import ETAGMixin
from rest_framework import renderers
from rest_framework.response import Response
from rest_framework import status
from url_filter.filtersets import ModelFilterSet
import ipaddress

from mreg.api.v1.serializers import (CnameSerializer, HinfoPresetSerializer,
        HostNameSerializer, HostSerializer, HostSaveSerializer,
        IpaddressSerializer, NameServerSerializer, NaptrSerializer,
        PtrOverrideSerializer, SrvSerializer, SubnetSerializer, TxtSerializer,
        ZoneSerializer, ModelChangeLogSerializer)
from mreg.models import (Cname, HinfoPreset, Host, Ipaddress, NameServer,
        Naptr, PtrOverride, Srv, Subnet, Txt, Zone, ModelChangeLog)
from mreg.utils import create_serialno

from .zonefile import ZoneFile


# These filtersets are used for applying generic filtering to all objects.
class CnameFilterSet(ModelFilterSet):
    class Meta(object):
        model = Cname


class HinfoFilterSet(ModelFilterSet):
    class Meta(object):
        model = HinfoPreset


class HostFilterSet(ModelFilterSet):
    class Meta(object):
        model = Host


class IpaddressFilterSet(ModelFilterSet):
    class Meta(object):
        model = Ipaddress


class NaptrFilterSet(ModelFilterSet):
    class Meta(object):
        model = Naptr


class NameServerFilterSet(ModelFilterSet):
    class Meta(object):
        model = NameServer


class PtrOverrideFilterSet(ModelFilterSet):
    class Meta(object):
        model = PtrOverride


class SrvFilterSet(ModelFilterSet):
    class Meta(object):
        model = Srv


class SubnetFilterSet(ModelFilterSet):
    class Meta(object):
        model = Subnet


class TxtFilterSet(ModelFilterSet):
    class Meta(object):
        model = Txt


class ZoneFilterSet(ModelFilterSet):
    class Meta(object):
        model = Zone


class StrictCRUDMixin(object):
    """
    Applies stricter handling of HTTP requests and responses.
    Apply this mixin to generic classes that don't implement their own CRUD-operations.
    Makes sure patch returns sempty body, 204 - No Content, and location of object.
    """

    def patch(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer_class = self.get_serializer_class()
        obj = get_object_or_404(queryset, pk=self.kwargs[self.lookup_field])
        serializer = serializer_class(obj, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            resource = self.kwargs['resource']
            location = '/%s/%s' % (resource, obj.pk)
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

    def get_queryset(self):
        qs = super(CnameList, self).get_queryset()
        return CnameFilterSet(data=self.request.GET, queryset=qs).filter()


class CnameDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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
        qs = super(HinfoPresetList, self).get_queryset()
        return HinfoFilterSet(data=self.request.GET, queryset=qs).filter()


class HinfoPresetDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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


class HostList(generics.GenericAPIView):
    """
    get:
    Lists all hostnames.

    post:
    Create a new host object. Allows posting with IP address in data.
    """
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def get_queryset(self):
        qs = super(HostList, self).get_queryset()
        return HostFilterSet(data=self.request.GET, queryset=qs).filter()

    def get(self, request, *args, **kwargs):
        serializer = HostNameSerializer(self.get_queryset(), many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        zoneid = None
        if "name" in request.data:
            if self.queryset.filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)
            zd = ZoneDetail()
            zoneid = zd.get_zone_by_hostname(name=request.data["name"])
            if not zoneid:
                return Response(status=status.HTTP_400_BAD_REQUEST,
                                data={"ERROR": "Hostname not in a mreg zone"})
        hostdata = request.data.copy()
        hostdata["zoneid"] = zoneid

        if 'ipaddress' in request.data:
            ipkey = hostdata['ipaddress']
            del hostdata['ipaddress']
            host = Host()
            hostserializer = HostSerializer(host, data=hostdata)

            if hostserializer.is_valid(raise_exception=True):
                try:
                    ipaddress.ip_address(ipkey)
                    with transaction.atomic():
                        hostserializer.save()
                        ipdata = {'hostid': host.pk, 'ipaddress': ipkey}
                        ip = Ipaddress()
                        ipserializer = IpaddressSerializer(ip, data=ipdata)
                        if ipserializer.is_valid(raise_exception=True):
                            ipserializer.save()
                            location = '/hosts/%s' % host.name
                            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})
                except ValueError:
                    return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            host = Host()
            hostserializer = HostSerializer(host, data=hostdata)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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

        if "hostid" in request.data:
            if self.queryset.filter(hostid=request.data["hostid"]).exists():
                content = {'ERROR': 'hostid already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

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


class IpaddressList(generics.ListCreateAPIView):
    """
    get:
    Lists all ipaddresses in use.

    post:
    Creates a new ipaddress object. Requires an existing host.
    """
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer

    def get_queryset(self):
        qs = super(IpaddressList, self).get_queryset()
        return IpaddressFilterSet(data=self.request.GET, queryset=qs).filter()

    def get(self, request, *args, **kwargs):
        serializer = IpaddressSerializer(self.get_queryset(), many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if "ipaddress" in request.data:
            ip = Ipaddress()
            serializer = IpaddressSerializer(ip, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/ipaddresses/%s' % ip.id
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class IpaddressDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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

    def patch(self, request, *args, **kwargs):
        ip = get_object_or_404(Ipaddress, id=self.kwargs['pk'])
        serializer = IpaddressSerializer(ip, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if "ipaddress" in request.data:
            for i in self.queryset.filter(ipaddress=request.data["ipaddress"]):
                if i.hostid == ip.hostid:
                    content = {'ERROR': 'ipaddress already in use by the host'}
                    return Response(content, status=status.HTTP_409_CONFLICT)

        if "macaddress" in request.data:
            if self.queryset.filter(macaddress=request.data["macaddress"]).exists():
                content = {'ERROR': 'macaddress already registered',
                           'ipaddress': self.queryset.get(macaddress=request.data['macaddress']).ipaddress}
                return Response(content, status=status.HTTP_409_CONFLICT)

        serializer.save()
        location = '/ipaddresses/%s' % ip.id
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


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
        qs = super(NaptrList, self).get_queryset()
        return NaptrFilterSet(data=self.request.GET, queryset=qs).filter()


class NaptrDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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
        qs = super(NameServerList, self).get_queryset()
        return NameServerFilterSet(data=self.request.GET, queryset=qs).filter()


class NameServerDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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
        qs = super(PtrOverrideList, self).get_queryset()
        return PtrOverrideFilterSet(data=self.request.GET, queryset=qs).filter()


class PtrOverrideDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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
        qs = super(SrvList, self).get_queryset()
        return SrvFilterSet(data=self.request.GET, queryset=qs).filter()


class SrvDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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


class SubnetList(generics.ListAPIView):
    """
    list:
    Returns a list of subnets

    post:
    Create a new subnet. The new subnet can't overlap with any existing subnets.
    """
    queryset = Subnet.objects.all()
    serializer_class = SubnetSerializer

    def post(self, request, *args, **kwargs):
        try:
            network = ipaddress.ip_network(request.data['range'])
            overlap = Subnet.overlap_check(network)
            if overlap:
                info = ", ".join(map(str,overlap))
                return Response({'ERROR': 'Subnet overlaps with: {}'.format(info)},
                                status=status.HTTP_409_CONFLICT)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            subnet = serializer.create()
            # Changed the default value of reserved if the size of the subnet is too low
            if network.num_addresses <= 4:
                subnet.reserved = min(2, network.num_addresses)
            subnet.save()
            location = '/subnets/%s' % request.data
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})

        except ValueError as error:
            return Response({'ERROR': str(error)}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        """
        Applies filtering to the queryset
        :return: filtered list of subnets
        """
        qs = super(SubnetList, self).get_queryset()
        return SubnetFilterSet(data=self.request.GET, queryset=qs).filter()


class SubnetDetail(ETAGMixin, generics.GenericAPIView):
    """
    get:
    List details for a subnet. Query parameter ?used_list returns list of used IP addresses on the subnet

    patch:
    Partially update a subnet. Updating a zone's range is not allowed

    delete:
    Deletes a subnet unless it has IP addresses that are still in use
    """
    queryset = Subnet.objects.all()
    serializer_class = SubnetSerializer

    lookup_field = 'range'

    def get(self, request, queryset=queryset, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)

        valid_range = self.is_range(iprange)
        if not valid_range:
            return valid_range

        subnet = get_object_or_404(Subnet, range=iprange)

        if request.META.get('QUERY_STRING') == 'used_count':
            return Response(subnet.get_used_ipaddress_count(), status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'used_list':
            used_ipaddresses = list(map(str, sorted(subnet.get_used_ipaddresses())))
            return Response(used_ipaddresses, status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'unused_count':
            unused_ipaddresses = subnet.get_unused_ipaddresses()
            return Response(len(unused_ipaddresses), status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'unused_list':
            unused_ipaddresses = list(map(str, sorted(subnet.get_unused_ipaddresses())))
            return Response(unused_ipaddresses, status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'first_unused':
            ip = subnet.get_first_unused()
            if ip:
                return Response(ip, status=status.HTTP_200_OK)
            else:
                content = {'ERROR': 'No available IPs'}
                return Response(content, status=status.HTTP_404_NOT_FOUND)
        elif request.META.get('QUERY_STRING') == 'reserved_list':
            reserved = list(map(str, sorted(subnet.get_reserved_ipaddresses())))
            return Response(reserved, status=status.HTTP_200_OK)

        serializer = self.get_serializer(subnet)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)
        valid_range = self.is_range(iprange)

        if not valid_range:
            return valid_range

        if 'range' in request.data:
            return Response({'ERROR': 'Not allowed to change range'}, status=status.HTTP_403_FORBIDDEN)

        subnet = get_object_or_404(Subnet, range=iprange)
        serializer = self.get_serializer(subnet, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        location = '/subnets/%s' % iprange
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def delete(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)

        valid_range = self.is_range(iprange)
        if not valid_range:
            return valid_range

        subnet = get_object_or_404(Subnet, range=iprange)
        used_ipaddresses = subnet.get_used_ipaddresses()
        if used_ipaddresses:
            return Response({'ERROR': 'Subnet contains IP addresses that are in use'}, status=status.HTTP_409_CONFLICT)

        subnet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def is_range(self, iprange):
        """
        Helper function to check if given string isn't a valid range
        :param iprange: the IP range
        :return: true or a response with an error that describes what's wrong with the string
        """
        try:
            ipaddress.ip_network(iprange)
            return True
        except ValueError as error:
            return Response({'ERROR': str(error)}, status=status.HTTP_400_BAD_REQUEST)

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
        qs = super(TxtList, self).get_queryset()
        return TxtFilterSet(data=self.request.GET, queryset=qs).filter()


class TxtDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
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


class ZoneList(generics.ListAPIView):
    """
    get:
    Returns a list of all zones.

    post:
    Create a zone. The primary_ns field is a list where the first element will be the primary nameserver.

    """
    queryset = Zone.objects.all()
    queryset_hosts = Host.objects.all()
    queryset_ns = NameServer.objects.all()
    serializer_class = ZoneSerializer

    def get_zoneserial():
        """
        Get the latest updated serialno from all zones
        :return: 10-digit serialno
        """
        serials = Zone.objects.values_list('serialno', flat=True)
        if serials:
            return max(serials)
        else:
            return 0

    def get_queryset(self):
        """
        Applies filtering to the queryset
        :return: filtered list of zones
        """
        qs = super(ZoneList, self).get_queryset()
        return ZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if self.queryset.filter(name=request.data["name"]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)
        # A copy is required since the original is immutable
        data = request.data.copy()
        nameservers = request.POST.getlist('primary_ns')
        data['primary_ns'] = nameservers[0]
        data['serialno'] = create_serialno(ZoneList.get_zoneserial())

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        zone = serializer.create()
        zone.save()

        # Check if nameserver is an existing host and add it as a nameserver to the zone
        for nameserver in nameservers:
            try:
                ns = self.queryset_ns.get(name=nameserver)
                zone.nameservers.add(ns.nsid)
            except NameServer.DoesNotExist:
                ns = NameServer(name=nameserver)
                ns.save()
                zone.nameservers.add(ns.nsid)
        zone.save()
        return Response(status=status.HTTP_201_CREATED, headers={'Location': '/zones/%s' % data['name']})


class ZoneDetail(ETAGMixin, generics.RetrieveAPIView):
    """
    get:
    List details for a zone.

    patch:
    Update parts of a zone.
    Nameservers need to be patched through /zones/<name>/nameservers. primary_ns needs to be a nameserver of the zone

    delete:
    Delete a zone.
    """
    queryset = Zone.objects.all()
    queryset_hosts = Zone.objects.all()
    queryset_ns = NameServer.objects.all()
    serializer_class = ZoneSerializer
    lookup_field = 'name'

    # TODO: Implement authentication
    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]

        if "zoneid" in request.data:
            if self.queryset.filter(zoneid=request.data["zoneid"]).exists():
                content = {'ERROR': 'zoneid already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if "name" in request.data:
            content = {'ERROR': 'Not allowed to change name'}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        if "serialno" in request.data:
            if self.queryset.filter(serialno=request.data["serialno"]).exists():
                content = {'ERROR': 'serialno already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if "nameservers" in request.data:
            content = {'ERROR': 'Not allowed to patch nameservers, use zones/{}/nameservers'.format(query)}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        zone = get_object_or_404(Zone, name=query)
        # Check if primary_ns is in the zone's list of nameservers
        if "primary_ns" in request.data:
            if request.data['primary_ns'] not in [nameserver['name'] for nameserver in zone.nameservers.values()]:
                content = {'ERROR': "%s is not one of %s's nameservers" % (request.data['primary_ns'], query)}
                return Response(content, status=status.HTTP_403_FORBIDDEN)
        data = request.data.copy()
        data['serialno'] = create_serialno(ZoneList.get_zoneserial())
        serializer = self.get_serializer(zone, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        location = '/zones/%s' % zone.name
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})

    def delete(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(Zone, name=query)

        for nameserver in zone.nameservers.values():
            ns = self.queryset_ns.get(name=nameserver['name'])
            if ns.zone_set.count() == 1:
                ns.delete()

        zone.delete()
        location = '/zones/%s' % zone.name
        return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})


    def get_zone_by_hostname(self, name):
        """Get zoneid for a hostname.
	Return zoneid or None if not found."""

        def _get_reverse_order(lst):
            """Return index of sorted zones"""
            # We must sort the zones to assert that ifi.uio.no hosts
            # does not end up in the uio.no zone.  This is acheived by
            # spelling the zone postfix backwards and sorting the
            # resulting list backwards
            lst = [str(x.name)[::-1] for x in lst]
            t = range(len(lst))
            return sorted(t, reverse=True)

        zones = self.get_queryset()
        for n in _get_reverse_order(zones):
            z = zones[n]
            if z.name and name.endswith(z.name):
                return z.zoneid
        return None


class ZoneNameServerDetail(ETAGMixin, generics.GenericAPIView):
    """
    get:
    Returns a list of nameservers for a given zone.

    patch:
    Set the nameserver list of a zone. Requires all the nameservers of the zone and removes the ones not mentioned.
    """
    queryset = Zone.objects.all()
    queryset_ns = NameServer.objects.all()
    queryset_hosts = Host.objects.all()
    serializer_class = ZoneSerializer

    lookup_field = 'name'

    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(Zone, name=query)
        return Response([ns['name'] for ns in zone.nameservers.values()], status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        zone = get_object_or_404(Zone, name=query)
        if 'primary_ns' not in request.data:
            return Response({'ERROR': 'No nameserver found in body'}, status=status.HTTP_400_BAD_REQUEST)

        # Check existing  nameservers and delete them if this zone is the only one that uses them
        for nameserver in zone.nameservers.values():
            ns = self.queryset_ns.get(name=nameserver['name'])
            if ns.zone_set.count() == 1:
                ns.delete()
        # Clear remaining references
        zone.nameservers.clear()

        for nameserver in request.data.getlist('primary_ns'):
            # Check if a hosts with the name exists
            try:
                self.queryset_hosts.get(name=nameserver)
                # Check if there already is a entry in the table
                try:
                    ns = self.queryset_ns.get(name=nameserver)
                    zone.nameservers.add(ns)
                except NameServer.DoesNotExist:
                    ns = NameServer(name=nameserver)
                    ns.save()
                    zone.nameservers.add(ns)
            except Host.DoesNotExist:
                return Response({'ERROR': "No host entry for %s" % nameserver}, status=status.HTTP_404_NOT_FOUND)

        zone.serialno = create_serialno(ZoneList.get_zoneserial())
        zone.primary_ns = request.data.getlist('primary_ns')[0]
        zone.save()
        location = 'zones/%s/nameservers' % query
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


class ModelChangeLogDetail(StrictCRUDMixin, generics.RetrieveAPIView):
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

            
class PlainTextRenderer(renderers.BaseRenderer):
    """
    Custom renderer used for outputting plaintext.
    """
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        return data


class ZoneFileDetail(generics.GenericAPIView):
    """
    Handles a DNS zone file in plaintext.
    All models should have a zf_string method that outputs its relevant data.

    get:
    Generate zonefile for a given zone.
    """
    queryset = Zone.objects.all()
    renderer_classes = (PlainTextRenderer, )

    def get(self, request, *args, **kwargs):
        zone = get_object_or_404(Zone, name=self.kwargs['pk'])
        zonefile = ZoneFile(zone)
        return Response(zonefile.generate())
