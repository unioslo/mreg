from rest_framework import generics
from django.http import Http404, QueryDict
from django.core.exceptions import ObjectDoesNotExist
from mreg.models import *
from mreg.api.v1.serializers import *
from rest_framework_extensions.etag.mixins import ETAGMixin
from rest_framework import renderers
from rest_framework.response import Response
from rest_framework import status
from url_filter.filtersets import ModelFilterSet
import ipaddress


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
        resource = self.kwargs['resource']
        try:
            obj = queryset.get(pk=self.kwargs[self.lookup_field])
            serializer = serializer_class(obj, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/%s/%s' % (resource, obj.pk)
                return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except ObjectDoesNotExist:
            raise Http404


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
                    try:
                        Ipaddress.objects.get(ipaddress=ipkey)
                        return Response(status=status.HTTP_409_CONFLICT, data={'ERROR': "IP address already exists"})
                    except Ipaddress.DoesNotExist:
                        # This is good to go
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
        query = self.kwargs['pk']
        try:
            ipaddress.ip_address(query)
            try:
                ip = Ipaddress.objects.get(ipaddress=query)
                host = ip.hostid
            except Ipaddress.DoesNotExist:
                raise Http404
        except ValueError:
            try:
                host = queryset.get(name=query)
            except Host.DoesNotExist:
                raise Http404
        return host

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

        try:
            host = Host.objects.get(name=query)
            serializer = HostSaveSerializer(host, data=request.data, partial=True)

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Host.DoesNotExist:
            raise Http404


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
            if self.queryset.filter(ipaddress=request.data["ipaddress"]).exists():
                content = {'ERROR': 'ip already already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

            else:
                ip = Ipaddress()
                serializer = IpaddressSerializer(ip, data=request.data)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    location = '/ipaddresses/%s' % ip.ipaddress
                    return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class IpaddressDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for the specified address. {id} can be replaced with {ipaddress}.

    patch:
    Update parts of the ipaddress. {id} can be replaced with {ipaddress}.

    delete:
    Delete the specified ipaddress. {id} can be replaced with {ipaddress}.
    """
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer

    def get_object(self, queryset=queryset):
        query = self.kwargs['pk']
        try:
            ipaddress.ip_address(query)
            try:
                found_ip = Ipaddress.objects.get(ipaddress=query)
            except Ipaddress.DoesNotExist:
                raise Http404
        except ValueError:
            content = {'ERROR': 'Not a valid IP address'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        return found_ip

    def patch(self, request, *args, **kwargs):
        query = self.kwargs['pk']

        if "ipaddress" in request.data:
            if self.queryset.filter(ipaddress=request.data["ipaddress"]).exists():
                content = {'ERROR': 'ipaddress already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if "macaddress" in request.data:
            if self.queryset.filter(macaddress=request.data["macaddress"]).exists():
                content = {'ERROR': 'macaddress already registered',
                           'ipaddress': self.queryset.get(macaddress=request.data['macaddress']).ipaddress}
                return Response(content, status=status.HTTP_409_CONFLICT)

        try:
            ip = Ipaddress.objects.get(ipaddress=query)
            serializer = IpaddressSerializer(ip, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/ipaddresses/%s' % ip.ipaddress
                return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Ipaddress.DoesNotExist:
            raise Http404


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
            hosts = network.num_addresses

            overlap = self.overlap_check(network)
            if overlap:
                return Response({'ERROR': 'Subnet overlaps with: {}'.format(network.supernet().with_prefixlen)},
                                status=status.HTTP_409_CONFLICT)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            subnet = serializer.create()
            # Changed the default value of reserved if the size of the subnet is too low
            if hosts <= 4:
                subnet.reserved = 2
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

    def overlap_check(self, subnet):
        """
        Recursively checks supernets for current subnet to look for overlap with existing entries.
        If an entry is found it returns True (Overlap = True).
        It will keep searching until it reaches a prefix length of 16 bits, which is
        usually low enough to cover all relevant IPs. If you have more available addresses
        than e.g 192.168.***.***, reduce the prefix length limit.
        """
        if subnet.prefixlen < 16:
            return False
        if self.queryset.filter(range=subnet.supernet().with_prefixlen).exists():
            return True

        return self.overlap_check(subnet.supernet())


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

        try:
            subnet = Subnet.objects.get(range=iprange)
        except Subnet.DoesNotExist:
            raise Http404
        serializer = self.get_serializer(subnet)

        # Returns a list of used IP addresses on a given subnet.
        if request.META.get('QUERY_STRING') == 'used_list':
            used_ipaddresses = self.get_used_ipaddresses_on_subnet(serializer.data)
            return Response(used_ipaddresses, status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'unused_list':
            unused_ipaddresses = self.get_unused_ipaddresses_on_subnet(serializer.data)
            return Response(unused_ipaddresses, status=status.HTTP_200_OK)
        elif request.META.get('QUERY_STRING') == 'first_unused':
            ip = self.get_first_unused(serializer.data)
            if ip:
                return Response(ip, status=status.HTTP_200_OK)
            else:
                content = {'ERROR': 'No available IPs'}
                return Response(content, status=status.HTTP_404_NOT_FOUND)

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

        try:
            subnet = Subnet.objects.get(range=iprange)

            serializer = self.get_serializer(subnet, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            location = '/subnets/%s' % iprange
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Subnet.DoesNotExist:
            raise Http404

    def delete(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)

        valid_range = self.is_range(iprange)
        if not valid_range:
            return valid_range

        used_ipaddresses = self.get_used_ipaddresses_on_subnet(iprange)
        if used_ipaddresses:
            return Response({'ERROR': 'Subnet contains IP addresses that are in use'}, status=status.HTTP_409_CONFLICT)

        try:
            found_subnet = Subnet.objects.get(range=iprange)

            found_subnet.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Subnet.DoesNotExist:
            raise Http404

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

    def _get_used_ippaddresses_on_subnet(self, subnet):
        """
        Takes a subnet serializer data dict, and returns which ip-addresses on the subnet are used.
        """
        network = ipaddress.ip_network(subnet['range'])
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        ips = Ipaddress.objects.filter(ipaddress__gt=from_ip)
        # XXX:  __lt does not work correctly with sqlite :( postgres is OK.
        ips = ips.filter(ipaddress__lt=to_ip)
        used = {ipaddress.ip_address(i.ipaddress) for i in ips}
        return used

    def get_used_ipaddresses_on_subnet(self, subnet):
        """
        Takes a subnet serializer data dict, and returns which ip-addresses on the subnet are used.
        """
        used = self._get_used_ippaddresses_on_subnet(subnet)
        return map(str,sorted(used))

    def get_unused_ipaddresses_on_subnet(self, subnet):
        """
        Takes a subnet serializer data dict, and returns which ip-addresses on the subnet are unused.
        """
        network = ipaddress.ip_network(subnet['range'])
        subnet_ips = []
        if isinstance(network, ipaddress.IPv6Network):
            # Getting all availible IPs for a ipv6 prefix can easily cause
            # the webserver to hang due to lots and lots of IPs. Instead limit
            # to the first 4000 hosts. Should probably be configurable.
            for i, ip in zip(range(4000), network.hosts()):
                subnet_ips.append(ip)
        else:
            subnet_ips = list(network.hosts())

        subnet_ips = set(subnet_ips[subnet['reserved']:])
        used = self._get_used_ippaddresses_on_subnet(subnet)
        unused = subnet_ips - used
        return map(str,sorted(unused))

    def get_first_unused(self, subnet):
        """
        Return the first unused IP found, if any.
        """

        used = self._get_used_ippaddresses_on_subnet(subnet)
        # Get the first unused address without using
        # get_unused_ipaddresses_on_subnet() as it is quite slow if the subnet
        # is large.
        network = ipaddress.ip_network(subnet['range'])
        i = 0
        for ip in network.hosts():
            if i < subnet['reserved']:
                i += 1
                continue
            if ip not in used:
                return str(ip)
        return None

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

        try:
            zone = Zone.objects.get(name=query)
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
        except Zone.DoesNotExist:
            raise Http404

    def delete(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)
        except Zone.DoesNotExist:
            raise Http404

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
        try:
            zone = self.get_queryset().get(name=query)
            return Response([ns['name'] for ns in zone.nameservers.values()], status=status.HTTP_200_OK)
        except Zone.DoesNotExist:
            raise Http404

    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)

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
        except Zone.DoesNotExist:
            raise Http404
            
            
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
        zone = self.get_queryset().get(name=self.kwargs['pk'])
        # Print info about Zone and its nameservers
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # Print info about hosts and their corresponding data
        data += ';\n; Host addresses\n;\n'
        hosts = Host.objects.filter(zoneid=zone.zoneid)
        for host in hosts:
            for ip in host.ipaddress.all():
                data += ip.zf_string(zone.name)
            if host.hinfo is not None:
                data += host.hinfo.zf_string(zone.name)
            if host.loc is not None:
                data += host.loc_string(zone.name)
            for cname in host.cname.all():
                data += cname.zf_string(zone.name)
            for txt in host.txt.all():
                data += txt.zf_string(zone.name)
        # Print misc entries
        data += ';\n; Name authority pointers\n;\n'
        naptrs = Naptr.objects.filter(zoneid=zone.zoneid)
        for naptr in naptrs:
            data += naptr.zf_string(zone.name)
        data += ';\n; Pointers\n;\n'
        ptroverrides = PtrOverride.objects.all()
        for ptroverride in ptroverrides:
            data += ptroverride.zf_string
        data += ';\n; Services\n;\n'
        srvs = Srv.objects.filter(zoneid=zone.zoneid)
        for srv in srvs:
            data += srv.zf_string(zone.name)
        return Response(data)

