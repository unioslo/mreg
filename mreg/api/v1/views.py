from rest_framework import generics
from django.http import Http404, QueryDict
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from mreg.models import *
from mreg.api.v1.serializers import *
from rest_framework_extensions.etag.mixins import ETAGMixin
from rest_framework.response import Response
from rest_framework import status
from url_filter.filtersets import ModelFilterSet
import ipaddress, time


class CnameFilterSet(ModelFilterSet):
    class Meta(object):
        model = Cname


class HinfoFilterSet(ModelFilterSet):
    class Meta(object):
        model = HinfoPresets


class HostsFilterSet(ModelFilterSet):
    class Meta(object):
        model = Hosts


class IpaddressFilterSet(ModelFilterSet):
    class Meta(object):
        model = Ipaddress


class NaptrFilterSet(ModelFilterSet):
    class Meta(object):
        model = Naptr


class NameserverFilterSet(ModelFilterSet):
    class Meta(object):
        model = Ns


class PtroverrideFilterSet(ModelFilterSet):
    class Meta(object):
        model = PtrOverride


class SrvFilterSet(ModelFilterSet):
    class Meta(object):
        model = Srv


class SubnetFilterSet(ModelFilterSet):
    class Meta(object):
        model = Subnets


class TxtFilterSet(ModelFilterSet):
    class Meta(object):
        model = Txt


class ZoneFilterSet(ModelFilterSet):
    class Meta(object):
        model = Zones


class StrictCRUDMixin(object):
    """Applies stricter handling of HTTP requests and responses"""

    """PATCH should return empty body, 204 - No Content, and location of object"""
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
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer

    def get_queryset(self):
        qs = super(CnameList, self).get_queryset()
        return CnameFilterSet(data=self.request.GET, queryset=qs).filter()


class CnameDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer


class HinfoPresetsList(generics.ListCreateAPIView):
    queryset = HinfoPresets.objects.all()
    serializer_class = HinfoPresetsSerializer

    def get_queryset(self):
        qs = super(HinfoPresetsList, self).get_queryset()
        return HinfoFilterSet(data=self.request.GET, queryset=qs).filter()


class HinfoPresetsDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = HinfoPresets.objects.all()
    serializer_class = HinfoPresetsSerializer


class HostList(generics.GenericAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer

    def get_queryset(self):
        qs = super(HostList, self).get_queryset()
        return HostsFilterSet(data=self.request.GET, queryset=qs).filter()

    def get(self, request, *args, **kwargs):
        serializer = HostsNameSerializer(self.get_queryset(), many=True)
        return Response(serializer.data)

    # TODO Authentication
    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.queryset.filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if 'ipaddress' in request.data:
            ipkey = request.data['ipaddress']
            hostdata = QueryDict.copy(request.data)
            del hostdata['ipaddress']
            host = Hosts()
            hostserializer = HostsSerializer(host, data=hostdata)
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
            host = Hosts()
            hostserializer = HostsSerializer(host, data=request.data)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer

    # TODO Authentication
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
            except Hosts.DoesNotExist:
                raise Http404
        return host

    # TODO Authentication
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
            host = Hosts.objects.get(name=query)
            serializer = HostsSaveSerializer(host, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Hosts.DoesNotExist:
            raise Http404


class IpaddressList(generics.ListCreateAPIView):
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
            if self.queryset.filter(name=request.data["macaddress"]).exists():
                content = {'ERROR': 'macaddress already registered',
                           'ipaddress': self.queryset.filter(macaddress=request.data['macaddress'])}
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
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer

    def get_queryset(self):
        qs = super(NaptrList, self).get_queryset()
        return NaptrFilterSet(data=self.request.GET, queryset=qs).filter()


class NaptrDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer


class NsList(generics.ListCreateAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer

    def get_queryset(self):
        qs = super(NsList, self).get_queryset()
        return NameserverFilterSet(data=self.request.GET, queryset=qs).filter()


class NsDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer


class PtrOverrideList(generics.ListCreateAPIView):
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer

    def get_queryset(self):
        qs = super(PtrOverrideList, self).get_queryset()
        return PtroverrideFilterSet(data=self.request.GET, queryset=qs).filter()


class PtrOverrideDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer


class SrvList(generics.ListCreateAPIView):
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer

    def get_queryset(self):
        qs = super(SrvList, self).get_queryset()
        return SrvFilterSet(data=self.request.GET, queryset=qs).filter()


class SrvDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer


class SubnetsList(generics.ListCreateAPIView):
    queryset = Subnets.objects.all()
    serializer_class = SubnetsSerializer

    def post(self, request, *args, **kwargs):
        try:
            network = ipaddress.ip_network(request.data['range'])
            hosts  = network.num_addresses

            overlap = self.overlap_check(network)
            if overlap:
                return Response({'ERROR': 'Subnet overlaps with: {}'.format(network.supernet().with_prefixlen)},
                                status=status.HTTP_409_CONFLICT)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            subnet = serializer.create()
            if hosts <= 4:
                subnet.reserved = 2
            subnet.save()
            location = '/subnets/%s' % request.data
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})

        except ValueError as error:
            return Response({'ERROR': str(error)}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        qs = super(SubnetsList, self).get_queryset()
        return SubnetFilterSet(data=self.request.GET, queryset=qs).filter()

    def overlap_check(self, subnet):
        """
        Recursively checks supernets for current subnet to look for existing entries.
        If an entry is found it returns True (Overlap = True).
        It will keep searching until it reaches a prefix length of 16 bits, after which there is
        no point searching unless you own an ridiculous amount of IPv4 addresses.
        Can of course be changed at will.
        """
        if subnet.prefixlen < 16:
            return False
        if self.queryset.filter(range=subnet.supernet().with_prefixlen).exists():
            return True

        return self.overlap_check(subnet.supernet())


class SubnetsDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Subnets.objects.all()
    serializer_class = SubnetsSerializer
    lookup_field = 'range'

    def get(self, request, queryset=queryset, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        range = '%s/%s' % (ip, mask)

        invalid_range = self.isnt_range(range)
        if invalid_range:
            return invalid_range

        # Returns a list of used ipaddresses on a given subnet.
        if request.META.get('QUERY_STRING') == 'used_list':
            used_ipaddresses = self.get_used_ipaddresses_on_subnet(range)
            return Response(used_ipaddresses, status=status.HTTP_200_OK)

        try:
            found_subnet = Subnets.objects.get(range=range)
        except Subnets.DoesNotExist:
            raise Http404

        serializer = self.get_serializer(found_subnet)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        range = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(range)
        if invalid_range:
            return invalid_range

        if 'range' in request.data:
            if self.queryset.filter(range=request.data['range']).exists():
                content = {'ERROR': 'subnet already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        try:
            subnet = Subnets.objects.get(range=range)
            serializer = self.get_serializer(subnet, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            location = '/subnets/%s' % subnet.range
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Subnets.DoesNotExist:
            raise Http404

    def delete(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        range = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(range)
        if invalid_range:
            return invalid_range

        used_ipaddresses = self.get_used_ipaddresses_on_subnet(range)
        if used_ipaddresses:
            return Response({'ERROR': 'Subnet contains IP addresses that are in use'}, status=status.HTTP_409_CONFLICT)

        try:
            found_subnet = Subnets.objects.get(range=range)
            found_subnet.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Subnets.DoesNotExist:
            raise Http404

    def isnt_range(self, range):
        try:
            ipaddress.ip_network(range)
            return None
        except ValueError as error:
            return Response({'ERROR': str(error)}, status=status.HTTP_400_BAD_REQUEST)

    def get_used_ipaddresses_on_subnet(self, subnet):
        """
        Takes a valid subnet (ip-range), and checks which ip-addresses on the subnet are used.
        ip_network.hosts() automatically ignores the network and broadcast addresses of the subnet,
        unless the subnet consists of only these two addresses.
        """
        all_ipaddresses = [ipaddress.ip_address(ip_db.ipaddress) for ip_db in Ipaddress.objects.all()]
        network = ipaddress.ip_network(subnet)
        used_ipaddresses = []
        for ip in all_ipaddresses:
            if ip in network:
                used_ipaddresses.append(str(ip))

        return used_ipaddresses


class TxtList(generics.ListCreateAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer

    def get_queryset(self):
        qs = super(TxtList, self).get_queryset()
        return TxtFilterSet(data=self.request.GET, queryset=qs).filter()


class TxtDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


class ZonesList(generics.ListCreateAPIView):
    queryset = Zones.objects.all()
    queryset_ns = Ns.objects.all()
    serializer_class = ZonesSerializer
    count_day = int(time.strftime('%Y%m%d'))
    count = 0

    def get_queryset(self):
        qs = super(ZonesList, self).get_queryset()
        return ZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    # TODO: Implement authentication
    def post(self, request, *args, **kwargs):
        if ZonesList.count_day < int(time.strftime('%Y%m%d')):
            ZonesList.count_day = int(time.strftime('%Y%m%d'))
            ZonesList.count = 0

        if self.queryset.filter(name=request.data["name"]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)

        data = request.data.copy()
        data['primary_ns'] = data['nameservers'] if isinstance(request.data['nameservers'], str) else data['nameservers'][0]
        data['serialno'] = "%s%02d" % (time.strftime('%Y%m%d'), self.count)
        ZonesList.count += 1

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        zone = serializer.create()
        zone.save()

        for nameserver in request.POST.getlist('nameservers'):
            try:
                ns = self.queryset_ns.get(name=nameserver)
                zone.nameservers.add(ns.nsid)
            except Ns.DoesNotExist:
                return Response({'ERROR': 'Could not find NS: %s' % nameserver}, status=status.HTTP_404_NOT_FOUND)
        zone.save()
        return Response(status=status.HTTP_201_CREATED, headers={'Location': '/zones/%s' % data['name']})


class ZonesDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Zones.objects.all()
    serializer_class = ZonesSerializer
    lookup_field = 'name'

    # TODO: Implement authentication
    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        if "name" in request.data:
            content = {'ERROR': 'Not allowed to change name'}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        if "zoneid" in request.data:
            if self.queryset.filter(zoneid=request.data["zoneid"]).exists():
                content = {'ERROR': 'zoneid already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if "serialno" in request.data:
            if self.queryset.filter(serialno=request.data["serialno"]).exists():
                content = {'ERROR': 'serialno already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)
        try:
            zone = Zones.objects.get(name=query)
            serializer = self.get_serializer(zone, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            location = '/zones/%s' % zone.name
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Zones.DoesNotExist:
            raise Http404


class ZonesNsDetail(ETAGMixin, generics.GenericAPIView):
    queryset = Zones.objects.all()
    queryset_ns = Ns.objects.all()
    lookup_field = 'name'

    # TODO Authorization
    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)
            ns_list = []
            for ns in zone.nameservers.values():
                ns_list.append(ns['name'])
            return Response(ns_list, status=status.HTTP_200_OK)
        except Zones.DoesNotExist:
            raise Http404

    # TODO Authorization
    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)
            if 'nameservers' not in request.data:
                return Response({'ERROR': 'No NS name found in body'}, status=status.HTTP_400_BAD_REQUEST)
            zone.nameservers.clear()
            for nameserver in request.data.getlist('nameservers'):
                try:
                    ns = self.queryset_ns.get(name=nameserver)
                    zone.nameservers.add(ns)
                except Ns.DoesNotExist:
                    raise Http404
            zone.save()
            location = 'zones/%s/nameservers' % query
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Zones.DoesNotExist:
            raise Http404