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
import time


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
    """Applies stricter handling of HTTP requests and responses"""

    def patch(self, request, *args, **kwargs):
        """PATCH should return empty body, 204 - No Content, and location of object"""
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


class HinfoPresetList(generics.ListCreateAPIView):
    queryset = HinfoPreset.objects.all()
    serializer_class = HinfoPresetSerializer

    def get_queryset(self):
        qs = super(HinfoPresetList, self).get_queryset()
        return HinfoFilterSet(data=self.request.GET, queryset=qs).filter()


class HinfoPresetDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = HinfoPreset.objects.all()
    serializer_class = HinfoPresetSerializer


class HostList(generics.GenericAPIView):
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def get_queryset(self):
        qs = super(HostList, self).get_queryset()
        return HostFilterSet(data=self.request.GET, queryset=qs).filter()

    def get(self, request, *args, **kwargs):
        serializer = HostNameSerializer(self.get_queryset(), many=True)
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
            hostserializer = HostSerializer(host, data=request.data)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class HostDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Host.objects.all()
    serializer_class = HostSerializer

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
            except Host.DoesNotExist:
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
            host = Host.objects.get(name=query)
            serializer = HostSaveSerializer(host, data=request.data, partial=True)

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/hosts/%s' % host.name
                return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Host.DoesNotExist:
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
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer

    def get_queryset(self):
        qs = super(NaptrList, self).get_queryset()
        return NaptrFilterSet(data=self.request.GET, queryset=qs).filter()


class NaptrDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer


class NameServerList(generics.ListCreateAPIView):
    queryset = NameServer.objects.all()
    serializer_class = NameServerSerializer

    def get_queryset(self):
        qs = super(NameServerList, self).get_queryset()
        return NameServerFilterSet(data=self.request.GET, queryset=qs).filter()


class NameServerDetail(StrictCRUDMixin, ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NameServer.objects.all()
    serializer_class = NameServerSerializer


class PtrOverrideList(generics.ListCreateAPIView):
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer

    def get_queryset(self):
        qs = super(PtrOverrideList, self).get_queryset()
        return PtrOverrideFilterSet(data=self.request.GET, queryset=qs).filter()


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


class SubnetList(generics.ListCreateAPIView):
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
            if hosts <= 4:
                subnet.reserved = 2
            subnet.save()
            location = '/subnets/%s' % request.data
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})

        except ValueError as error:
            return Response({'ERROR': str(error)}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        qs = super(SubnetList, self).get_queryset()
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


class SubnetDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Subnet.objects.all()
    serializer_class = SubnetSerializer

    lookup_field = 'range'

    def get(self, request, queryset=queryset, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)

        invalid_range = self.isnt_range(iprange)
        if invalid_range:
            return invalid_range

        # Returns a list of used ipaddresses on a given subnet.
        if request.META.get('QUERY_STRING') == 'used_list':
            used_ipaddresses = self.get_used_ipaddresses_on_subnet(iprange)
            return Response(used_ipaddresses, status=status.HTTP_200_OK)

        try:
            found_subnet = Subnet.objects.get(range=iprange)
        except Subnet.DoesNotExist:

            raise Http404

        serializer = self.get_serializer(found_subnet)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(iprange)
        if invalid_range:
            return invalid_range

        if 'range' in request.data:
            if self.queryset.filter(range=request.data['range']).exists():
                content = {'ERROR': 'subnet already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        try:
            subnet = Subnet.objects.get(range=iprange)

            serializer = self.get_serializer(subnet, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            location = '/subnets/%s' % subnet.range
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Subnet.DoesNotExist:
            raise Http404

    def delete(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        iprange = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(iprange)
        if invalid_range:
            return invalid_range

        used_ipaddresses = self.get_used_ipaddresses_on_subnet(iprange)
        if used_ipaddresses:
            return Response({'ERROR': 'Subnet contains IP addresses that are in use'}, status=status.HTTP_409_CONFLICT)

        try:
            found_subnet = Subnet.objects.get(range=iprange)

            found_subnet.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Subnet.DoesNotExist:
            raise Http404

    def isnt_range(self, iprange):
        try:
            ipaddress.ip_network(iprange)
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


class ZoneList(generics.ListCreateAPIView):
    queryset = Zone.objects.all()
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
        qs = super(ZoneList, self).get_queryset()
        return ZoneFilterSet(data=self.request.GET, queryset=qs).filter()

    # TODO: Implement authentication
    def post(self, request, *args, **kwargs):
        if self.queryset.filter(name=request.data["name"]).exists():
            content = {'ERROR': 'Zone name already in use'}
            return Response(content, status=status.HTTP_409_CONFLICT)

        data = request.data.copy()
        data['primary_ns'] = data['nameservers'] if isinstance(request.data['nameservers'], str) else data['nameservers'][0]
        data['serialno'] = create_serialno(ZoneList.get_zoneserial())

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        zone = serializer.create()
        zone.save()

        for nameserver in request.POST.getlist('nameservers'):
            try:
                ns = self.queryset_ns.get(name=nameserver)
                zone.nameservers.add(ns.nsid)
            except NameServer.DoesNotExist:
                ns = NameServer(name=nameserver)
                ns.save()
                zone.nameservers.add(ns.nsid)
        zone.save()
        return Response(status=status.HTTP_201_CREATED, headers={'Location': '/zones/%s' % data['name']})


class ZoneDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Zone.objects.all()
    queryset_ns = NameServer.objects.all()
    serializer_class = ZoneSerializer
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

        if "nameservers" in request.data:
            content = {'ERROR': 'Not allowed to patch nameservers, use zones/{}/nameservers'.format(query)}
            return Response(content, status=status.HTTP_403_FORBIDDEN)

        try:
            zone = Zone.objects.get(name=query)
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


class ZoneNameServerDetail(ETAGMixin, generics.GenericAPIView):
    queryset = Zone.objects.all()
    queryset_ns = NameServer.objects.all()
    serializer_class = ZoneSerializer

    lookup_field = 'name'

    # TODO Authorization
    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)
            return Response([ns['name'] for ns in zone.nameservers.values()], status=status.HTTP_200_OK)
        except Zone.DoesNotExist:
            raise Http404

    # TODO Authorization
    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.get_queryset().get(name=query)

            if 'nameservers' not in request.data:
                return Response({'ERROR': 'No NS name found in body'}, status=status.HTTP_400_BAD_REQUEST)

            # Check existing  nameservers and delete them if this zone is the only one that uses them
            for nameserver in zone.nameservers.values():
                ns = self.queryset_ns.get(name=nameserver['name'])
                if ns.zone_set.count() == 1:
                    ns.delete()
            # Clear remaining references
            zone.nameservers.clear()

            for nameserver in request.data.getlist('nameservers'):
                try:
                    ns = self.queryset_ns.get(name=nameserver)
                    zone.nameservers.add(ns)
                except NameServer.DoesNotExist:
                    ns = NameServer(name=nameserver)
                    ns.save()
                    zone.nameservers.add(ns.nsid)

            zone.serialno = create_serialno(ZoneList.get_zoneserial())
            zone.primary_ns = request.data.getlist('nameservers')[0]
            zone.save()
            location = 'zones/%s/nameservers' % query
            return Response(status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Zone.DoesNotExist:
            raise Http404
            
            
class ModelChangeLogList(generics.ListAPIView):
    queryset = ModelChangeLog.objects.all()
    serializer_class = ModelChangeLogSerializer

    def get(self, request, *args, **kwargs):
        # Return a list of available tables there are logged histories for.
        tables = list(set([value['table_name'] for value in self.queryset.values('table_name')]))
        return Response(data=tables, status=status.HTTP_200_OK)


class ModelChangeLogDetail(StrictCRUDMixin, generics.RetrieveAPIView):
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
    media_type = 'text/plain'
    format = 'txt'

    def render(self, data, media_type=None, renderer_context=None):
        return data


class ZoneFileDetail(generics.GenericAPIView):
    queryset = Zone.objects.all()
    renderer_classes = (PlainTextRenderer, )

    def get(self, request, *args, **kwargs):
        zone = self.get_queryset().get(name=self.kwargs['pk'])
        data = zone.zf_string()
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string()
        data += ';\n; Host addresses\n;\n'
        hosts = Host.objects.all()
        for host in hosts:
            for ip in host.ipaddress.all():
                data += ip.zf_string()
            if host.hinfo is not None:
                data += host.hinfo.zf_string()
            if host.loc is not None:
                data += host.loc_string()
            for cname in host.cname.all():
                data += cname.zf_string()
            for txt in host.txt.all():
                data += txt.zf_string()
        data += ';\n; Name authority pointers\n;\n'
        naptrs = Naptr.objects.all()
        for naptr in naptrs:
            data += naptr.zf_string()
        data += ';\n; Pointers\n;\n'
        ptroverrides = PtrOverride.objects.all()
        for ptroverride in ptroverrides:
            data += ptroverride.zf_string()
        data += ';\n; Services\n;\n'
        srvs = Srv.objects.all()
        for srv in srvs:
            data += srv.zf_string()
        return Response(data)

