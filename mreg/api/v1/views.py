from rest_framework import generics
from rest_framework.renderers import JSONRenderer
from django.http import Http404, QueryDict
from mreg.models import *
from mreg.api.v1.serializers import *
from rest_framework_extensions.etag.mixins import ETAGMixin
from rest_framework.response import Response
from rest_framework import status
import ipaddress, time

class CnameList(generics.ListCreateAPIView):
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer


class CnameDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer


class HinfoPresetsList(generics.ListCreateAPIView):
    queryset = HinfoPresets.objects.all()
    serializer_class = HinfoPresetsSerializer


class HinfoPresetsDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = HinfoPresets.objects.all()
    serializer_class = HinfoPresetsSerializer


class HostList(generics.GenericAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer

    def get(self, request, *args, **kwargs):
        hosts = self.get_queryset()
        if request.GET.get('hostid'):
            hosts = hosts.filter(hostid=request.GET.get('hostid'))
        if request.GET.get('contact'):
            hosts = hosts.filter(contact=request.GET.get('contact'))
        if request.GET.get('ttl'):
            hosts = hosts.filter(ttl=request.GET.get('ttl'))
        if request.GET.get('loc'):
            hosts = hosts.filter(loc=request.GET.get('loc'))
        if request.GET.get('comment'):
            hosts = hosts.filter(comment=request.GET.get('comment'))
        if request.GET.get('hinfo'):
            hosts = hosts.filter(hinfo__hinfoid=request.GET.get('hinfo'))

        serializer = HostsNameSerializer(hosts, many=True)
        return Response(serializer.data)

    # TODO Authentication
    def post(self, request):
        if "name" in request.data:
            if self.queryset.filter(name=request.data["name"]).exists():
                content = {'ERROR': 'name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)

        if 'ipaddress' in request.data:
            ipaddress = request.data['ipaddress']
            hostdata = QueryDict.copy(request.data)
            del hostdata['ipaddress']
            host = Hosts()
            hostserializer = HostsSerializer(host, data=hostdata)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/' + host.name
                ipdata = {'hostid': host.pk, 'ipaddress': ipaddress}
                ip = Ipaddress()
                ipserializer = IpaddressSerializer(ip, data=ipdata)
                if ipserializer.is_valid(raise_exception=True):
                    ipserializer.save()
                return Response(hostserializer.data, status=status.HTTP_201_CREATED, headers={'Location': location})
        else:
            host = Hosts()
            hostserializer = HostsSerializer(host, data=request.data)
            if hostserializer.is_valid(raise_exception=True):
                hostserializer.save()
                location = '/hosts/' + host.name
                return Response(hostserializer.data, status=status.HTTP_201_CREATED, headers={'Location': location})


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
            serializer = HostsSerializer(host, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                location = '/hosts/' + host.name
                return Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Hosts.DoesNotExist:
            raise Http404


class IpaddressList(generics.ListCreateAPIView):
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer

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
                    location = '/ipaddresses/' + ip.ipaddress
                    return Response(serializer.data, status=status.HTTP_201_CREATED, headers={'Location': location})


class IpaddressDetail(generics.RetrieveUpdateDestroyAPIView):
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
                location = '/ipaddresses/' + ip.ipaddress
                return Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Ipaddress.DoesNotExist:
            raise Http404


class NaptrList(generics.ListCreateAPIView):
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer


class NaptrDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Naptr.objects.all()
    serializer_class = NaptrSerializer


class NsList(generics.ListCreateAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer


class NsDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer


class PtrOverrideList(generics.ListCreateAPIView):
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer


class PtrOverrideDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = PtrOverride.objects.all()
    serializer_class = PtrOverrideSerializer


class SrvList(generics.ListCreateAPIView):
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer


class SrvDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Srv.objects.all()
    serializer_class = SrvSerializer


class SubnetsList(generics.ListCreateAPIView):
    queryset = Subnets.objects.all()
    serializer_class = SubnetsSerializer

    def post(self, request, *args, **kwargs):
        try:
            ipaddress.IPv4Network(request.data['range'])
            res = self.create(request, *args, **kwargs)
            return res
        except ipaddress.AddressValueError:
            return Response({'ERROR': 'Not a valid IP address'}, status=status.HTTP_400_BAD_REQUEST)
        except ipaddress.NetmaskValueError:
            return Response({'ERROR': 'Not a valid net mask'}, status=status.HTTP_400_BAD_REQUEST)


class SubnetsDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Subnets.objects.all()
    serializer_class = SubnetsSerializer
    lookup_field = 'range'

    def get(self, queryset=queryset, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        range = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(range)
        if invalid_range: return invalid_range
        try:
            found_subnet = Subnets.objects.get(range=range)
            serializer = self.get_serializer(found_subnet)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Subnets.DoesNotExist:
            raise Http404

    def patch(self, request, *args, **kwargs):
        ip = self.kwargs['ip']
        mask = self.kwargs['range']
        range = '%s/%s' % (ip, mask)
        invalid_range = self.isnt_range(range)
        if invalid_range: return invalid_range
        try:
            subnet = Subnets.objects.get(range=range)
            serializer = self.get_serializer(subnet, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            print(serializer.data)
            location = '/subnets/%s/' % subnet.range
            return Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Subnets.DoesNotExist:
            raise Http404

    def isnt_range(self, range):
        try:
            ipaddress.IPv4Network(range)
            return None
        except ipaddress.AddressValueError:
            return Response({'ERROR': 'Not a valid IP address'}, status=status.HTTP_400_BAD_REQUEST)
        except ipaddress.NetmaskValueError:
            return Response({'ERROR': 'Not a valid net mask'}, status=status.HTTP_400_BAD_REQUEST)



class TxtList(generics.ListCreateAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


class TxtDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


class ZonesList(generics.ListCreateAPIView):
    queryset = Zones.objects.all()
    queryset_ns = Ns.objects.all()
    serializer_class = ZonesSerializer
    count_day = int(time.strftime('%Y%m%d'))
    count = 0

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
                print('ERROR Could not find NS: %s\n' % (nameserver))
                return Response({'ERROR': 'Could not find NS: %s' % (nameserver)}, status=status.HTTP_404_NOT_FOUND)
        zone.save()
        return Response(self.get_serializer(zone).data, status=status.HTTP_201_CREATED, headers={'Location': '/zones/%s' % data['name']})


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
            if self.queryset.filter(zoneid=request.data["zoneid"]).exists() :
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
            return Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Zones.DoesNotExist:
            raise Http404


class ZonesNsDetail(ETAGMixin, generics.GenericAPIView):
    queryset_zones = Zones.objects.all()
    queryset_ns = Ns.objects.all()
    lookup_field = 'name'

    # TODO Authorization
    def get(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.queryset_zones.get(name=query)
            return Response(NsSerializer(zone.nameservers.all(), many=True).data, status=status.HTTP_200_OK)
        except Zones.DoesNotExist:
            raise Http404

    # TODO Authorization
    def patch(self, request, *args, **kwargs):
        query = self.kwargs[self.lookup_field]
        try:
            zone = self.queryset_zones.get(name=query)
            try:
                if self.lookup_field not in request.data:
                    return Response({'ERROR': 'No NS name found in body'}, status=status.HTTP_400_BAD_REQUEST)
                ns = self.queryset_ns.get(name=request.data[self.lookup_field])
                zone.nameservers.add(ns)
                zone.save()
                return Response(ZonesSerializer(zone).data, status=status.HTTP_204_NO_CONTENT)
            except Ns.DoesNotExist:
                return Response({'ERROR': 'Could not find Zone'}, status=status.HTTP_404_NOT_FOUND)
        except Zones.DoesNotExist:
            raise Http404

    # TODO Authorization
    def delete(self, request, *args, **kwargs):
        query = self.kwargs['name']
        try:
            zone = self.queryset_zones.get(name=query)
            try:
                if self.lookup_field not in request.data:
                    return Response({'ERROR': 'No NS name found in body'}, status=status.HTTP_400_BAD_REQUEST)
                ns = self.queryset_ns.get(name=request.data[self.lookup_field])
                zone.nameservers.remove(ns)
                zone.save()
                return Response(ZonesSerializer(zone).data, status=status.HTTP_204_NO_CONTENT)
            except Ns.DoesNotExist:
                return Response({'ERROR': 'Could not find NS'}, status=status.HTTP_404_NOT_FOUND)
        except Zones.DoesNotExist:
            raise Http404