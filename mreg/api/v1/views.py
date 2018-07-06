from rest_framework import generics, status, mixins
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

    def get(self, request):
        serializer = HostsNameSerializer(self.get_queryset(), many=True)
        return Response(serializer.data)

    def post(self, request):
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

    def patch(self, request, *args, **kwargs):
        query = self.kwargs['pk']
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


class IpaddressDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Ipaddress.objects.all()
    serializer_class = IpaddressSerializer


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


class SubnetsDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Subnets.objects.all()
    serializer_class = SubnetsSerializer


class TxtList(generics.ListCreateAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


class TxtDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Txt.objects.all()
    serializer_class = TxtSerializer


class ZonesList(generics.ListCreateAPIView):
    queryset = Zones.objects.all()
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
        data['primary_ns'] = request.data['ns'][0]
        data['serialno'] = "%s%02d" % (time.strftime('%Y%m%d'), self.count)
        ZonesList.count += 1

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers={'Location': '/zones/%s' % data['name']})


class ZonesDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Zones.objects.all()
    serializer_class = ZonesSerializer

    # TODO: Implement authentication
    def get_object(self, queryset=queryset):
        query=self.kwargs['pk']
        try:
            zone = queryset.get(name=query)
            return zone
        except Zones.DoesNotExist:
            raise Http404

    # TODO: Implement authentication
    def patch(self, request, *args, **kwargs):
        query = self.kwargs['pk']

        if "name" in request.data:
            content = {'ERROR': 'Not allowed to changed name'}
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
            serializer = ZonesSerializer(zone, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                location = '/zones/' + zone.name
                return Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
        except Zones.DoesNotExist:
            raise Http404

