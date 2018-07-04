from rest_framework import generics, status, mixins
from django.http import Http404
from mreg.models import *
from mreg.api.v1.serializers import *
from rest_framework_extensions.etag.mixins import ETAGMixin
from rest_framework.response import Response
from rest_framework_extensions.etag.decorators import etag
import ipaddress


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


class HostList(generics.ListCreateAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer


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
                return host
            except Ipaddress.DoesNotExist:
                raise Http404
        except ValueError:
            try:
                host = queryset.get(name=query)
                return host
            except Hosts.DoesNotExist:
                raise Http404

    def patch(self, request, *args, **kwargs):
        query = self.kwargs['pk']
        try:
            host = Hosts.objects.get(name=query)
            serializer = HostsSerializer(host, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                location = '/hosts/' + host.name
                response = Response(serializer.data, status=status.HTTP_204_NO_CONTENT, headers={'Location': location})
                return response
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


class ZonesDetail(ETAGMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Zones.objects.all()
    serializer_class = ZonesSerializer
