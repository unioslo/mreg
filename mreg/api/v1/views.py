from rest_framework import generics
from mreg.models import *
from mreg.api.v1.serializers import *
from rest_framework_extensions.etag.mixins import ETAGMixin


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
