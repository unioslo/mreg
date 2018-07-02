from rest_framework import generics
from mreg.models import *
from mreg.api.v1.serializers import *


class HostList(generics.ListCreateAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer


class HostDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Hosts.objects.all()
    serializer_class = HostsSerializer


class CnameList(generics.ListCreateAPIView):
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer


class CnameDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Cname.objects.all()
    serializer_class = CnameSerializer


class NsList(generics.ListCreateAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer


class NsDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Ns.objects.all()
    serializer_class = NsSerializer
