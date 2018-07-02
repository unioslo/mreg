from django.http import Http404
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from mreg.models import Hosts
from mreg.api.v1.serializers import HostsSerializer


class HostList(APIView):
    """
    List all hosts, or create a new host.
    """

    def get(self, request, format=None):
        hosts = Hosts.objects.all()
        serializer = HostsSerializer(hosts, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = HostsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class HostDetail(APIView):
    """
    Retrieve, update or delete a host instance.
    """

    def get_object(self, pk):
        try:
            return Hosts.objects.get(pk=pk)
        except Hosts.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        host = self.get_object(pk)
        serializer = HostsSerializer(host)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        host = self.get_object(pk)
        serializer = HostsSerializer(host, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        host = self.get_object(pk)
        host.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
