from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from mreg.models import Hosts
from mreg.api.v1.serializers import HostsSerializer


@api_view(['GET', 'POST'])
def host_list(request, format=None):
    """ List all hosts, or create a new host """
    if request.method == 'GET':
        hosts = Hosts.objects.all()
        serializer = HostsSerializer(hosts, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        serializer = HostsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def host_detail(request, pk, format=None):
    """ Retrieve, update or delete a host """
    try:
        host = Hosts.objects.get(pk=pk)
    except Hosts.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = HostsSerializer(host)
        return Response(serializer.data)
    elif request.method == 'PUT':
        # data = JSONParser().parse(request)
        serializer = HostsSerializer(host, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'DELETE':
        host.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
