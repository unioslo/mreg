from rest_framework import status
from rest_framework.response import Response

from mreg.api.v1.views import (
    MregListCreateAPIView,
    MregRetrieveUpdateDestroyAPIView,
)
from mreg.api.permissions import IsGrantedNetGroupRegexPermission
from mreg.models import (Host, BACnetID)
from . import serializers

from .filters import BACnetIDFilterSet


class BACnetIDList(MregListCreateAPIView):
    queryset = BACnetID.objects.order_by('id')
    serializer_class = serializers.BACnetIDSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission, )
    lookup_field = 'id'
    filterset_fields = 'id'
    filter_class = BACnetIDFilterSet

    def post(self, request, *args, **kwargs):
        # request.data is immutable
        data = request.data.copy()

        # if no ID value was supplied, pick the next available ID value
        if 'id' not in data:
            data['id'] = BACnetID.first_unused_id()
        else:
            # if an ID value was supplied, and it is already in use, return 409 conflict instead of the default 400 bad request
            if BACnetID.objects.filter(id=data['id']).exists():
                return Response(status=status.HTTP_409_CONFLICT)

        try:
            # allow clients to supply a hostname instead of a host id
            host = None
            if 'hostname' in data:
                host = Host.objects.get(name=data['hostname'])
                data['host'] = host.id
            elif 'host' in data:
                host = Host.objects.get(id=data['host'])
            # if a host was supplied and that host already has a BACnet ID, return 409 conflict instead of the default 400 bad request
            if host and hasattr(host,'bacnetid'):
                content = {'ERROR': 'The host already has a BACnet ID.'}
                return Response(content, status=status.HTTP_409_CONFLICT)
        except Host.DoesNotExist:
            content = {'ERROR': 'The host does not exist.'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        # validate the data
        obj = BACnetID()
        ser = serializers.BACnetIDSerializer(obj, data=data)
        if ser.is_valid(raise_exception=True):
            # create a new object
            self.perform_create(ser)
            location = request.path + str(obj.id)
            return Response(status=status.HTTP_201_CREATED, headers={'Location': location})


class BACnetIDDetail(MregRetrieveUpdateDestroyAPIView):
    queryset = BACnetID.objects.all()
    serializer_class = serializers.BACnetIDSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission, )
    lookup_field = 'id'

    # Don't allow patch or put requests
    def patch(self, request, *args, **kwargs):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
