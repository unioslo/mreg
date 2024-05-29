from rest_framework import status
from rest_framework.response import Response

from .views import MregListCreateAPIView, MregRetrieveUpdateDestroyAPIView
from mreg.models.base import Label
from mreg.api.permissions import IsSuperOrAdminOrReadOnly

from mreg.mixins import LowerCaseLookupMixin
from . import serializers

from .filters import LabelFilterSet


class LabelList(MregListCreateAPIView, LowerCaseLookupMixin):
    queryset = Label.objects.all()
    serializer_class = serializers.LabelSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)
    filterset_class = LabelFilterSet
    lookup_field = "name"

    def post(self, request, *args, **kwargs):        
        if self.get_object_from_request(request):
            content = {"ERROR": "Label name already in use"}
            return Response(content, status=status.HTTP_409_CONFLICT)
        return super().post(request, *args, **kwargs)


class LabelDetail(LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):
    """
    get:
    Returns details for a Label.

    patch:
    Update parts of a Label.

    delete:
    Delete a Label.
    """

    queryset = Label.objects.all()
    serializer_class = serializers.LabelSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)


class LabelDetailByName(LowerCaseLookupMixin, MregRetrieveUpdateDestroyAPIView):
    queryset = Label.objects.all()
    serializer_class = serializers.LabelSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)
    filterset_class = LabelFilterSet
    lookup_field = "name"
