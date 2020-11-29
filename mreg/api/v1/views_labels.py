from django.core.exceptions import ValidationError
from django.db.models import Prefetch

from rest_framework import status
from rest_framework.response import Response

from url_filter.filtersets import ModelFilterSet
from .views import MregListCreateAPIView, MregRetrieveUpdateDestroyAPIView
from mreg.models import Label
from mreg.api.permissions import IsSuperOrAdminOrReadOnly
from . import serializers

class LabelFilterSet(ModelFilterSet):
    class Meta:
        model = Label


class LabelList(MregListCreateAPIView):
    queryset = Label.objects.all()
    serializer_class = serializers.LabelSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)

    def get_queryset(self):
        qs = super().get_queryset()
        return LabelFilterSet(data=self.request.GET, queryset=qs).filter()

    def post(self, request, *args, **kwargs):
        if "name" in request.data:
            if self.get_queryset().filter(name=request.data['name']).exists():
                content = {'ERROR': 'Label name already in use'}
                return Response(content, status=status.HTTP_409_CONFLICT)
            if ' ' in request.data['name']:
                content = {'ERROR': "Label name can't contain spaces"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
            if not "description" in request.data or request.data['description'] == '':
                content = {'ERROR': "A description is required for a label"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
        self.lookup_field = 'name'
        return super().post(request, *args, **kwargs)


class LabelDetail(MregRetrieveUpdateDestroyAPIView):
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


class LabelDetailByName(MregRetrieveUpdateDestroyAPIView):
    queryset = Label.objects.all()
    serializer_class = serializers.LabelSerializer
    permission_classes = (IsSuperOrAdminOrReadOnly,)
    lookup_field = 'name'
