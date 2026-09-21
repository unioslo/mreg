from .views import MregListCreateAPIView, MregRetrieveUpdateDestroyAPIView
from mreg.api.errors import Conflict
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
    # The detail endpoint (labels/<pk>) keys on pk, not name, so Location must too.
    location_lookup_field = "pk"

    def post(self, request, *args, **kwargs):
        existing = self.get_object_from_request(request)
        if existing:
            raise Conflict(f"Label name '{existing.name}' already in use")
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
