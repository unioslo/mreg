from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import ListCreateAPIView, RetrieveDestroyAPIView

from mreg.api.permissions import IsSuperOrPolicyAdminOrReadOnly
from mreg.models.policy import ApprovedModelForPolicy
from mreg.api.v1.serializers import ApprovedModelSerializer
from mreg.api.v1.filters import ApprovedModelFilterSet


from structlog import get_logger

logger = get_logger()

class ApprovedModelForPolicylListCreateAPIView(ListCreateAPIView):
    """API view to list or create ApprovedModelForPolicy entries."""

    queryset = ApprovedModelForPolicy.objects.all().order_by("content_type")
    serializer_class = ApprovedModelSerializer
    permission_classes = [IsSuperOrPolicyAdminOrReadOnly]
    filterset_class = ApprovedModelFilterSet

    def post(self, request, *args, **kwargs):
        # The content_type field is a string, but the ApprovedModel model expects a ContentType ID, so we need to
        # do some mapping. This is done in the serializer, which has a custom to_internal_value method.
        model_name = request.data["content_type"]

        # Note that the serializer here utilizes the to_internal_value method to convert the content_type        
        # string into a ContentType ID. This is a custom method defined in the ApprovedModelSerializer.
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        model_id = serializer.validated_data["content_type"]

        if self.queryset.filter(content_type=model_id).exists():
            content = {"ERROR": f"Resource {model_name} already approved for policies."}
            return Response(content, status=status.HTTP_409_CONFLICT)

        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)



class ApprovedModelForPolicyDetailAPIView(RetrieveDestroyAPIView):
    """API view to retrieve or delete an ApprovedModel entry."""

    queryset = ApprovedModelForPolicy.objects.all()
    serializer_class = ApprovedModelSerializer
    permission_classes = [IsSuperOrPolicyAdminOrReadOnly]