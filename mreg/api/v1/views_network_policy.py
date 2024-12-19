from django.db import transaction
from django.urls import reverse

from rest_framework import generics, exceptions, status, response
from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, Community
from mreg.api.v1.serializers import (
    NetworkPolicySerializer,
    NetworkPolicyAttributeSerializer,
    CommunitySerializer
)
from mreg.api.v1.views import JSONContentTypeMixin
from mreg.api.permissions import IsGrantedNetGroupRegexPermission, IsSuperOrNetworkAdminMember

BASE_PATH = '/api/v1/networkpolicies/'

class NetworkPolicyList(JSONContentTypeMixin, generics.ListCreateAPIView):
    queryset = NetworkPolicy.objects.all()
    serializer_class = NetworkPolicySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission,)
    ordering_fields = ('id',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            network_policy = serializer.save()
        headers = self.get_success_headers(serializer.data)

        # Dynamically generate the Location URL
        headers['Location'] = request.build_absolute_uri(
            reverse('networkpolicy-detail', kwargs={'pk': network_policy.id})
        )
        return response.Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
    
class NetworkPolicyDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NetworkPolicy.objects.all()
    serializer_class = NetworkPolicySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission,)

    def perform_update(self, serializer):
        with transaction.atomic():
            serializer.save()

    def perform_destroy(self, instance):
        with transaction.atomic():
            instance.delete()

class NetworkPolicyAttributeList(JSONContentTypeMixin, generics.ListCreateAPIView):
    queryset = NetworkPolicyAttribute.objects.all()
    serializer_class = NetworkPolicyAttributeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)
    ordering_fields = ('id',)

class NetworkPolicyAttributeDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NetworkPolicyAttribute.objects.all()
    serializer_class = NetworkPolicyAttributeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)

class NetworkCommunityList(JSONContentTypeMixin, generics.ListCreateAPIView):
    serializer_class = CommunitySerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)

    def get_queryset(self):
        policy_pk = self.kwargs.get('pk')
        return Community.objects.filter(policy__pk=policy_pk).order_by('id')

    def perform_create(self, serializer):
        policy_pk = self.kwargs.get('pk')

        # Ensure the NetworkPolicy exists, even though the queryset has already done this
        # This is in case the NetworkPolicy is deleted between the time the queryset is called and
        # the time this create is called
        try:
            policy = NetworkPolicy.objects.get(pk=policy_pk)
        except NetworkPolicy.DoesNotExist: # pragma: no cover
            raise exceptions.NotFound("NetworkPolicy not found.")
        serializer.save(policy=policy)

# Retrieve, update, or delete a specific Community under a specific NetworkPolicy
class NetworkCommunityDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CommunitySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission,)

    def get_queryset(self):
        policy_pk = self.kwargs.get('pk')
        return Community.objects.filter(policy__pk=policy_pk).order_by('id')

    def get_object(self):
        queryset = self.get_queryset()
        cpk = self.kwargs.get('cpk')
        obj = generics.get_object_or_404(queryset, pk=cpk)
        return obj
