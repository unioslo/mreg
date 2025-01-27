from django.db import transaction
from django.urls import reverse

from rest_framework import generics, exceptions, status, response
from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, Community
from mreg.models.host import Host
from mreg.api.v1.serializers import (
    NetworkPolicySerializer,
    NetworkPolicyAttributeSerializer,
    CommunitySerializer,
    HostSerializer,
)

from mreg.api.v1.filters import NetworkPolicyAttributeFilterSet, NetworkPolicyFilterSet, CommunityFilterSet, HostFilterSet

from mreg.api.v1.views import JSONContentTypeMixin
from mreg.api.permissions import IsGrantedNetGroupRegexPermission, IsSuperOrNetworkAdminMember

class NetworkPolicyList(JSONContentTypeMixin, generics.ListCreateAPIView):
    queryset = NetworkPolicy.objects.all()
    serializer_class = NetworkPolicySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission,)
    ordering_fields = ('id',)
    filterset_class = NetworkPolicyFilterSet

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
    filterset_class = NetworkPolicyAttributeFilterSet
    ordering_fields = ('id',)

class NetworkPolicyAttributeDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NetworkPolicyAttribute.objects.all()
    serializer_class = NetworkPolicyAttributeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)

class NetworkCommunityList(JSONContentTypeMixin, generics.ListCreateAPIView):
    serializer_class = CommunitySerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)
    filterset_class = CommunityFilterSet

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

# Retrieve, update, or delete a specific Community under a specific Network
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

class HostInCommunityMixin(JSONContentTypeMixin):
    def get_policy_and_community(self):
        policy_pk = self.kwargs.get('pk') # type: ignore
        cpk = self.kwargs.get('cpk') # type: ignore

        try:
            policy = NetworkPolicy.objects.get(pk=policy_pk)
        except NetworkPolicy.DoesNotExist:
            raise exceptions.NotFound("NetworkPolicy not found.")
        
        try:
            community = Community.objects.get(pk=cpk)
        except Community.DoesNotExist:
            raise exceptions.NotFound("Community not found.")
        
        if community.policy != policy:
            raise exceptions.NotFound("Community does not belong to the requested policy.")
        
        return policy, community

# List all hosts in a specific community, or add a host to a community
class NetworkCommunityHostList(HostInCommunityMixin, generics.ListCreateAPIView):
    serializer_class = HostSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission,IsSuperOrNetworkAdminMember)

    def get_queryset(self):
        # Retrieve community via helper. The policy is not used directly here.
        _, community = self.get_policy_and_community()
        return HostFilterSet(data=self.request.GET, queryset=Host.objects.filter(network_community=community).order_by('id')).qs

    def create(self, request, *args, **kwargs):
        _, community = self.get_policy_and_community()
        host_id = request.data.get('id')

        # Ensure host exists. If not, an appropriate 404 is raised.
        host = generics.get_object_or_404(Host, pk=host_id)

        # Attempt to set the community (this method will validate if the host has an IP in a network
        # that is associated with the policy in which this community is defined).
        if not host.set_community(community):
            # If set_community returns False, then either the host has no IP address that matches
            # any network in the community's policy, or there was another problem.            
            raise exceptions.ValidationError("Host cannot be associated with the specified community (IP mismatch?)")

        return response.Response(HostSerializer(host).data, status=status.HTTP_201_CREATED)
    
# Retrieve or delete a specific host in a specific community
class NetworkCommunityHostDetail(HostInCommunityMixin, generics.RetrieveDestroyAPIView):
    serializer_class = HostSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission, IsSuperOrNetworkAdminMember)

    def get_queryset(self):
        _, community = self.get_policy_and_community()
        return HostFilterSet(data=self.request.GET, queryset=Host.objects.filter(network_community=community).order_by('id')).qs

    def get_object(self):
        queryset = self.get_queryset()
        host_id = self.kwargs.get('hostpk')
        obj = generics.get_object_or_404(queryset, pk=host_id)
        return obj
    
    def delete(self, request, *args, **kwargs):
        host = self.get_object()
        host.network_community = None
        host.save()
        return response.Response(status=status.HTTP_204_NO_CONTENT)