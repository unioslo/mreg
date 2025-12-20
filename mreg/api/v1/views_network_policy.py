from django.db import transaction
from django.urls import reverse

from rest_framework import generics, exceptions, status, response
from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, Community, HostCommunityMapping
from mreg.models.network import Network
from mreg.models.host import Host, Ipaddress
from mreg.api.v1.serializers import (
    NetworkPolicySerializer,
    NetworkPolicyAttributeSerializer,
    CommunitySerializer,
    HostSerializer,
)

from mreg.api.v1.filters import (
    NetworkPolicyAttributeFilterSet,
    NetworkPolicyFilterSet,
    CommunityFilterSet,
    HostFilterSet,
)

from mreg.api.errors import ValidationError409

from mreg.api.v1.views import JSONContentTypeMixin, HistoryLog
from mreg.api.permissions import IsGrantedNetGroupRegexPermission, IsSuperOrNetworkAdminMember
from mreg.api.v1.endpoints import URL

class CommunityLogMixin(HistoryLog):
    log_resource = "community"
    model = Community
    foreign_key_name = "community"

    @staticmethod
    def manipulate_data(action, serializer, data, orig_data):
        """Manipulate the data for the history log."""
        pass

class HostCommunityMappingLogMixin(HistoryLog):
    log_resource = "community"
    model = HostCommunityMapping
    foreign_key_name = "host"

    @staticmethod
    def manipulate_data(action, serializer, data, orig_data):
        """Manipulate the data for the history log."""
        pass  # pragma: no cover
        # Not covered: Empty implementation required by HistoryLog parent class.
        # No data manipulation needed for host-community mapping history.


class NetworkPolicyList(JSONContentTypeMixin, generics.ListCreateAPIView):
    queryset = NetworkPolicy.objects.all().order_by("id")
    serializer_class = NetworkPolicySerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)
    ordering_fields = ("id",)
    filterset_class = NetworkPolicyFilterSet

    def create(self, request, *args, **kwargs):
        # Note, we can't use the serializer's is_valid method here because that'll raise a 400 exception
        # if the data is invalid (even if something exists). We need to catch that and raise a 409 instead.
        name = request.data.get("name")
        if not name:
            raise exceptions.ValidationError("'name' is required.")

        try:
            NetworkPolicy.objects.get(name=name)
            raise ValidationError409(detail=f"NetworkPolicy with the name '{name}' already exists.")
        except NetworkPolicy.DoesNotExist:
            pass

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            network_policy = serializer.save()
        headers = self.get_success_headers(serializer.data)

        # Dynamically generate the Location URL
        headers["Location"] = request.build_absolute_uri(
            reverse(URL.NetworkPolicy.DETAIL, kwargs={"pk": network_policy.id})
        )
        return response.Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class NetworkPolicyDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NetworkPolicy.objects.all().order_by("id")
    serializer_class = NetworkPolicySerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)

    def perform_update(self, serializer):
        with transaction.atomic():
            serializer.save()

    def perform_destroy(self, instance):
        with transaction.atomic():
            instance.delete()


class NetworkPolicyAttributeList(JSONContentTypeMixin, generics.ListCreateAPIView):
    queryset = NetworkPolicyAttribute.objects.all().order_by("id")
    serializer_class = NetworkPolicyAttributeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)
    filterset_class = NetworkPolicyAttributeFilterSet
    ordering_fields = ("id",)


    def create(self, request, *args, **kwargs):
        name = request.data.get("name")
        if not name:
            raise exceptions.ValidationError("'name' is required.")
        
        try:
            NetworkPolicyAttribute.objects.get(name=name)
            raise ValidationError409(detail=f"NetworkPolicyAttribute with the name '{name}' already exists.")
        except NetworkPolicyAttribute.DoesNotExist:
            pass

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            network_policy_attribute = serializer.save()

        headers = self.get_success_headers(serializer.data)
        headers["Location"] = request.build_absolute_uri(
            reverse(URL.NetworkPolicy.ATTRIBUTE_DETAIL, kwargs={"pk": network_policy_attribute.id})
        )

        return response.Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class NetworkPolicyAttributeDetail(JSONContentTypeMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = NetworkPolicyAttribute.objects.all().order_by("id")
    serializer_class = NetworkPolicyAttributeSerializer
    permission_classes = (IsSuperOrNetworkAdminMember,)


class NetworkCommunityList(JSONContentTypeMixin, CommunityLogMixin, generics.ListCreateAPIView):
    serializer_class = CommunitySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission | IsSuperOrNetworkAdminMember,)
    filterset_class = CommunityFilterSet

    def get_queryset(self):
        network = self.kwargs.get("network")
        return Community.objects.filter(network__network=network).order_by("id")

    def create(self, request, *args, **kwargs):
        network = self.kwargs.get("network")

        if not network: # pragma: no cover (we are using this as part of the URL)
            raise exceptions.ValidationError("A network is required.")

        # Note, we can't use the serializer's is_valid method here because that'll raise a 400 exception
        # if the data is invalid (even if something exists). We need to catch that and raise a 409 instead.
        name = request.data.get("name")
        if not name:
            raise exceptions.ValidationError("'name' is required.")

        try:
            network = Network.objects.get(network=network)
        except Network.DoesNotExist:  # pragma: no cover
            raise exceptions.NotFound("Network not found.")

        # We do not have to worry about case sensitivity here, as the LowerCaseManager for the model will handle that.
        if Community.objects.filter(name=name, network=network).exists():
            raise ValidationError409(detail=f"Community with the name '{name}' already exists.")

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            community = serializer.save(network=network)
            self.save_log_create(serializer)
        headers = self.get_success_headers(serializer.data)

        # Dynamically generate the Location URL
        headers["Location"] = request.build_absolute_uri(
            reverse(URL.NetworkPolicy.COMMUNITY_DETAIL, kwargs={"network": str(network.network), "cpk": community.id})
        )
        return response.Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)        



# Retrieve, update, or delete a specific Community under a specific Network
class NetworkCommunityDetail(JSONContentTypeMixin, CommunityLogMixin, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CommunitySerializer
    permission_classes = (IsGrantedNetGroupRegexPermission | IsSuperOrNetworkAdminMember,)

    def get_queryset(self):
        network = self.kwargs.get("network")
        return Community.objects.filter(network__network=network).order_by("id")

    def get_object(self):
        queryset = self.get_queryset()
        cpk = self.kwargs.get("cpk")
        obj = generics.get_object_or_404(queryset, pk=cpk)
        return obj


class HostInCommunityMixin(JSONContentTypeMixin, HostCommunityMappingLogMixin):
    def get_policy_and_community(self):
        network= self.kwargs.get("network")  # type: ignore
        cpk = self.kwargs.get("cpk")  # type: ignore

        try:
            network = Network.objects.get(network=network)
        except Network.DoesNotExist:
            raise exceptions.NotFound("Network not found.")

        try:
            community = Community.objects.get(pk=cpk)
        except Community.DoesNotExist:
            raise exceptions.NotFound("Community not found.")

        if community.network != network:
            raise exceptions.NotFound("Community does not belong to the requested network.")

        return network, community


# List all hosts in a specific community, or add a host to a community
class NetworkCommunityHostList(HostInCommunityMixin, generics.ListCreateAPIView):
    serializer_class = HostSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission | IsSuperOrNetworkAdminMember,)

    def get_queryset(self):
        _, community = self.get_policy_and_community()
        return HostFilterSet(
            data=self.request.GET, queryset=Host.objects.filter(communities__in=[community]).order_by("id")
        ).qs

    def create(self, request, *args, **kwargs):
        _, community = self.get_policy_and_community()
        host_id = request.data.get("id")
        ipaddress = request.data.get("ipaddress")
        host = None

        if not host_id and not ipaddress:
            raise exceptions.ValidationError("Either 'id' or 'ipaddress' is required")

        if not host_id:
            # Get host from IP address
            ip_hits = Ipaddress.objects.filter(ipaddress=ipaddress)
            ip = ip_hits.first()
            if ip is None:
                raise exceptions.NotFound(f"Host not found based on ip '{ipaddress}'.")
            
            if ip_hits.count() > 1:
                raise exceptions.NotAcceptable(f"Multiple hosts found for ip '{ipaddress}', must provide host ID as well.")
            
            host = ip.host

        if not host:
            # Ensure host exists. If not, an appropriate 404 is raised.
            host = generics.get_object_or_404(Host, pk=host_id)
            
        host.add_to_community(community, ipaddress)

        return response.Response(HostSerializer(host).data, status=status.HTTP_201_CREATED)


# Retrieve or delete a specific host in a specific community
class NetworkCommunityHostDetail(HostInCommunityMixin, generics.RetrieveDestroyAPIView):
    serializer_class = HostSerializer
    permission_classes = (IsGrantedNetGroupRegexPermission | IsSuperOrNetworkAdminMember,)

    def get_queryset(self):
        _, community = self.get_policy_and_community()
        return HostFilterSet(
            data=self.request.GET, queryset=Host.objects.filter(communities__in=[community]).order_by("id")
        ).qs

    def get_object(self):
        queryset = self.get_queryset()
        host_id = self.kwargs.get("hostpk")
        obj = generics.get_object_or_404(queryset, pk=host_id)
        return obj

    def delete(self, request, *args, **kwargs):
        host = self.get_object()
        _, community = self.get_policy_and_community()
        host.remove_from_community(community)
        host.save()
        return response.Response(status=status.HTTP_204_NO_CONTENT)
