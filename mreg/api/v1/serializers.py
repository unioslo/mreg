import ipaddress

from django.contrib.auth.models import Group
from django.utils import timezone
from django.db import transaction
from django.conf import settings

from rest_framework import serializers

from mreg.models.base import NameServer, Label, History
from mreg.models.zone import ForwardZone, ReverseZone, ForwardZoneDelegation, ReverseZoneDelegation
from mreg.models.host import Host, HostGroup, BACnetID, Ipaddress, PtrOverride
from mreg.models.resource_records import Cname, Loc, Naptr, Srv, Sshfp, Txt, Hinfo, Mx
from mreg.models.network_policy import NetworkPolicy, NetworkPolicyAttribute, NetworkPolicyAttributeValue, Community, HostCommunityMapping

from mreg.models.network import Network, NetGroupRegexPermission, NetworkExcludedRange

from mreg.utils import (nonify, normalize_mac)
from mreg.validators import (validate_keys, validate_normalizeable_mac_address)
from mreg.api.errors import ValidationError409


class ValidationMixin:
    """Provides standard validation of data fields"""

    def validate(self, data):
        """Only allow known keys, and convert -1 or empty strings to None"""
        validate_keys(self)
        data = {key: nonify(value) for key, value in data.items()}
        return data


class CommunitySerializer(serializers.ModelSerializer):

    # Members are all the hosts that have this community assigned.
    hosts = serializers.SerializerMethodField(read_only=True)
    global_name = serializers.SerializerMethodField(read_only=True)

    def get_hosts(self, obj):
        return list(obj.hosts.values_list("name", flat=True))

    def get_global_name(self, obj):
        # Only map if the setting is enabled.
        if not getattr(settings, "MREG_MAP_GLOBAL_COMMUNITY_NAMES", False):
            return None

        prefix = getattr(settings, "MREG_GLOBAL_COMMUNITY_PREFIX", "community")
        
        # Retrieve all communities for the network in a stable order (using pk).
        communities = obj.network.communities.order_by("pk")
        communities_list = list(communities)

        try:
            index = communities_list.index(obj) + 1
        except ValueError:
            index = None

        if index is None:
            raise ValueError({"error": f"Community {obj} not found in network {obj.network}"})

        max_comm = getattr(settings, "MREG_MAX_COMMUNITES_PER_NETWORK", None)
        if max_comm is not None:
            pad_width = len(str(max_comm))
            if index > max_comm:
                raise ValueError({"error": f"Community index {index} exceeds maximum {max_comm}"})
            return f"{prefix}{index:0{pad_width}d}"
        else:
            return f"{prefix}{index:02d}"

    class Meta:
        model = Community
        fields = ['id', 'name', 'description', 'network', 'hosts', 'global_name', 'created_at', 'updated_at']
        read_only_fields = ['network'] 


class ForwardZoneMixin(ValidationMixin):
    """Create a zone entry from the hostname."""

    def validate(self, data):
        data = super().validate(data)
        if data.get('name'):
            hostname = data['name']
            zone = ForwardZone.get_zone_by_hostname(hostname)
            if zone is not None and zone.name != hostname:
                for delegation in zone.delegations.all():
                    if hostname == delegation.name or hostname.endswith(f".{delegation.name}"):
                        # this host is in a delegation
                        zone = None
                        break
            data['zone'] = zone
        return data


class CnameSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    class Meta:
        model = Cname
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)
        if data.get('name'):
            if not data['zone']:
                raise serializers.ValidationError(
                        "No zone found for {}. Rejecting CNAME.".format(data['name']))
            elif Host.objects.filter(name=data['name']).exists():
                raise serializers.ValidationError(
                    "Name in use by existing host.")

        return data


class SshfpSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Sshfp
        fields = '__all__'


class HinfoSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Hinfo
        fields = '__all__'


class MacAddressSerializerField(serializers.CharField):
    """Normalize the provided MAC address into the common format."""
    def to_representation(self, obj):
        return obj

    def to_internal_value(self, data):
        validate_normalizeable_mac_address(data)
        return normalize_mac(data)


class IpaddressSerializer(ValidationMixin, serializers.ModelSerializer):
    macaddress = MacAddressSerializerField(required=False, allow_blank=True)

    class Meta:
        model = Ipaddress
        fields = '__all__'

    def validate(self, data):
        """
        Make sure a mac address is semi-unique:
        - Unique if the IP is not in a network.
        - Only in use by one IP per network.
        """

        def _raise_if_mac_found(qs, mac):
            # There is a theoretical possibility that a mac address can be in use
            # by multiple IP addresses, although normally it would never be more than 1.
            inuse_set = qs.filter(macaddress=mac)
            if inuse_set.exists():
                ips = inuse_set.values_list('ipaddress', flat=True)
                msg = "macaddress already in use by: " + ", ".join(ips)
                raise ValidationError409(msg)

        data = super().validate(data)
        _validate_ip_not_in_network_excluded_range(data.get('ipaddress'))
        mac = data.get('macaddress')
        if mac is None and self.instance and self.instance.macaddress:
            mac = self.instance.macaddress

        if mac:
            macip = data.get('ipaddress') or self.instance.ipaddress
            # If MAC and IP unchanged, nothing to validate.
            instance = self.instance
            if instance:
                if instance.macaddress == mac and instance.ipaddress == macip:
                    return data

            network = Network.objects.filter(network__net_contains=macip).first()
            if not network:
                # Not in any network. What to do? Currently just make sure it is a unique mac
                # if the mac changed.
                if self.instance and self.instance.macaddress != mac:
                    _raise_if_mac_found(Ipaddress.objects, mac)
                return data

            # Validate the mac address, it should be unique in the network.
            # Exclude the existing ip address object, only look at the other addresses in the network.
            qs = network._used_ipaddresses()
            if self.instance:
                qs = qs.exclude(id=self.instance.id)
            _raise_if_mac_found(qs, mac)
        return data


class LocSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Loc
        fields = '__all__'


class MxSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Mx
        fields = '__all__'


class TxtSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Txt
        fields = '__all__'


class PtrOverrideSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = PtrOverride
        fields = '__all__'

    def validate_ipaddress(self, value):
        _validate_ip_not_in_network_excluded_range(value)
        return value


class HistorySerializer(serializers.ModelSerializer):

    class Meta:
        model = History
        fields = '__all__'


class BACnetIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = BACnetID
        fields = ('id', 'host', 'hostname',)


class BACnetID_ID_Serializer(serializers.ModelSerializer):
    class Meta:
        model = BACnetID
        fields = ('id',)

class HostCommunityMappingSerializer(serializers.ModelSerializer):
    community = CommunitySerializer(read_only=True)
    ipaddress = serializers.PrimaryKeyRelatedField(read_only=True)
    
    class Meta:
        model = HostCommunityMapping
        fields = ('ipaddress', 'community')

class SrvSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    class Meta:
        model = Srv
        fields = '__all__'


class NaptrSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Naptr
        fields = '__all__'

class HostSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    """
    To properly represent a host we include its related objects.
    """
    ipaddresses = IpaddressSerializer(many=True, read_only=True)
    cnames = CnameSerializer(many=True, read_only=True)
    mxs = MxSerializer(many=True, read_only=True)
    txts = TxtSerializer(many=True, read_only=True)
    ptr_overrides = PtrOverrideSerializer(many=True, read_only=True)
    srvs = SrvSerializer(many=True, read_only=True)
    naptrs = NaptrSerializer(many=True, read_only=True)
    sshfps = SshfpSerializer(many=True, read_only=True)

    groups = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name',
        source='hostgroups'
    )

    roles = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name',
        source='hostpolicyroles'
    )
    hinfo = HinfoSerializer(read_only=True)
    loc = LocSerializer(read_only=True)
    bacnetid = BACnetID_ID_Serializer(read_only=True)

#    communities = CommunitySerializer(
#        many=True,
#        required=False,
#        allow_null=True,
#        help_text="Communities to which the host belongs."
#    )

    # New read-only field that includes the IP mapping information.
    communities = HostCommunityMappingSerializer(
        many=True, read_only=True, source="hostcommunitymapping_set",
        allow_null=True, help_text="Communities to which the host belongs, with IP mapping."
    )


    class Meta:
        model = Host
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)
        name = data.get('name')
        if name:
            if Cname.objects.filter(name=name).exists():
                raise ValidationError409("CNAME record exists for {}".format(name))
            if Host.objects.filter(name=name).exists():
                raise ValidationError409("Host already exists with name {}".format(name))
    
        # We defer all validation of community data to update and create as we cannot
        # validate community information before IP address creation has potentially
        # taken place during create or update.
        return data
    
    def create(self, validated_data):
        ipaddr = validated_data.pop('ipaddress', None)
        community = validated_data.pop('communities', None)
        
        with transaction.atomic():
            host = Host.objects.create(**validated_data)

            if ipaddr:
                try:
                    ipaddress.ip_address(ipaddr)
                except ValueError:
                    raise serializers.ValidationError({"ipaddress": "Invalid IP address."})
                Ipaddress.objects.create(host=host, ipaddress=ipaddr)
            
            # Assign community if provided
            if community:
                self._assign_community(host, community)
        
        return host
    
    def update(self, instance, validated_data):
        ipaddr = validated_data.pop('ipaddress', None)
        community = validated_data.pop('communities', None)
        
        with transaction.atomic():
            # Update host fields
            for attr, value in validated_data.items():
                # Communities are handled separately, below
                if attr == 'communities': 
                    continue
                setattr(instance, attr, value)
            instance.save()
            
            # Update IP addresses if provided
            if ipaddr is not None:
                # We won't touch existing IPs. This is a semantic debate of
                # patch vs put at some point.
                # instance.ipaddresses.all().delete()
                try:
                    ipaddress.ip_address(ipaddr)
                except ValueError:
                    raise serializers.ValidationError({"ipaddress": "Invalid IP address."})
                Ipaddress.objects.create(host=instance, ipaddress=ipaddr)
            
            # Assign or unassign community
            if community is not None:
                if community:
                    self._assign_community(instance, community)
                else:
                    self._unassign_community(instance, community)
        
        return instance
    
    def _assign_community(self, host: Host, community: Community) -> None:
        """
        Assigns the community to the host after validating network compatibility.
        """
        policy = community.policy # type: ignore (reverse relation)
        if not policy:
            raise serializers.ValidationError({"error": "Community must be associated with a NetworkPolicy."})
        
        # Check if any of the host's IPs are within the networks
        compatible = False
        for ip in host.ipaddresses.all(): # type: ignore (reverse relation)
            if Network.objects.filter(network__net_contains=ip.ipaddress, policy=policy).exists():
                compatible = True
                break
        
        if not compatible:
            raise serializers.ValidationError({
                "error": "Host's IP addresses do not match the community's network policy."
            })
        
        host.add_to_community(community)
        host.save()    

    def _unassign_community(self, host: Host, community: Community) -> None:
        """
        Unassigns the community from the host.
        """
        host.remove_from_community(community)
        host.save()

class HostNameSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ('name',)




class NameServerSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = NameServer
        fields = '__all__'



class NetworkExcludedRangeSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = NetworkExcludedRange
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)

        def _get_ip(attr):
            ip = data.get(attr) or getattr(self.instance, attr)
            return ipaddress.ip_address(ip)

        start_ip = _get_ip('start_ip')
        end_ip = _get_ip('end_ip')
        network_obj = data.get('network') or self.instance.network
        if start_ip > end_ip:
            raise serializers.ValidationError(
                f"start_ip {start_ip} larger than end_ip {end_ip}")
        for ip in (start_ip, end_ip):
            if ip not in network_obj.network:
                raise serializers.ValidationError(
                    f"IP {ip} is not contained in {network_obj.network}")
        for existing in network_obj.excluded_ranges.all():
            if start_ip <= ipaddress.ip_address(existing.start_ip) <= end_ip or \
              start_ip <= ipaddress.ip_address(existing.end_ip) <= end_ip:
                if hasattr(self.instance, 'pk'):
                    if existing == self.instance:
                        continue
                raise serializers.ValidationError(
                        f"Request overlaps with existing: {existing}")
        return data




class NetGroupRegexPermissionSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = NetGroupRegexPermission
        fields = '__all__'


class BaseZoneSerializer(ValidationMixin, serializers.ModelSerializer):
    nameservers = NameServerSerializer(read_only=True, many=True)

    class Meta:
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)
        if data.get('serialno'):
            data['serialno_updated_at'] = timezone.now()
        return data

    def create(self):
        return self.Meta.model(**self.validated_data)


class ForwardZoneSerializer(BaseZoneSerializer):

    class Meta(BaseZoneSerializer.Meta):
        model = ForwardZone


class ReverseZoneSerializer(BaseZoneSerializer):
    network = serializers.CharField(read_only=True, required=False)

    class Meta(BaseZoneSerializer.Meta):
        model = ReverseZone


class BaseZoneDelegationSerializer(BaseZoneSerializer):

    class Meta(BaseZoneSerializer.Meta):
        pass

    def validate(self, data):
        data = super().validate(data)
        if data.get('name') and data.get('zone'):
            parentzone = data.get('zone')
            name = data.get('name')
            if not name.endswith(f".{parentzone.name}"):
                raise serializers.ValidationError(
                    f"Delegation {name} is not contained in {parentzone}")
        return data


class ForwardZoneDelegationSerializer(BaseZoneDelegationSerializer):

    class Meta(BaseZoneDelegationSerializer.Meta):
        model = ForwardZoneDelegation


class ReverseZoneDelegationSerializer(BaseZoneDelegationSerializer):

    class Meta(BaseZoneSerializer.Meta):
        model = ReverseZoneDelegation


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields = ('name',)


class HostGroupNameSerializer(serializers.ModelSerializer):

    class Meta:
        model = HostGroup
        fields = ('name', )


class HostGroupSerializer(serializers.ModelSerializer):
    parent = HostGroupNameSerializer(many=True, read_only=True)
    groups = HostGroupNameSerializer(many=True, read_only=True)
    hosts = HostNameSerializer(many=True, read_only=True)
    owners = GroupSerializer(many=True, read_only=True)

    class Meta:
        model = HostGroup
        fields = '__all__'


def _validate_ip_not_in_network_excluded_range(ip):
    if ip is None:
        return
    qs = NetworkExcludedRange.objects.filter(start_ip__lte=ip,
                                                         end_ip__gte=ip)
    if qs.exists():
        raise serializers.ValidationError(
                f"IP {ip} in an excluded range: {qs.first()}")


class LabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Label
        fields = '__all__'


class NetworkPolicyAttributeValueSerializer(serializers.ModelSerializer):
    name = serializers.CharField(write_only=True)
    value = serializers.BooleanField()

    class Meta:
        model = NetworkPolicyAttributeValue
        fields = ['name', 'value']

    def to_representation(self, instance):
        return {
            'name': instance.attribute.name,
            'value': instance.value
        }

    def create(self, validated_data):
        name = validated_data.pop('name')
        try:
            attribute = NetworkPolicyAttribute.objects.get(name=name)
        except NetworkPolicyAttribute.DoesNotExist:
            raise serializers.ValidationError(
                f"NetworkPolicyAttribute with name '{name}' does not exist."
            )
        policy = self.context.get('policy')
        if not policy:
            raise serializers.ValidationError("Policy context is required.")
        return NetworkPolicyAttributeValue.objects.create(
            attribute=attribute, value=validated_data.get('value', False), policy=policy
        )

    def update(self, instance, validated_data):
        name = validated_data.get('name', instance.attribute.name)
        value = validated_data.get('value', instance.value)

        if name != instance.attribute.name:
            try:
                attribute = NetworkPolicyAttribute.objects.get(name=name)
            except NetworkPolicyAttribute.DoesNotExist:
                raise serializers.ValidationError(
                    f"NetworkPolicyAttribute with name '{name}' does not exist."
                )
            instance.attribute = attribute

        instance.value = value
        instance.save()
        return instance


class NetworkPolicySerializer(serializers.ModelSerializer):
    attributes = NetworkPolicyAttributeValueSerializer(
        many=True,
        source='network_policy_attribute_values',
        required=False
    )
    communities = CommunitySerializer(many=True, read_only=True)

    class Meta:
        model = NetworkPolicy
        fields = ['id', 'name', 'description', 'attributes', 'communities', 'created_at', 'updated_at']

    def validate_name(self, value):
        value = value.lower()
        if self.instance:
            if NetworkPolicy.objects.exclude(id=self.instance.id).filter(name=value).exists():
                raise serializers.ValidationError(f"NetworkPolicy with the name '{value}' already exists.")
        else:
            if NetworkPolicy.objects.filter(name=value).exists():
                raise serializers.ValidationError(f"NetworkPolicy with the name '{value}' already exists.")
        return value

    def validate_attributes(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Attributes must be a list of dictionaries.")
        
        for element in value:
            if not isinstance(element, dict):
                raise serializers.ValidationError("Each attribute must be a dictionary.")

        attribute_names = [attr['name'] for attr in value]
        existing_attributes = NetworkPolicyAttribute.objects.filter(
            name__in=attribute_names
        ).values_list('name', flat=True)
        missing_attributes = set(attribute_names) - set(existing_attributes)
        if missing_attributes:
            raise serializers.ValidationError(
                f"The following attributes do not exist: {', '.join(missing_attributes)}"
            )
        return value

    @transaction.atomic
    def create(self, validated_data):
        attributes_data = validated_data.pop('network_policy_attribute_values', [])
        network_policy = NetworkPolicy.objects.create(**validated_data)

        # Pass the policy instance to the nested serializer via context
        for attr in attributes_data:
            serializer = NetworkPolicyAttributeValueSerializer(
                data=attr,
                context={'policy': network_policy}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

        return network_policy

    @transaction.atomic
    def update(self, instance, validated_data):
        attributes_data = validated_data.pop('network_policy_attribute_values', None)

        # Update the NetworkPolicy fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if attributes_data is not None:
            # Clear existing attributes
            NetworkPolicyAttributeValue.objects.filter(policy=instance).delete()
            # Recreate attributes
            for attr in attributes_data:
                serializer = NetworkPolicyAttributeValueSerializer(
                    data=attr,
                    context={'policy': instance}
                )
                serializer.is_valid(raise_exception=True)
                serializer.save()

        return instance

class NetworkPolicyAttributeSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkPolicyAttribute
        fields = ['id', 'name', 'description', 'created_at', 'updated_at']


class NetworkSerializer(ValidationMixin, serializers.ModelSerializer):
    excluded_ranges = NetworkExcludedRangeSerializer(many=True, read_only=True)
    
    # Expand the entire policy object
    policy = NetworkPolicySerializer(read_only=True)
    communities = CommunitySerializer(many=True, read_only=True)

    class Meta:
        model = Network
        fields = '__all__'

