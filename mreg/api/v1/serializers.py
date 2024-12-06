import ipaddress

from structlog import get_logger

from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from rest_framework import serializers

from mreg.models.base import NameServer, Label, History
from mreg.models.zone import ForwardZone, ReverseZone, ForwardZoneDelegation, ReverseZoneDelegation
from mreg.models.host import Host, HostGroup, BACnetID, Ipaddress, PtrOverride
from mreg.models.policy import ApprovedModelForPolicy
from mreg.models.resource_records import Cname, Loc, Naptr, Srv, Sshfp, Txt, Hinfo, Mx

from mreg.models.network import Network, NetGroupRegexPermission, NetworkExcludedRange

from mreg.utils import (nonify, normalize_mac)
from mreg.validators import (validate_keys, validate_normalizeable_mac_address)
from mreg.api.errors import ValidationError409

logger = get_logger()

class ValidationMixin:
    """Provides standard validation of data fields"""

    def validate(self, data):
        """Only allow known keys, and convert -1 or empty strings to None"""
        validate_keys(self)
        data = {key: nonify(value) for key, value in data.items()}
        return data


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


class HostSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    """
    To properly represent a host we include its related objects.
    """
    ipaddresses = IpaddressSerializer(many=True, read_only=True)
    cnames = CnameSerializer(many=True, read_only=True)
    mxs = MxSerializer(many=True, read_only=True)
    txts = TxtSerializer(many=True, read_only=True)
    ptr_overrides = PtrOverrideSerializer(many=True, read_only=True)
    hinfo = HinfoSerializer(read_only=True)
    loc = LocSerializer(read_only=True)
    bacnetid = BACnetID_ID_Serializer(read_only=True)

    class Meta:
        model = Host
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)
        name = data.get('name')
        if name and Cname.objects.filter(name=name).exists():
            raise ValidationError409("CNAME record exists for {}".format(name))
        return data


class HostNameSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ('name',)


class NaptrSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Naptr
        fields = '__all__'


class NameServerSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = NameServer
        fields = '__all__'


class SrvSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    class Meta:
        model = Srv
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


class NetworkSerializer(ValidationMixin, serializers.ModelSerializer):
    excluded_ranges = NetworkExcludedRangeSerializer(many=True, read_only=True)

    class Meta:
        model = Network
        fields = '__all__'


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


class ApprovedModelSerializer(serializers.ModelSerializer):
    """Serializer for ApprovedModel.

    Note: This maps the content_type field from a string facing the user (both in and out)
    to a content_type ID internally.
    """

    content_type = serializers.CharField()

    class Meta:
        model = ApprovedModelForPolicy
        fields = ['id', 'content_type']

    def to_internal_value(self, data):
        """
        Convert the string model name to a ContentType instance.
        """
        logpoint = "ApprovedModelSerializer.to_internal_value"

        logger.debug(logpoint, data=data)
        internal_value = super().to_internal_value(data)

        # Convert string name (app_label.ModelName) to ContentType
        content_type_str = internal_value.get('content_type')
        if not content_type_str:
            raise serializers.ValidationError({"content_type": "This field is required."})

        logger.debug(logpoint, content_type_str=content_type_str)

        try:
            model = content_type_str
            app_label = "mreg"
            logger.debug(logpoint, app_label=app_label, model=model)
            content_type = ContentType.objects.get(app_label=app_label, model=model.lower())
            logger.debug(logpoint, content_type=content_type)
        except ContentType.DoesNotExist:
            msg = f"Resource '{content_type_str}' does not exist."
            logger.warning(logpoint, msg=msg, content_type=content_type_str) 
            raise serializers.ValidationError({"content_type": msg})

        internal_value['content_type'] = content_type
        return internal_value

    def to_representation(self, instance):
        """
        Convert the ContentType instance back to a string.
        """
        representation = super().to_representation(instance)
        content_type = instance.content_type
        # Note, we ignore the app_label here, as it is always 'mreg'. No, we do not want o
        # apply Policies for HostPolicy structures.
        representation['content_type'] = content_type.model 
        return representation