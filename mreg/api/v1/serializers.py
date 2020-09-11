import ipaddress

from django.contrib.auth.models import Group
from django.utils import timezone

from rest_framework import serializers

import mreg.models
from mreg.models import (Cname, ForwardZone, ForwardZoneDelegation,
                         Hinfo, Host, HostGroup, Ipaddress, Loc,
                         Mx, NameServer, Naptr,
                         NetGroupRegexPermission, Network, PtrOverride,
                         ReverseZone, ReverseZoneDelegation, Srv, Sshfp, Txt)
from mreg.utils import (nonify, normalize_mac)
from mreg.validators import (validate_keys, validate_normalizeable_mac_address)


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
            data['zone'] = ForwardZone.get_zone_by_hostname(data['name'])
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

class MacAddressSerializerField(serializers.Field):
    """Normalize the provided MAC address into the common format."""
    def to_representation(self, obj):
        return obj

    def to_internal_value(self, data):
        if data and isinstance(data, str):
            validate_normalizeable_mac_address(data)
            return normalize_mac(data)
        return data

class IpaddressSerializer(ValidationMixin, serializers.ModelSerializer):
    macaddress = MacAddressSerializerField(required=False)

    class Meta:
        model = Ipaddress
        fields = '__all__'

    def validate(self, data):
        """
        Make sure a macaddress is semi-unique:
        - Unique if the IP is not in a network.
        - Only in use by one IP per network.
        - If the network has a vlan id, make sure it is only in use by one of
          the networks on the same vlan. Exception: allow both a ipv4 and ipv6
          address on the same vlan to share the same mac address.
        """

        def _raise_if_mac_found(qs, mac):
            if qs.filter(macaddress=mac).exists():
                inuse_ip = qs.get(macaddress=mac).ipaddress
                raise serializers.ValidationError(
                    "macaddress already in use by {}".format(inuse_ip))

        data = super().validate(data)
        _validate_ip_not_in_network_excluded_range(data.get('ipaddress'))
        mac = data.get('macaddress')
        if mac is None and self.instance and self.instance.macaddress:
            mac = self.instance.macaddress

        if mac:
            macip = data.get('ipaddress') or self.instance.ipaddress
            # If MAC and IP unchanged, nothing to validate.
            if self.instance:
                if self.instance.macaddress == mac and \
                   self.instance.ipaddress == macip:
                    return data
            network = Network.objects.filter(network__net_contains=macip).first()
            if not network:
                # XXX: what to do? Currently just make sure it is a unique mac
                # if the mac changed.
                if self.instance and self.instance.macaddress != mac:
                    _raise_if_mac_found(Ipaddress.objects, mac)
                return data
            if network.vlan:
                networks = Network.objects.filter(vlan=network.vlan)
            else:
                networks = [network]
            ipversion = ipaddress.ip_address(macip).version
            for network in networks:
                # Allow mac to be bound to both an ipv4 and ipv6 address on the same vlan
                if ipversion != network.network.version:
                    continue
                qs = network._used_ipaddresses()
                # Validate the MAC unless it belonged to the old IP.
                if self.instance and not self.instance in qs:
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
        model = mreg.models.History
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
    hinfo = HinfoSerializer(read_only=True)
    loc = LocSerializer(read_only=True)

    class Meta:
        model = Host
        fields = '__all__'


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
        model = mreg.models.NetworkExcludedRange
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)

        def _get_ip(attr):
            ip = data.get(attr) or getattr(self.instance, attr)
            if isinstance(ip, str):
                return ipaddress.ip_address(ip)
            return ip
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
    qs = mreg.models.NetworkExcludedRange.objects.filter(start_ip__lte=ip,
                                                         end_ip__gte=ip)
    if qs.exists():
        raise serializers.ValidationError(
                f"IP {ip} in an excluded range: {qs.first()}")
