import ipaddress

from django.utils import timezone
from rest_framework import serializers

from mreg.models import (Cname, HinfoPreset, Host, HostGroup, HostGroupMember, Ipaddress, Mx, NameServer,
                         Naptr, PtrOverride, Srv, Network, Txt, ForwardZone,
                         ForwardZoneDelegation, ReverseZone,
                         ReverseZoneDelegation, ModelChangeLog, Sshfp)

from mreg.utils import nonify
from mreg.validators import validate_keys


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


class HinfoPresetSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = HinfoPreset
        fields = '__all__'


class IpaddressSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Ipaddress
        fields = '__all__'

    def validate(self, data):
        """
        Make sure a macaddress are semi-unique:
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
        if data.get('macaddress'):
            mac = data['macaddress']
            macip = data.get('ipaddress') or self.instance.ipaddress
            host = data.get('host') or self.instance.host
            # If MAC and IP unchanged, nothing to validate.
            if self.instance:
                if self.instance.macaddress == mac and \
                   self.instance.ipaddress == macip:
                    return data
            network = Network.get_network_by_ip(macip)
            if not network:
                # XXX: what to do? Currently just make sure it is a unique mac
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
                ips = network._get_used_ipaddresses()
                _raise_if_mac_found(ips, mac)
        return data


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


class HostSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    """
    To properly represent a host we include its related objects.
    """
    ipaddresses = serializers.SerializerMethodField()
    cnames = CnameSerializer(many=True, read_only=True)
    mxs = MxSerializer(many=True, read_only=True)
    txts = TxtSerializer(many=True, read_only=True)
    ptr_overrides = PtrOverrideSerializer(many=True, read_only=True)
    hinfo = HinfoPresetSerializer(required=False)['id']

    class Meta:
        model = Host
        fields = '__all__'

    def get_ipaddresses(self, instance):
        ipaddresses = instance.ipaddresses.all().order_by('ipaddress')
        return IpaddressSerializer(ipaddresses, many=True, read_only=True).data



class HostSaveSerializer(ForwardZoneMixin, serializers.ModelSerializer):
    """
    Used for saving hosts, due to complications with nulling out a field by patching it with '-1'.
    """
    ipaddresses = IpaddressSerializer(many=True, read_only=True)
    cnames = CnameSerializer(many=True, read_only=True)
    mxs = MxSerializer(many=True, read_only=True)
    txts = TxtSerializer(many=True, read_only=True)
    ptr_overrides = PtrOverrideSerializer(many=True, read_only=True)
    hinfo = serializers.IntegerField(required=False)

    class Meta:
        model = Host
        fields = '__all__'

    def validate_hinfo(self, value):
        value = nonify(value)

        if value is not None:
            value = HinfoPreset.objects.get(pk=value)
        return value


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


class NetworkSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Network
        fields = '__all__'

    def create(self):
        return Network(**self.validated_data)


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
    range = serializers.CharField(read_only=True, required=False)

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


class ModelChangeLogSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = ModelChangeLog
        fields = '__all__'

    def create(self):
        return ModelChangeLog(**self.validated_data)


class HostGroupMemberSerializer(ValidationMixin, serializers.ModelSerializer):
    name = serializers.SlugRelatedField(read_only=True, slug_field="name", source="host")
    #id = serializers.PrimaryKeyRelatedField(read_only=True, source="host")

    class Meta:
        model = HostGroupMember
        fields = ['name']

    #def get_hosts(self, instance):
    #    return instance.hostgroupmember_set.all()


class HostGroupSerializer(ValidationMixin, serializers.ModelSerializer):
    # groups_count = serializers.SerializerMethodField()
    hosts = HostGroupMemberSerializer(many=True, read_only=True)

    class Meta:
        model = HostGroup
        fields = ['name','hosts']


class HostGroupDetailSerializer(ValidationMixin, serializers.ModelSerializer):
    groups = HostGroupSerializer(many=True,read_only=True)
    hosts = HostGroupMemberSerializer(many=True, source="hostmembers",read_only=True)

    class Meta:
        model = HostGroup
        fields = ['name', 'hosts', 'groups']



class HostGroupGroupsSerializer(ValidationMixin, serializers.ModelSerializer):
    groups = HostGroupMemberSerializer(many=True)

    class Meta:
        model = HostGroupMember
        fields = ['name']