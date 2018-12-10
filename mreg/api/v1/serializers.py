import ipaddress

from django.utils import timezone
from rest_framework import serializers

from mreg.models import (Cname, HinfoPreset, Host, Ipaddress, NameServer,
        Naptr, PtrOverride, Srv, Subnet, Txt, Zone, ModelChangeLog)
from mreg.utils import (create_serialno, nonify)
from mreg.validators import (validate_keys, validate_ttl)


class ValidationMixin(object):
    """Provides standard validation of data fields"""

    def validate(self, data):
        """Only allow known keys, and convert -1 or empty strings to None"""
        validate_keys(self)
        data = {key: nonify(value) for key, value in data.items()}
        return data

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        value = nonify(value)
        if value:
            validate_ttl(value)
        return value

class ForwardZoneMixin(ValidationMixin):
    """Create a zone entry from the hostname."""

    def _get_zone_by_hostname(self, name):
        """Get a zone's id for a hostname.
        Return zone's id or None if not found."""

        def _get_reverse_order(lst):
            """Return index of sorted zones"""
            # We must sort the zones to assert that foo.example.org hosts
            # does not end up in the example.org zone.  This is acheived by
            # spelling the zone postfix backwards and sorting the
            # resulting list backwards
            lst = [str(x.name)[::-1] for x in lst]
            t = range(len(lst))
            return sorted(t, reverse=True)

        zones = Zone.objects.all()
        for n in _get_reverse_order(zones):
            z = zones[n]
            if z.name and name.endswith(z.name):
                return z
        return None

    def validate(self, data):
        data = super().validate(data)
        if data.get('name'):
            data['zone'] = self._get_zone_by_hostname(data['name'])
        return data

class CnameSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Cname
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
        - Unique if the IP is not in a subnet.
        - Only in use by one IP per subnet.
        - If the subnet has a vlan id, make sure it is only in use by one of
          the subnets on the same vlan. Exception: allow both a ipv4 and ipv6
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
            subnet = Subnet.get_subnet_by_ip(macip)
            if not subnet:
                # XXX: what to do? Currently just make sure it is a unique mac
                _raise_if_mac_found(Ipaddress.objects, mac)
                return data
            if subnet.vlan:
                subnets = Subnet.objects.filter(vlan=subnet.vlan)
            else:
                subnets = [subnet]
            ipversion = ipaddress.ip_address(macip).version
            for subnet in subnets:
                # Allow mac to be bound to both an ipv4 and ipv6 address on the same vlan
                if ipversion != subnet.network.version:
                    continue
                ips = subnet._get_used_ipaddresses()
                _raise_if_mac_found(ips, mac)
        return data

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


class SubnetSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Subnet
        fields = '__all__'

    def create(self):
        return Subnet(**self.validated_data)


class ZoneSerializer(ValidationMixin, serializers.ModelSerializer):
    nameservers = NameServerSerializer(read_only=True, many=True)

    class Meta:
        model = Zone
        fields = '__all__'

    def validate(self, data):
        data = super().validate(data)
        if data.get('serialno'):
            data['serialno_updated_at'] = timezone.now()
        return data

    def create(self):
        return Zone(**self.validated_data)


class ModelChangeLogSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = ModelChangeLog
        fields = '__all__'

    def create(self):
        return ModelChangeLog(**self.validated_data)
