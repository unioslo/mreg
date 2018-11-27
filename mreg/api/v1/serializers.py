from mreg.models import *
from mreg.utils import *
from mreg.validators import validate_keys
from mreg.validators import validate_ttl


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


class TxtSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = Txt
        fields = '__all__'


class PtrOverrideSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = PtrOverride
        fields = '__all__'


class HostSerializer(ValidationMixin, serializers.ModelSerializer):
    """
    To properly represent a host we include its related objects.
    """
    ipaddress = IpaddressSerializer(many=True, read_only=True)
    cname = CnameSerializer(many=True, read_only=True)
    txt = TxtSerializer(many=True, read_only=True)
    ptr_override = PtrOverrideSerializer(many=True, read_only=True)
    hinfo = HinfoPresetSerializer(required=False)['hinfoid']

    class Meta:
        model = Host
        fields = ('hostid', 'name', 'zoneid', 'contact', 'ttl', 'hinfo', 'loc',
                  'comment', 'cname', 'ipaddress', 'txt', 'ptr_override')


class HostSaveSerializer(ValidationMixin, serializers.ModelSerializer):
    """
    Used for saving hosts, due to complications with nulling out a field by patching it with '-1'.
    """
    ipaddress = IpaddressSerializer(many=True, read_only=True)
    cname = CnameSerializer(many=True, read_only=True)
    txt = TxtSerializer(many=True, read_only=True)
    ptr_override = PtrOverrideSerializer(many=True, read_only=True)
    hinfo = serializers.IntegerField(required=False)

    class Meta:
        model = Host
        fields = ('hostid', 'name', 'zoneid', 'contact', 'ttl', 'hinfo', 'loc',
                  'comment', 'cname', 'ipaddress', 'txt', 'ptr_override')

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


class SrvSerializer(ValidationMixin, serializers.ModelSerializer):
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

    def create(self):
        return Zone(**self.validated_data)


class ModelChangeLogSerializer(ValidationMixin, serializers.ModelSerializer):
    class Meta:
        model = ModelChangeLog
        fields = '__all__'

    def create(self):
        return ModelChangeLog(**self.validated_data)
