from django.contrib.sessions.backends.base import CreateError
from rest_framework import serializers
from mreg.models import *


def ttl_validate(value):
    """Ensures a ttl-value is within accepted range. -1 returns None"""
    if value == -1:
        return None
    if value < 300:
        raise serializers.ValidationError("Ensure this value is greater than or equal to 300.")
    if value > 68400:
        raise serializers.ValidationError("Ensure this value is less than or equal to 68400.")
    return value


class CnameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cname
        fields = '__all__'

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        return ttl_validate(value)


class HinfoPresetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HinfoPresets
        fields = '__all__'


class IpaddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ipaddress
        fields = '__all__'


class TxtSerializer(serializers.ModelSerializer):
    class Meta:
        model = Txt
        fields = '__all__'


class HostsSerializer(serializers.ModelSerializer):
    ipaddress = IpaddressSerializer(many=True, read_only=True)
    cname = CnameSerializer(many=True, read_only=True)
    txt = TxtSerializer(many=True, read_only=True)

    class Meta:
        model = Hosts
        fields = ('hostid', 'name', 'contact', 'ttl', 'hinfo', 'loc', 'comment', 'cname', 'ipaddress', 'txt')

    def validate(self, data):
        """Don't allow patching of unknown fields."""
        invalid_keys = set(self.initial_data.keys()) - set(self.fields.keys())
        if invalid_keys:
            raise serializers.ValidationError('invalid keys passed into serializer: {0}'.format(invalid_keys))
        return data

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        return ttl_validate(value)


class HostsNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hosts
        fields = ('name',)


class NaptrSerializer(serializers.ModelSerializer):
    class Meta:
        model = Naptr
        fields = '__all__'


class NsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ns
        fields = '__all__'

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        return ttl_validate(value)


class PtrOverrideSerializer(serializers.ModelSerializer):
    class Meta:
        model = PtrOverride
        fields = '__all__'


class SrvSerializer(serializers.ModelSerializer):
    class Meta:
        model = Srv
        fields = '__all__'

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        return ttl_validate(value)


class SubnetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subnets
        fields = '__all__'


class ZonesSerializer(serializers.ModelSerializer):
    nameservers = NsSerializer(read_only=True, many=True)

    class Meta:
        model = Zones
        fields = '__all__'

    def create(self):
        return Zones(**self.validated_data)

    def validate_ttl(self, value):
        """Ensures ttl is within range. -1 equals None/Null"""
        return ttl_validate(value)




