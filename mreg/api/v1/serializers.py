from rest_framework import serializers
from mreg.models import *


class CnameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cname
        fields = '__all__'


class HinfoPresetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HinfoPresets
        fields = '__all__'


class HostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hosts
        fields = '__all__'


class IpaddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ipaddress
        fields = '__all__'


class NaptrSerializer(serializers.ModelSerializer):
    class Meta:
        model = Naptr
        fields = '__all__'


class NsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ns
        fields = '__all__'


class PtrOverrideSerializer(serializers.ModelSerializer):
    class Meta:
        model = PtrOverride
        fields = '__all__'


class SrvSerializer(serializers.ModelSerializer):
    class Meta:
        model = Srv
        fields = '__all__'


class SubnetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subnets
        fields = '__all__'


class TxtSerializer(serializers.ModelSerializer):
    class Meta:
        model = Txt
        fields = '__all__'


class ZonesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Zones
        fields = '__all__'
