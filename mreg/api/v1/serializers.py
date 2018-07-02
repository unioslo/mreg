from rest_framework import serializers
from mreg.models import *


class HostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hosts
        fields = '__all__'


# TODO: cname foreign key stuff
class CnameSerializer(serializers.ModelSerializer):
    hostid = models.ForeignKey(Hosts, related_name='hostid', on_delete=models.CASCADE)

    class Meta:
        model = Cname
        fields = ('hostid', 'cname', 'ttl')


class NsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ns
        fields = '__all__'
