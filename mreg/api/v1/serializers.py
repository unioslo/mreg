from rest_framework import serializers
from mreg.models import Cname, Hosts


class HostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hosts
        fields = ('hostid', 'name', 'contact', 'ttl', 'hinfo', 'loc', 'comment')


class CnameSerializer(serializers.Serializer):
    hostid = serializers.IntegerField(read_only=True)
    cname = serializers.CharField(read_only=True)
    ttl = serializers.IntegerField(read_only=True)

    def create(self, validated_data):
        """ Create and return a new Cname instance, given the validated data """
        return Cname.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """ Update and return an existing 'Cname' instance, given the validated data """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.cname = validated_data.get('cname', instance.cname)
        instance.ttl = validated_data.get('ttl', instance.ttl)
        instance.save()
        return instance
