
from rest_framework import serializers

from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.api.v1.serializers import HostNameSerializer


class HostPolicyAtomNameSerializer(serializers.ModelSerializer):

    class Meta:
        model = HostPolicyAtom
        fields = ('name', )


class HostPolicyAtomSerializer(serializers.ModelSerializer):

    class Meta:
        model = HostPolicyAtom
        fields = '__all__'


class HostPolicyRoleNameSerializer(serializers.ModelSerializer):

    class Meta:
        model = HostPolicyRole
        fields = ('name', )


class HostPolicyRoleSerializer(serializers.ModelSerializer):

    hosts = HostNameSerializer(many=True, read_only=True)
    atoms = HostPolicyAtomNameSerializer(many=True, read_only=True)
    parent = HostPolicyRoleNameSerializer(many=True, read_only=True)

    class Meta:
        model = HostPolicyRole
        fields = '__all__'
