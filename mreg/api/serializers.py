from rest_framework import serializers


REPORTED_LIBRARY_VERSION_FIELDS = (
    "djangorestframework",
    "django-auth-ldap",
    "django-filter",
    "django-logging-json",
    "django-netfields",
    "gunicorn",
    "sentry-sdk",
    "structlog",
    "rich",
    "psycopg",
)


class TokenStateSerializer(serializers.Serializer):
    is_valid = serializers.BooleanField()
    created = serializers.DateTimeField()
    expire = serializers.DateTimeField()
    last_used = serializers.DateTimeField(allow_null=True)
    lifespan = serializers.CharField()


class DjangoUserStatusSerializer(serializers.Serializer):
    superuser = serializers.BooleanField()
    staff = serializers.BooleanField()
    active = serializers.BooleanField()


class MregUserStatusSerializer(serializers.Serializer):
    superuser = serializers.BooleanField()
    admin = serializers.BooleanField()
    group_admin = serializers.BooleanField()
    network_admin = serializers.BooleanField()
    hostpolicy_admin = serializers.BooleanField()
    dns_wildcard_admin = serializers.BooleanField()
    underscore_admin = serializers.BooleanField()


class UserPermissionSerializer(serializers.Serializer):
    group = serializers.CharField()
    range = serializers.CharField()
    regex = serializers.CharField()
    labels = serializers.ListField(child=serializers.CharField())


class UserInfoSerializer(serializers.Serializer):
    username = serializers.CharField()
    last_login = serializers.DateTimeField(allow_null=True)
    token = TokenStateSerializer(allow_null=True)
    django_status = DjangoUserStatusSerializer()
    mreg_status = MregUserStatusSerializer()
    groups = serializers.ListField(child=serializers.CharField())
    permissions = UserPermissionSerializer(many=True)


class MregVersionSerializer(serializers.Serializer):
    version = serializers.CharField()


class MetaVersionsSerializer(serializers.Serializer):
    python = serializers.CharField()
    django = serializers.CharField()
    libpq = serializers.CharField()

    def get_fields(self):
        fields = super().get_fields()
        for library in REPORTED_LIBRARY_VERSION_FIELDS:
            fields[library] = serializers.CharField()
        return fields


class HealthHeartbeatSerializer(serializers.Serializer):
    start_time = serializers.IntegerField()
    uptime = serializers.IntegerField()
