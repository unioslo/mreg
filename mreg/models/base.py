"""Base models for mreg.

These are models with no internal dependencies.
"""

from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from rest_framework.authtoken.models import Token

from mreg.fields import DnsNameField, LCICharField
from mreg.utils import (
    clear_none,
    idna_encode,
    qualify,
)
from mreg.validators import (
    validate_hostname,
    validate_ttl,
    validate_nowhitespace,
)


MAX_UNUSED_LIST = 4096  # 12 bits for addresses. A large ipv4, but tiny ipv6 network.

# To avoid circular imports, this base file is not allowed to import any other models
# from any other files. We do however want to include the model ForwardZoneMember here 
# to ensure it is always available for import elsewhere. To achieve this, we use the
# lazy loading feature of django models where we use a string instead of the class
# reference. Here we thus use the string "ForwardZone" as the target for the foreign key
# in the ForwardZoneMember model -- and to avoid hardcoding the string "ForwardZone"
# deep into the file, we use the following constant "_FORWARD_ZONE" as the reference.
_FORWARD_ZONE = "ForwardZone"

class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class NameServer(BaseModel):
    name = DnsNameField(unique=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])

    class Meta:
        db_table = "ns"
        ordering = ("name",)

    def __str__(self):
        return str(self.name)

    def zf_string(self, zone, subzone=None):
        """String representation for zonefile export."""
        if subzone:
            subzone = idna_encode(qualify(subzone, zone))
        data = {
            "subzone": clear_none(subzone),
            "ttl": clear_none(self.ttl),
            "record_type": "NS",
            "record_data": idna_encode(qualify(self.name, zone)),
        }
        return "{subzone:24} {ttl:5} IN {record_type:6} {record_data}\n".format_map(
            data
        )

    @staticmethod
    def validate_name(name):
        validate_hostname(name)


class ZoneHelpers:
    def update_nameservers(self, new_ns):
        existing = {i.name for i in self.nameservers.all()}
        remove_ns = existing - set(new_ns)
        add_ns = set(new_ns) - existing

        # Remove ns from zone and also delete the NameServer if only
        # used by this zone.
        for ns in remove_ns:
            ns = NameServer.objects.get(name=ns)
            usedcount = 0
            # Must check all zone sets
            for i in (
                "forwardzone",
                "reversezone",
                "forwardzonedelegation",
                "reversezonedelegation",
            ):
                usedcount += getattr(ns, f"{i}_set").count()

            if usedcount == 1:
                ns.delete()
            self.nameservers.remove(ns)

        for ns in add_ns:
            try:
                ns = NameServer.objects.get(name=ns)
            except NameServer.DoesNotExist:
                ns = NameServer(name=ns)
                ns.save()
            self.nameservers.add(ns)
        self.save()

    def remove_nameservers(self):
        self.update_nameservers([])


class Label(BaseModel):
    name = LCICharField(max_length=64, unique=True, validators=[validate_nowhitespace])
    description = models.TextField(blank=False)

    class Meta:
        db_table = "label"
        ordering = ("name",)

    def __str__(self):
        return str(self.name)


class History(models.Model):
    """
    Store history for various models.

    Use the resource field to set the scope for each group of events.
    """

    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=64)
    resource = models.CharField(max_length=64)
    name = models.CharField(max_length=255)
    model_id = models.PositiveIntegerField()
    model = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    data = models.JSONField()

    def __str__(self):
        return f"{self.name}, {self.model}, {self.action}, {self.timestamp}"


class ForwardZoneMember(BaseModel):
    zone = models.ForeignKey(
        _FORWARD_ZONE, models.DO_NOTHING, db_column="zone", blank=True, null=True
    )
    class Meta:
        abstract = True


class ExpiringToken(Token):
    last_used = models.DateTimeField(auto_now=True)

    @property
    def is_expired(self):
        EXPIRE_HOURS = getattr(settings, "REST_FRAMEWORK_TOKEN_EXPIRE_HOURS", 8)
        return self.last_used < timezone.now() - timedelta(hours=EXPIRE_HOURS)
