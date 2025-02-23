from django.contrib.auth.models import Group
from django.db import models

from mreg.fields import LowerCaseCharField, LowerCaseDNSNameField
from mreg.managers import LowerCaseManager
from mreg.models.base import BaseModel, ForwardZoneMember
from mreg.validators import validate_BACnetID, validate_mac_address, validate_ttl
from mreg.models.network_policy import Community


class Host(ForwardZoneMember):
    name = LowerCaseDNSNameField(unique=True)
    contact = models.EmailField(blank=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    comment = models.TextField(blank=True)

    network_community = models.ForeignKey(
        Community,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='hosts',
        help_text="Network community this host belongs to."
    )

    objects = LowerCaseManager()

    class Meta:
        db_table = "host"

    def __str__(self):
        return str(self.name)

    def community(self):
        return self.network_community
    
    def set_community(self, community: Community) -> bool:
        """Set the community for this host.
        
        :param community: The community to set.
        :return: True if the community was set, False otherwise
        """
        # We need to check that the community is applicable to the same
        # network as one of the IP addresses of the host.
        for ipaddress in self.ipaddresses.all(): # type: ignore
            from mreg.models.network import Network
            try:
                net = Network.objects.get(network__net_contains=ipaddress.ipaddress)
                if community.network == net:
                    self.network_community = community
                    self.save()
                    return True
            except Network.DoesNotExist:
                return False
            
        return False

class Ipaddress(BaseModel):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="ipaddresses"
    )
    ipaddress = models.GenericIPAddressField()
    macaddress = models.CharField(
        max_length=17, blank=True, validators=[validate_mac_address]
    )

    class Meta:
        db_table = "ipaddress"
        unique_together = (("host", "ipaddress"),)

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.macaddress) or "None")

    def delete(self, using=None, keep_parents=False):
        PtrOverride.objects.filter(host=self.host, ipaddress=self.ipaddress).delete()
        return super().delete(using=using, keep_parents=keep_parents)


class PtrOverride(BaseModel):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="ptr_overrides"
    )
    ipaddress = models.GenericIPAddressField(unique=True)

    class Meta:
        db_table = "ptr_override"

    def __str__(self):
        return "{} -> {}".format(str(self.ipaddress), str(self.host.name))


class HostGroup(BaseModel):
    name = LowerCaseCharField(max_length=50, unique=True)
    description = models.CharField(max_length=200, blank=True)
    owners = models.ManyToManyField(Group, blank=True)
    parent = models.ManyToManyField(
        "self", symmetrical=False, blank=True, related_name="groups"
    )
    hosts = models.ManyToManyField(Host, related_name="hostgroups")

    objects = LowerCaseManager()

    class Meta:
        db_table = "hostgroup"
        ordering = ("name",)

    def __str__(self):
        return "%s" % self.name


class BACnetID(models.Model):
    id = models.IntegerField(primary_key=True, validators=[validate_BACnetID])
    host = models.OneToOneField(Host, on_delete=models.CASCADE, related_name="bacnetid")

    class Meta:
        db_table = "bacnetid"

    @property
    def hostname(self):
        return self.host.name

    @staticmethod
    def first_unused_id() -> int:
        j = 0
        for i in BACnetID.objects.values_list("id", flat=True).order_by("id"):
            if i == j:
                j += 1
            else:
                return j
        return j
