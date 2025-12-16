from django.contrib.auth.models import Group
from django.db import models, transaction
from rest_framework.exceptions import NotAcceptable
from typing import Union, Optional, Tuple

from django.conf import settings


from mreg.fields import LowerCaseCharField, LowerCaseDNSNameField
from mreg.managers import LowerCaseManager
from mreg.models.base import BaseModel, ForwardZoneMember
from mreg.validators import validate_BACnetID, validate_mac_address, validate_ttl
from mreg.models.network_policy import Community, HostCommunityMapping
from mreg.models.network import Network

from structlog import get_logger

logger = get_logger()


class HostContact(BaseModel):
    """Model to store contact email addresses for hosts."""
    email = models.EmailField()
    
    class Meta:
        db_table = "host_contact"
        
    def __str__(self):
        return self.email


class Host(ForwardZoneMember):
    name = LowerCaseDNSNameField(unique=True)
    contacts = models.ManyToManyField(
        HostContact,
        blank=True,
        related_name='hosts',
        help_text="Contact email addresses for this host."
    )
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    comment = models.TextField(blank=True)

    communities = models.ManyToManyField(
        Community,
        blank=True,
        related_name='hosts',
        through='HostCommunityMapping',
        help_text="Network communities this host belongs to."
    )

    objects = LowerCaseManager()

    class Meta:
        db_table = "host"

    def __str__(self):
        return str(self.name)

    def add_contact(self, email: str) -> HostContact:
        """
        Add a contact email to this host.
        
        Args:
            email: Email address to add
            
        Returns:
            The HostContact instance
        """
        contact, _ = HostContact.objects.get_or_create(email=email)
        self.contacts.add(contact)
        return contact

    def remove_contact(self, email: str) -> None:
        """
        Remove a contact email from this host.
        
        Args:
            email: Email address to remove
            
        Raises:
            HostContact.DoesNotExist: If the contact doesn't exist
        """
        try:
            contact = HostContact.objects.get(email=email)
            self.contacts.remove(contact)
        except HostContact.DoesNotExist:
            raise NotAcceptable(f"Contact email '{email}' not found for this host.")

    def get_contact_emails(self) -> list[str]:
        """
        Get all contact emails for this host.
        
        Returns:
            List of email addresses
        """
        return list(self.contacts.values_list('email', flat=True))

    def _resolve_community_mapping(
        self,
        community: Union[Community, str],
        ip: Optional['Ipaddress'] = None
    ) -> Tuple['Ipaddress', Community]:
        """
        Helper method to resolve a community and IP address for mapping.
        
        If `community` is a string, it looks up the Community in the network corresponding to
        the provided ipaddress (or, if not provided, tries each of the host's IPs).
        
        Returns a tuple (ipaddress, community) if a unique match is found.
        Raises NotAcceptable if no match is found or if the match is ambiguous.
        """
        # Case 1: community is already a Community instance.
        if isinstance(community, Community):
            if ip:
                if ip.host != self:
                    raise NotAcceptable("Provided IP address does not belong to this host.")
                try:
                    net = Network.objects.get(network__net_contains=ip.ipaddress)
                except Network.DoesNotExist:
                    raise NotAcceptable("No network found for the provided IP address.")
                if community.network != net:
                    raise NotAcceptable("Community network does not match the network of the provided IP address.")
                return ip, community
            else:
                matches = []
                for ip in self.ipaddresses.all(): # type: ignore
                    try:
                        net = Network.objects.get(network__net_contains=ip.ipaddress)
                    except Network.DoesNotExist:
                        # Skip IP addresses that don't belong to a network, they can't have communities.
                        # But, we don't raise an error here because there may be other IPs that do.
                        continue
                    if community.network == net:
                        matches.append((ip, community))
                if not matches:
                    raise NotAcceptable("No IP address on host matches the community's network.")
                if len(matches) > 1:
                    raise NotAcceptable("Multiple IP addresses match the community's network; please specify one.")
                return matches[0]

        # Case 2: community is provided as a string.
        else:
            if ip:
                if ip.host != self:
                    raise NotAcceptable("Provided IP address does not belong to this host.")
                try:
                    net = Network.objects.get(network__net_contains=ip.ipaddress)
                except Network.DoesNotExist:
                    raise NotAcceptable("No network found for the provided IP address.")
                try:
                    comm_inst = Community.objects.get(name=community, network=net)
                except Community.DoesNotExist:
                    raise NotAcceptable(f"No community named '{community}' found for network {net}.")
                except Community.MultipleObjectsReturned:
                    raise NotAcceptable(f"Multiple communities found for network {net} with name '{community}'.")
                return ip, comm_inst
            else:
                matches = []
                for ipaddr in self.ipaddresses.all(): # type: ignore
                    try:
                        net = Network.objects.get(network__net_contains=ipaddr.ipaddress)
                    except Network.DoesNotExist:
                        # Skip IP addresses that don't belong to a network, they can't have communities.
                        # But, we don't raise an error here because there may be other IPs that do.
                        continue
                    try:
                        comm_inst = Community.objects.get(name=community, network=net)
                        matches.append((ipaddr, comm_inst))
                    except Community.DoesNotExist:
                        continue
                    except Community.MultipleObjectsReturned:
                        raise NotAcceptable(f"Multiple communities found for network {net} with name '{community}'.")
                if not matches:
                    raise NotAcceptable(f"No community named '{community}' found on any IP network for this host.")
                if len(matches) > 1:
                    raise NotAcceptable(f"Community name '{community}' is ambiguous across multiple networks on this host.")
                return matches[0]

    @transaction.atomic
    def add_to_community(
        self,
        community: Union[Community, str],
        ip: Optional[Union['Ipaddress', str]] = None
    ) -> None:
        """
        Adds this host to the given community.
        
        Accepts a Community instance or a community name (string). If an ipaddress is not provided,
        the helper method attempts to resolve a unique matching IP address from the host's IPs.
        
        Raises NotAcceptable if any check fails.
        """
        if isinstance(ip, str):
            try:
                ipaddress = Ipaddress.objects.get(host=self, ipaddress=ip)
            except Ipaddress.DoesNotExist:
                raise NotAcceptable("No IP address found on this host with the provided value.")
        else:
            ipaddress = ip

        if not self.ipaddresses.exists(): # type: ignore
            raise NotAcceptable("Host has no IP addresses, cannot add to community.")

        resolved_ip, resolved_comm = self._resolve_community_mapping(community, ipaddress)
        try:
            net = Network.objects.get(network__net_contains=resolved_ip.ipaddress)
        except Network.DoesNotExist:
            raise NotAcceptable("No network found for the provided IP address.")

        mac_required = getattr(settings, "MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY", False)
        if mac_required and not resolved_ip.macaddress:
            raise NotAcceptable("The IP must have a MAC address to bind it to a community.")

        # Remove any existing mapping on the same network.
        HostCommunityMapping.objects.filter(
            host=self,
            ipaddress=resolved_ip,
            community__network=net
        ).delete()
        HostCommunityMapping.objects.create(
            host=self,
            ipaddress=resolved_ip,
            community=resolved_comm
        )

    @transaction.atomic
    def remove_from_community(
        self,
        community: Union[Community, str],
        ipaddress: Optional['Ipaddress'] = None
    ) -> None:
        """
        Removes this host's mapping to the specified community.
        
        Accepts a Community instance or a community name (string). If an ipaddress is not provided,
        the helper method attempts to resolve a unique matching IP address from the host's IPs.
        
        Raises NotAcceptable if no matching mapping is found.
        """
        resolved_ip, resolved_comm = self._resolve_community_mapping(community, ipaddress)
        mapping = HostCommunityMapping.objects.filter(
            host=self,
            ipaddress=resolved_ip,
            community=resolved_comm
        )
        if mapping.exists():
            mapping.delete()
        else:
            raise NotAcceptable("No community mapping exists for this host with the specified criteria.")

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
