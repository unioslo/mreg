from django.db import models
from django.conf import settings
from mreg.models.base import BaseModel
from mreg.fields import LowerCaseCharField
from mreg.managers import LowerCaseManager
from mreg.models.network import Network

from rest_framework import exceptions

from mreg.utils import is_protected_policy_attribute

class NetworkPolicyAttribute(BaseModel):
    """
    Represents an attribute that can be applied to a NetworkPolicy.
    """

    objects = LowerCaseManager()

    name = LowerCaseCharField(max_length=100, unique=True)
    description = models.TextField(blank=True, help_text="Description of the attribute.")

    def save(self, *args, **kwargs):
        if self.pk:
            original = NetworkPolicyAttribute.objects.filter(pk=self.pk).first()
            if original and is_protected_policy_attribute(original.name) and self.name != original.name:
                raise exceptions.PermissionDenied(detail=f"Cannot rename protected attribute '{original.name}'.")

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if is_protected_policy_attribute(self.name):
            raise exceptions.PermissionDenied(detail=f"Cannot delete the attribute '{self.name}', it is protected.")
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.name



class NetworkPolicy(BaseModel):
    """
    Represents a network policy which consists of a set of NetworkPolicyAttributes.
    """

    objects = LowerCaseManager()

    name = LowerCaseCharField(max_length=100, unique=True, help_text="Name of the network policy.")
    description = models.TextField(blank=True, help_text="Description of the network policy.")
    attributes = models.ManyToManyField(
        NetworkPolicyAttribute,
        through="NetworkPolicyAttributeValue",
        related_name="policies",
        help_text="Attributes associated with this policy.",
    )

    def can_be_used_with_communities_or_raise(self):
        """Determine if this policy can be used with communities.
        
        In settings.py, we may have MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES set, and if we do not have
        all of those attributes in this policy, then we cannot use it with communities.

        :return: Nothing if the policy can be used with communities, otherwise we raise an exception.
        :raises: rest_framework.exceptions.ValidationError if the policy cannot be used with communities.
        """
        required_attributes = getattr(
            settings, "MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES", []
        )
        if required_attributes:
            current_attributes = set(
                self.attributes.filter(name__in=required_attributes).values_list("name", flat=True)
            )
            missing_attributes = [attr for attr in required_attributes if attr not in current_attributes]
            if missing_attributes:
                raise exceptions.ValidationError(
                    {
                        "error":
                        f"Network policy '{self.name}' is missing the following required attributes: {missing_attributes}"
                    }
                )


    def __str__(self):
        return self.name


class NetworkPolicyAttributeValue(models.Model):
    """
    Through model to associate NetworkPolicy with NetworkPolicyAttribute and store their values.
    """

    policy = models.ForeignKey(NetworkPolicy, on_delete=models.CASCADE, related_name="network_policy_attribute_values")
    attribute = models.ForeignKey(
        NetworkPolicyAttribute, on_delete=models.CASCADE, related_name="network_policy_attribute_values"
    )
    value = models.BooleanField(default=False, help_text="Value of the attribute for this network policy.")

    class Meta:
        unique_together = ("policy", "attribute")
        verbose_name = "Policy Attribute Value"
        verbose_name_plural = "Policy Attribute Values"

    def __str__(self):
        return f"{self.policy.name} - {self.attribute.name}: {self.value}"


class Community(BaseModel):
    """
    Represents a community within a NetworkPolicy. Hosts can belong to a community.
    """

    objects = LowerCaseManager()

    name = LowerCaseCharField(max_length=100, help_text="Policy-unique name of the community.")
    description = models.CharField(blank=True, max_length=250, help_text="Description of the community.")
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="communities",
        help_text="The network this community is associated with.",
    )

    def clean(self):
        super().clean()
        required_attributes = getattr(
            settings, "MREG_CREATING_COMMUNITY_REQUIRES_POLICY_WITH_ATTRIBUTES", []
        )
        if required_attributes:
            if self.network.policy:
                self.network.policy.can_be_used_with_communities_or_raise()
            else:
                raise exceptions.ValidationError(
                    {
                        "error":
                        f"Network does not have a policy. The policy must have the following attributes: {required_attributes}" 
                    }
                )

        # Enforce maximum communities per network.
        max_communities = getattr(settings, "MREG_MAX_COMMUNITES_PER_NETWORK", None)
        if max_communities is not None:
            qs = Community.objects.filter(network=self.network)
            # Exclude self when updating an existing record.
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.count() >= max_communities:
                raise exceptions.ValidationError(
                    {"error": f"Network '{self.network}' already has the maximum allowed communities ({max_communities})." }
                )


    def save(self, *args, **kwargs):
        # Run full_clean() to ensure clean() is invoked even when using objects.create()
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ("name",)
        unique_together = ("name", "network")

class HostCommunityMapping(BaseModel):
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    ipaddress = models.ForeignKey('Ipaddress', on_delete=models.CASCADE)
    community = models.ForeignKey(Community, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("host", "ipaddress", "community")
        db_table = "host_community_mapping"

    def __str__(self):
        return f"{self.host} - {self.ipaddress} -> {self.community}"

