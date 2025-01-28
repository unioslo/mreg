from django.db import models
from mreg.models.base import BaseModel


class NetworkPolicyAttribute(BaseModel):
    """
    Represents an attribute that can be applied to a NetworkPolicy.
    """

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, help_text="Description of the attribute.")

    def __str__(self):
        return self.name


class NetworkPolicy(BaseModel):
    """
    Represents a network policy which consists of a set of NetworkPolicyAttributes.
    """

    name = models.CharField(max_length=100, unique=True, help_text="Name of the network policy.")
    description = models.TextField(blank=True, help_text="Description of the network policy.")
    attributes = models.ManyToManyField(
        NetworkPolicyAttribute,
        through="NetworkPolicyAttributeValue",
        related_name="policies",
        help_text="Attributes associated with this policy.",
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

    name = models.CharField(max_length=100, help_text="Policy-unique name of the community.")
    description = models.CharField(blank=True, max_length=250, help_text="Description of the community.")
    policy = models.ForeignKey(
        NetworkPolicy,
        on_delete=models.CASCADE,
        related_name="communities",
        help_text="The network policy this community is associated with.",
    )

    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ("name",)
        unique_together = ("name", "policy")
