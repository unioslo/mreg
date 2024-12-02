
from abc import abstractmethod

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models


from structlog import get_logger

from mreg.models.base import BaseModel
from mreg.fields import LowerCaseCharField
from mreg.managers import LowerCaseManager
from mreg.models.base import Label

logger = get_logger()


class PolicyComponent(BaseModel):
    """Abstract base class for policy components.

    This class provides common fields and methods for policy-related models.
    Subclasses are expected to define a 'name' field.
    """

    description = models.CharField(max_length=150)

    class Meta:
        abstract = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Abstract property for the name of the policy component.

        Subclasses must implement this property.
        """
        pass

    def __str__(self) -> str:
        return self.name


def _validate_atom_name(name: str) -> None:
    """Validator to ensure the given atom name is not already used by a PolicyRole.

    :param name: The name to validate.
    :raises: ValidationError: If a PolicyRole with the given name already exists.
    """
    if PolicyRole.objects.filter(name=name).exists():
        raise ValidationError("Already a Role with that name")


class PolicyAtom(PolicyComponent):
    """Model representing an individual policy atom."""

    name = LowerCaseCharField(max_length=64, unique=True, validators=[_validate_atom_name]) # type: ignore

    objects = LowerCaseManager()

    class Meta:
        db_table = "policy_atom"
        ordering = ("name",)


def _validate_role_name(name: str) -> None:
    """Validator to ensure the given role name is not already used by a PolicyAtom.

    :param name: The name to validate.
    :raises: ValidationError: If a PolicyAtom with the given name already exists.
    """
    if PolicyAtom.objects.filter(name=name).exists():
        raise ValidationError("Already an Atom with that name")


class PolicyRole(PolicyComponent):
    """
    Model representing a policy role.

    Roles are collections of policy atoms and can be assigned to various objects.
    """

    name = LowerCaseCharField(max_length=64, unique=True, validators=[_validate_role_name]) # type: ignore
    atoms = models.ManyToManyField(PolicyAtom, related_name="roles")
    labels = models.ManyToManyField(Label, blank=True, related_name="policy_roles")

    objects = LowerCaseManager()

    class Meta:
        db_table = "policy_role"
        ordering = ("name",)


class ApprovedModelForPolicy(BaseModel):
    """
    Model representing an approved model for policy assignments.

    Stores ContentType references to models that can have policies assigned.

    NOTE: Django does not allow ForeignKeys to abstract models, so there is no danger
    of approving an abstract model for policy assignments.
    """

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return f"{self.content_type.app_label}.{self.content_type.model}"

    class Meta:
        db_table = "approved_model_for_policy"


class PolicyAssignment(BaseModel):
    """
    Model representing the assignment of a policy role to an object.

    Uses a generic foreign key to associate the policy role with any object from an approved model.
    """

    policy_role = models.ForeignKey(PolicyRole, on_delete=models.CASCADE, related_name="assignments")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    def clean(self) -> None:
        """Validates that the content_type is in the list of approved models.

        Raises:
            ValidationError: If the content_type is not approved for policy assignments.
        """
        super().clean()
        approved_content_types = ApprovedModelForPolicy.objects.values_list("content_type_id", flat=True)
        if self.content_type not in approved_content_types:
            raise ValidationError("The selected model is not approved for policy assignments.")

    class Meta:
        db_table = "policy_assignment"
