
from typing import Any, Type
from django.db import models


class LowerCaseManager(models.Manager[Any]):
    """Compatibility manager; LowerCaseCharField lookups handle normalization."""


def lower_case_manager_factory(base_manager: Type[models.Manager[Any]]):
    """Retain custom manager behavior for models using LowerCaseManager."""

    class LowerCaseBaseManager(base_manager, LowerCaseManager):
        """Combine a custom manager with the compatibility manager."""
        pass

    return LowerCaseBaseManager
